from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient  # noqa: E402
from agentguard_langgraph_adapter.event_models import AuditEvent, PolicyDecision, ToolCallEvent, ToolDescriptor  # noqa: E402
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway  # noqa: E402


def test_guard_api_v03_client_preserves_top_level_approval(monkeypatch) -> None:
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="http://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    def fake_post_json(self: AgentGuardCoreClient, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert path == "/v1/guard/evaluate"
        return {
            "decision": {
                "decision_id": "dec_ask",
                "decision": "ask",
                "risk_score": 55,
                "severity": "medium",
                "rule_hits": [],
                "reason": "human review required",
            },
            "approval": {
                "approval_id": "app_123",
                "required": True,
                "options": ["allow_once", "deny"],
            },
        }

    monkeypatch.setattr(AgentGuardCoreClient, "_post_json", fake_post_json)

    decision = client.evaluate_tool_call(
        {
            "trace_id": "trace_approval",
            "tool": {"name": "memory_write"},
            "arguments": {"namespace": "user_preferences"},
        }
    )

    assert decision["approval"]["approval_id"] == "app_123"


def test_gateway_executes_ask_tool_call_after_allow_once_approval() -> None:
    guard = _ApprovingGuardAdapter()
    runtime = _Runtime()
    gateway = GuardedToolGateway(guard_adapter=guard, tool_runtime=runtime)

    result = gateway.invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "user_preferences", "key": "style", "value": "concise"},
        security={"user_task": "Remember my report style."},
        trace_id="trace_approval",
        call_id="call_approval",
    )

    assert guard.waited_for == "app_allow"
    assert runtime.calls == [("memory_write", {"namespace": "user_preferences", "key": "style", "value": "concise"})]
    assert result.executed is True
    assert result.blocked is False
    assert result.decision == "ask"


class _ApprovingGuardAdapter:
    waited_for: str | None = None

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        event = ToolCallEvent(
            trace_id=trace_id,
            tool=ToolDescriptor(name=tool_name, category="memory", kind="memory_write", call_id=call_id or "call"),
            arguments=arguments,
        )
        decision = PolicyDecision(
            decision_id="dec_ask",
            decision="ask",
            risk_score=55,
            severity="medium",
            rule_hits=[],
            reason="human review required",
            safe_message="Approval required.",
            approval={"approval_id": "app_allow", "required": True},
        )
        return event, decision

    def build_audit_event(self, event: ToolCallEvent, decision: PolicyDecision) -> AuditEvent:
        return AuditEvent(
            trace_id=event.trace_id,
            summary="review memory write",
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            reason=decision.reason,
        )

    def submit_audit_event(self, audit_event: AuditEvent) -> dict[str, Any]:
        return {"ok": True, "audit_id": audit_event.audit_id}

    def wait_for_approval(self, approval_id: str) -> dict[str, Any]:
        self.waited_for = approval_id
        return {"status": "resolved", "decision": "allow_once"}


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.calls)

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return {"ok": True}

    def diff(self, before: list[tuple[str, dict[str, Any]]] | None) -> list[dict[str, Any]]:
        return [{"type": "call", "count": len(self.calls) - len(before or [])}]
