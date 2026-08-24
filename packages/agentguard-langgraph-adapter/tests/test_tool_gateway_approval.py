from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient  # noqa: E402
from agentguard_langgraph_adapter.event_models import (  # noqa: E402
    AuditEvent,
    Decision,
    PolicyDecision,
    RuntimeGuardEvent,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway  # noqa: E402


def test_guard_api_v03_client_preserves_top_level_approval(monkeypatch) -> None:
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    def fake_post_json(
        self: AgentGuardCoreClient, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
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
    assert runtime.calls == [
        (
            "memory_write",
            {"namespace": "user_preferences", "key": "style", "value": "concise"},
        )
    ]
    assert result.executed is True
    assert result.blocked is False
    assert result.decision == "ask"


def test_message_gate_polls_until_late_allow_once_approval() -> None:
    guard = _MessageSendApprovingGuardAdapter(
        main_decision="allow",
        approval_sequence=[
            {"status": "pending"},
            {"status": "resolved", "decision": "allow_once"},
        ],
    )
    runtime = _Runtime()
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=runtime,
        approval_timeout=2.0,
        approval_poll_interval=0.1,
    )

    result = gateway.invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_approval",
        call_id="call_message_approval",
    )

    assert guard.wait_calls == ["app_message", "app_message"]
    assert result.executed is True
    assert result.blocked is False
    assert runtime.calls == [
        ("send_email", {"to": "owner@example.test", "body": "status update"})
    ]


def test_message_gate_fails_closed_when_approval_stays_pending() -> None:
    guard = _MessageSendApprovingGuardAdapter(
        main_decision="allow",
        approval_sequence=[{"status": "pending"}],
    )
    runtime = _Runtime()
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=runtime,
        approval_timeout=0.2,
        approval_poll_interval=0.1,
    )

    result = gateway.invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_pending",
        call_id="call_message_pending",
    )

    assert guard.wait_calls
    assert result.executed is False
    assert result.blocked is True
    assert result.decision == "ask"
    assert result.block_semantics == "approval_block"
    assert runtime.calls == []


def test_message_gate_fails_closed_when_allow_arrives_after_deadline() -> None:
    guard = _MessageSendApprovingGuardAdapter(
        main_decision="allow",
        approval_sequence=[{"status": "resolved", "decision": "allow_once"}],
        wait_delay_seconds=0.03,
    )
    runtime = _Runtime()
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=runtime,
        approval_timeout=0.01,
        approval_poll_interval=0.001,
    )

    result = gateway.invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_late_approval",
        call_id="call_message_late_approval",
    )

    assert guard.wait_calls == ["app_message"]
    assert result.executed is False
    assert result.blocked is True
    assert result.decision == "ask"
    assert result.block_semantics == "approval_block"
    assert runtime.calls == []


def test_approved_message_gate_owns_started_and_terminal_receipts() -> None:
    guard = _ReceiptMessageSendApprovingGuardAdapter()
    runtime = _Runtime()

    result = GuardedToolGateway(guard_adapter=guard, tool_runtime=runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_receipt",
        call_id="call_message_receipt",
    )

    assert result.executed is True
    assert [receipt["record_type"] for receipt in guard.receipts] == [
        "runtime_observation",
        "runtime_outcome",
    ]
    started, terminal = guard.receipts
    for receipt in (started, terminal):
        assert receipt["links"]["event_id"] == "evt_call_message_receipt"
        assert receipt["links"]["action_id"] == "act_evt_call_message_receipt"
        assert receipt["links"]["decision_id"] == "dec_ask_message"
        assert receipt["links"]["policy_audit_id"] == "audit_policy_message"
        assert receipt["links"]["approval_id"] == "app_message"
        assert receipt["evidence"]["approval"]["status"] == "allowed"
        assert receipt["evidence"]["approval"]["decision"] == "allow_once"
    assert started["links"]["parent_audit_id"] == "audit_policy_message"
    assert terminal["links"]["parent_audit_id"] == started["audit_id"]


def test_late_message_approval_records_message_linked_not_invoked_receipt() -> None:
    guard = _ReceiptMessageSendApprovingGuardAdapter(wait_delay_seconds=0.03)
    runtime = _Runtime()

    result = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=runtime,
        approval_timeout=0.01,
        approval_poll_interval=0.001,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_timeout_receipt",
        call_id="call_message_timeout_receipt",
    )

    assert result.blocked is True
    assert runtime.calls == []
    assert len(guard.receipts) == 1
    terminal = guard.receipts[0]
    assert terminal["record_type"] == "runtime_outcome"
    assert terminal["links"] == {
        "event_id": "evt_call_message_timeout_receipt",
        "decision_id": "dec_ask_message",
        "policy_audit_id": "audit_policy_message",
        "action_id": "act_evt_call_message_timeout_receipt",
        "approval_id": "app_message",
    }
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert terminal["evidence"]["approval"]["status"] == "expired"


def test_allowed_message_gate_keeps_primary_tool_receipt_context() -> None:
    guard = _ReceiptMessageSendAllowingGuardAdapter()

    result = GuardedToolGateway(
        guard_adapter=guard, tool_runtime=_Runtime()
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "owner@example.test", "body": "status update"},
        security={"user_task": "Send my status update."},
        trace_id="trace_message_allow_receipt",
        call_id="call_message_allow_receipt",
    )

    assert result.executed is True
    for receipt in guard.receipts:
        assert receipt["links"]["action_id"] == "call_message_allow_receipt"
        assert receipt["links"]["policy_audit_id"] == "audit_policy_tool"
        assert "approval_id" not in receipt["links"]


class _ApprovingGuardAdapter:
    def __init__(
        self,
        *,
        main_decision: Decision = "ask",
        approval_sequence: list[dict[str, Any]] | None = None,
        wait_delay_seconds: float = 0.0,
    ) -> None:
        self.main_decision: Decision = main_decision
        self.approval_sequence = list(
            approval_sequence or [{"status": "resolved", "decision": "allow_once"}]
        )
        self.waited_for: str | None = None
        self.wait_calls: list[str] = []
        self.wait_delay_seconds = wait_delay_seconds

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
            tool=ToolDescriptor(
                name=tool_name,
                category="memory",
                kind="memory_write",
                call_id=call_id or "call",
            ),
            arguments=arguments,
        )
        decision = PolicyDecision(
            decision_id="dec_ask",
            decision=self.main_decision,
            risk_score=55,
            severity="medium",
            rule_hits=[],
            reason="human review required",
            safe_message="Approval required.",
            approval=(
                {"approval_id": "app_allow", "required": True}
                if self.main_decision == "ask"
                else None
            ),
        )
        return event, decision

    def build_audit_event(
        self, event: ToolCallEvent, decision: PolicyDecision
    ) -> AuditEvent:
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
        self.wait_calls.append(approval_id)
        if self.wait_delay_seconds:
            time.sleep(self.wait_delay_seconds)
        if len(self.approval_sequence) > 1:
            return self.approval_sequence.pop(0)
        return self.approval_sequence[0]


class _MessageSendApprovingGuardAdapter(_ApprovingGuardAdapter):
    def evaluate_message_send(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = RuntimeGuardEvent(
            event_id=f"evt_{call_id or 'message'}",
            event_type="message_send_proposed",
            trace_id=trace_id,
            security_context=SecurityContext(agent_id="langgraph"),
            payload={
                "channel": "email",
                "recipient": arguments.get("to"),
                "content_preview": arguments.get("body", ""),
                "contains_sensitive_data": False,
                "sanitized": False,
                "derived_resources": [],
            },
        )
        decision = PolicyDecision(
            decision_id="dec_ask_message",
            decision="ask",
            risk_score=55,
            severity="medium",
            rule_hits=[],
            reason="human review required",
            safe_message="Approval required.",
            approval={"approval_id": "app_message", "required": True},
        )
        return event, decision


class _ReceiptMessageSendApprovingGuardAdapter(_MessageSendApprovingGuardAdapter):
    def __init__(self, *, wait_delay_seconds: float = 0.0) -> None:
        super().__init__(
            main_decision="allow",
            approval_sequence=[{"status": "resolved", "decision": "allow_once"}],
            wait_delay_seconds=wait_delay_seconds,
        )
        self.config = SimpleNamespace(
            core_api_mode="guard-api-v0.3",
            defense_enabled=True,
            competition_mode=False,
        )
        self.receipts: list[dict[str, Any]] = []

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        event, decision = super().evaluate_before_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        decision.policy_audit_id = "audit_policy_tool"
        return event, decision

    def evaluate_message_send(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event, decision = super().evaluate_message_send(
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        decision.policy_audit_id = "audit_policy_message"
        return event, decision

    def submit_audit_event(self, audit_event: AuditEvent) -> dict[str, Any]:
        self.receipts.append(audit_event.model_dump(mode="json"))
        return {"ok": True, "audit_id": audit_event.audit_id}


class _ReceiptMessageSendAllowingGuardAdapter(_ReceiptMessageSendApprovingGuardAdapter):
    def evaluate_message_send(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event, decision = super().evaluate_message_send(
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        decision.decision = "allow"
        decision.approval = None
        return event, decision


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.calls)

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return {"ok": True}

    def diff(
        self, before: list[tuple[str, dict[str, Any]]] | None
    ) -> list[dict[str, Any]]:
        return [{"type": "call", "count": len(self.calls) - len(before or [])}]
