from __future__ import annotations

from typing import Any

from agentguard_langgraph_bench.adapter.event_models import AuditEvent, PolicyDecision, ToolCallEvent, ToolDescriptor
from agentguard_langgraph_bench.bench.config import ensure_sandbox
from agentguard_langgraph_bench.bench.runner import _decision_record
from agentguard_langgraph_bench.bench.runtime.tool_gateway import GuardedToolGateway
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def test_gateway_fail_closed_keeps_ask_as_block_default(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    guard = _AskApprovalGuard({"status": "resolved", "decision": "allow_once"})
    gateway = GuardedToolGateway(guard_adapter=guard, tool_runtime=MockToolRegistry(tmp_path))

    result = gateway.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/blocked.txt", "content": "blocked"},
        security={"case_id": "BN-ASK", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_ask",
        call_id="call_ask",
    )

    assert result.executed is False
    assert result.blocked is True
    assert result.approval_mode == "fail-closed"
    assert result.approval_id == "app_wait"
    assert result.approval_consumed is False
    assert result.block_semantics == "ask_as_block"
    assert result.counts_as_effective_block is False
    assert guard.wait_calls == []
    assert not (tmp_path / "files" / "reports" / "blocked.txt").exists()

    record = _decision_record(result.model_dump(), {"trace_id": "trace_ask", "case_id": "BN-ASK"})
    assert record["approval_mode"] == "fail-closed"
    assert record["block_semantics"] == "ask_as_block"
    assert record["counts_as_effective_block"] is False


def test_gateway_wait_mode_executes_original_call_after_allow_once(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    guard = _AskApprovalGuard({"status": "resolved", "decision": "allow_once"})
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=MockToolRegistry(tmp_path),
        approval_mode="wait",
        approval_timeout=1.0,
    )

    result = gateway.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/approved.txt", "content": "approved"},
        security={"case_id": "BN-ALLOW", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_allow",
        call_id="call_allow",
    )

    assert result.executed is True
    assert result.blocked is False
    assert result.decision == "ask"
    assert result.approval_mode == "wait"
    assert result.approval_consumed is True
    assert result.approval_decision == "allow_once"
    assert result.approved_arguments_hash
    assert result.tool_executed_after_approval is True
    assert result.block_semantics == "approval_allow_continue"
    assert result.counts_as_effective_block is False
    assert guard.wait_calls[0][0] == "app_wait"
    assert 0 < (guard.wait_calls[0][1] or 0) <= 1.0
    assert (tmp_path / "files" / "reports" / "approved.txt").read_text(encoding="utf-8") == "approved"


def test_gateway_wait_mode_blocks_after_consumed_deny(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    guard = _AskApprovalGuard({"status": "resolved", "decision": "deny"})
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=MockToolRegistry(tmp_path),
        approval_mode="wait",
        approval_timeout=1.0,
    )

    result = gateway.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/denied.txt", "content": "denied"},
        security={"case_id": "AA-DENY", "attack_type": "agent_abuse", "is_malicious": True},
        trace_id="trace_deny",
        call_id="call_deny",
    )

    assert result.executed is False
    assert result.blocked is True
    assert result.approval_consumed is True
    assert result.approval_decision == "deny"
    assert result.tool_executed_after_approval is False
    assert result.block_semantics == "approval_denied_before_harm"
    assert result.counts_as_effective_block is True
    assert not (tmp_path / "files" / "reports" / "denied.txt").exists()


def test_gateway_wait_mode_timeout_is_not_effective_block(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    guard = _AskApprovalGuard({"status": "pending", "decision": None})
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=MockToolRegistry(tmp_path),
        approval_mode="wait",
        approval_timeout=0.001,
    )

    result = gateway.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/timeout.txt", "content": "timeout"},
        security={"case_id": "BN-TIMEOUT", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_timeout",
        call_id="call_timeout",
    )

    assert result.executed is False
    assert result.blocked is True
    assert result.approval_consumed is False
    assert result.approval_decision == "timeout"
    assert result.block_semantics == "approval_timeout_block"
    assert result.counts_as_effective_block is False
    assert guard.wait_calls
    assert not (tmp_path / "files" / "reports" / "timeout.txt").exists()


def test_gateway_wait_mode_blocks_allow_once_binding_mismatch(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    guard = _AskApprovalGuard(
        {
            "status": "resolved",
            "decision": "allow_once",
            "tool_call_id": "call_other",
            "tool_name": "write_file",
            "trace_id": "trace_allow",
            "arguments_hash": "sha256:not-the-reviewed-arguments",
        }
    )
    gateway = GuardedToolGateway(
        guard_adapter=guard,
        tool_runtime=MockToolRegistry(tmp_path),
        approval_mode="wait",
        approval_timeout=1.0,
    )

    result = gateway.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/mismatch.txt", "content": "mismatch"},
        security={"case_id": "BN-MISMATCH", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_allow",
        call_id="call_allow",
    )

    assert result.executed is False
    assert result.blocked is True
    assert result.approval_consumed is True
    assert result.approval_decision == "allow_once"
    assert result.block_semantics == "approval_binding_mismatch"
    assert result.counts_as_effective_block is False
    assert result.tool_executed_after_approval is False
    assert not (tmp_path / "files" / "reports" / "mismatch.txt").exists()


class _AskApprovalGuard:
    def __init__(self, resolution: dict[str, Any]) -> None:
        self.resolution = resolution
        self.wait_calls: list[tuple[str, float | None]] = []

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
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            tool=ToolDescriptor(name=tool_name, category="file", kind="file_write", call_id=call_id or "call"),
            arguments=arguments,
        )
        decision = PolicyDecision(
            decision_id="dec_ask",
            decision="ask",
            risk_score=70,
            severity="medium",
            rule_hits=[],
            reason="approval required",
            safe_message="Approval required.",
            approval={"approval_id": "app_wait", "required": True},
        )
        return event, decision

    def build_audit_event(self, event: ToolCallEvent, decision: PolicyDecision) -> AuditEvent:
        return AuditEvent(
            trace_id=event.trace_id,
            case_id=event.case_id,
            summary="approval test",
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            reason=decision.reason,
        )

    def submit_audit_event(self, audit_event: AuditEvent) -> dict[str, Any]:
        return {"ok": True, "audit_id": audit_event.audit_id}

    def wait_for_approval(self, approval_id: str, timeout: float | None = None) -> dict[str, Any]:
        self.wait_calls.append((approval_id, timeout))
        return dict(self.resolution)
