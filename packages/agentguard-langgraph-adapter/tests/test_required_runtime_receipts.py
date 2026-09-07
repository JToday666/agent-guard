"""Exercise required receipt gates through the public product tool gateway."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    RuntimeGuardEvent,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.strong_binding import ExecutionLeaseReference
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway

CALL_ID = "call_required_receipt"
BINDING_ID = "binding:required_receipt"
FINGERPRINT = "hmac-sha256:" + "a" * 64


def _decision(*, ask: bool = False, durable_directive: bool = False) -> PolicyDecision:
    raw: dict[str, Any] = {
        "decision_id": "dec_required_receipt",
        "decision": "ask" if ask else "allow",
        "risk_score": 60 if ask else 0,
        "severity": "medium" if ask else "low",
        "reason": "Exercise the real gateway with deterministic receipt responses.",
        "policy_audit_id": "audit_policy_required_receipt",
    }
    if ask:
        raw["approval"] = {"approval_id": "app_required_receipt", "required": True}
        raw["enforcement_binding"] = {
            "schema_version": "2.1",
            "action_id": CALL_ID,
            "authorization_fingerprint": FINGERPRINT,
            "runtime_binding_id": BINDING_ID,
            "requires_execution_lease": True,
        }
    if durable_directive:
        raw["decision_authority"] = {
            "source": "v21",
            "mode": "active",
            "selection_basis": "profile_all",
            "legacy_floor_applied": False,
            "activation_ref_digest": "sha256:" + "b" * 64,
            "approval_release": "strong_binding_required",
        }
        raw["approval_release_directive"] = {
            "mode": "strong_binding",
            "required_runtime_profile": "C3",
            "human_only": True,
            "single_use": True,
            "action_binding": "exact",
            "receipt_requirement": "required_durable",
            "activation_ref_digest": "sha256:" + "b" * 64,
            "scope_digest": "sha256:" + "c" * 64,
            "capability_digest": "sha256:" + "d" * 64,
            "residual_boundaries": [],
        }
    return PolicyDecision.model_validate(raw)


class _Guard:
    def __init__(
        self,
        *,
        mode: str | None = "required",
        ask: bool = False,
        durable_directive: bool = False,
        start_response: str = "recorded",
        terminal_response: str = "recorded",
    ) -> None:
        self.config = SimpleNamespace(
            core_api_mode="guard-api-v0.3",
            defense_enabled=True,
            runtime_binding_id=BINDING_ID,
        )
        if mode is not None:
            self.config.runtime_receipt_mode = mode
        self.decision = _decision(ask=ask, durable_directive=durable_directive)
        self.start_response = start_response
        self.terminal_response = terminal_response
        self.timeline: list[str] = []
        self.receipts: list[dict[str, Any]] = []
        self.wait_calls = 0
        self.consume_calls = 0

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        self.timeline.append("evaluate")
        return (
            ToolCallEvent(
                event_id="evt_required_receipt",
                trace_id=trace_id,
                security_context=SecurityContext(agent_id="langgraph"),
                tool=ToolDescriptor(
                    name=tool_name, category="tool", kind="execute", call_id=call_id
                ),
                arguments=arguments,
            ),
            self.decision,
        )

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        assert approval_id == "app_required_receipt"
        self.timeline.append("human_approval")
        self.wait_calls += 1
        return {
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
        }

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        assert approval_id == "app_required_receipt"
        assert action_id == CALL_ID
        assert authorization_fingerprint == FINGERPRINT
        self.timeline.append("lease_consume")
        self.consume_calls += 1
        return ExecutionLeaseReference(
            lease_id="lease_required_receipt",
            consumption_id="consume_required_receipt",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        )

    def submit_audit_event(self, receipt: Any) -> Any:
        raw = receipt.model_dump(mode="json")
        self.receipts.append(raw)
        started = raw["record_type"] == "runtime_observation"
        self.timeline.append("start_receipt" if started else "terminal_receipt")
        behavior = self.start_response if started else self.terminal_response
        if behavior == "exception":
            raise OSError("Receipt transport unavailable")
        if behavior == "rejected":
            return {"ok": False, "error": "Receipt rejected"}
        if behavior == "wrong_audit_id":
            return {"ok": True, "audit_id": "audit_another_invocation"}
        if behavior == "no_response":
            return None
        if behavior == "missing_ok":
            return {"audit_id": receipt.audit_id}
        return {"ok": True, "audit_id": receipt.audit_id}


class _IsolatingGuard(_Guard):
    def evaluate_tool_result(
        self, **kwargs: Any
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        self.timeline.append("result_isolation")
        return (
            RuntimeGuardEvent(
                event_id="evt_result_required_receipt",
                event_type="tool_result_produced",
                trace_id=kwargs["trace_id"],
                security_context=SecurityContext(agent_id="langgraph"),
                payload={"tool": {"name": kwargs["tool_name"], "call_id": CALL_ID}},
            ),
            PolicyDecision(
                decision_id="dec_result_required_receipt",
                decision="deny",
                risk_score=95,
                severity="high",
                reason="Tool output must not enter the model context.",
                policy_audit_id="audit_policy_result_required_receipt",
            ),
        )


class _Runtime:
    def __init__(self, guard: _Guard, *, raises: bool = False) -> None:
        self.guard = guard
        self.raises = raises
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.guard.timeline.append("invoke")
        self.calls.append((tool_name, dict(arguments)))
        if self.raises:
            raise RuntimeError("The tool invocation failed")
        return {"content": "Sandbox result"}


def _invoke(guard: _Guard, runtime: _Runtime):
    return GuardedToolGateway(guard_adapter=guard, tool_runtime=runtime).invoke_tool(
        tool_name="sandbox_tool",
        arguments={"path": "/sandbox/example.txt"},
        security={"user_task": "Read the safe sandbox fixture."},
        trace_id="trace_required_receipt",
        call_id=CALL_ID,
    )


@pytest.mark.integration
@pytest.mark.parametrize("mode", [None, "best_effort"])
def test_best_effort_retains_execution_when_receipts_are_disabled(
    mode: str | None,
) -> None:
    guard = _Guard(mode=mode)
    guard.config.defense_enabled = False
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert len(runtime.calls) == 1
    assert result.executed is True
    assert result.runtime_receipt_status == "disabled"
    assert result.runtime_receipt_error is None
    assert guard.receipts == []


@pytest.mark.integration
@pytest.mark.parametrize("missing", ["submit", "enabled", "policy_audit_id"])
def test_required_receipt_preflight_blocks_before_human_wait_or_lease(
    missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _Guard(ask=True)
    if missing == "submit":
        monkeypatch.setattr(guard, "submit_audit_event", None)
    elif missing == "enabled":
        guard.config.defense_enabled = False
    else:
        guard.decision.policy_audit_id = None
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert runtime.calls == []
    assert guard.wait_calls == 0
    assert guard.consume_calls == 0
    assert result.executed is False
    assert result.blocked is True
    assert result.runtime_receipt_status == "failed"
    assert result.runtime_receipt_error


@pytest.mark.integration
@pytest.mark.parametrize("drift", ["disabled", "missing_submit"])
def test_required_start_cannot_be_skipped_after_snapshot_configuration_drift(
    drift: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DriftingRuntime(_Runtime):
        def snapshot(self) -> None:
            if drift == "disabled":
                self.guard.config.defense_enabled = False
            else:
                monkeypatch.setattr(self.guard, "submit_audit_event", None)

        def diff(self, before: None) -> list[dict[str, Any]]:
            return []

    guard = _Guard()
    runtime = DriftingRuntime(guard)

    result = _invoke(guard, runtime)

    assert runtime.calls == []
    assert result.executed is False
    assert result.blocked is True
    assert result.runtime_receipt_status == "failed"
    assert result.runtime_receipt_error
    assert guard.timeline == ["evaluate"]
    assert guard.receipts == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "tool_name,event_type",
    [
        ("memory_write", "memory_write_proposed"),
        ("send_email", "message_send_proposed"),
    ],
)
@pytest.mark.parametrize(
    "approval_outcome,uncorrelated_stage",
    [
        ("allow_once", "start"),
        ("allow_once", "terminal"),
        ("deny", "terminal"),
        ("non_human", "terminal"),
    ],
)
def test_secondary_gate_preserves_required_receipts_across_approval_config_downgrade(
    tool_name: str, event_type: str, approval_outcome: str, uncorrelated_stage: str
) -> None:
    class SecondaryGuard(_Guard):
        def _evaluate_secondary(
            self, **kwargs: Any
        ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
            assert self.config.runtime_receipt_mode == "best_effort"
            self.config.runtime_receipt_mode = "required"
            self.timeline.append(event_type)
            decision = _decision(ask=True)
            decision.policy_audit_id = "audit_policy_secondary_required_receipt"
            return (
                RuntimeGuardEvent(
                    event_id="evt_secondary_required_receipt",
                    event_type=event_type,
                    trace_id=kwargs["trace_id"],
                    security_context=SecurityContext(agent_id="langgraph"),
                    payload={"action_id": CALL_ID},
                ),
                decision,
            )

        def evaluate_memory_write(
            self, **kwargs: Any
        ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
            return self._evaluate_secondary(**kwargs)

        def evaluate_message_send(
            self, **kwargs: Any
        ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
            return self._evaluate_secondary(**kwargs)

        def wait_for_approval(
            self, approval_id: str, timeout: float | None = None
        ) -> dict[str, Any]:
            assert self.config.runtime_receipt_mode == "required"
            resolution = super().wait_for_approval(approval_id, timeout)
            self.config.runtime_receipt_mode = "best_effort"
            if approval_outcome == "deny":
                resolution["decision"] = "deny"
            elif approval_outcome == "non_human":
                resolution["resolution_source"] = "llm"
            return resolution

        def submit_audit_event(self, receipt: Any) -> Any:
            response = super().submit_audit_event(receipt)
            stage = (
                "start" if receipt.record_type == "runtime_observation" else "terminal"
            )
            if stage == uncorrelated_stage:
                response.pop("audit_id")
            return response

    guard = SecondaryGuard(mode="best_effort")
    runtime = _Runtime(guard)

    result = GuardedToolGateway(guard_adapter=guard, tool_runtime=runtime).invoke_tool(
        tool_name=tool_name,
        arguments={"path": "/sandbox/example.txt"},
        security={"user_task": "Run the safe secondary gate fixture."},
        trace_id="trace_secondary_required_receipt",
        call_id=CALL_ID,
    )

    approval_released = approval_outcome == "allow_once"
    invoked = approval_released and uncorrelated_stage == "terminal"
    assert guard.wait_calls == 1
    assert guard.consume_calls == int(approval_released)
    assert guard.config.runtime_receipt_mode == "best_effort"
    assert len(runtime.calls) == int(invoked)
    assert result.executed is invoked
    assert result.runtime_receipt_status == "failed"
    assert result.runtime_receipt_error and "audit_id" in result.runtime_receipt_error
    assert guard.timeline == [
        "evaluate",
        event_type,
        "human_approval",
        *(["lease_consume", "start_receipt"] if approval_released else []),
        *(["invoke"] if invoked else []),
        "terminal_receipt",
    ]


@pytest.mark.integration
@pytest.mark.parametrize("ask", [False, True])
def test_required_receipts_record_start_before_exactly_one_invoke_and_terminal(
    ask: bool,
) -> None:
    guard = _Guard(ask=ask)
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert runtime.calls == [("sandbox_tool", {"path": "/sandbox/example.txt"})]
    assert result.executed is True
    assert result.blocked is False
    assert result.runtime_receipt_status == "recorded"
    assert result.runtime_receipt_error is None
    assert guard.timeline == [
        "evaluate",
        *(["human_approval", "lease_consume"] if ask else []),
        "start_receipt",
        "invoke",
        "terminal_receipt",
    ]
    started, terminal = guard.receipts
    assert terminal["links"]["parent_audit_id"] == started["audit_id"]
    assert terminal["evidence"]["execution"]["status"] == "executed"


@pytest.mark.integration
@pytest.mark.parametrize(
    "response", ["rejected", "exception", "wrong_audit_id", "no_response", "missing_ok"]
)
def test_required_start_requires_positive_acknowledgement_of_exact_audit_id(
    response: str,
) -> None:
    guard = _Guard(start_response=response)
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert runtime.calls == []
    assert result.executed is False
    assert result.blocked is True
    assert result.runtime_receipt_status == "failed"
    assert result.runtime_receipt_error
    assert "invoke" not in guard.timeline
    for receipt in guard.receipts:
        if receipt["record_type"] == "runtime_outcome":
            assert receipt["evidence"]["execution"]["status"] == "not_invoked"


@pytest.mark.integration
@pytest.mark.parametrize("response", ["rejected", "exception", "wrong_audit_id"])
def test_required_terminal_failure_preserves_execution_without_retry(
    response: str,
) -> None:
    guard = _Guard(terminal_response=response)
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert len(runtime.calls) == 1
    assert result.executed is True
    assert result.status == "executed"
    assert result.result == {"content": "Sandbox result"}
    assert result.runtime_receipt_status == "failed"
    assert result.runtime_receipt_error
    assert guard.timeline.count("invoke") == 1
    assert guard.timeline.count("terminal_receipt") == 1
    assert guard.receipts[-1]["evidence"]["execution"]["status"] == "executed"


@pytest.mark.integration
def test_tool_exception_is_invoked_once_and_records_execution_failed() -> None:
    guard = _Guard()
    runtime = _Runtime(guard, raises=True)

    result = _invoke(guard, runtime)

    assert len(runtime.calls) == 1
    assert result.status == "error"
    assert result.runtime_receipt_status == "recorded"
    assert result.runtime_receipt_error is None
    assert guard.timeline == ["evaluate", "start_receipt", "invoke", "terminal_receipt"]
    terminal = guard.receipts[-1]
    assert terminal["metadata"]["outcome_kind"] == "execution_failed"
    assert terminal["evidence"]["execution"]["status"] == "failed"


@pytest.mark.integration
@pytest.mark.parametrize("response", ["recorded", "rejected"])
def test_result_isolation_preserves_invocation_and_explicit_terminal_status(
    response: str,
) -> None:
    guard = _IsolatingGuard(terminal_response=response)
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert len(runtime.calls) == 1
    assert result.executed is True
    assert result.blocked is True
    assert result.status == "quarantined"
    assert result.result is None
    assert result.quarantine_applied is True
    assert result.runtime_receipt_status == (
        "recorded" if response == "recorded" else "failed"
    )
    assert guard.timeline == [
        "evaluate",
        "start_receipt",
        "invoke",
        "result_isolation",
        "terminal_receipt",
    ]
    terminal = guard.receipts[-1]
    assert terminal["evidence"]["execution"]["status"] == "executed"
    assert terminal["evidence"]["execution"]["tool_result_entered_context"] is False
    assert terminal["evidence"]["result"]["disposition"] == "quarantined"


@pytest.mark.integration
def test_required_quarantine_missing_policy_id_cannot_be_overwritten_by_success() -> (
    None
):
    class MissingPolicyGuard(_IsolatingGuard):
        def evaluate_tool_result(
            self, **kwargs: Any
        ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
            event, decision = super().evaluate_tool_result(**kwargs)
            decision.policy_audit_id = None
            return event, decision

    guard = MissingPolicyGuard()
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert len(runtime.calls) == 1
    assert result.executed is True
    assert result.status == "quarantined"
    assert result.result is None
    assert result.quarantine_applied is True
    assert result.runtime_receipt_status == "failed"
    assert (
        result.runtime_receipt_error
        and "policy_audit_id" in result.runtime_receipt_error
    )
    assert guard.timeline == ["evaluate", "start_receipt", "invoke", "result_isolation"]
    assert [receipt["record_type"] for receipt in guard.receipts] == [
        "runtime_observation"
    ]


@pytest.mark.integration
def test_required_durable_directive_cannot_be_weakened_by_best_effort_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _Guard(mode="best_effort", ask=True, durable_directive=True)
    monkeypatch.setattr(guard, "submit_audit_event", None)
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert runtime.calls == []
    assert guard.wait_calls == 0
    assert guard.consume_calls == 0
    assert result.runtime_receipt_status == "failed"
    assert result.blocked is True


@pytest.mark.integration
@pytest.mark.parametrize("response", ["recorded", "wrong_audit_id"])
def test_required_durable_directive_enforces_strict_start_ack_in_best_effort_mode(
    response: str,
) -> None:
    guard = _Guard(
        mode="best_effort", ask=True, durable_directive=True, start_response=response
    )
    runtime = _Runtime(guard)

    result = _invoke(guard, runtime)

    assert guard.wait_calls == 1
    assert guard.consume_calls == 1
    assert len(runtime.calls) == (1 if response == "recorded" else 0)
    assert result.runtime_receipt_status == (
        "recorded" if response == "recorded" else "failed"
    )
