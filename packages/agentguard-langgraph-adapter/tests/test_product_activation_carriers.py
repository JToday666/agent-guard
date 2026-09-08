"""Historical Product ACKs remain private and follow the server authority anchor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from agentguard_core.decisions.models import RuntimeOutcomeReceipt as CoreReceipt
from agentguard_langgraph_adapter.activation_ack import ActivationAckV1
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    RuntimeOutcomeMetadata,
    RuntimeOutcomeReceipt,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.runtime_receipts import (
    build_runtime_outcome,
    build_tool_started_observation,
    submit_runtime_receipt_result,
)
import agentguard_langgraph_adapter.strong_binding as binding_module
from agentguard_langgraph_adapter.strong_binding import (
    ExecutionLeaseConsumeError,
    ExecutionLeaseCorrelation,
    ExecutionLeaseReference,
    StrongBindingFailure,
    authorize_strong_approval,
)
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway

NOW = datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc)
AGENT = "agent_product_carrier"
BINDING = "binding:product_carrier"
ACTION = "call_product_carrier"


def _ack(
    *, age: int = 0, duration: int = 120, token: str = "a", **changes: Any
) -> ActivationAckV1:
    issued = NOW - timedelta(seconds=age)
    return ActivationAckV1.model_validate(
        {
            "schema_version": "1.0",
            "runtime": "langgraph",
            "runtime_version": "1.2.7",
            "plugin_version": "0.1.0rc1",
            "agent_id": AGENT,
            "runtime_binding_id": BINDING,
            "profile_id": "agentguard-langgraph-v2",
            "activation_ref_digest": "sha256:" + "1" * 64,
            "capability_digest": "sha256:" + "2" * 64,
            "host_inventory_digest": "sha256:" + "3" * 64,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": "sha256:" + "4" * 64,
            "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(seconds=duration)).isoformat(),
            "ack_token": "hmac-sha256:" + token * 64,
            **changes,
        }
    )


def _decision(*, ask: bool = False) -> PolicyDecision:
    decision = PolicyDecision(
        decision_id="dec_product_carrier",
        decision="ask" if ask else "deny",
        risk_score=70,
        severity="high",
        reason="Carrier contract test",
        policy_audit_id="audit_policy_product_carrier",
    )
    if ask:
        decision.approval = {"approval_id": "approval_product_carrier"}
        decision.enforcement_binding = {
            "schema_version": "2.1",
            "action_id": ACTION,
            "authorization_fingerprint": "hmac-sha256:" + "f" * 64,
            "runtime_binding_id": BINDING,
            "requires_execution_lease": True,
        }
    return decision


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        event_id="event_product_carrier",
        trace_id="trace_product_carrier",
        security_context=SecurityContext(agent_id=AGENT),
        tool=ToolDescriptor(
            name="write", category="file", kind="write", call_id=ACTION
        ),
        arguments={"path": "fixture.txt", "content": "fixture"},
    )


def _receipt(decision: PolicyDecision, **changes: Any) -> RuntimeOutcomeReceipt:
    return build_runtime_outcome(
        _event(),
        decision,
        completed_at=(NOW + timedelta(minutes=10)).isoformat(),
        execution_status="not_invoked",
        **changes,
    )


def test_policy_private_ack_snapshots_cannot_be_injected_or_dumped() -> None:
    ack = _ack()
    raw = _decision().model_dump()
    raw["_evaluation_activation_ack"] = ack.to_wire()
    decision = PolicyDecision.model_validate(raw)
    assert decision._evaluation_activation_ack is None
    decision._evaluation_activation_ack = ack
    decision._consumption_activation_ack = _ack(token="b")
    for public in (
        repr(decision),
        decision.model_dump_json(),
        str(decision.model_dump()),
    ):
        assert "activation_ack" not in public
        assert "ack_token" not in public
        assert ack.header_value() not in public
    assert decision.model_copy(deep=True)._evaluation_activation_ack == ack


def test_historical_expired_ack_is_complete_only_in_explicit_receipt_wire() -> None:
    decision = _decision()
    original = _ack(age=20)
    decision._evaluation_activation_ack = original
    receipt = _receipt(decision)
    decision._evaluation_activation_ack = _ack(token="b")
    assert receipt.metadata.activation_ack is original
    wire = receipt.to_wire()
    assert wire["metadata"]["activation_ack"] == original.to_wire()
    server_ack = CoreReceipt.model_validate(wire).metadata.activation_ack
    assert server_ack is not None and server_ack.ack_token == original.header_value()
    for public in (repr(receipt), receipt.model_dump_json(), str(receipt.model_dump())):
        assert original.header_value() not in public
        assert "ack_token" not in public
    assert RuntimeOutcomeReceipt.model_validate(wire).to_wire() == wire


def test_legacy_receipt_omits_ack_and_explicit_null_is_rejected() -> None:
    receipt = _receipt(_decision())
    assert "activation_ack" not in receipt.to_wire()["metadata"]
    with pytest.raises(ValidationError, match="omitted instead of null"):
        RuntimeOutcomeMetadata(
            agent_id=AGENT, outcome_kind="pre_execution_deny", activation_ack=None
        )


@pytest.mark.parametrize("change", ["runtime", "agent", "issued_after_receipt"])
def test_receipt_ack_identity_and_issue_time_match_core_validation(change: str) -> None:
    decision = _decision()
    decision._evaluation_activation_ack = _ack()
    wire = _receipt(decision).to_wire()
    if change == "runtime":
        wire["runtime"] = "openclaw"
    elif change == "agent":
        wire["metadata"]["agent_id"] = "wrong_agent"
    else:
        future = NOW + timedelta(minutes=11)
        wire["metadata"]["activation_ack"].update(
            issued_at=future.isoformat(),
            expires_at=(future + timedelta(seconds=120)).isoformat(),
        )
    for model in (RuntimeOutcomeReceipt, CoreReceipt):
        with pytest.raises(ValidationError):
            model.model_validate(wire)
    with pytest.raises(ValidationError) as caught:
        RuntimeOutcomeReceipt.model_validate(wire)
    assert decision._evaluation_activation_ack.header_value() not in str(caught.value)


def test_started_observation_never_carries_product_ack() -> None:
    decision = _decision()
    decision._evaluation_activation_ack = _ack()
    start = build_tool_started_observation(
        _event(), decision, timestamp=NOW.isoformat()
    )
    assert "activation_ack" not in start.model_dump_json()
    assert decision._evaluation_activation_ack.header_value() not in repr(start)


class _ApprovalGuard:
    def __init__(
        self, refreshed: object, *, consume_error: Exception | None = None
    ) -> None:
        self.config = SimpleNamespace(activation_ack_max_age_seconds=120)
        self.refreshed = refreshed
        self.consume_error = consume_error
        self.timeline: list[str] = []
        self.consume_kwargs: dict[str, Any] | None = None

    def wait_for_approval(self, approval_id: str, timeout: float) -> dict[str, str]:
        self.timeline.append("wait")
        return {
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
        }

    def refresh_product_ack(self) -> object:
        self.timeline.append("refresh")
        if isinstance(self.refreshed, Exception):
            raise self.refreshed
        return self.refreshed

    def consume_execution_lease(
        self, approval_id: str, **kwargs: Any
    ) -> ExecutionLeaseReference:
        self.timeline.append("consume")
        self.consume_kwargs = kwargs
        if self.consume_error is not None:
            raise self.consume_error
        return ExecutionLeaseReference(
            lease_id="lease_product_carrier",
            consumption_id="consume_product_carrier",
            expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        )


def _authorize(
    guard: _ApprovalGuard, decision: PolicyDecision, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(binding_module, "_utc_now", lambda: NOW)
    return authorize_strong_approval(
        guard,
        decision,
        expected_action_id=ACTION,
        expected_runtime_binding_id=BINDING,
        approval_id="approval_product_carrier",
        timeout_seconds=60,
        monotonic=lambda: 100.0,
    )


def test_approval_refreshes_ack_once_after_wait_and_clamps_consume_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _decision(ask=True)
    decision._evaluation_activation_ack = _ack(age=119)
    fresh = _ack(token="b", duration=20)
    guard = _ApprovalGuard(fresh)
    release = _authorize(guard, decision, monkeypatch)
    assert release is not None and release.deadline == 120.0
    assert guard.timeline == ["wait", "refresh", "consume"]
    assert guard.consume_kwargs is not None
    assert guard.consume_kwargs["activation_ack"] is fresh
    assert guard.consume_kwargs["deadline"] == 120.0
    assert decision._consumption_activation_ack is fresh
    receipt = _receipt(
        decision,
        lease_id=release.lease.lease_id,
        consumption_id=release.lease.consumption_id,
        approval_resolution=release.approval_resolution,
        enforcement=release.enforcement,
    )
    assert receipt.metadata.activation_ack is fresh
    server_ack = CoreReceipt.model_validate(receipt.to_wire()).metadata.activation_ack
    assert server_ack is not None and server_ack.ack_token == fresh.header_value()


def test_consume_deadline_respects_configured_shorter_ack_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _decision(ask=True)
    decision._evaluation_activation_ack = _ack(age=80)
    guard = _ApprovalGuard(_ack(token="b", age=4))
    guard.config.activation_ack_max_age_seconds = 9
    release = _authorize(guard, decision, monkeypatch)
    assert release is not None and release.deadline == 105.0


@pytest.mark.parametrize(
    "refreshed",
    [
        _ack(token="b", agent_id="changed_agent"),
        _ack(token="b", activation_ref_digest="sha256:" + "5" * 64),
        _ack(token="b", host_inventory_digest="sha256:" + "5" * 64),
        _ack(token="b", age=120),
        RuntimeError("private heartbeat response"),
        {"ack_token": "untrusted"},
    ],
)
def test_refresh_failures_or_identity_drift_never_attempt_consumption(
    refreshed: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    decision = _decision(ask=True)
    decision._evaluation_activation_ack = _ack()
    guard = _ApprovalGuard(refreshed)
    with pytest.raises(StrongBindingFailure) as caught:
        _authorize(guard, decision, monkeypatch)
    assert caught.value.evidence.lease_consume_outcome == "not_attempted"
    assert guard.timeline == ["wait", "refresh"]
    assert decision._consumption_activation_ack is None
    assert (
        _receipt(decision).metadata.activation_ack
        is decision._evaluation_activation_ack
    )


@pytest.mark.parametrize("correlated", [True, False])
def test_failed_consumption_uses_ack_for_the_server_receipt_anchor(
    correlated: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    decision = _decision(ask=True)
    evaluation = _ack(age=110)
    consumption = _ack(token="b")
    decision._evaluation_activation_ack = evaluation
    ids = (
        ExecutionLeaseCorrelation("lease_uncertain", "consume_uncertain")
        if correlated
        else None
    )
    guard = _ApprovalGuard(
        consumption,
        consume_error=ExecutionLeaseConsumeError("invalid_response", correlation=ids),
    )
    with pytest.raises(StrongBindingFailure) as caught:
        _authorize(guard, decision, monkeypatch)
    failure = caught.value
    receipt = _receipt(
        decision,
        approval_resolution=failure.approval_resolution,
        enforcement=failure.evidence,
        lease_id=ids.lease_id if ids else None,
        consumption_id=ids.consumption_id if ids else None,
    )
    assert receipt.metadata.activation_ack is (
        consumption if correlated else evaluation
    )
    CoreReceipt.model_validate(receipt.to_wire())


def test_legacy_strong_approval_does_not_add_ack_keyword_or_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _ApprovalGuard(None)
    assert _authorize(guard, _decision(ask=True), monkeypatch) is not None
    assert guard.timeline == ["wait", "consume"]
    assert guard.consume_kwargs is not None
    assert "activation_ack" not in guard.consume_kwargs


def test_correlated_product_receipt_never_falls_back_to_evaluation_ack() -> None:
    decision = _decision(ask=True)
    decision._evaluation_activation_ack = _ack()
    with pytest.raises(ValueError, match="consumption ACK"):
        _receipt(decision, lease_id="lease_missing", consumption_id="consume_missing")


def test_gateway_rejects_product_execution_at_construction_and_invocation() -> None:
    guard = SimpleNamespace(
        config=SimpleNamespace(product_manifest_path="/private/manifest")
    )
    with pytest.raises(ValueError, match="execution remains disabled"):
        GuardedToolGateway(guard, object())
    guard.config.product_manifest_path = None
    gateway = GuardedToolGateway(guard, object())
    guard.config.product_manifest_path = "/private/manifest"
    with pytest.raises(ValueError, match="execution remains disabled"):
        gateway.invoke_tool(
            tool_name="write", arguments={}, security={}, trace_id="trace"
        )
    guard.config.product_manifest_path = None
    guard.product_enabled = True
    with pytest.raises(ValueError, match="execution remains disabled"):
        gateway.invoke_tool(
            tool_name="write", arguments={}, security={}, trace_id="trace"
        )


def test_historical_product_receipt_submission_survives_disabled_current_config() -> (
    None
):
    decision = _decision()
    historical = _ack(age=120)
    decision._evaluation_activation_ack = historical
    receipt = _receipt(decision)
    submitted: list[dict[str, Any]] = []

    def submit(event: RuntimeOutcomeReceipt) -> dict[str, Any]:
        submitted.append(event.to_wire())
        return {"ok": True, "audit_id": event.audit_id}

    guard = SimpleNamespace(
        product_enabled=True,
        config=SimpleNamespace(defense_enabled=False, core_api_mode="legacy"),
        submit_audit_event=submit,
    )
    result = submit_runtime_receipt_result(guard, receipt, required=True)
    assert result.status == "recorded"
    assert submitted[0]["metadata"]["activation_ack"] == historical.to_wire()
    guard.product_enabled = False
    assert (
        submit_runtime_receipt_result(guard, receipt, required=True).status == "failed"
    )
    assert len(submitted) == 1
