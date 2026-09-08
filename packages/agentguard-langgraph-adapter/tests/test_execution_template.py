"""Synthetic official authority with real encrypted journal and one-shot callbacks."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import time
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
import agentguard_langgraph_adapter.execution_template as module
from agentguard_langgraph_adapter.execution_template import (
    GuardedExecutionTemplate,
    GuardedResultDisposition,
)
from agentguard_langgraph_adapter.native_events import (
    NativeGuardEventBuilder,
    NativeModelOrigin,
)
from agentguard_langgraph_adapter.native_tools import (
    create_isolated_product_tools,
    close_isolated_product_tools,
    prepare_native_tool_call,
)
from agentguard_langgraph_adapter.product_action_barrier import ProductActionBarrier
from agentguard_langgraph_adapter.product_delivery import (
    ProductReceiptDeliveryResult,
    ProductReceiptTransportResult,
)
from agentguard_langgraph_adapter.strong_binding import (
    EnforcementEvidence,
    ExecutionLeaseReference,
    StrongBindingRelease,
)

_spec = importlib.util.spec_from_file_location(
    "_outbox_template_support", Path(__file__).with_name("test_product_outbox.py")
)
assert _spec is not None and _spec.loader is not None
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)
factory = _support.factory
_ok = _support._ok

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("floored", [False, True])
def test_product_c1_ask_without_approval_has_valid_blocked_receipt(floored):
    from agentguard_core.decisions.models import RuntimeOutcomeReceipt as CoreReceipt
    from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome

    decision = _decision(decision="ask")
    decision.decision_authority = decision.decision_authority.model_copy(
        update={"legacy_floor_applied": floored}
    )
    for status, disposition in [
        ("not_invoked", "not_applicable"),
        ("executed", "quarantined"),
    ]:
        receipt = build_runtime_outcome(
            _event(),
            decision,
            execution_status=status,
            invoked_at=(
                datetime.now(timezone.utc).isoformat() if status == "executed" else None
            ),
            result_disposition=disposition,
        )
        assert receipt.evidence.approval == {
            "approval_id": None,
            "status": "not_required",
            "decision": None,
            "resolved_at": None,
        }
        CoreReceipt.model_validate(receipt.to_wire())


@pytest.mark.parametrize(
    "change",
    [
        "missing_ack",
        "current",
        "shadow",
        "matched_path",
        "strong_binding",
        "approval_present",
        "resolution_present",
        "wrong_digest",
    ],
)
def test_nonqualifying_ask_cannot_hide_missing_approval(change):
    from agentguard_core.decisions.models import RuntimeOutcomeReceipt as CoreReceipt
    from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome

    decision = _decision(decision="ask")
    resolution = None
    if change == "missing_ack":
        decision._evaluation_activation_ack = None
    elif change in {"current", "shadow", "matched_path"}:
        patch = {
            "current": {"source": "current"},
            "shadow": {"mode": "shadow"},
            "matched_path": {"matched_path_ids": ["path_unofficial"]},
        }[change]
        decision.decision_authority = decision.decision_authority.model_copy(
            update=patch
        )
    elif change in {"forbidden", "strong_binding"}:
        decision.approval_release_directive = (
            decision.approval_release_directive.model_copy(update={"mode": change})
        )
    elif change == "approval_present":
        decision.approval = {}
    elif change == "resolution_present":
        resolution = {}
    else:
        decision._evaluation_activation_ack = (
            decision._evaluation_activation_ack.model_copy(
                update={"activation_ref_digest": "sha256:" + "7" * 64}
            )
        )
    receipt = build_runtime_outcome(
        _event(),
        decision,
        execution_status="not_invoked",
        approval_resolution=resolution,
    )
    assert receipt.evidence.approval["status"] == "pending"
    with pytest.raises(ValueError):
        CoreReceipt.model_validate(receipt.to_wire())


@pytest.mark.parametrize("floored", [False, True])
def test_product_forbidden_without_approval_only_records_not_invoked(floored):
    from agentguard_core.decisions.models import RuntimeOutcomeReceipt as CoreReceipt
    from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome

    decision = _decision(decision="ask")
    decision.decision_authority = decision.decision_authority.model_copy(
        update={"legacy_floor_applied": floored}
    )
    decision.approval_release_directive = (
        decision.approval_release_directive.model_copy(update={"mode": "forbidden"})
    )
    blocked = build_runtime_outcome(_event(), decision, execution_status="not_invoked")
    assert blocked.evidence.approval["status"] == "not_required"
    assert blocked.metadata.outcome_kind == "pre_execution_deny"
    assert blocked.evidence.execution["invoked_at"] is None
    CoreReceipt.model_validate(blocked.to_wire())
    executed = build_runtime_outcome(
        _event(),
        decision,
        execution_status="executed",
        invoked_at=datetime.now(timezone.utc).isoformat(),
    )
    assert executed.evidence.approval["status"] == "pending"
    with pytest.raises(ValueError):
        CoreReceipt.model_validate(executed.to_wire())


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("agentguard_memory_write", {"key": "approved", "value": "safe"}),
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox",
                "message": "safe",
            },
        ),
    ],
)
@pytest.mark.parametrize("floored", [False, True])
def test_specialized_ask_authorizes_once_with_exact_action_and_consume_ack(
    env, tmp_path, monkeypatch, name, arguments, floored
):
    root = tmp_path / "approved-tools"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:1/inbox"
    )
    try:
        prepared = prepare_native_tool_call(
            next(spec for spec in specs if spec.name == name),
            "call_approved",
            arguments,
        )
        sent = []
        setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
        events = []
        consumed = []
        calls = []
        policy, release = _ask_release()
        policy.decision_authority = policy.decision_authority.model_copy(
            update={"legacy_floor_applied": floored}
        )
        consume_ack = policy._consumption_activation_ack
        policy._consumption_activation_ack = None

        def evaluate(event):
            events.append(event)
            return _decision() if event.event_type == "tool_result_produced" else policy

        def authorize(_adapter, decision, **kwargs):
            consumed.append(kwargs["expected_action_id"])
            decision._consumption_activation_ack = consume_ack
            return release

        setup.adapter.evaluate_guard_event = evaluate
        monkeypatch.setattr(module, "authorize_strong_approval", authorize)
        result = setup.template.execute_action(
            prepared,
            security={
                "agent_id": "main",
                "source_type": "model",
                "source_trust": "unknown",
                "visible_source_refs": ["source:model:evt_origin"],
            },
            trace_id="trace_approved",
            invoke_once=lambda: calls.append(1) or "safe",
            model_origin=NativeModelOrigin(
                "audit_origin", "source:model:evt_origin", prepared.call_id
            ),
        )
        expected = (
            f"act_{events[0].event_id}" if name == "message" else prepared.call_id
        )
        assert consumed == [expected] and calls == [1], result
        assert result.approval_consumed and result.consumption_id == "consume_template"
        assert sent[-1]["metadata"]["activation_ack"] == consume_ack.to_wire()
        assert sent[-1]["links"]["action_id"] == expected
    finally:
        close_isolated_product_tools(specs)


def test_session_failure_after_consumption_records_known_not_invoked_history(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    decision, release = _ask_release()

    def closed():
        raise ProductActivationError("session_closed")

    setup.adapter._product_client = lambda: SimpleNamespace(snapshot_product_ack=closed)
    result = setup.template.run_guarded_action(
        _event(),
        decision,
        action_id="call_template",
        invoke_once=lambda: pytest.fail("closed session invoked"),
        postprocess=lambda _: pytest.fail("no result"),
        start_kind="tool_call",
        strong_release=release,
        approval_resolution=release.approval_resolution,
    )
    assert (
        result.invocation_status == "not_invoked"
        and result.delivery.status == "recorded"
    )
    assert (
        len(sent) == 1 and sent[0]["metadata"]["outcome_kind"] == "pre_execution_deny"
    )
    assert sent[0]["links"]["consumption_id"] == release.lease.consumption_id
    assert (
        sent[0]["metadata"]["activation_ack"]
        == decision._consumption_activation_ack.to_wire()
    )


@pytest.mark.parametrize("callback_fails", [False, True])
def test_terminal_builder_failure_cannot_rewrite_actual_invocation_as_not_invoked(
    env, monkeypatch, callback_fails
):
    setup = env()
    calls = []

    def broken_builder(*_args, **_kwargs):
        raise RuntimeError("private terminal serialization failure")

    monkeypatch.setattr(module, "build_runtime_outcome", broken_builder)

    def invoke():
        calls.append(1)
        if callback_fails:
            raise RuntimeError("private invocation failure")
        return "observed return"

    result = _run(setup, invoke)
    assert result.invocation_status == ("failed" if callback_fails else "executed")
    assert result.value is None and result.delivery.status == "failed"
    assert setup.outbox.status().unknown_action_count == 1
    assert setup.outbox.status().breaker_open
    _run(setup, invoke)
    assert calls == [1]


def _ask_release(*, expired=False):
    base = _decision()
    wire = base.model_dump(mode="json")
    wire.update(decision="ask", approval={"approval_id": "approval_template"})
    wire["decision_authority"] = base.decision_authority.model_dump()
    wire["decision_authority"]["approval_release"] = "strong_binding_required"
    wire["approval_release_directive"] = {
        **base.approval_release_directive.model_dump(),
        "mode": "strong_binding",
        "required_runtime_profile": "C3",
        "action_binding": "exact",
        "receipt_requirement": "required_durable",
    }
    decision = PolicyDecision.model_validate(wire)
    decision._evaluation_activation_ack = base._evaluation_activation_ack
    decision._consumption_activation_ack = _decision("b")._evaluation_activation_ack
    resolution = {
        "approval_id": "approval_template",
        "status": "resolved",
        "decision": "allow_once",
        "resolution_source": "human",
        "resolved_at": datetime.now(timezone.utc).isoformat(),
    }
    release = StrongBindingRelease(
        resolution,
        1,
        ExecutionLeaseReference(
            "lease_template",
            "consume_template",
            (
                datetime.now(timezone.utc) + timedelta(seconds=-1 if expired else 60)
            ).isoformat(),
        ),
        EnforcementEvidence(
            "approval_released",
            "passed",
            "consumed",
            ("rte-05:binding_exact", "rte-05:lease_consumed"),
        ),
        time.monotonic() + 60,
    )
    return decision, release


@pytest.mark.parametrize("retry_start", [False, True])
def test_consumed_action_start_terminal_and_abort_keep_consume_ack(env, retry_start):
    sent = []
    setup = env(
        lambda wire: sent.append(json.loads(wire))
        or (ProductReceiptTransportResult("retryable") if retry_start else _ok(wire))
    )
    decision, release = _ask_release()
    calls = []
    result = setup.template.run_guarded_action(
        _event(),
        decision,
        action_id="call_template",
        invoke_once=lambda: calls.append(1) or "safe",
        postprocess=lambda value: GuardedResultDisposition(
            value, False, ProductReceiptDeliveryResult("recorded")
        ),
        start_kind="tool_call",
        strong_release=release,
        approval_resolution=release.approval_resolution,
    )
    assert calls == ([] if retry_start else [1]), result
    if retry_start:
        data = next(
            json.loads(item.payload)
            for item in setup.store.records()
            if item.kind == "action"
        )
        terminal = json.loads(data["terminal"]["wire"])
        assert data["start"]["activation_ack"] == data["terminal"]["activation_ack"]
    else:
        terminal = sent[-1]
    assert (
        terminal["metadata"]["activation_ack"]
        == decision._consumption_activation_ack.to_wire()
    )
    assert (
        terminal["links"]["lease_id"] == "lease_template"
        and terminal["links"]["consumption_id"] == "consume_template"
    )
    from agentguard_core.decisions.models import RuntimeOutcomeReceipt as CoreReceipt

    CoreReceipt.model_validate(terminal)


def test_expired_consumed_lease_is_not_invoked_and_retains_original_correlation(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    decision, release = _ask_release(expired=True)
    result = setup.template.run_guarded_action(
        _event(),
        decision,
        action_id="call_template",
        invoke_once=lambda: pytest.fail("expired lease invoked"),
        postprocess=lambda _: pytest.fail("no result"),
        start_kind="tool_call",
        strong_release=release,
        approval_resolution=release.approval_resolution,
    )
    assert (
        result.invocation_status == "not_invoked"
        and result.delivery.status == "recorded"
    )
    assert (
        len(sent) == 1 and sent[0]["metadata"]["outcome_kind"] == "pre_execution_deny"
    )
    assert sent[0]["links"]["consumption_id"] == "consume_template"


@pytest.mark.parametrize(
    "change", ["source", "mode", "selection_basis", "legacy_floor_applied"]
)
def test_current_shadow_and_legacy_floor_never_authorize(env, change):
    setup = env()
    value = {
        "source": "current",
        "mode": "shadow",
        "selection_basis": "current",
        "legacy_floor_applied": True,
    }[change]
    setup.decision.decision_authority = setup.decision.decision_authority.model_copy(
        update={change: value}
    )
    result = _run(setup, lambda: pytest.fail("legacy authority invoked"))
    assert (
        result.invocation_status == "not_invoked" and result.delivery.status == "failed"
    )


@pytest.mark.parametrize("decision", ["ask", "deny"])
def test_official_conservative_floor_without_release_records_only_denial(env, decision):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    setup.decision = _decision(decision=decision)
    setup.decision.decision_authority = setup.decision.decision_authority.model_copy(
        update={"legacy_floor_applied": True}
    )
    result = _run(setup, lambda: pytest.fail("a conservative floor is not a release"))
    assert result.invocation_status == "not_invoked"
    assert result.delivery.status == "recorded"
    assert len(sent) == 1
    assert sent[0]["metadata"]["outcome_kind"] == "pre_execution_deny"
    assert "lease_id" not in sent[0]["links"]
    assert sent[0]["evidence"]["execution"]["invoked_at"] is None


def _event():
    return ToolCallEvent(
        event_id="event_template",
        trace_id="trace_template",
        security_context=SecurityContext(agent_id="main"),
        tool=ToolDescriptor(
            name="write", category="file", kind="write", call_id="call_template"
        ),
        arguments={"path": "fixture.txt"},
    )


def _decision(token="a", mode="active", decision="allow"):
    now = datetime.now(timezone.utc)
    ack = _support._ack(
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(seconds=119)).isoformat(),
        ack_token="hmac-sha256:" + token * 64,
    )
    result = PolicyDecision.model_validate(
        {
            "decision_id": "decision_template",
            "decision": decision,
            "risk_score": 0,
            "severity": "low",
            "reason": "synthetic official contract",
            "policy_audit_id": "policy_template",
            "decision_authority": {
                "source": "v21",
                "mode": mode,
                "selection_basis": "profile_all",
                "legacy_floor_applied": False,
                "activation_ref_digest": ack.activation_ref_digest,
                "approval_release": "not_applicable",
            },
            "approval_release_directive": {
                "mode": "not_applicable",
                "required_runtime_profile": None,
                "human_only": True,
                "single_use": True,
                "action_binding": "none",
                "receipt_requirement": "not_applicable",
                "activation_ref_digest": ack.activation_ref_digest,
                "scope_digest": "sha256:" + "9" * 64,
                "capability_digest": ack.capability_digest,
            },
        }
    )
    result._evaluation_activation_ack = ack
    return result


@pytest.fixture
def env(factory, monkeypatch):
    monkeypatch.setattr(module, "assert_product_execution_available", lambda: None)

    def make(sender=_ok):
        outbox, store, clock = factory(sender)
        decision = _decision()
        adapter = SimpleNamespace(
            product_enabled=True,
            config=SimpleNamespace(
                agent_id="main",
                runtime="langgraph",
                runtime_binding_id="binding:main",
                activation_ack_max_age_seconds=120,
            ),
            product_action_barrier=ProductActionBarrier(outbox),
            submit_product_receipt=outbox.submit,
        )
        adapter._product_client = lambda: SimpleNamespace(
            snapshot_product_ack=lambda: decision._evaluation_activation_ack
        )
        builder = NativeGuardEventBuilder(adapter)
        template = GuardedExecutionTemplate(adapter, event_builder=builder)
        return SimpleNamespace(
            outbox=outbox,
            store=store,
            clock=clock,
            decision=decision,
            adapter=adapter,
            builder=builder,
            template=template,
        )

    return make


def _run(env, invoke=lambda: "result", post=None):
    return env.template.run_guarded_action(
        _event(),
        env.decision,
        action_id="call_template",
        invoke_once=invoke,
        postprocess=post
        or (
            lambda value: GuardedResultDisposition(
                value, False, ProductReceiptDeliveryResult("recorded")
            )
        ),
        start_kind="tool_call",
    )


def test_public_fuse_is_fixed_and_zero_callback(env, monkeypatch):
    setup = env()

    def fused():
        raise ProductActivationError("product_execution_unavailable")

    monkeypatch.setattr(module, "assert_product_execution_available", fused)
    with pytest.raises(ProductActivationError):
        _run(setup, lambda: pytest.fail("callback crossed public fuse"))
    assert setup.outbox.status().record_count == 1


def test_success_keeps_original_ack_and_invokes_once(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    original = setup.decision._evaluation_activation_ack.to_wire()
    calls = []

    def invoke():
        calls.append(1)
        setup.decision._evaluation_activation_ack = _decision(
            "b"
        )._evaluation_activation_ack
        return {"safe": "native"}

    result = _run(setup, invoke)
    assert (
        calls == [1]
        and result.value == {"safe": "native"}
        and result.delivery.status == "recorded"
    )
    assert [item["record_type"] for item in sent] == [
        "runtime_observation",
        "runtime_outcome",
    ]
    assert sent[0]["evidence"]["execution"]["invoked_at"] is None
    assert sent[1]["metadata"]["activation_ack"] == original
    assert setup.outbox.status().completed_count == 1


@pytest.mark.parametrize("status", ["retryable", "permanent_rejected", "failed"])
def test_unconfirmed_start_never_invokes_and_persists_abort(env, status):
    setup = env(lambda _: ProductReceiptTransportResult(status))
    result = _run(setup, lambda: pytest.fail("unconfirmed start invoked"))
    assert result.invocation_status == "not_invoked" and result.value is None
    record = next(
        json.loads(item.payload)
        for item in setup.store.records()
        if item.kind == "action"
    )
    assert not record["start_acknowledged"] and record["terminal"] is not None
    assert (
        json.loads(record["terminal"]["wire"])["evidence"]["execution"]["invoked_at"]
        is None
    )
    assert setup.outbox.status().unknown_action_count == 0


def test_terminal_unconfirmed_withholds_result_and_never_reexecutes(env):
    setup = env(
        lambda wire: (
            _ok(wire)
            if json.loads(wire)["record_type"] == "runtime_observation"
            else ProductReceiptTransportResult("retryable")
        )
    )
    calls = []
    result = _run(setup, lambda: calls.append(1) or "SECRET_RESULT")
    assert (
        result.invocation_status == "executed"
        and result.value is None
        and result.delivery.status == "queued_durable"
    )
    assert _run(setup, lambda: calls.append(1)).invocation_status == "not_invoked"
    assert calls == [1] and "SECRET_RESULT" not in repr(result)


@pytest.mark.parametrize("status", ["queued_durable", "permanent_rejected", "failed"])
def test_checkpoint_unconfirmed_withholds_even_when_terminal_confirmed(env, status):
    setup = env()
    result = _run(
        setup,
        post=lambda value: GuardedResultDisposition(
            value, False, ProductReceiptDeliveryResult(status)
        ),
    )
    assert result.value is None and result.delivery.status == status
    assert setup.outbox.status().completed_count == 1


def test_output_isolation_does_not_replace_action_anchor(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    result = _run(
        setup,
        post=lambda _: GuardedResultDisposition(
            None, True, ProductReceiptDeliveryResult("recorded")
        ),
    )
    terminal = sent[-1]
    assert (
        result.invocation_status == "executed"
        and result.quarantined
        and result.value is None
    )
    assert terminal["metadata"]["outcome_kind"] == "execution_completed"
    assert terminal["links"]["event_id"] == "event_template"
    assert terminal["evidence"]["result"]["disposition"] == "quarantined"


def test_invocation_error_records_failed_without_raw_exception(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    secret = "hmac-sha256:" + "c" * 64

    def invoke():
        raise RuntimeError(secret)

    result = _run(setup, invoke)
    assert result.invocation_status == "failed" and result.delivery.status == "recorded"
    assert secret not in repr(result) + json.dumps(sent)
    assert sent[-1]["metadata"]["outcome_kind"] == "execution_failed"


def test_postprocess_exception_retains_real_executed_terminal(env):
    setup = env()

    def post(_):
        raise RuntimeError("private body")

    result = _run(setup, post=post)
    assert (
        result.invocation_status == "executed"
        and result.value is None
        and result.delivery.status == "failed"
    )
    assert setup.outbox.status().completed_count == 1


def test_no_parallel_or_reentrant_actions(env):
    setup = env()
    entered, release = Event(), Event()

    def invoke():
        assert _run(setup).error_code == "action_already_active"
        entered.set()
        assert release.wait(2)
        return "safe"

    with ThreadPoolExecutor(max_workers=1) as pool:
        active = pool.submit(_run, setup, invoke)
        assert entered.wait(2)
        assert _run(setup).error_code == "action_already_active"
        release.set()
        assert active.result().delivery.status == "recorded"


def test_abrupt_callback_exit_leaves_unknown_action_for_recovery(env):
    setup = env()

    def invoke():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _run(setup, invoke)
    assert (
        setup.outbox.status().unknown_action_count == 1
        and setup.outbox.status().breaker_open
    )


def test_missing_official_ack_never_calls_or_falls_back(env):
    setup = env()
    setup.decision._evaluation_activation_ack = None
    result = _run(setup, lambda: pytest.fail("legacy fallback"))
    assert (
        result.invocation_status == "not_invoked" and result.delivery.status == "failed"
    )


@pytest.mark.parametrize(
    "name,arguments,event_type",
    [
        ("write", {"path": "result.txt", "content": "safe"}, "tool_call_proposed"),
        (
            "agentguard_memory_write",
            {"key": "fixture", "value": "safe"},
            "memory_write_proposed",
        ),
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox",
                "message": "safe",
            },
            "message_send_proposed",
        ),
    ],
)
def test_one_authoritative_action_event_and_exact_canonical_identity(
    env, tmp_path, name, arguments, event_type
):
    root = tmp_path / "native-tools"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:1/inbox"
    )
    try:
        spec = next(item for item in specs if item.name == name)
        prepared = prepare_native_tool_call(spec, "call_native", arguments)
        sent = []
        setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
        seen = []

        def evaluate(event):
            seen.append(event)
            policy = _decision()
            policy.decision_id = f"dec_{event.event_id}"
            policy.policy_audit_id = f"policy_{event.event_id}"
            return policy

        setup.adapter.evaluate_guard_event = evaluate
        calls = []
        result = setup.template.execute_action(
            prepared,
            security={
                "agent_id": "main",
                "source_type": "model",
                "source_trust": "unknown",
                "visible_source_refs": ["source:model:evt_origin"],
            },
            trace_id="trace_native",
            invoke_once=lambda: calls.append(1) or "safe",
            model_origin=NativeModelOrigin(
                "audit_origin", "source:model:evt_origin", prepared.call_id
            ),
        )
        assert (
            result.executed and not result.blocked and result.result == "safe"
        ), result
        assert [event.event_type for event in seen] == [
            event_type,
            "tool_result_produced",
        ]
        assert calls == [1]
        assert seen[0].metadata["product_model_content"] == {
            "model_output_audit_id": "audit_origin",
            "model_source_ref": "source:model:evt_origin",
            "call_id": prepared.call_id,
        }
        start = next(
            receipt
            for receipt in sent
            if receipt["record_type"] == "runtime_observation"
        )
        terminal = sent[-1]
        expected = (
            f"act_{seen[0].event_id}"
            if event_type == "message_send_proposed"
            else "call_native"
        )
        assert start["links"]["action_id"] == terminal["links"]["action_id"] == expected
        assert (
            start["links"]["event_id"]
            == terminal["links"]["event_id"]
            == seen[0].event_id
        )
        assert terminal["metadata"]["outcome_kind"] == "execution_completed"
    finally:
        close_isolated_product_tools(specs)


@pytest.mark.parametrize("drift", ["call_id", "user_origin", "missing_source"])
def test_invalid_model_origin_stops_before_policy_or_invocation(env, tmp_path, drift):
    root = tmp_path / "invalid-origin-tools"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:1/inbox"
    )
    try:
        prepared = prepare_native_tool_call(
            next(item for item in specs if item.name == "write"),
            "call_native_origin",
            {"path": "result.txt", "content": "safe"},
        )
        setup = env()
        calls = []
        setup.adapter.evaluate_guard_event = lambda *_: calls.append("evaluate")
        security = {
            "agent_id": "main",
            "source_type": "model",
            "source_trust": "unknown",
            "visible_source_refs": ["source:model:evt_origin"],
        }
        if drift == "user_origin":
            security.update(source_type="user", source_trust="trusted")
        elif drift == "missing_source":
            security["visible_source_refs"] = []
        result = setup.template.execute_action(
            prepared,
            security=security,
            trace_id="trace_origin",
            invoke_once=lambda: calls.append("invoke"),
            model_origin=NativeModelOrigin(
                "audit_origin",
                "source:model:evt_origin",
                "call_wrong" if drift == "call_id" else prepared.call_id,
            ),
        )
        assert result.blocked and not result.executed
        assert calls == []
        assert not (root / "result.txt").exists()
    finally:
        close_isolated_product_tools(specs)


def test_original_ack_expiring_after_start_confirmation_does_not_rebind(
    env, monkeypatch
):
    setup = env()
    observed = []

    def remaining(self, **_kwargs):
        observed.append(self)
        if len(observed) > 1:
            raise ProductActivationError("activation_ack_expired")
        return 1.0

    monkeypatch.setattr(
        type(setup.decision._evaluation_activation_ack), "remaining_seconds", remaining
    )
    assert _run(setup).delivery.status == "recorded"
    assert len(observed) == 1


def test_terminal_disk_failure_leaves_unknown_and_never_publishes(env, monkeypatch):
    setup = env()
    original = setup.store.replace

    def replace(record_id, payload, **kwargs):
        data = json.loads(payload)
        if data.get("record_type") == "action" and data.get("terminal") is not None:
            raise OSError("private disk path")
        return original(record_id, payload, **kwargs)

    monkeypatch.setattr(setup.store, "replace", replace)
    result = _run(setup)
    assert (
        result.invocation_status == "executed"
        and result.value is None
        and result.delivery.status == "failed"
    )
    setup.outbox.close()


def test_model_action_uses_same_journal_without_tool_start(env):
    sent = []
    setup = env(lambda wire: sent.append(json.loads(wire)) or _ok(wire))
    event = setup.builder.build_model(
        phase="input",
        provider="controlled",
        model="no-provider",
        content="controlled model request",
        security={"agent_id": "main"},
        trace_id="trace_model",
    )
    result = setup.template.run_guarded_action(
        event,
        setup.decision,
        action_id=f"act_{event.event_id}",
        invoke_once=lambda: "controlled output",
        postprocess=lambda value: GuardedResultDisposition(
            value, False, ProductReceiptDeliveryResult("recorded")
        ),
        start_kind="model_call",
    )
    assert result.value == "controlled output" and result.delivery.status == "recorded"
    assert sent[0]["event_type"] == "model_call_committed"
    assert (
        sent[0]["links"]["action_id"]
        == sent[-1]["links"]["action_id"]
        == f"act_{event.event_id}"
    )
