"""Real encrypted persistence with controlled transport and crash boundaries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import pickle
from threading import Event

import pytest

from agentguard_langgraph_adapter.activation_ack import (
    ActivationAckV1,
    ProductActivationError,
)
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.product_action_barrier import (
    ProductActionBarrier,
    ProductActionTicket,
)
from agentguard_langgraph_adapter.product_delivery import ProductReceiptTransportResult
from agentguard_langgraph_adapter.product_envelope_store import (
    ProductEnvelopeStore,
    ProductEnvelopeStoreError,
    ProductStoreNamespace,
)
import agentguard_langgraph_adapter.product_outbox as delivery
from agentguard_langgraph_adapter.product_outbox import ProductReceiptOutbox
from agentguard_langgraph_adapter.runtime_receipts import (
    build_runtime_outcome,
    build_tool_started_observation,
)

pytestmark = pytest.mark.integration
NOW = datetime(2026, 9, 8, tzinfo=timezone.utc)
TOKEN = "hmac-sha256:" + "a" * 64


def _ack(token=TOKEN, **changes):
    return ActivationAckV1.model_validate(
        {
            "schema_version": "1.0",
            "runtime": "langgraph",
            "runtime_version": "1.2.7",
            "plugin_version": "0.1.0rc1",
            "agent_id": "main",
            "runtime_binding_id": "binding:main",
            "profile_id": "agentguard-langgraph-v2",
            "activation_ref_digest": "sha256:" + "1" * 64,
            "capability_digest": "sha256:" + "2" * 64,
            "host_inventory_digest": "sha256:" + "3" * 64,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": "sha256:" + "4" * 64,
            "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(seconds=120)).isoformat(),
            "ack_token": token,
            **changes,
        }
    )


def _receipts(name="one", ack=None):
    event = ToolCallEvent(
        event_id=f"event_{name}",
        trace_id="trace_test",
        security_context=SecurityContext(agent_id="main"),
        tool=ToolDescriptor(
            name="write", category="file", kind="write", call_id=f"action_{name}"
        ),
        arguments={"path": "fixture.txt"},
    )
    decision = PolicyDecision(
        decision_id=f"decision_{name}",
        decision="allow",
        risk_score=0,
        severity="low",
        reason="test",
        policy_audit_id=f"policy_{name}",
    )
    decision._evaluation_activation_ack = ack or _ack()
    start = build_tool_started_observation(
        event, decision, timestamp=(NOW + timedelta(seconds=1)).isoformat()
    )
    terminal = build_runtime_outcome(
        event,
        decision,
        execution_status="not_invoked",
        completed_at=(NOW + timedelta(minutes=10)).isoformat(),
    )
    return start, terminal


def _ok(wire):
    return ProductReceiptTransportResult(
        "recorded", audit_id=json.loads(wire)["audit_id"], http_status=200
    )


@pytest.fixture
def factory(tmp_path, monkeypatch):
    opened = []
    clock = {"now": 1_000_000}
    monkeypatch.setattr(delivery, "_now_ms", lambda: clock["now"])

    def make(sender=_ok, **store_options):
        store = ProductEnvelopeStore(
            tmp_path / "queue",
            tmp_path / "keys" / "key",
            namespace=ProductStoreNamespace(
                runtime="langgraph",
                agent_id="main",
                principal_id="principal_main",
                runtime_binding_id="binding:main",
            ),
            **store_options,
        )
        outbox = ProductReceiptOutbox(
            store,
            send_receipt=sender,
            retry_base_seconds=0.01,
            retry_max_seconds=0.04,
            drain_interval_seconds=0.01,
        )
        opened.append(outbox)
        return outbox, store, clock

    yield make
    for item in opened:
        item.close()


def _data(store, kind):
    return [
        json.loads(record.payload) for record in store.records() if record.kind == kind
    ]


def _begin(barrier, start):
    return barrier.begin_action(
        action_id=start.links["action_id"],
        event_id=start.links["event_id"],
        start_receipt=start,
    )


def test_receipt_is_persisted_before_http_and_ack_becomes_small_tombstone(
    factory, tmp_path
):
    records_at_send = []
    sent = []

    def send(wire):
        sent.append(wire)
        records_at_send.extend(_data(store, "receipt"))
        return _ok(wire)

    outbox, store, _ = factory(send)
    _, terminal = _receipts()
    result = outbox.submit(terminal)
    assert result.status == "recorded" and result.audit_id == terminal.audit_id
    assert records_at_send[0]["terminal"]["wire"].encode() == sent[0]
    assert (
        json.loads(sent[0])["metadata"]["activation_ack"]
        == terminal.metadata.activation_ack.to_wire()
    )
    assert _data(store, "receipt") == []
    tombstone = _data(store, "tombstone")[0]
    assert "wire" not in json.dumps(tombstone)
    assert TOKEN not in json.dumps(tombstone)
    status = outbox.status()
    assert (status.pending_count, status.completed_count, status.record_count) == (
        0,
        1,
        2,
    )
    assert not status.breaker_open
    assert outbox.submit(terminal).status == "recorded"
    assert len(sent) == 1
    assert TOKEN not in repr(outbox) + repr(status)
    for path in (tmp_path / "queue").glob("*.agq"):
        assert TOKEN.encode() not in path.read_bytes()


def test_queued_result_never_claims_acknowledgement_and_retry_has_identical_bytes(
    factory,
):
    sent = []
    fail = {"yes": True}

    def send(wire):
        sent.append(wire)
        return (
            ProductReceiptTransportResult(
                "retryable", http_status=503, error_code=TOKEN
            )
            if fail["yes"]
            else _ok(wire)
        )

    outbox, store, clock = factory(send)
    _, terminal = _receipts()
    result = outbox.submit(terminal)
    assert (
        result.status == "queued_durable"
        and result.compatibility_response()["ok"] is False
    )
    assert TOKEN not in repr(result)
    assert outbox.status().pending_count == 1
    assert outbox.drain_once() == ()
    assert outbox.submit(terminal).status == "queued_durable"
    assert len(sent) == 1
    clock["now"] += 10
    assert outbox.drain_once()[0].status == "queued_durable"
    assert _data(store, "receipt")[0]["next_attempt_at_ms"] == clock["now"] + 20
    fail["yes"] = False
    clock["now"] += 20
    assert outbox.drain_once()[0].status == "recorded"
    assert sent == [sent[0]] * 3


def test_restart_drains_expired_historical_ack_without_evaluate_or_current_session(
    factory,
):
    _, terminal = _receipts()
    outbox, _, clock = factory(
        lambda _: ProductReceiptTransportResult("retryable", http_status=503)
    )
    assert outbox.submit(terminal).status == "queued_durable"
    outbox.close()
    sent = []
    recovered, _, _ = factory(lambda wire: sent.append(wire) or _ok(wire))
    clock["now"] += 60_000
    assert recovered.drain_once()[0].status == "recorded"
    assert len(sent) == 1
    assert json.loads(sent[0])["metadata"]["activation_ack"]["ack_token"] == TOKEN
    ProductActionBarrier(recovered).assert_ready()


@pytest.mark.parametrize("http_status", [409, 422, 401])
def test_permanent_rejection_is_retained_blocks_and_does_not_hot_retry(
    factory, http_status
):
    sent = []

    def send(wire):
        sent.append(wire)
        return ProductReceiptTransportResult(
            "permanent_rejected", http_status=http_status, error_code=TOKEN
        )

    outbox, store, clock = factory(send)
    _, terminal = _receipts()
    result = outbox.submit(terminal)
    assert result.status == "permanent_rejected" and result.http_status == http_status
    assert TOKEN not in repr(result)
    assert (
        _data(store, "receipt")[0]["terminal"]["activation_ack"]["ack_token"] == TOKEN
    )
    assert outbox.status().breaker_open
    clock["now"] += 1_000_000
    assert outbox.drain_once() == ()
    assert outbox.submit(terminal).status == "permanent_rejected"
    assert len(sent) == 1
    outbox.close()
    recovered, _, _ = factory()
    assert recovered.status().breaker_open
    with pytest.raises(ProductActivationError):
        ProductActionBarrier(recovered).assert_ready()


@pytest.mark.parametrize(
    "reply",
    [
        ProductReceiptTransportResult("recorded", audit_id="wrong", http_status=200),
        ProductReceiptTransportResult("recorded", audit_id=None, http_status=200),
        ProductReceiptTransportResult(
            "recorded",
            audit_id="audit_outcome_event_one_pre_execution_deny",
            http_status=503,
        ),
    ],
)
def test_false_success_never_removes_durable_wire(factory, reply):
    outbox, store, _ = factory(lambda _: reply)
    _, terminal = _receipts()
    result = outbox.submit(terminal)
    assert result.status == "failed"
    assert result.error_code == "receipt_acknowledgement_invalid"
    assert outbox.status().breaker_open
    assert len(_data(store, "receipt")) == 1
    assert _data(store, "tombstone") == []
    assert outbox.drain_once() == ()


def test_conflicting_same_audit_id_retains_original_and_trips_breaker(factory):
    sent = []
    outbox, store, _ = factory(
        lambda wire: sent.append(wire) or ProductReceiptTransportResult("retryable")
    )
    _, original = _receipts()
    assert outbox.submit(original).status == "queued_durable"
    changed = original.model_copy(update={"reason": "changed"})
    result = outbox.submit(changed)
    assert result.status == "failed" and result.error_code == "outbox_receipt_conflict"
    assert (
        json.loads(_data(store, "receipt")[0]["terminal"]["wire"])["reason"]
        == original.reason
    )
    assert len(sent) == 1 and outbox.status().breaker_open


@pytest.mark.parametrize(
    "change", ["missing", "mismatched_explicit", "namespace", "raw_metadata"]
)
def test_receipt_carrier_must_be_private_typed_and_consistent(factory, change):
    sent = []
    outbox, _, _ = factory(lambda wire: sent.append(wire) or _ok(wire))
    start, terminal = _receipts()
    if change == "missing":
        terminal.metadata.activation_ack = None
        result = outbox.submit(terminal)
    elif change == "mismatched_explicit":
        result = outbox.submit(
            terminal, activation_ack=_ack(token="hmac-sha256:" + "b" * 64)
        )
    elif change == "namespace":
        _, terminal = _receipts(ack=_ack(runtime_binding_id="binding:other"))
        result = outbox.submit(terminal)
    else:
        start.event_type = "action_intent"
        start.metadata["activation_ack"] = _ack().to_wire()
        result = outbox.submit(start)
    assert result.status == "failed"
    assert sent == []


def test_generic_started_submit_requires_barrier_but_other_observation_uses_encryption(
    factory,
):
    sent = []
    outbox, store, _ = factory(lambda wire: sent.append(wire) or _ok(wire))
    start, _ = _receipts()
    assert outbox.submit(start).error_code == "action_barrier_required"
    start.event_type = "action_intent"
    assert outbox.submit(start).status == "recorded"
    assert len(sent) == 1 and "activation_ack" not in json.loads(sent[0])["metadata"]
    assert _data(store, "tombstone")


def test_disk_failure_prevents_http_and_latches_breaker(factory, monkeypatch):
    sent = []
    outbox, store, _ = factory(lambda wire: sent.append(wire) or _ok(wire))

    def failed_write(*_args, **_kwargs):
        raise ProductEnvelopeStoreError("write_failed")

    monkeypatch.setattr(store, "_atomic_write", failed_write)
    _, terminal = _receipts()
    assert outbox.submit(terminal).status == "failed"
    assert sent == [] and outbox.status().breaker_open


def test_tombstones_consume_capacity_and_are_never_evicted(factory):
    sent = []
    outbox, store, _ = factory(
        lambda wire: sent.append(wire) or _ok(wire), max_records=2
    )
    _, terminal = _receipts()
    assert outbox.submit(terminal).status == "recorded"
    _, second = _receipts("two")
    assert outbox.submit(second).status == "failed"
    assert len(sent) == 1
    assert store.usage().record_count == 2
    assert len(_data(store, "tombstone")) == 1
    assert outbox.status().breaker_open


def test_begin_and_finish_share_one_action_record_and_confirm_before_permit(factory):
    phases = []

    def send(wire):
        phases.append(_data(store, "action")[0])
        return _ok(wire)

    outbox, store, _ = factory(send)
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert begun.delivery.status == "recorded" and begun.ticket is not None
    assert phases[0]["phase"] == "intent" and phases[0]["terminal"] is None
    assert _data(store, "action")[0]["phase"] == "active"
    assert store.usage().record_count == 2
    with pytest.raises(ProductActivationError, match="action_already_active"):
        barrier.assert_ready()
    assert TOKEN not in repr(begun) + repr(begun.ticket)
    with pytest.raises(ProductActivationError):
        pickle.dumps(begun.ticket)
    finished = barrier.finish_action(begun.ticket, terminal)
    assert finished.status == "recorded"
    assert phases[1]["phase"] == "terminal_pending"
    assert (
        phases[1]["start"]["activation_ack"] == phases[1]["terminal"]["activation_ack"]
    )
    assert _data(store, "action") == [] and len(_data(store, "tombstone")) == 1
    barrier.assert_ready()
    assert barrier.finish_action(begun.ticket, terminal).status == "recorded"
    assert len(phases) == 2
    duplicate = _begin(barrier, start)
    assert duplicate.ticket is None and duplicate.delivery.status == "failed"


def test_start_retry_can_only_complete_receipt_never_later_issue_a_ticket(factory):
    transport = {"fail": True}
    outbox, _, clock = factory(
        lambda wire: (
            ProductReceiptTransportResult("retryable")
            if transport["fail"]
            else _ok(wire)
        )
    )
    barrier = ProductActionBarrier(outbox)
    start, _ = _receipts()
    begun = _begin(barrier, start)
    assert begun.ticket is None and begun.delivery.status == "queued_durable"
    assert outbox.status().unknown_action_count == 1
    transport["fail"] = False
    clock["now"] += 100
    assert outbox.drain_once()[0].status == "recorded"
    assert _begin(barrier, start).ticket is None
    assert outbox.status().unknown_action_count == 1


def test_restart_of_intent_blocks_and_never_manufactures_terminal_or_ticket(factory):
    outbox, _, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, _ = _receipts()
    assert _begin(barrier, start).ticket is not None
    outbox.close()
    sent = []
    recovered, store, _ = factory(lambda wire: sent.append(wire) or _ok(wire))
    barrier = ProductActionBarrier(recovered)
    assert barrier.recover().unknown_action_count == 1
    assert barrier.recover().breaker_open
    assert recovered.drain_once() == ()
    second_start, _ = _receipts("two")
    assert _begin(barrier, second_start).ticket is None
    assert _data(store, "action")[0]["terminal"] is None
    assert sent == []


def test_restart_with_terminal_pending_only_replays_terminal_and_then_unblocks(factory):
    count = {"sends": 0}

    def send(wire):
        count["sends"] += 1
        return (
            _ok(wire)
            if count["sends"] == 1
            else ProductReceiptTransportResult("retryable")
        )

    outbox, _, clock = factory(send)
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert barrier.finish_action(begun.ticket, terminal).status == "queued_durable"
    outbox.close()
    sent = []
    recovered, _, _ = factory(lambda wire: sent.append(wire) or _ok(wire))
    assert recovered.status().unknown_action_count == 0
    clock["now"] += 100
    assert recovered.drain_once()[0].status == "recorded"
    assert [json.loads(wire)["audit_id"] for wire in sent] == [terminal.audit_id]
    ProductActionBarrier(recovered).assert_ready()


def test_global_action_reservation_survives_concurrent_rejected_begin(factory):
    entered, release = Event(), Event()
    count = {"sends": 0}

    def send(wire):
        count["sends"] += 1
        if count["sends"] == 1:
            entered.set()
            assert release.wait(3)
        return _ok(wire)

    outbox, _, _ = factory(send)
    first, second = ProductActionBarrier(outbox), ProductActionBarrier(outbox)
    start, terminal = _receipts()
    other, _ = _receipts("other")
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(_begin, first, start)
        try:
            assert entered.wait(3)
            blocked = pool.submit(_begin, second, other).result(timeout=1)
            assert (
                blocked.ticket is None
                and blocked.delivery.error_code == "action_already_active"
            )
            assert not outbox.status().breaker_open
            release.set()
            permitted = pending.result(timeout=3)
            assert permitted.ticket is not None
        finally:
            release.set()
    assert first.finish_action(permitted.ticket, terminal).status == "recorded"
    assert count["sends"] == 2


def test_close_during_send_preserves_durable_record_and_discards_late_success(factory):
    entered, release = Event(), Event()

    def send(wire):
        entered.set()
        assert release.wait(3)
        return _ok(wire)

    outbox, _, _ = factory(send)
    _, terminal = _receipts()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(outbox.submit, terminal)
        try:
            assert entered.wait(3)
            outbox.close()
            release.set()
            assert pending.result(timeout=3).error_code == "outbox_closed"
        finally:
            release.set()
    recovered, _, _ = factory()
    assert recovered.status().pending_count == 1
    assert recovered.drain_once()[0].status == "recorded"


def test_false_or_foreign_tickets_cannot_finish_an_action(factory):
    outbox, _, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert (
        ProductActionBarrier(outbox).finish_action(begun.ticket, terminal).error_code
        == "action_ticket_invalid"
    )
    assert (
        barrier.finish_action(object(), terminal).error_code == "action_ticket_invalid"
    )
    with pytest.raises(ProductActivationError):
        ProductActionTicket(object(), barrier, "invented")
    assert barrier.finish_action(begun.ticket, terminal).status == "recorded"


@pytest.mark.parametrize("change", ["policy", "ack", "action", "wire"])
def test_terminal_cannot_rebind_a_started_action(factory, change):
    outbox, store, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    if change == "policy":
        terminal.links.policy_audit_id = "other"
    elif change == "ack":
        terminal.metadata.activation_ack = _ack(token="hmac-sha256:" + "b" * 64)
    elif change == "action":
        terminal.links.action_id = "action_other"
    else:
        terminal.metadata.agent_id = "other"
    assert barrier.finish_action(begun.ticket, terminal).status == "failed"
    assert _data(store, "action")[0]["terminal"] is None
    assert outbox.status().breaker_open


def test_failure_to_persist_terminal_leaves_unknown_intent_for_restart(
    factory, monkeypatch
):
    outbox, store, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    original = store._atomic_write
    monkeypatch.setattr(
        store,
        "_atomic_write",
        lambda *_args: (_ for _ in ()).throw(ProductEnvelopeStoreError("write_failed")),
    )
    assert barrier.finish_action(begun.ticket, terminal).status == "failed"
    monkeypatch.setattr(store, "_atomic_write", original)
    outbox.close()
    recovered, _, _ = factory()
    assert (
        recovered.status().unknown_action_count == 1 and recovered.status().breaker_open
    )


def test_worker_retries_persisted_receipts_and_close_stops_it(factory):
    retried = Event()
    count = {"sends": 0}

    def send(wire):
        count["sends"] += 1
        if count["sends"] > 1:
            retried.set()
            return _ok(wire)
        return ProductReceiptTransportResult("retryable")

    outbox, _, clock = factory(send)
    _, terminal = _receipts()
    assert outbox.submit(terminal).status == "queued_durable"
    clock["now"] += 100
    outbox.start()
    assert retried.wait(3)
    outbox.close()
    assert outbox._worker is not None and not outbox._worker.is_alive()


@pytest.mark.parametrize("interruption", ["close", "breaker", "pending"])
def test_ticket_publication_rechecks_close_and_breaker(
    factory, monkeypatch, interruption
):
    outbox, _, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, _ = _receipts()
    original = outbox._begin

    def intercepted(*args):
        result = original(*args)
        assert result[0].status == "recorded" and result[1] is not None
        if interruption == "close":
            outbox.close()
        elif interruption == "pending":
            monkeypatch.setattr(
                outbox, "_send", lambda _: ProductReceiptTransportResult("retryable")
            )
            _, other_terminal = _receipts("other")
            assert outbox.submit(other_terminal).status == "queued_durable"
        else:
            with outbox._mutex:
                outbox._trip_locked("receipt_permanently_rejected")
        return result

    monkeypatch.setattr(outbox, "_begin", intercepted)
    result = _begin(barrier, start)
    assert result.delivery.status == "failed" and result.ticket is None
    assert barrier._tickets == {}
    assert outbox.status().unknown_action_count == 1
    assert outbox.status().breaker_open


def test_close_reports_pending_storage_without_prior_status_call(factory):
    outbox, store, _ = factory(lambda _: ProductReceiptTransportResult("retryable"))
    _, terminal = _receipts()
    assert outbox.submit(terminal).status == "queued_durable"
    usage = store.usage()
    outbox.close()
    status = outbox.status()
    assert status.pending_count == 1 and status.completed_count == 0
    assert (status.record_count, status.stored_bytes) == (
        usage.record_count,
        usage.stored_bytes,
    )
    assert status.error_code == "outbox_closed" and status.breaker_open
