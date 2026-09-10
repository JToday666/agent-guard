"""Explicit encrypted receipt reconciliation never creates execution authority."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from threading import Event

import pytest

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.product_action_barrier import ProductActionBarrier
from agentguard_langgraph_adapter.product_delivery import ProductReceiptTransportResult
from agentguard_langgraph_adapter.product_envelope_store import (
    ProductEnvelopeStore,
    ProductEnvelopeStoreError,
    ProductStoreNamespace,
)
from agentguard_langgraph_adapter.product_outbox import ProductReceiptOutbox
import agentguard_langgraph_adapter.product_outbox as delivery

_spec = importlib.util.spec_from_file_location(
    "_reconciliation_support", Path(__file__).with_name("test_product_outbox.py")
)
assert _spec is not None and _spec.loader is not None
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)
_begin, _data, _ok, _receipts = (
    _support._begin,
    _support._data,
    _support._ok,
    _support._receipts,
)
DIGEST = "b" * 64
pytestmark = pytest.mark.integration


@pytest.fixture
def factory(tmp_path, monkeypatch):
    boxes = []
    clock = {"now": 1_000_000}
    monkeypatch.setattr(delivery, "_now_ms", lambda: clock["now"])

    def make(sender=_ok, *, binding=DIGEST, receipts_only=False, **options):
        store = ProductEnvelopeStore(
            tmp_path / "queue",
            tmp_path / "keys" / "key",
            namespace=ProductStoreNamespace(
                runtime="langgraph",
                agent_id="main",
                principal_id="principal_main",
                runtime_binding_id="binding:main",
            ),
            **options,
        )
        try:
            box = ProductReceiptOutbox(
                store,
                send_receipt=sender,
                receipts_only=receipts_only,
                transport_binding_digest=binding,
                retry_base_seconds=0.01,
                retry_max_seconds=0.04,
                drain_interval_seconds=0.01,
            )
        except BaseException:
            store.close()
            raise
        boxes.append(box)
        return box, store, clock

    yield make
    for box in boxes:
        box.close()


def rejected(factory, *, status=409, binding=DIGEST):
    wires = []
    box, store, clock = factory(
        lambda wire: wires.append(wire)
        or ProductReceiptTransportResult(
            "permanent_rejected",
            json.loads(wire)["audit_id"],
            status,
        ),
        binding=binding,
    )
    _, receipt = _receipts()
    assert box.submit(receipt).status == "permanent_rejected"
    digest = sha256(wires[0]).hexdigest()
    return box, store, clock, receipt, digest, wires


@pytest.mark.parametrize("status", [None, 200, 408, 429, 503])
def test_bound_delivery_requires_actual_permanent_http_evidence(factory, status):
    sent = []
    box, _, _ = factory(
        lambda wire: sent.append(wire)
        or ProductReceiptTransportResult(
            "permanent_rejected", json.loads(wire)["audit_id"], status
        )
    )
    _, receipt = _receipts()
    reply = box.submit(receipt)
    assert reply.status == "failed"
    assert reply.error_code == "receipt_transport_invalid"
    box.close()
    recovery, _, _ = factory(
        lambda _wire: pytest.fail("invalid original rejection cannot be reconciled"),
        receipts_only=True,
    )
    result = recovery.reconcile_rejected_receipt(
        receipt.audit_id, sha256(sent[0]).hexdigest()
    )
    assert result.status == "failed"
    assert result.error_code == "receipt_reconciliation_ineligible"
    assert recovery.status().pending_count == 1


def test_manual_confirmation_requires_actual_successful_http_status(factory):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    recovery, _, _ = factory(
        lambda _wire: ProductReceiptTransportResult("recorded", receipt.audit_id),
        receipts_only=True,
    )
    result = recovery.reconcile_rejected_receipt(receipt.audit_id, digest)
    assert result.status == "failed"
    assert result.error_code == "receipt_acknowledgement_invalid"
    snapshot = recovery.reconciliation_snapshot(receipt.audit_id, digest)
    assert snapshot.confirmed is False
    assert snapshot.attempts[-1].outcome == "failed"
    assert recovery.status().pending_count == 1
    recovery.close()
    reopened, _, _ = factory(
        lambda _wire: pytest.fail(
            "invalid confirmation is not a retryable transport failure"
        ),
        receipts_only=True,
    )
    assert (
        reopened.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_ineligible"
    )


@pytest.mark.parametrize("status", [409, 422])
def test_exact_immutable_receipt_is_explicitly_confirmed_once_and_stays_blocked(
    factory,
    status,
):
    box, store, _, receipt, digest, original = rejected(factory, status=status)
    assert box.transport_binding_digest == DIGEST
    assert (
        box.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_worker_required"
    )
    assert box.drain_once() == ()
    assert box.submit(receipt).status == "permanent_rejected"
    assert len(original) == 1
    box.close()
    sends = []

    def send(wire):
        snapshot = recovered.reconciliation_snapshot(receipt.audit_id, digest)
        assert snapshot.attempts[-1].outcome == "prepared"
        assert snapshot.requires_explicit_retry
        sends.append(wire)
        return _ok(wire)

    recovered, store, _ = factory(send, receipts_only=True)
    assert recovered.drain_once() == ()
    result = recovered.reconcile_rejected_receipt(receipt.audit_id, digest)
    assert result.status == "recorded" and sends == original
    snapshot = recovered.reconciliation_snapshot(receipt.audit_id, digest)
    assert snapshot.confirmed and not snapshot.pending and snapshot.breaker_open
    assert snapshot.original_rejection.http_status == status
    assert snapshot.attempts[-1].outcome == "recorded"
    assert _support.TOKEN not in json.dumps(asdict(snapshot))
    assert "wire" not in _data(store, "tombstone")[0]
    assert (
        recovered.reconcile_rejected_receipt(receipt.audit_id, digest).status
        == "recorded"
    )
    assert len(sends) == 1
    recovered.close()
    normal, _, _ = factory(lambda _: pytest.fail("confirmed receipt resent"))
    assert normal.status().breaker_open
    with pytest.raises(ProductActivationError):
        ProductActionBarrier(normal).assert_ready()


@pytest.mark.parametrize("binding", [None, "c" * 64])
def test_bound_queue_cannot_reopen_with_missing_or_different_transport(
    factory, binding
):
    box, _, _, _, _, _ = rejected(factory)
    box.close()
    with pytest.raises(ProductActivationError, match="transport_binding_mismatch"):
        factory(lambda _: pytest.fail("foreign endpoint used"), binding=binding)


@pytest.mark.parametrize("binding", [None, DIGEST])
def test_legacy_queue_is_never_retroactively_bound(factory, binding):
    box, _, _, receipt, digest, _ = rejected(factory, binding=None)
    box.close()
    legacy, store, _ = factory(binding=binding, receipts_only=True)
    assert legacy.transport_binding_digest is None
    assert (
        legacy.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "outbox_transport_binding_missing"
    )
    assert _data(store, "breaker")[0]["schema_version"] == "1.0"
    assert _data(store, "receipt")[0]["schema_version"] == "1.0"


@pytest.mark.parametrize(
    "digest", ["sha256:" + "b" * 64, "B" * 64, "b" * 63, True, " b" * 32]
)
def test_selector_and_binding_are_strict_raw_lowercase_hex(factory, digest):
    box, _, _, receipt, _, _ = rejected(factory)
    box.close()
    recovery, _, _ = factory(receipts_only=True)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_selector_invalid"
    )
    with pytest.raises(ProductActivationError, match="selector_invalid"):
        recovery.reconciliation_snapshot(receipt.audit_id, digest)
    recovery.close()
    with pytest.raises(ProductActivationError, match="invalid_configuration"):
        factory(binding=digest)


@pytest.mark.parametrize("change", ["digest", "missing", "unknown"])
def test_selection_failures_send_nothing(factory, change):
    if change == "unknown":
        box, _, _ = factory(
            lambda _: ProductReceiptTransportResult(
                "permanent_rejected", http_status=409
            )
        )
        start, _ = _receipts()
        _begin(ProductActionBarrier(box), start)
        data = next(d for _, d in box._records.values() if d["record_type"] == "action")
        audit, digest = start.audit_id, data["start"]["wire_digest"]
    else:
        box, _, _, receipt, digest, _ = rejected(factory)
        audit = "absent" if change == "missing" else receipt.audit_id
        digest = "0" * 64 if change == "digest" else digest
    box.close()
    recovery, _, _ = factory(
        lambda _: pytest.fail("unselected wire sent"), receipts_only=True
    )
    assert recovery.reconcile_rejected_receipt(audit, digest).status == "failed"


def test_start_and_real_not_invoked_abort_require_two_distinct_explicit_calls(factory):
    wires = []
    box, _, _ = factory(
        lambda w: wires.append(w)
        or ProductReceiptTransportResult("permanent_rejected", http_status=422)
    )
    barrier = ProductActionBarrier(box)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert begun.ticket is None and begun.abort_proof is not None
    assert (
        barrier.abort_action(begun.abort_proof, terminal).status == "permanent_rejected"
    )
    owner = next(d for _, d in box._records.values() if d["record_type"] == "action")
    start_digest, terminal_digest = (
        owner["start"]["wire_digest"],
        owner["terminal"]["wire_digest"],
    )
    box.close()
    sent = []
    recovery, _, _ = factory(lambda w: sent.append(w) or _ok(w), receipts_only=True)
    assert (
        recovery.reconcile_rejected_receipt(
            terminal.audit_id, terminal_digest
        ).error_code
        == "receipt_reconciliation_order_invalid"
    )
    assert (
        recovery.reconcile_rejected_receipt(start.audit_id, start_digest).status
        == "recorded"
    )
    assert recovery.status().pending_count == 1 and recovery.drain_once() == ()
    assert (
        recovery.reconcile_rejected_receipt(start.audit_id, start_digest).status
        == "recorded"
    )
    assert len(sent) == 1
    assert (
        recovery.reconcile_rejected_receipt(terminal.audit_id, terminal_digest).status
        == "recorded"
    )
    assert [json.loads(w)["audit_id"] for w in sent] == [
        start.audit_id,
        terminal.audit_id,
    ]
    assert sent[0] == wires[0] and recovery.status().completed_count == 1
    assert recovery._active is None and recovery._starting is None
    with pytest.raises(ProductActivationError, match="receipts_only"):
        recovery.start()
    assert recovery.submit(terminal).error_code == "outbox_receipts_only"


@pytest.mark.parametrize("outcome", ["retryable", "permanent_rejected"])
def test_explicit_failure_never_becomes_background_retry_and_trace_is_bounded(
    factory, outcome
):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    sent = []
    recovery, _, clock = factory(
        lambda w: sent.append(w)
        or ProductReceiptTransportResult(
            outcome, http_status=503 if outcome == "retryable" else 409
        ),
        receipts_only=True,
    )
    for _ in range(32):
        assert recovery.reconcile_rejected_receipt(receipt.audit_id, digest).status == (
            "queued_durable" if outcome == "retryable" else "permanent_rejected"
        )
        clock["now"] += 100_000
        assert recovery.drain_once() == ()
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_limit"
    )
    assert len(sent) == 32
    snapshot = recovery.reconciliation_snapshot(receipt.audit_id, digest)
    assert len(snapshot.attempts) == 32 and not snapshot.confirmed
    recovery.close()
    reopened, _, _ = factory(
        lambda _: pytest.fail("permanent retry after restart"), receipts_only=True
    )
    assert reopened.drain_once() == ()
    assert (
        len(reopened.reconciliation_snapshot(receipt.audit_id, digest).attempts) == 32
    )


@pytest.mark.parametrize("stage", ["prepared", "confirmation"])
def test_disk_failure_never_claims_recorded_and_original_wire_can_recover(
    factory, monkeypatch, stage
):
    box, _, _, receipt, digest, original = rejected(factory)
    box.close()
    sent = []
    recovery, store, _ = factory(lambda w: sent.append(w) or _ok(w), receipts_only=True)
    replace = store.replace

    def fail(record_id, payload, **kwargs):
        data = json.loads(payload)
        if data["record_type"] != "breaker" and (
            stage == "prepared" or data["record_type"] == "tombstone"
        ):
            raise ProductEnvelopeStoreError("write_failed")
        return replace(record_id, payload, **kwargs)

    monkeypatch.setattr(store, "replace", fail)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).status == "failed"
    )
    assert sent == ([] if stage == "prepared" else original)
    monkeypatch.setattr(store, "replace", replace)
    recovery.close()
    recovered, _, _ = factory(lambda w: sent.append(w) or _ok(w), receipts_only=True)
    assert (
        recovered.reconcile_rejected_receipt(receipt.audit_id, digest).status
        == "recorded"
    )
    snapshot = recovered.reconciliation_snapshot(receipt.audit_id, digest)
    assert snapshot.attempts[-1].outcome == "recorded"
    if stage == "confirmation":
        assert snapshot.attempts[0].outcome == "outcome_unknown"
    assert all(w == original[0] for w in sent)


def test_close_retains_owner_and_single_flight_until_actual_send_finishes(factory):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    entered, release = Event(), Event()

    def send(wire):
        entered.set()
        assert release.wait(5)
        return _ok(wire)

    recovery, _, _ = factory(send, receipts_only=True)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            recovery.reconcile_rejected_receipt, receipt.audit_id, digest
        )
        try:
            assert entered.wait(3)
            assert (
                recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
                == "receipt_reconciliation_busy"
            )
            assert recovery.drain_once() == ()
            status = recovery.close()
            assert status.closing and status.error_code == "outbox_closing"
            with pytest.raises(ProductEnvelopeStoreError, match="store_locked"):
                factory(receipts_only=True)
        finally:
            release.set()
        assert pending.result(timeout=3).error_code == "outbox_closed"
    assert not recovery.status().closing
    resumed, _, _ = factory(receipts_only=True)
    assert (
        resumed.reconcile_rejected_receipt(receipt.audit_id, digest).status
        == "recorded"
    )
    assert (
        resumed.reconciliation_snapshot(receipt.audit_id, digest).attempts[0].outcome
        == "outcome_unknown"
    )


def test_completed_reconciliation_derives_sticky_even_if_breaker_writes_always_fail(
    factory, monkeypatch
):
    box, store, _ = factory(
        lambda _: ProductReceiptTransportResult("permanent_rejected", http_status=409)
    )
    replace = store.replace

    def skip_breaker(record_id, payload, **kwargs):
        if json.loads(payload)["record_type"] == "breaker":
            raise ProductEnvelopeStoreError("write_failed")
        return replace(record_id, payload, **kwargs)

    monkeypatch.setattr(store, "replace", skip_breaker)
    _, receipt = _receipts()
    assert box.submit(receipt).status == "permanent_rejected"
    data = _data(store, "receipt")[0]
    digest = data["terminal"]["wire_digest"]
    assert not _data(store, "breaker")[0]["tripped"]
    box.close()
    recovery, store, _ = factory(receipts_only=True)
    replace = store.replace
    monkeypatch.setattr(store, "replace", skip_breaker)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).status
        == "recorded"
    )
    assert not _data(store, "breaker")[0]["tripped"]
    recovery.close()
    normal, _, _ = factory()
    assert normal.status().breaker_open
    assert _begin(ProductActionBarrier(normal), _receipts("next")[0]).ticket is None


@pytest.mark.parametrize("state", ["empty", "tombstone", "retryable"])
def test_existing_legacy_control_never_upgrades_even_with_new_adapter_digest(
    factory, state
):
    box, _, _ = factory(
        (
            _ok
            if state != "retryable"
            else lambda _: ProductReceiptTransportResult("retryable")
        ),
        binding=None,
    )
    _, receipt = _receipts()
    if state != "empty":
        box.submit(receipt)
    box.close()
    upgraded, store, clock = factory(binding=DIGEST)
    assert upgraded.transport_binding_digest is None
    clock["now"] += 10_000
    if state == "retryable":
        assert upgraded.drain_once()[0].status == "recorded"
    elif state == "empty":
        assert upgraded.submit(receipt).status == "recorded"
    assert all(
        json.loads(record.payload)["schema_version"] == "1.0"
        for record in store.records()
    )


def test_ordinary_confirmed_receipt_is_not_a_reconciliation(factory):
    box, _, _ = factory()
    _, receipt = _receipts()
    assert box.submit(receipt).status == "recorded"
    tomb = next(data for _, data in box._records.values())
    digest = tomb["terminal_digest"]
    box.close()
    recovery, _, _ = factory(
        lambda _: pytest.fail("normal success resent"), receipts_only=True
    )
    assert recovery.reconciliation_snapshot(receipt.audit_id, digest).confirmed
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_ineligible"
    )


def test_normal_start_is_not_reconciled_by_terminal_lineage(factory):
    start, terminal = _receipts()
    box, _, _ = factory(
        lambda wire: (
            _ok(wire)
            if json.loads(wire)["audit_id"] == start.audit_id
            else ProductReceiptTransportResult("permanent_rejected", http_status=409)
        )
    )
    barrier = ProductActionBarrier(box)
    begun = _begin(barrier, start)
    assert begun.ticket is not None
    assert barrier.finish_action(begun.ticket, terminal).status == "permanent_rejected"
    owner = next(data for _, data in box._records.values())
    start_digest = owner["start"]["wire_digest"]
    terminal_digest = owner["terminal"]["wire_digest"]
    box.close()
    wires = []
    recovery, _, _ = factory(
        lambda wire: wires.append(wire) or _ok(wire), receipts_only=True
    )
    for terminal_reconciled in (False, True):
        if terminal_reconciled:
            assert (
                recovery.reconcile_rejected_receipt(
                    terminal.audit_id, terminal_digest
                ).status
                == "recorded"
            )
        assert recovery.reconciliation_snapshot(start.audit_id, start_digest).confirmed
        assert (
            recovery.reconcile_rejected_receipt(start.audit_id, start_digest).error_code
            == "receipt_reconciliation_ineligible"
        )
    assert [json.loads(wire)["audit_id"] for wire in wires] == [terminal.audit_id]


@pytest.mark.parametrize("binding", [None, DIGEST])
def test_existing_empty_owner_anchor_cannot_be_adopted_as_new(
    factory, tmp_path, binding
):
    box, _, _ = factory(binding=binding)
    # Simulate loss of all encrypted control/records while retaining the owner
    # anchor and original key; ordinary producer reopening must fail closed too.
    root = tmp_path / "queue"
    box.close()
    for record in root.glob("*.agq"):
        record.unlink()
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(ProductActivationError, match="outbox_control_missing"):
        factory(binding=binding)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy_record",
        "legacy_control",
        "record_binding",
        "tombstone_binding",
        "missing_control",
    ],
)
def test_mixed_or_unbound_control_cannot_attest_existing_records(
    factory, tmp_path, mutation
):
    if mutation == "tombstone_binding":
        box, store, _ = factory()
        assert box.submit(_receipts()[1]).status == "recorded"
    else:
        box, store, _, _, _, _ = rejected(factory)
    for stored in store.records():
        data = json.loads(stored.payload)
        if mutation == "missing_control" and stored.kind == "breaker":
            control_name = sha256(stored.record_id.encode()).hexdigest() + ".agq"
            continue
        chosen = (
            stored.kind == "breaker"
            if mutation == "legacy_control"
            else stored.kind != "breaker"
        )
        if not chosen:
            continue
        if mutation in {"legacy_control", "legacy_record"}:
            data["schema_version"] = "1.0"
            data.pop("transport_binding_digest")
            data.pop("reconciliation", None)
        elif mutation in {"record_binding", "tombstone_binding"}:
            data["transport_binding_digest"] = "c" * 64
        else:
            continue
        store.replace(
            stored.record_id,
            delivery._encode(data),
            expected_revision=stored.revision,
            kind=stored.kind,
        )
    box.close()
    if mutation == "missing_control":
        (tmp_path / "queue" / control_name).unlink()
    originals = {p.name: p.read_bytes() for p in (tmp_path / "queue").glob("*.agq")}
    with pytest.raises(ProductActivationError):
        factory(lambda _: pytest.fail("mixed binding sent"), receipts_only=True)
    assert {
        p.name: p.read_bytes() for p in (tmp_path / "queue").glob("*.agq")
    } == originals


def test_bound_control_creation_failure_never_falls_back_to_unbound(
    factory, monkeypatch
):
    create = ProductEnvelopeStore.create

    def fail(self, identity, payload, **kwargs):
        if kwargs.get("kind") == "breaker":
            assert json.loads(payload)["transport_binding_digest"] == DIGEST
            raise ProductEnvelopeStoreError("write_failed")
        return create(self, identity, payload, **kwargs)

    monkeypatch.setattr(ProductEnvelopeStore, "create", fail)
    with pytest.raises(ProductActivationError, match="outbox_recovery_failed"):
        factory(lambda _: pytest.fail("unbound fallback"))


def test_prepared_attempt_capacity_failure_keeps_original_and_sends_zero(
    factory, monkeypatch
):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    recovery, store, _ = factory(
        lambda _: pytest.fail("capacity bypass"), receipts_only=True
    )
    owner = next(r for r in store.records() if r.kind == "receipt")
    monkeypatch.setattr(store, "_max_record_bytes", owner.stored_bytes)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).status == "failed"
    )
    assert store.get(owner.record_id).payload == owner.payload


def test_intervening_record_revision_cannot_be_confirmed_or_silently_reconciled(
    factory,
):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    sent = []

    def send(wire):
        sent.append(wire)
        owner = next(r for r in store.records() if r.kind == "receipt")
        changed = json.loads(owner.payload)
        changed["attempts"] += 1
        store.replace(
            owner.record_id,
            delivery._encode(changed),
            expected_revision=owner.revision,
            kind=owner.kind,
        )
        return _ok(wire)

    recovery, store, _ = factory(send, receipts_only=True)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "outbox_receipt_conflict"
    )
    assert not recovery.reconciliation_snapshot(receipt.audit_id, digest).confirmed
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "outbox_receipt_conflict"
    )
    assert len(sent) == 1 and _data(store, "receipt")


@pytest.mark.parametrize(
    "reply",
    [
        ProductReceiptTransportResult("recorded", "foreign-audit", 200),
        ProductReceiptTransportResult("recorded", "ignored", 409),
        {"ok": False},
    ],
)
def test_invalid_acknowledgement_is_retained_and_never_confirmed(factory, reply):
    box, _, _, receipt, digest, _ = rejected(factory)
    box.close()
    sent = []
    recovery, store, _ = factory(lambda w: sent.append(w) or reply, receipts_only=True)
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).status == "failed"
    )
    snapshot = recovery.reconciliation_snapshot(receipt.audit_id, digest)
    assert not snapshot.confirmed and snapshot.attempts[-1].outcome == "failed"
    assert recovery.drain_once() == ()
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "receipt_reconciliation_ineligible"
    )
    assert len(sent) == 1 and _data(store, "receipt")


def test_duplicate_audit_across_owner_records_is_not_arbitrarily_selected(factory):
    box, store, _, receipt, digest, _ = rejected(factory)
    start, _ = _receipts()
    start_item, action_id, event_id = box._receipt_item(start, None)
    terminal_item, _, _ = box._receipt_item(receipt, None)
    data = delivery._new_record(
        "action", action_id, event_id, start=start_item, terminal=terminal_item
    )
    data.update(
        schema_version="1.1",
        start_acknowledged=True,
        phase="terminal_pending",
        transport_binding_digest=DIGEST,
        reconciliation=None,
    )
    store.create(
        delivery._record_id("action", action_id), delivery._encode(data), kind="action"
    )
    box.close()
    recovery, _, _ = factory(
        lambda _: pytest.fail("ambiguous owner sent"), receipts_only=True
    )
    assert (
        recovery.reconcile_rejected_receipt(receipt.audit_id, digest).error_code
        == "outbox_receipt_conflict"
    )


def test_control_and_records_cannot_be_downgraded_in_a_live_owner(factory):
    box, store, _, receipt, digest, _ = rejected(factory)
    for record in store.records():
        data = json.loads(record.payload)
        data["schema_version"] = "1.0"
        data.pop("transport_binding_digest")
        data.pop("reconciliation", None)
        store.replace(
            record.record_id,
            delivery._encode(data),
            expected_revision=record.revision,
            kind=record.kind,
        )
    with pytest.raises(ProductActivationError, match="transport_binding_mismatch"):
        box.reconciliation_snapshot(receipt.audit_id, digest)
