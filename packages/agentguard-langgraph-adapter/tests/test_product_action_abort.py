"""A failed start grants only same-process proof that no callback was invoked."""

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import pickle
from pathlib import Path
from threading import Event

import pytest

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.product_action_barrier import ProductActionBarrier
from agentguard_langgraph_adapter.product_delivery import ProductReceiptTransportResult

_spec = importlib.util.spec_from_file_location(
    "_product_outbox_test_support", Path(__file__).with_name("test_product_outbox.py")
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
factory = _support.factory

pytestmark = pytest.mark.integration


def test_failed_start_abort_persists_both_wires_then_recovers_without_invoking(factory):
    outbox, store, _ = factory(lambda _: ProductReceiptTransportResult("retryable"))
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert begun.ticket is None and begun.abort_proof is not None
    assert barrier.abort_action(begun.abort_proof, terminal).status == "queued_durable"
    record = _data(store, "action")[0]
    assert record["terminal"] is not None and not record["start_acknowledged"]
    assert outbox.status().unknown_action_count == 0
    expected = [record[key]["wire"] for key in ("start", "terminal")]
    outbox.close()
    sent = []
    recovered, _, clock = factory(lambda wire: sent.append(wire.decode()) or _ok(wire))
    clock["now"] += 1000
    assert not recovered.status().breaker_open
    recovered.drain_once()
    assert recovered.status().pending_count == 1
    recovered.drain_once()
    assert sent == expected and recovered.status().completed_count == 1
    recovered._assert_ready()
    assert (
        ProductActionBarrier(recovered).abort_action(begun.abort_proof, terminal).status
        == "failed"
    )


@pytest.mark.parametrize("status", ["failed", "permanent_rejected"])
def test_permanently_failed_start_retains_abort_without_retry(factory, status):
    calls = []
    outbox, store, _ = factory(
        lambda wire: calls.append(wire) or ProductReceiptTransportResult(status)
    )
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert barrier.abort_action(begun.abort_proof, terminal).status == status
    assert len(calls) == 1 and _data(store, "action")[0]["terminal"] is not None
    outbox.close()
    recovered, _, _ = factory(lambda _: pytest.fail("permanent start was retried"))
    assert recovered.status().breaker_open
    assert recovered.drain_once() == ()


def test_abort_proof_is_not_ticket_and_duplicate_begin_cannot_obtain_proof(factory):
    outbox, _, _ = factory(lambda _: ProductReceiptTransportResult("retryable"))
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert barrier.finish_action(begun.abort_proof, terminal).status == "failed"
    assert _begin(barrier, start).abort_proof is None
    assert "action_one" not in repr(begun.abort_proof)
    with pytest.raises(ProductActivationError):
        pickle.dumps(begun.abort_proof)


def test_successful_start_cannot_use_an_abort_proof(factory):
    outbox, _, _ = factory()
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    assert begun.abort_proof is None
    assert barrier.abort_action(begun.ticket, terminal).status == "failed"


@pytest.mark.parametrize("mutation", ["invoked", "ack", "action"])
def test_abort_requires_not_invoked_original_anchor(factory, mutation):
    outbox, store, _ = factory(lambda _: ProductReceiptTransportResult("retryable"))
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    if mutation == "invoked":
        terminal.evidence.execution["invoked_at"] = terminal.timestamp
    elif mutation == "ack":
        _, terminal = _receipts(
            ack=start._product_activation_ack.model_copy(
                update={"ack_token": "hmac-sha256:" + "b" * 64}
            )
        )
    else:
        terminal.links.action_id = "other_action"
    assert barrier.abort_action(begun.abort_proof, terminal).status == "failed"
    assert _data(store, "action")[0]["terminal"] is None


def test_abort_merges_with_inflight_start_ack_without_losing_terminal(
    factory, monkeypatch
):
    outbox, store, clock = factory(lambda _: ProductReceiptTransportResult("retryable"))
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    entered, release = Event(), Event()

    def send(wire):
        entered.set()
        assert release.wait(2)
        return _ok(wire)

    monkeypatch.setattr(outbox, "_send", send)
    clock["now"] += 100
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(outbox.drain_once)
        assert entered.wait(2)
        result = barrier.abort_action(begun.abort_proof, terminal)
        assert result.status == "queued_durable"
        release.set()
        assert pending.result()[0].status == "recorded"
    record = _data(store, "action")[0]
    assert record["start_acknowledged"] and record["terminal"] is not None
    assert record["phase"] == "terminal_pending" and not outbox.status().breaker_open
    assert outbox.drain_once()[0].audit_id == terminal.audit_id
    assert outbox.status().completed_count == 1


def test_unaborted_start_on_restart_remains_unknown(factory):
    outbox, _, _ = factory(lambda _: ProductReceiptTransportResult("retryable"))
    start, _ = _receipts()
    assert _begin(ProductActionBarrier(outbox), start).abort_proof is not None
    outbox.close()
    recovered, _, _ = factory()
    assert recovered.status().unknown_action_count == 1
    with pytest.raises(ProductActivationError):
        ProductActionBarrier(recovered).assert_ready()


def test_abort_confirmation_refers_to_terminal_not_start(factory, monkeypatch):
    outbox, _, clock = factory(lambda _: ProductReceiptTransportResult("retryable"))
    barrier = ProductActionBarrier(outbox)
    start, terminal = _receipts()
    begun = _begin(barrier, start)
    clock["now"] += 100
    monkeypatch.setattr(
        outbox,
        "_send",
        lambda wire: (
            _ok(wire)
            if json.loads(wire)["record_type"] == "runtime_observation"
            else ProductReceiptTransportResult("retryable")
        ),
    )
    result = barrier.abort_action(begun.abort_proof, terminal)
    assert result.status == "queued_durable" and result.audit_id == terminal.audit_id
