"""Real SDK/Core HTTP and encrypted delivery contracts, not native admission.

The RC package version and signed authority are explicit TEST assumptions.
MemoryControlPlaneStore is the API test store, not final PostgreSQL evidence.
No provider or tool is invoked: terminal receipts truthfully say not_invoked.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
import json
from pathlib import Path
from typing import Any

import pytest
from agentguard_langgraph_adapter import activation_session, product_outbox
from agentguard_langgraph_adapter.activation_ack import (
    ActivationAckV1,
    ProductActivationError,
)
from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient
from agentguard_langgraph_adapter.event_models import AuditEvent, RuntimeOutcomeReceipt
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.product_action_barrier import ProductActionBarrier
from agentguard_langgraph_adapter.product_envelope_store import (
    ProductEnvelopeStore,
    ProductEnvelopeStoreError,
    ProductStoreNamespace,
)
from agentguard_langgraph_adapter.product_outbox import ProductReceiptOutbox
from agentguard_langgraph_adapter.runtime_receipts import (
    build_runtime_outcome,
    build_tool_started_observation,
)

from guard_api.runtime_status import activation_ack_token_digest
from tests.support.product_delivery_http import DeliveryProxy, product_delivery_proxy
from tests.support.product_runtime_http import (
    ProductRuntimeHttpHarness,
    product_runtime_http,
)

pytestmark = pytest.mark.e2e


@dataclass(slots=True)
class DeliveryHarness:
    http: ProductRuntimeHttpHarness = field(repr=False)
    proxy: DeliveryProxy = field(repr=False)
    adapter: LangGraphAdapter = field(repr=False)
    original_ack: ActivationAckV1 = field(repr=False)
    directory: Path
    key_path: Path = field(repr=False)
    outboxes: list[ProductReceiptOutbox] = field(default_factory=list, repr=False)

    def receipt(self, suffix: str) -> tuple[RuntimeOutcomeReceipt, AuditEvent]:
        event = self.http.event()
        event["event_id"] = f"evt:durable-http:{suffix}"
        event["payload"] = {
            "tool": {"name": "read_file", "call_id": f"call:durable-http:{suffix}"},
            "arguments": {"path": "/docs/quarterly-results.txt"},
            "derived_resources": [],
        }
        decision = self.adapter.evaluate_guard_event(event)
        assert decision.decision == "allow"
        assert decision._evaluation_activation_ack is self.original_ack
        terminal = build_runtime_outcome(
            event, decision, execution_status="not_invoked"
        )
        started = build_tool_started_observation(
            event, decision, timestamp=terminal.timestamp
        )
        evidence = dict(started.evidence)
        evidence["execution"] = {
            **evidence["execution"],
            "invoked_at": None,
        }
        evidence["side_effects"] = {
            "measurement_status": "not_measured",
            "count": None,
            "summary": "Transport test intent only; no tool was invoked.",
        }
        # Exercise the intent protocol without inventing a native invocation.
        intent = started.model_copy(
            update={
                "audit_id": f"audit_intent_{event['event_id']}",
                "stage": "action_intent",
                "event_type": "action_intent",
                "summary": "Transport test action intent",
                "reason": "Recorded intent; no tool was invoked.",
                "evidence": evidence,
            }
        )
        return terminal, intent

    def outbox(self) -> tuple[ProductReceiptOutbox, ProductEnvelopeStore]:
        entry = self.http.fixture.bundle.runtime_entry("langgraph")
        store = ProductEnvelopeStore(
            self.directory,
            self.key_path,
            namespace=ProductStoreNamespace(
                runtime="langgraph",
                agent_id=entry.agent_id,
                principal_id=entry.principal_id,
                runtime_binding_id=entry.runtime_binding_id,
            ),
        )
        client = self.adapter.core_client
        assert isinstance(client, AgentGuardCoreClient)
        outbox = ProductReceiptOutbox(
            store,
            send_receipt=client.submit_product_receipt_wire,
            retry_base_seconds=0.01,
            retry_max_seconds=0.01,
        )
        self.outboxes.append(outbox)
        return outbox, store

    def assert_private_disk(self) -> None:
        token = self.original_ack.header_value().encode()
        records = list(self.directory.glob("*.agq"))
        assert records
        for record in records:
            assert token not in record.read_bytes()
            assert record.stat().st_mode & 0o777 == 0o600
        assert self.directory.stat().st_mode & 0o777 == 0o700
        assert self.key_path.stat().st_mode & 0o777 == 0o600
        assert self.directory not in self.key_path.parents


@pytest.fixture
def delivery_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[DeliveryHarness]:
    with (
        product_runtime_http(tmp_path) as http,
        product_delivery_proxy(http.base_url) as proxy,
    ):

        def assumed_candidate_version(distribution: str) -> str:
            if distribution == "agentguard-langgraph-adapter":
                return http.fixture.bundle.runtime_entry("langgraph").plugin_version
            return version(distribution)

        monkeypatch.setattr(
            activation_session, "_installed_version", assumed_candidate_version
        )
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
        adapter = LangGraphAdapter(
            config=replace(http.config(), core_base_url=proxy.base_url)
        )
        ack = adapter.start_product_session(observe=lambda: http.observation)
        harness = DeliveryHarness(
            http=http,
            proxy=proxy,
            adapter=adapter,
            original_ack=ack,
            directory=tmp_path / "encrypted-delivery",
            key_path=tmp_path / "private-keys" / "delivery.key",
        )
        try:
            yield harness
        finally:
            for outbox in harness.outboxes:
                outbox.close()
            adapter.close_product_session()


def _due(monkeypatch: pytest.MonkeyPatch) -> None:
    current = product_outbox._now_ms()
    monkeypatch.setattr(product_outbox, "_now_ms", lambda: current + 60_000)


def _assert_recorded(harness: DeliveryHarness, receipt: RuntimeOutcomeReceipt) -> None:
    persisted = harness.http.store.get_audit_event(receipt.audit_id)
    assert persisted is not None
    assert persisted.links["policy_audit_id"] == receipt.links.policy_audit_id
    assert persisted.evidence is not None
    assert persisted.evidence["execution"]["status"] == "not_invoked"
    assert harness.original_ack.header_value() not in persisted.model_dump_json()


def test_product_delivery_http_records_only_after_exact_core_ack(
    delivery_http: DeliveryHarness,
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("recorded")
    outbox, _ = harness.outbox()
    result = outbox.submit(receipt)
    assert result.status == "recorded"
    assert result.audit_id == receipt.audit_id
    assert len(harness.proxy.exchanges) == 1
    assert harness.proxy.exchanges[0].upstream_status == 200
    status = outbox.status()
    assert status.completed_count == 1
    assert status.pending_count == 0
    _assert_recorded(harness, receipt)
    harness.assert_private_disk()


def test_product_delivery_http_restarts_terminal_with_original_expired_closed_ack(
    delivery_http: DeliveryHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("restart-terminal")
    outbox, _ = harness.outbox()
    harness.proxy.inject("disconnect_before")
    result = outbox.submit(receipt)
    assert result.status == "queued_durable"
    assert harness.http.store.get_audit_event(receipt.audit_id) is None
    wire = harness.proxy.exchanges[0].request_body
    fresh = harness.adapter.refresh_product_ack()
    assert fresh.header_value() != harness.original_ack.header_value()
    # Advance only the SDK test clock, never rewrite signed or historical data.
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    with pytest.raises(ProductActivationError, match="expired"):
        harness.original_ack.remaining_seconds(now=future)
    monkeypatch.setattr(activation_session, "_now_utc", lambda: future)
    harness.adapter.close_product_session()
    record = harness.http.store.get_product_activation_ack(
        activation_ack_token_digest(harness.original_ack.header_value())
    )
    assert record is not None
    harness.http.store.revoke_product_activation_acks(
        record.identity(), revoked_at=datetime.now(timezone.utc).isoformat()
    )
    outbox.close()
    restarted, _ = harness.outbox()
    harness.proxy.inject("none")
    before = len(harness.http.requests)
    _due(monkeypatch)
    results = restarted.drain_once()
    assert [item.status for item in results] == ["recorded"]
    assert harness.proxy.exchanges[-1].request_body == wire
    assert (
        json.loads(wire)["metadata"]["activation_ack"] == harness.original_ack.to_wire()
    )
    assert [item.path for item in harness.http.requests[before:]] == [
        "/v1/audit/events"
    ]
    _assert_recorded(harness, receipt)
    harness.assert_private_disk()


def test_product_delivery_http_adapter_requires_durable_paths_before_any_send(
    delivery_http: DeliveryHarness,
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("missing-durable-paths")
    result = harness.adapter.submit_audit_event(receipt)
    assert result["ok"] is False
    assert result["delivery_status"] == "failed"
    assert harness.proxy.exchanges == []
    assert harness.http.store.get_audit_event(receipt.audit_id) is None


def test_product_delivery_http_adapter_uses_encrypted_outbox_and_exact_server_ack(
    delivery_http: DeliveryHarness,
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("adapter-durable")
    adapter = LangGraphAdapter(
        config=replace(
            harness.adapter.config,
            product_receipt_directory=str(harness.directory),
            product_receipt_key_path=str(harness.key_path),
        )
    )
    try:
        result = adapter.submit_audit_event(receipt)
        assert result["ok"] is True
        assert result["delivery_status"] == "recorded"
        assert result["audit_id"] == receipt.audit_id
        assert adapter.product_delivery_status().completed_count == 1
        _assert_recorded(harness, receipt)
        harness.assert_private_disk()
    finally:
        adapter.close_product_delivery()
        adapter.close_product_session()


def test_product_delivery_http_lost_response_retries_identical_record_idempotently(
    delivery_http: DeliveryHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("lost-response")
    outbox, _ = harness.outbox()
    harness.proxy.inject("disconnect_after", count=1)
    result = outbox.submit(receipt)
    assert result.status == "queued_durable"
    _assert_recorded(harness, receipt)
    _due(monkeypatch)
    assert [item.status for item in outbox.drain_once()] == ["recorded"]
    first, replay = harness.proxy.exchanges
    assert first.upstream_status == replay.upstream_status == 200
    assert first.request_body == replay.request_body
    assert replay.upstream_body is not None
    assert json.loads(replay.upstream_body)["idempotent_replay"] is True
    assert outbox.status().completed_count == 1


@pytest.mark.parametrize(
    "fault,http_status", [("tamper_parent", 409), ("tamper_ack", 422)]
)
def test_product_delivery_http_permanent_core_rejection_survives_restart(
    delivery_http: DeliveryHarness,
    monkeypatch: pytest.MonkeyPatch,
    fault: Any,
    http_status: int,
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt(f"rejected-{http_status}")
    outbox, _ = harness.outbox()
    harness.proxy.inject(fault)
    result = outbox.submit(receipt)
    assert result.status == "permanent_rejected"
    assert result.http_status == http_status
    assert harness.proxy.exchanges[0].upstream_status == http_status
    assert harness.http.store.get_audit_event(receipt.audit_id) is None
    assert outbox.status().breaker_open is True
    outbox.close()
    restarted, _ = harness.outbox()
    harness.proxy.inject("none")
    _due(monkeypatch)
    assert restarted.drain_once() == ()
    assert len(harness.proxy.exchanges) == 1
    assert restarted.status().record_count >= 1
    assert restarted.status().breaker_open is True
    harness.assert_private_disk()


def test_product_delivery_http_wrong_ack_id_never_clears_local_record(
    delivery_http: DeliveryHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("wrong-ack-id")
    outbox, _ = harness.outbox()
    harness.proxy.inject("wrong_audit_id", count=1)
    result = outbox.submit(receipt)
    assert result.status == "failed"
    assert result.error_code == "receipt_transport_failed"
    _assert_recorded(harness, receipt)
    assert outbox.status().breaker_open is True
    assert outbox.status().completed_count == 0
    _due(monkeypatch)
    assert outbox.drain_once() == ()
    assert len(harness.proxy.exchanges) == 1
    harness.assert_private_disk()


def test_product_delivery_http_disk_failure_has_no_direct_send_fallback(
    delivery_http: DeliveryHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = delivery_http
    receipt, _ = harness.receipt("disk-failure")
    outbox, store = harness.outbox()

    def fail_write(*args: Any, **kwargs: Any) -> None:
        raise ProductEnvelopeStoreError("write_failed")

    monkeypatch.setattr(store, "_atomic_write", fail_write)
    result = outbox.submit(receipt)
    assert result.status == "failed"
    assert harness.proxy.exchanges == []
    assert harness.http.store.get_audit_event(receipt.audit_id) is None
    assert outbox.status().breaker_open is True


def test_product_delivery_http_unfinished_intent_restart_cannot_begin_action(
    delivery_http: DeliveryHarness,
) -> None:
    harness = delivery_http
    terminal, intent = harness.receipt("unknown-intent")
    next_terminal, next_intent = harness.receipt("blocked-next-intent")
    assert terminal.links.action_id is not None
    assert next_terminal.links.action_id is not None
    outbox, _ = harness.outbox()
    barrier = ProductActionBarrier(outbox)
    begun = barrier.begin_action(
        action_id=terminal.links.action_id,
        event_id=terminal.links.event_id,
        start_receipt=intent,
        activation_ack=harness.original_ack,
    )
    assert begun.delivery.status == "recorded"
    assert begun.ticket is not None
    # No tool is called and no completion is invented before process restart.
    outbox.close()
    restarted, _ = harness.outbox()
    recovered = ProductActionBarrier(restarted)
    assert recovered.recover().unknown_action_count == 1
    before = len(harness.proxy.exchanges)
    blocked = recovered.begin_action(
        action_id=next_terminal.links.action_id,
        event_id=next_terminal.links.event_id,
        start_receipt=next_intent,
        activation_ack=harness.original_ack,
    )
    assert blocked.ticket is None
    assert blocked.delivery.status == "failed"
    assert len(harness.proxy.exchanges) == before
    assert harness.http.store.get_audit_event(terminal.audit_id) is None
    assert harness.http.store.get_audit_event(next_intent.audit_id) is None
    harness.assert_private_disk()


def test_product_delivery_http_terminal_outage_blocks_next_action_and_only_replays_receipt(
    delivery_http: DeliveryHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = delivery_http
    terminal, intent = harness.receipt("terminal-outage")
    next_terminal, next_intent = harness.receipt("blocked-after-terminal")
    assert terminal.links.action_id is not None
    assert next_terminal.links.action_id is not None
    outbox, _ = harness.outbox()
    barrier = ProductActionBarrier(outbox)
    begun = barrier.begin_action(
        action_id=terminal.links.action_id,
        event_id=terminal.links.event_id,
        start_receipt=intent,
        activation_ack=harness.original_ack,
    )
    assert begun.delivery.status == "recorded"
    assert begun.ticket is not None
    harness.proxy.inject("disconnect_before")
    result = barrier.finish_action(begun.ticket, terminal)
    assert result.status == "queued_durable"
    blocked = barrier.begin_action(
        action_id=next_terminal.links.action_id,
        event_id=next_terminal.links.event_id,
        start_receipt=next_intent,
        activation_ack=harness.original_ack,
    )
    assert blocked.ticket is None
    assert blocked.delivery.status == "failed"
    assert len(harness.proxy.exchanges) == 2
    terminal_wire = harness.proxy.exchanges[-1].request_body
    outbox.close()
    restarted, _ = harness.outbox()
    assert restarted.status().unknown_action_count == 0
    harness.proxy.inject("none")
    _due(monkeypatch)
    assert [item.status for item in restarted.drain_once()] == ["recorded"]
    assert len(harness.proxy.exchanges) == 3
    assert harness.proxy.exchanges[-1].request_body == terminal_wire
    assert harness.http.store.get_audit_event(next_intent.audit_id) is None
    _assert_recorded(harness, terminal)
