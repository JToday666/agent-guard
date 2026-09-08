"""SDK/real-HTTP transport contracts using synthetic signed TEST authority.

These tests assume the candidate adapter metadata version explicitly. They do
not qualify current 0.1.0 source, fixture digests, native execution, or a release
candidate for Product Active; no external model/provider is called.
"""

from __future__ import annotations

from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path

import pytest
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from agentguard_langgraph_adapter import activation_session
from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.core_client import (
    AgentGuardCoreClient,
    CoreClientError,
)
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.runtime_receipts import (
    build_runtime_outcome,
    submit_runtime_receipt_result,
)

from guard_api.runtime_status import activation_ack_token_digest
from tests.support.product_runtime_http import (
    ProductRuntimeHttpHarness,
    product_runtime_http,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def transport_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[ProductRuntimeHttpHarness]:
    with product_runtime_http(tmp_path) as harness:

        def assumed_candidate_version(distribution: str) -> str:
            # The installed project is still 0.1.0. This one explicit TEST
            # substitution exercises the transport contract, not artifact admission.
            if distribution == "agentguard-langgraph-adapter":
                return harness.fixture.bundle.runtime_entry("langgraph").plugin_version
            return version(distribution)

        monkeypatch.setattr(
            activation_session, "_installed_version", assumed_candidate_version
        )
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
        yield harness


@pytest.mark.parametrize("event_type", PRODUCT_EVENT_TYPES)
def test_sdk_http_contract_seven_events_use_server_ack_and_official_authority(
    transport_contract: ProductRuntimeHttpHarness, event_type: str
) -> None:
    harness = transport_contract
    adapter = LangGraphAdapter(config=harness.config())
    assert harness.requests_for("/v1/adapters/langgraph/heartbeat") == []
    try:
        ack = adapter.start_product_session(observe=lambda: harness.observation)
        heartbeats = harness.requests_for("/v1/adapters/langgraph/heartbeat")
        assert len(heartbeats) == 1
        assert heartbeats[0].status_code == 200
        record = harness.store.get_product_activation_ack(
            activation_ack_token_digest(ack.header_value())
        )
        assert record is not None
        assert (
            record.rebuild(ack.header_value()).model_dump(mode="json") == ack.to_wire()
        )

        event = harness.event(event_type)
        decision = adapter.evaluate_guard_event(event)
        assert decision.decision_id.startswith("dec:v21-product:")
        assert decision.decision_authority is not None
        authority = decision.decision_authority
        assert (authority.source, authority.mode, authority.selection_basis) == (
            "v21",
            "active",
            "profile_all",
        )
        assert authority.matched_path_ids == []
        assert authority.legacy_floor_applied is False
        assert (
            authority.activation_ref_digest
            == harness.fixture.bundle.activation_ref_digest
        )
        assert decision.approval_release_directive is not None
        assert (
            decision.approval_release_directive.capability_digest
            == ack.capability_digest
        )
        assert decision._evaluation_activation_ack is ack
        evaluated = harness.requests_for("/v1/guard/evaluate")
        assert len(evaluated) == 1
        assert evaluated[0].status_code == 200
        assert evaluated[0].activation_ack_header == ack.header_value()
        assert ack.header_value() not in decision.model_dump_json()
        assert ack.header_value() not in repr(decision)
        parent = harness.store.get_policy_evaluation_by_event_id(event["event_id"])
        assert parent is not None
        assert parent.audit_id == decision.policy_audit_id
        assert parent.metadata["product_authority_digest"].startswith("sha256:")
    finally:
        adapter.close_product_session()


def test_sdk_http_contract_unstarted_and_closed_session_make_zero_evaluate_requests(
    transport_contract: ProductRuntimeHttpHarness,
) -> None:
    harness = transport_contract
    adapter = LangGraphAdapter(config=harness.config())
    client = adapter.core_client
    assert isinstance(client, AgentGuardCoreClient)
    event = harness.event()
    try:
        for closed in (False, True):
            if closed:
                adapter.start_product_session(observe=lambda: harness.observation)
                adapter.close_product_session()
            before = len(harness.requests)
            with pytest.raises(ProductActivationError):
                client.evaluate_product_event(event)
            decision = adapter.evaluate_guard_event(event)
            assert decision.decision == "deny"
            assert decision.blocked is True
            assert decision._evaluation_activation_ack is None
            assert len(harness.requests) == before
        assert harness.requests_for("/v1/guard/evaluate") == []
        assert (
            harness.store.get_policy_evaluation_by_event_id(event["event_id"]) is None
        )
    finally:
        adapter.close_product_session()


def test_sdk_http_contract_peer_observation_drift_blocks_official_evaluation(
    transport_contract: ProductRuntimeHttpHarness,
) -> None:
    harness = transport_contract
    adapter = LangGraphAdapter(config=harness.config())
    client = adapter.core_client
    assert isinstance(client, AgentGuardCoreClient)
    try:
        ack = adapter.start_product_session(observe=lambda: harness.observation)
        drift = harness.heartbeat_openclaw(host_inventory_digest="sha256:" + "0" * 64)
        assert drift.status_code == 503
        assert (
            drift.json()["error"]["code"] == "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH"
        )
        event = harness.event()
        with pytest.raises((ProductActivationError, CoreClientError)):
            client.evaluate_product_event(event)
        decision = adapter.evaluate_guard_event(event)
        assert decision.decision == "deny"
        assert decision.blocked is True
        assert decision._evaluation_activation_ack is None
        attempts = harness.requests_for("/v1/guard/evaluate")
        assert attempts
        assert all(request.status_code == 503 for request in attempts)
        assert all(
            request.activation_ack_header == ack.header_value() for request in attempts
        )
        assert (
            harness.store.get_policy_evaluation_by_event_id(event["event_id"]) is None
        )
    finally:
        adapter.close_product_session()


def test_sdk_http_contract_receipt_keeps_evaluation_ack_after_refresh(
    transport_contract: ProductRuntimeHttpHarness,
) -> None:
    harness = transport_contract
    config = harness.config()
    config.product_receipt_directory = str(
        harness.manifest_path.parent / "receipt-queue"
    )
    config.product_receipt_key_path = str(
        harness.manifest_path.parent / "receipt-key.bin"
    )
    adapter = LangGraphAdapter(config=config)
    try:
        original_ack = adapter.start_product_session(
            observe=lambda: harness.observation
        )
        event = harness.event()
        event["payload"] = {
            "tool": {"name": "read_file", "call_id": "call:transport-receipt"},
            "arguments": {"path": "/docs/quarterly-results.txt"},
            "derived_resources": [],
        }
        decision = adapter.evaluate_guard_event(event)
        assert decision.decision == "allow"
        assert decision.policy_audit_id is not None
        fresh_ack = adapter.refresh_product_ack()
        assert fresh_ack.header_value() != original_ack.header_value()

        # No host tool is invoked in this transport test. Report that fact
        # explicitly while exercising durable receipt ingestion and ACK binding.
        receipt = build_runtime_outcome(event, decision, execution_status="not_invoked")
        assert original_ack.header_value() not in receipt.model_dump_json()
        assert original_ack.header_value() not in repr(receipt)
        assert receipt.to_wire()["metadata"]["activation_ack"] == original_ack.to_wire()
        result = submit_runtime_receipt_result(adapter, receipt, required=True)
        assert result.status == "recorded", result.error
        assert result.audit_id == receipt.audit_id
        sent = harness.requests_for("/v1/audit/events")
        assert len(sent) == 1
        assert sent[0].status_code == 200
        assert sent[0].activation_ack_header is None
        assert sent[0].body["metadata"]["activation_ack"] == original_ack.to_wire()
        persisted = harness.store.get_audit_event(receipt.audit_id)
        assert persisted is not None
        assert persisted.links["policy_audit_id"] == decision.policy_audit_id
        assert original_ack.header_value() not in persisted.model_dump_json()
        assert fresh_ack.header_value() not in persisted.model_dump_json()
    finally:
        adapter.close_product_session()
        adapter.close_product_delivery()
