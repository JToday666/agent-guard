"""Historical Product ACK verification on durable runtime outcome ingestion."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard_core import (
    RuntimeOutcomeReceipt,
    ToolCallPayload,
    ToolDescriptor,
    build_activation_ack,
)
from guard_api.runtime_status import (
    ProductRuntimeHeartbeatV2,
    activation_ack_token_digest,
)
from guard_api.services.audit import AuditService, RuntimeOutcomeReceiptError
from guard_api.main import create_app
from guard_api.services.approval import ApprovalService
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import (
    approval_execution_lease_service_from_settings,
)
from tests.support.product_evaluation import (
    PRODUCT_REPLAY_RAW_TOKEN,
    create_product_evaluation_harness,
)
from tests.test_rte05_execution_lease_api import _approval_release_receipt
from tests.test_product_v21_service_selector import _force_current_decision

pytestmark = pytest.mark.integration


def _rig(tmp_path: Path, runtime: str = "langgraph", *, harness=None):
    if harness is None:
        harness = create_product_evaluation_harness(tmp_path, runtime=runtime)
    event = harness.event()
    event.security_context.source_trust = "trusted"
    event.security_context.user_task = (
        "Summarize the quarterly results already present in the conversation."
    )
    event.payload = ToolCallPayload(
        tool=ToolDescriptor(name="read_file", call_id="call:receipt"),
        arguments={"path": "/docs/quarterly-results.txt"},
        derived_resources=[],
    )
    response = harness.evaluate(event)
    assert response.decision.decision == "allow"
    parent = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert parent is not None
    record = harness.store.get_product_activation_ack(
        activation_ack_token_digest(harness.activation_ack_token)
    )
    assert record is not None
    ack = record.rebuild(harness.activation_ack_token)
    # A long-running tool may complete after its release ACK has expired.
    completed = datetime.fromisoformat(parent.timestamp) + timedelta(minutes=5)
    payload = json.loads(
        (
            Path(__file__).parent
            / "fixtures/runtime_enforcement/execution_completed.json"
        ).read_text()
    )
    for key in (
        "trace_id",
        "case_id",
        "runtime",
        "decision",
        "risk_score",
        "severity",
        "blocked",
        "is_malicious",
        "rule_hits",
    ):
        payload[key] = getattr(parent, key)
    payload["audit_id"] = f"audit_outcome_{event.event_id}_execution_completed"
    payload["timestamp"] = completed.isoformat()
    payload["links"] = {
        **{
            key: parent.links.get(key)
            for key in (
                "event_id",
                "decision_id",
                "action_id",
                "approval_id",
            )
        },
        "policy_audit_id": parent.audit_id,
    }
    payload["metadata"].update(
        agent_id=parent.metadata["agent_id"],
        activation_ack=ack.model_dump(mode="json"),
    )
    payload["links"] = {
        key: value for key, value in payload["links"].items() if value is not None
    }
    payload["evidence"]["execution"].update(
        invoked_at=parent.timestamp,
        completed_at=completed.isoformat(),
    )
    service = AuditService(
        store=harness.store,
        product_activation_authority=harness.evaluation.product_activation_authority,
    )
    return harness, parent, payload, service


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_delayed_receipt_and_replay_use_historical_ack_without_live_authority(
    tmp_path: Path,
    runtime: str,
) -> None:
    harness, parent, payload, service = _rig(tmp_path, runtime)
    record = harness.store.get_product_activation_ack(
        activation_ack_token_digest(harness.activation_ack_token)
    )
    assert record is not None
    harness.store.revoke_product_activation_acks(
        record.identity(),
        revoked_at=(
            datetime.fromisoformat(parent.timestamp) + timedelta(seconds=1)
        ).isoformat(),
    )
    authority = service.product_activation_authority
    assert authority is not None
    service.product_activation_authority = replace(
        authority,
        clock=lambda: datetime.now(timezone.utc) + timedelta(days=30),
    )
    receipt = RuntimeOutcomeReceipt.model_validate(payload)
    first = service.submit(receipt, auth_context=harness.auth_context)
    replay = service.submit(receipt, auth_context=harness.auth_context)
    assert first["created"] is True
    assert replay["idempotent_replay"] is True
    persisted = harness.store.get_audit_event(receipt.audit_id)
    assert persisted is not None
    assert harness.activation_ack_token not in persisted.model_dump_json()
    assert harness.activation_ack_token not in repr(
        service.product_activation_authority
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "tampered",
        "unissued",
        "revoked",
        "wrong_principal",
        "expired_at_anchor",
    ],
)
def test_invalid_receipt_ack_is_permanent_and_writes_nothing(
    tmp_path: Path,
    mutation: str,
) -> None:
    harness, parent, payload, service = _rig(tmp_path)
    auth = harness.auth_context
    ack = payload["metadata"]["activation_ack"]
    record = harness.store.get_product_activation_ack(
        activation_ack_token_digest(harness.activation_ack_token)
    )
    assert record is not None
    if mutation == "missing":
        payload["metadata"].pop("activation_ack")
    elif mutation == "tampered":
        ack["ack_token"] = "hmac-sha256:" + "0" * 64
    elif mutation == "unissued":
        claims = {
            key: value
            for key, value in ack.items()
            if key not in {"schema_version", "ack_token"}
        }
        claims["runtime_binding_id"] = "binding:unissued"
        payload["metadata"]["activation_ack"] = build_activation_ack(
            server_secret=harness.fixture.server_secret,
            **claims,
        ).model_dump(mode="json")
    elif mutation == "revoked":
        harness.store.revoke_product_activation_acks(
            record.identity(),
            revoked_at=parent.timestamp,
        )
    elif mutation == "expired_at_anchor":
        # Signed and registered ACK, but the server authority anchor is outside
        # its half-open window. Runtime timestamps cannot repair that mismatch.
        original = service.product_activation_authority
        assert original is not None
        real_enforce = type(original).enforce_receipt

        def expired_anchor(
            self, receipt, auth_context, *, parent_authority, reference_time
        ):
            return real_enforce(
                self,
                receipt,
                auth_context,
                parent_authority=parent_authority,
                reference_time=datetime.fromisoformat(ack["expires_at"]),
            )

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(type(original), "enforce_receipt", expired_anchor)
            with pytest.raises(RuntimeOutcomeReceiptError) as raised:
                service.submit(
                    RuntimeOutcomeReceipt.model_validate(payload), auth_context=auth
                )
        assert raised.value.code == "RUNTIME_OUTCOME_INVALID"
        assert harness.store.get_audit_event(payload["audit_id"]) is None
        return
    else:
        auth = replace(auth, principal_id="principal:other")
    before = len(harness.store.audit_events)
    with pytest.raises(RuntimeOutcomeReceiptError) as raised:
        service.submit(RuntimeOutcomeReceipt.model_validate(payload), auth_context=auth)
    assert raised.value.code == "RUNTIME_OUTCOME_INVALID"
    assert len(harness.store.audit_events) == before


def test_ask_receipt_uses_consumed_lease_time_after_human_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event = harness.event()
    event.security_context.source_trust = "trusted"
    event.security_context.user_task = (
        "Summarize the quarterly results already present in the conversation."
    )
    event.payload = ToolCallPayload(
        tool=ToolDescriptor(name="read_file", call_id="call:receipt-ask"),
        arguments={"path": "/docs/quarterly-results.txt"},
        derived_resources=[],
    )
    _force_current_decision(monkeypatch, "ask")
    response = harness.evaluate(event)
    assert response.approval is not None
    assert response.enforcement_binding is not None
    authority = harness.evaluation.product_activation_authority
    assert authority is not None
    approvals = ApprovalService(
        store=harness.store,
        settings=harness.settings,
        state_service=SecurityStateService(harness.store),
    )
    approval = approvals.resolve_approval(
        response.approval.approval_id,
        "allow_once",
        resolution_source="human",
    )
    # Approval can complete after the evaluation heartbeat. Lease and receipt
    # carry the newly refreshed ACK, whose issuance is after the policy parent.
    status = harness.store.list_product_runtime_statuses(runtime="langgraph")[0]
    heartbeat = ProductRuntimeHeartbeatV2.model_validate(
        status.model_dump(
            mode="json",
            exclude={"runtime", "principal_id", "last_heartbeat_at"},
        )
    )
    refreshed_ack = authority.accept_heartbeat(
        "langgraph",
        heartbeat,
        harness.auth_context,
    ).activation_ack
    leases = approval_execution_lease_service_from_settings(
        harness.store,
        harness.settings,
        approvals,
        product_activation_authority=authority,
    )
    result = leases.consume(
        approval.approval_id,
        action_id=response.enforcement_binding.action_id,
        authorization_fingerprint=response.enforcement_binding.authorization_fingerprint,
        auth_context=harness.auth_context,
        activation_ack_token=refreshed_ack.ack_token,
    )
    parent = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert parent is not None
    payload = _approval_release_receipt(
        parent,
        lease_id=result.lease.lease_id,
        consumption_id=result.consumption.consumption_id,
    )
    completed = datetime.fromisoformat(result.lease.issued_at) + timedelta(minutes=5)
    payload["timestamp"] = completed.isoformat()
    payload["evidence"]["execution"]["completed_at"] = completed.isoformat()
    payload["evidence"]["approval"]["resolved_at"] = approval.resolved_at
    assert datetime.fromisoformat(refreshed_ack.issued_at) > datetime.fromisoformat(
        parent.timestamp
    )
    payload["metadata"]["activation_ack"] = refreshed_ack.model_dump(mode="json")
    service = AuditService(store=harness.store, product_activation_authority=authority)
    assert (
        service.submit(
            RuntimeOutcomeReceipt.model_validate(payload),
            auth_context=harness.auth_context,
        )["created"]
        is True
    )


@pytest.mark.parametrize("carrier", ["valid", "missing", "tampered"])
def test_receipt_http_uses_embedded_ack_and_maps_permanent_errors_to_422(
    tmp_path: Path,
    carrier: str,
) -> None:
    harness, _parent, payload, _service = _rig(tmp_path)
    if carrier == "missing":
        payload["metadata"].pop("activation_ack")
    elif carrier == "tampered":
        payload["metadata"]["activation_ack"]["ack_token"] = "hmac-sha256:" + "0" * 64
    with TestClient(
        create_app(store=harness.store, settings=harness.settings)
    ) as client:
        response = client.post(
            "/v1/audit/events",
            json=payload,
            headers={"Authorization": f"Bearer {PRODUCT_REPLAY_RAW_TOKEN}"},
        )
    assert response.status_code == (200 if carrier == "valid" else 422), response.text
    if carrier != "valid":
        assert response.json()["error"]["code"] == "RUNTIME_OUTCOME_INVALID"
        assert harness.store.get_audit_event(payload["audit_id"]) is None
