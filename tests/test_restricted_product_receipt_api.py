"""Restricted receipt authority against real API services and signed ACK rows.

The selected ASK uses an explicit controlled current-floor fixture. This checks
contracts, not a real native OpenClaw loop or Product activation qualification.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from agentguard_core import RuntimeOutcomeReceipt, ToolCallPayload, ToolDescriptor
from guard_api.runtime_status import (
    ProductRuntimeHeartbeatV2,
    activation_ack_token_digest,
)
from guard_api.services.audit import AuditService, RuntimeOutcomeReceiptError
from guard_api.services.approval import ApprovalService
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import (
    approval_execution_lease_service_from_settings,
)
from tests.support.product_evaluation import create_product_evaluation_harness
from tests.test_rte05_execution_lease_api import _approval_release_receipt
from tests.test_product_v21_service_selector import _force_current_decision

pytestmark = pytest.mark.integration


@pytest.fixture
def restricted_rig(tmp_path, monkeypatch):
    harness = create_product_evaluation_harness(tmp_path, runtime="openclaw")
    event = harness.event()
    event.security_context.source_trust = "trusted"
    event.security_context.user_task = (
        "Summarize the quarterly results already present in the conversation."
    )
    event.payload = ToolCallPayload(
        tool=ToolDescriptor(name="read_file", call_id="call:restricted-receipt"),
        arguments={"path": "/docs/quarterly-results.txt"},
        derived_resources=[],
    )
    _force_current_decision(monkeypatch, "ask")
    response = harness.evaluate(event)
    assert response.approval is not None
    assert response.enforcement_binding is None
    binding = harness.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.release_mode == "restricted_allow_once"
    authority = harness.evaluation.product_activation_authority
    assert authority is not None
    approvals = ApprovalService(
        store=harness.store,
        settings=harness.settings,
        state_service=SecurityStateService(harness.store),
    )
    approval = approvals.resolve_approval(
        response.approval.approval_id, "allow_once", resolution_source="human"
    )
    status = harness.store.list_product_runtime_statuses(runtime="openclaw")[0]
    heartbeat = ProductRuntimeHeartbeatV2.model_validate(
        status.model_dump(
            mode="json", exclude={"runtime", "principal_id", "last_heartbeat_at"}
        )
    )
    ack = authority.accept_heartbeat(
        "openclaw", heartbeat, harness.auth_context
    ).activation_ack
    leases = approval_execution_lease_service_from_settings(
        harness.store,
        harness.settings,
        approvals,
        product_activation_authority=authority,
    )
    result = leases.consume(
        approval.approval_id,
        action_id=binding.action_id,
        authorization_fingerprint=None,
        release_mode="restricted_allow_once",
        auth_context=harness.auth_context,
        activation_ack_token=ack.ack_token,
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
    payload["metadata"]["activation_ack"] = ack.model_dump(mode="json")
    payload["evidence"]["enforcement"] = {
        "release_mode": "restricted_allow_once",
        "gate_state": "approval_released",
        "binding_check_status": "not_performed",
        "lease_consume_outcome": "consumed",
        "reason_codes": ["v21:restricted_allow_once", "rte-05:lease_consumed"],
    }
    service = AuditService(store=harness.store, product_activation_authority=authority)
    return harness, parent, payload, service, binding, result


def test_historical_restricted_consumption_receipt_survives_ack_revocation(
    restricted_rig,
):
    harness, _, payload, service, _, _ = restricted_rig
    record = harness.store.get_product_activation_ack(
        activation_ack_token_digest(payload["metadata"]["activation_ack"]["ack_token"])
    )
    assert record is not None
    harness.store.revoke_product_activation_acks(
        record.identity(),
        revoked_at=(
            datetime.fromisoformat(record.ack_projection["issued_at"])
            + timedelta(seconds=1)
        ).isoformat(),
    )
    receipt = RuntimeOutcomeReceipt.model_validate(payload)
    assert service.submit(receipt, auth_context=harness.auth_context)["created"] is True
    assert (
        service.submit(receipt, auth_context=harness.auth_context)["idempotent_replay"]
        is True
    )
    stored = harness.store.get_audit_event(receipt.audit_id)
    assert stored and stored.evidence["execution"]["invoked_at"] is None
    assert stored.metadata["activation_ack"].get("ack_token") == "[redacted]"


@pytest.mark.parametrize(
    "reason,gate",
    [
        ("v21:restricted_host_mismatch", "binding_failed"),
        ("rte-05:lease_expired", "binding_failed"),
        ("rte-05:lease_response_invalid", "binding_failed"),
        ("rte-05:lease_consume_timed_out", "timed_out"),
    ],
)
def test_restricted_postconsume_denial_keeps_consumption(restricted_rig, reason, gate):
    harness, _, payload, service, _, _ = restricted_rig
    payload["metadata"]["outcome_kind"] = "pre_execution_deny"
    payload["audit_id"] = (
        f"audit_outcome_{payload['links']['event_id']}_pre_execution_deny"
    )
    payload["evidence"]["execution"]["status"] = "not_invoked"
    payload["evidence"]["result"]["disposition"] = "not_applicable"
    payload["evidence"]["enforcement"]["gate_state"] = gate
    payload["evidence"]["enforcement"]["reason_codes"].append(reason)
    assert (
        service.submit(
            RuntimeOutcomeReceipt.model_validate(payload),
            auth_context=harness.auth_context,
        )["created"]
        is True
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "strong_claim",
        "private_mode",
        "private_and_wire_strong",
        "lease",
        "consumption",
        "old_eval_ack",
        "nonhuman",
        "approval_directive",
    ],
)
def test_restricted_private_authority_mismatch_rejects_zero_writes(
    restricted_rig, mutation
):
    harness, _, payload, service, binding, _ = restricted_rig
    if mutation == "strong_claim":
        payload["evidence"]["enforcement"] = {
            "gate_state": "approval_released",
            "binding_check_status": "passed",
            "lease_consume_outcome": "consumed",
            "reason_codes": ["rte-05:binding_exact", "rte-05:lease_consumed"],
        }
    elif mutation in {"private_mode", "private_and_wire_strong"}:
        harness.store.enforcement_bindings[binding.approval_id] = replace(
            binding, release_mode="strong_binding"
        )
        if mutation == "private_and_wire_strong":
            payload["evidence"]["enforcement"] = {
                "gate_state": "approval_released",
                "binding_check_status": "passed",
                "lease_consume_outcome": "consumed",
                "reason_codes": ["rte-05:binding_exact", "rte-05:lease_consumed"],
            }
    elif mutation in {"lease", "consumption"}:
        payload["links"]["lease_id" if mutation == "lease" else "consumption_id"] = (
            "unrelated"
        )
    elif mutation == "old_eval_ack":
        record = harness.store.get_product_activation_ack(
            activation_ack_token_digest(harness.activation_ack_token)
        )
        payload["metadata"]["activation_ack"] = record.rebuild(
            harness.activation_ack_token
        ).model_dump(mode="json")
        # It is valid historical authority only at evaluation, not at consume.
        record = record.model_copy(update={"revoked_at": binding.created_at})
        harness.store.product_activation_acks_v1[record.token_digest] = record
    else:
        approval = harness.store.get_approval(binding.approval_id)
        assert approval
        changed = approval.model_copy(deep=True)
        if mutation == "nonhuman":
            changed.resolution_source = "auto_critic"
        else:
            changed.evidence["approval_release_directive"] = deepcopy(
                changed.evidence["approval_release_directive"]
            )
            changed.evidence["approval_release_directive"]["mode"] = "strong_binding"
        harness.store.approvals[binding.approval_id] = changed
    with pytest.raises(RuntimeOutcomeReceiptError):
        service.submit(
            RuntimeOutcomeReceipt.model_validate(payload),
            auth_context=harness.auth_context,
        )
    assert harness.store.get_audit_event(payload["audit_id"]) is None


@pytest.mark.parametrize(
    "observation", ["pending", "local_timeout", "lease_unavailable"]
)
def test_restricted_preconsume_failure_keeps_evaluation_ack(
    tmp_path, monkeypatch, observation
):
    from guard_api.storage.memory import MemoryControlPlaneStore
    from tests.test_product_activation_ack_lease import _prepare_rig

    store = MemoryControlPlaneStore()
    rig = _prepare_rig(
        tmp_path,
        monkeypatch,
        "memory",
        store,
        suffix="receipt-preconsume",
        runtime="openclaw",
        strong_enabled=False,
    )
    binding = store.get_enforcement_binding(rig.approval_id)
    assert binding is not None
    parent = store.get_policy_evaluation_by_event_id(binding.event_id)
    assert parent is not None
    payload = _approval_release_receipt(
        parent, lease_id="unused", consumption_id="unused"
    )
    del payload["links"]["lease_id"]
    del payload["links"]["consumption_id"]
    kind = "pre_execution_deny"
    payload["metadata"]["outcome_kind"] = kind
    payload["audit_id"] = f"audit_outcome_{binding.event_id}_{kind}"
    completed = rig.clock.current + timedelta(minutes=5)
    payload["timestamp"] = completed.isoformat()
    payload["evidence"]["execution"].update(
        status="not_invoked", completed_at=completed.isoformat()
    )
    payload["evidence"]["result"]["disposition"] = "not_applicable"
    payload["evidence"]["approval"]["resolved_at"] = None
    payload["evidence"]["enforcement"] = {
        "release_mode": "restricted_allow_once",
        "gate_state": "binding_failed",
        "binding_check_status": "not_performed",
        "lease_consume_outcome": "not_attempted",
        "reason_codes": ["v21:restricted_allow_once", "rte-05:lease_unavailable"],
    }
    if observation != "lease_unavailable":
        payload["evidence"]["approval"].update(
            status="pending" if observation == "pending" else "expired", decision=None
        )
        payload["evidence"]["enforcement"].update(
            gate_state="timed_out",
            reason_codes=["v21:restricted_allow_once", "rte-05:approval_timed_out"],
        )
    record = store.get_product_activation_ack(
        activation_ack_token_digest(rig.activation_ack_token)
    )
    assert record is not None
    payload["metadata"]["activation_ack"] = record.rebuild(
        rig.activation_ack_token
    ).model_dump(mode="json")
    service = AuditService(store=store, product_activation_authority=rig.authority)
    assert (
        service.submit(
            RuntimeOutcomeReceipt.model_validate(payload), auth_context=rig.auth_context
        )["created"]
        is True
    )
    assert not store.approval_execution_was_consumed(binding.approval_id)
