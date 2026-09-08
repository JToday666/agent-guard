"""Restricted Product grant/consume parity; controlled ASK, no Host qualification."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError as JsonValidationError, validate
from pydantic import TypeAdapter, ValidationError

from guard_api.models import (
    ExecutionLeaseConsumeRequest,
    RestrictedExecutionLeaseConsumeRequest,
)
from guard_api.storage.base import (
    ApprovalExecutionLeaseUnavailableError,
    ApprovalLeaseConsumeCommand,
    ApprovalLeaseConsumptionConflictError,
)
from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from tests.test_product_activation_ack_lease import (
    _assert_not_consumed,
    _expired_caller_ack,
    _prepare_rig,
    _write_runtime_drift,
    lease_store,  # noqa: F401
)


@pytest.fixture
def restricted_lease(tmp_path, monkeypatch, lease_store):  # noqa: F811
    backend, store = lease_store
    return _prepare_rig(
        tmp_path,
        monkeypatch,
        backend,
        store,
        suffix="restricted",
        runtime="openclaw",
        strong_enabled=False,
    )


def test_restricted_real_product_grant_concurrent_single_consumption(restricted_lease):
    rig = restricted_lease
    binding = rig.store.get_enforcement_binding(rig.approval_id)
    assert binding and binding.release_mode == "restricted_allow_once"
    assert rig.approvals.settings.rte05_strong_binding_enabled is False
    parent = rig.store.get_policy_evaluation_by_event_id(binding.event_id)
    assert parent and binding.authorization_fingerprint not in parent.model_dump_json()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: rig.consume(rig.activation_ack_token), range(8))
        )
    assert sum(not result.replayed for result in results) == 1
    assert len({result.lease.lease_id for result in results}) == 1
    assert len({result.consumption.consumption_id for result in results}) == 1
    assert len({result.lease_token for result in results}) == 1
    assert (
        rig.store.get_capability_grant_runtime(binding.grant_id)["remaining_uses"] == 0
    )
    rows = rig.store.list_rebuild_inputs(binding.scope_digest, limit=100)
    assert len([row for row in rows if row.source_record_type == "approval"]) == 1


@pytest.mark.parametrize("mutation", ["strong_mode", "caller_fingerprint", "action"])
def test_restricted_wrong_mode_or_binding_zero_consumption(restricted_lease, mutation):
    rig = restricted_lease
    with pytest.raises(ApprovalLeaseConsumptionConflictError):
        rig.leases.consume(
            rig.approval_id,
            action_id="other-action" if mutation == "action" else rig.action_id,
            authorization_fingerprint=(
                rig.authorization_fingerprint if mutation != "action" else None
            ),
            release_mode=(
                "strong_binding"
                if mutation == "strong_mode"
                else "restricted_allow_once"
            ),
            auth_context=rig.auth_context,
            activation_ack_token=rig.activation_ack_token,
        )
    _assert_not_consumed(rig)


def test_restricted_atomic_store_rechecks_mode_and_requires_activation(
    restricted_lease,
):
    rig = restricted_lease
    auth = rig.auth_context
    command = ApprovalLeaseConsumeCommand(
        credential_id=auth.credential_id,
        credential_token_hash=auth.credential_token_hash,
        principal_id=auth.principal_id,
        runtime=auth.runtime,
        agent_id=auth.agent_id,
        approval_id=rig.approval_id,
        action_id=rig.action_id,
        authorization_fingerprint=rig.authorization_fingerprint,
        lease_token="synthetic-unused-token",
        expires_at=rig.store.get_approval(rig.approval_id).expires_at,
        release_mode="restricted_allow_once",
    )
    with pytest.raises(ApprovalExecutionLeaseUnavailableError):
        rig.store.consume_approval_execution_lease(command)
    with pytest.raises(ApprovalLeaseConsumptionConflictError):
        rig.store.consume_approval_execution_lease(
            replace(command, release_mode="strong_binding")
        )
    _assert_not_consumed(rig)


@pytest.mark.parametrize(
    "failure", ["missing", "tampered", "expired", "revoked", "inventory"]
)
def test_restricted_release_ack_failure_never_consumes(restricted_lease, failure):
    rig = restricted_lease
    token = rig.activation_ack_token
    if failure == "missing":
        token = None
    elif failure == "tampered":
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
    elif failure == "expired":
        token = _expired_caller_ack(rig)
    elif failure == "revoked":
        entry = rig.fixture.bundle.runtime_entry("openclaw")
        count = rig.store.revoke_product_activation_acks(
            entry.model_dump(
                include={"runtime", "agent_id", "runtime_binding_id", "profile_id"}
            ),
            revoked_at=rig.clock.current.isoformat(),
        )
        assert count > 0
    else:
        _write_runtime_drift(rig, "openclaw")
    with pytest.raises(V21OfficialEvaluationUnavailableError):
        rig.consume(token)
    _assert_not_consumed(rig)


@pytest.mark.contract
def test_consume_request_union_schema_forbids_cross_mode_and_private_fields():
    parser = TypeAdapter(
        ExecutionLeaseConsumeRequest | RestrictedExecutionLeaseConsumeRequest
    )
    schema = json.loads(
        Path("schemas/execution_lease_consume_request.schema.json").read_text()
    )
    strong = {
        "action_id": "action-one",
        "authorization_fingerprint": "hmac-sha256:" + "a" * 64,
    }
    restricted = {"mode": "restricted_allow_once", "action_id": "action-one"}
    for valid in (strong, restricted):
        assert parser.validate_python(valid).model_dump() == valid
        validate(valid, schema)
    for invalid in (
        {"action_id": "action-one"},
        {**strong, "mode": "restricted_allow_once"},
        {**strong, "mode": "strong_binding"},
        {**restricted, "authorization_fingerprint": None},
        {**restricted, "grant_id": "caller-grant"},
        {**restricted, "runtime_binding_id": "caller-binding"},
        {**restricted, "scope_digest": "caller-scope"},
    ):
        with pytest.raises(ValidationError):
            parser.validate_python(invalid)
        with pytest.raises(JsonValidationError):
            validate(invalid, schema)
