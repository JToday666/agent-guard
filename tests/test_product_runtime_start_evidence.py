"""Actual SDK starts and hash-consistent rejected synthetic protocol evidence."""

from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from agentguard_core import AuditEvent
from guard_api.services.redaction import sanitize_audit_event
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.models import AdmissionError
from scripts.product_runtime.policy_evidence import (
    PolicyHistory,
    PolicyReplay,
    _HistoryStore,
    _key,
)
from scripts.product_runtime.policy_start import verify_policy_start
from tests.product_runtime_terminal_fixture import build_policy_terminal
from tests.test_product_runtime_policy_evidence import _save, make_policy_replay

pytestmark = pytest.mark.unit


@pytest.fixture(params=["allow", "ask"])
def start_fixture(tmp_path, request):
    replay = make_policy_replay(
        tmp_path / "policy",
        runtime="langgraph",
        group=request.param,
        category="file",
        evidence_root=tmp_path,
    )
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    return tmp_path, replay, terminal


def verify(fixture, reference=None):
    root, replay_fixture, terminal = fixture
    store = EvidenceStore(root)
    replay = PolicyReplay.model_validate(replay_fixture.replay)
    records = _HistoryStore(
        PolicyHistory.model_validate(terminal.history),
        replay_fixture.snapshot,
        replay_fixture.activation,
        _key(store, replay.product_key),
    )
    return verify_policy_start(
        reference or terminal.start.reference,
        row=replay_fixture.row,
        parent=terminal.parent,
        terminal=terminal.receipt,
        replay=replay,
        store=store,
        records=records,
    )


def test_actual_sdk_start_and_api_integrity_wrapper_are_accepted(start_fixture):
    root, _replay, terminal = start_fixture
    start = verify(start_fixture)
    wire = EvidenceStore(root).read_json(terminal.start.document["wire"]).data
    assert start.record_type == "runtime_observation"
    assert start.metadata["observation_state"] == "action_intent"
    assert "activation_ack" not in wire["metadata"]
    assert terminal.start.accepted.model_dump().get("integrity") is not None
    assert terminal.receipt.links.parent_audit_id == start.audit_id


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_ack",
        "changed_ack",
        "body_ack",
        "outcome_kind",
        "claimed_execution",
        "claimed_effect",
        "wrong_id",
        "wrong_parent",
        "wrong_lease",
        "wrong_resource",
        "start_after_invocation",
        "confirmation_before_start",
        "confirmation_after_invocation",
        "http_rejected",
        "response_not_recorded",
        "response_wrong_id",
        "wire_hash",
        "accepted_changed",
        "invocation_after_ack_expiry",
    ],
)
def test_start_rejects_rewritten_or_unconfirmed_protocol_inputs(
    start_fixture, mutation
):
    root, _replay, terminal = start_fixture
    original = terminal.start
    document = deepcopy(original.document)
    store = EvidenceStore(root)
    wire = store.read_json(document["wire"]).data
    confirmation = store.read_json(document["confirmation"]).data
    ack = store.read_json(document["ack"]).data

    def save(name, value):
        return _save(root / "mutation", name, value, evidence_root=root)

    if mutation == "missing_ack":
        document.pop("ack")
    elif mutation == "changed_ack":
        ack["ack_token"] = "hmac-sha256:" + "a" * 64
        document["ack"] = save("ack.json", ack)
    elif mutation == "body_ack":
        wire["metadata"]["activation_ack"] = ack
    elif mutation == "outcome_kind":
        wire["record_type"] = "runtime_outcome"
    elif mutation == "claimed_execution":
        wire["evidence"]["execution"]["status"] = "executed"
    elif mutation == "claimed_effect":
        wire["evidence"]["side_effects"]["count"] = 1
    elif mutation == "wrong_id":
        wire["audit_id"] = "audit_commit_unrelated"
    elif mutation == "wrong_parent":
        wire["links"]["parent_audit_id"] = "unrelated-policy"
    elif mutation == "wrong_lease":
        wire["links"]["lease_id"] = "unrelated-lease"
    elif mutation == "wrong_resource":
        wire["resource_targets"] = ["unrelated.txt"]
    elif mutation == "start_after_invocation":
        wire["timestamp"] = (
            datetime.fromisoformat(wire["timestamp"]) + timedelta(seconds=1)
        ).isoformat()
    elif mutation in {"confirmation_before_start", "confirmation_after_invocation"}:
        delta = -1 if mutation == "confirmation_before_start" else 1
        confirmation["confirmed_at"] = (
            datetime.fromisoformat(wire["timestamp"]) + timedelta(seconds=delta)
        ).isoformat()
    elif mutation == "http_rejected":
        confirmation["status"] = 409
    elif mutation == "response_not_recorded":
        confirmation["response"]["ok"] = False
    elif mutation == "response_wrong_id":
        confirmation["response"]["audit_id"] = "unrelated-audit"
    elif mutation == "invocation_after_ack_expiry":
        execution = terminal.receipt.evidence.execution.model_copy(
            update={"invoked_at": ack["expires_at"]}
        )
        evidence = terminal.receipt.evidence.model_copy(update={"execution": execution})
        terminal.receipt = terminal.receipt.model_copy(
            update={"evidence": evidence, "timestamp": ack["expires_at"]}
        )
    document["wire"] = save("wire.json", wire)
    confirmation["request_raw_sha256"] = (
        "sha256:" + "0" * 64
        if mutation == "wire_hash"
        else document["wire"]["raw_sha256"]
    )
    # Update the accepted row and all referring hashes too, so rejection tests
    # semantics, never just a stale digest of the mutated source document.
    accepted = sanitize_audit_event(AuditEvent.model_validate(wire)).model_dump(
        mode="json"
    )
    if mutation == "accepted_changed":
        accepted["metadata"]["observation_state"] = "invocation_started"
    document["accepted"] = save("accepted.json", accepted)
    document["confirmation"] = save("confirmation.json", confirmation)
    reference = save("start.json", document)
    with pytest.raises(AdmissionError, match="policy_start_invalid"):
        verify(start_fixture, reference)
