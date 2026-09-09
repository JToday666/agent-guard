"""Actual policy/receipt validators over explicit synthetic unit records."""

from copy import deepcopy

import pytest

from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.models import AdmissionError
from scripts.product_runtime.policy_terminal import verify_policy_terminal
from tests.product_runtime_memory_fixture import build_memory_prerequisite
from tests.product_runtime_terminal_fixture import build_policy_terminal
from tests.test_product_runtime_policy_evidence import _save, make_policy_replay

pytestmark = pytest.mark.unit


def verify(root, replay, terminal):
    return verify_policy_terminal(
        terminal.reference,
        row=replay.row,
        runtime=replay.event.runtime,
        scope_id=replay.scope_id,
        policy=replay.policy,
        store=EvidenceStore(root),
        candidate_manifest_digest=replay.replay["candidate_manifest_digest"],
        adapter_artifact_digest=replay.replay["adapter_artifact_digest"],
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("group", ["allow", "ask", "deny"])
@pytest.mark.parametrize("category", ["file", "command", "memory", "message"])
def test_actual_policy_and_terminal_readers_accept_complete_target(
    tmp_path, runtime, group, category
):
    replay = make_policy_replay(
        tmp_path / "policy",
        runtime=runtime,
        group=group,
        category=category,
        evidence_root=tmp_path,
    )
    if category == "memory" and group == "allow":
        replay = build_memory_prerequisite(
            tmp_path / "memory", replay, evidence_root=tmp_path
        ).read
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    assert verify(tmp_path, replay, terminal) == terminal.receipt
    assert terminal.receipt.decision == group
    if runtime == "openclaw":
        assert terminal.receipt.evidence.execution.invoked_at is None
        original_wire = (
            EvidenceStore(tmp_path).read_json(terminal.document["receipt"]).data
        )
        assert original_wire["timestamp"].endswith("Z")
        assert terminal.receipt.timestamp.endswith("+00:00")
        if group != "deny" and category != "memory":
            assert terminal.receipt.evidence.result.disposition == "unknown"
            assert terminal.receipt.evidence.side_effects.count is None


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_consumption",
        "wrong_fingerprint",
        "double_use",
        "non_human",
        "wrong_principal",
        "wrong_release",
        "wrong_lease_link",
        "new_ack",
        "wrong_authority",
        "wrong_ct",
        "missing_parent",
        "missing_ack_record",
        "parent_replaced",
        "expired_at_consume",
        "wrong_receipt_kind",
        "latest_ack_body",
    ],
)
def test_target_receipt_rejects_unproven_or_replaced_authority(
    tmp_path, runtime, mutation
):
    replay = make_policy_replay(
        tmp_path / "policy",
        runtime=runtime,
        group="ask",
        category="file",
        evidence_root=tmp_path,
    )
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    document = deepcopy(terminal.document)
    history = deepcopy(terminal.history)

    def save(name, value):
        return _save(tmp_path / "mutations", name, value, evidence_root=tmp_path)

    if mutation == "missing_consumption":
        document["consumption"] = None
    elif mutation == "wrong_fingerprint":
        value = "hmac-sha256:" + "d" * 64
        history["bindings"][-1]["authorization_fingerprint"] = value
        history["leases"][-1]["authorization_fingerprint"] = value
        consumption = terminal.consumption.model_dump(mode="json")
        consumption["authorization_fingerprint"] = value
        document["consumption"] = save("consumption.json", consumption)
    elif mutation == "double_use":
        consumption = terminal.consumption.model_dump(mode="json")
        consumption["consumed_uses"] = 2
        document["consumption"] = save("consumption.json", consumption)
    elif mutation == "non_human":
        history["approvals"][-1]["resolution_source"] = "system"
    elif mutation == "wrong_principal":
        history["approvals"][-1]["requesting_principal_id"] = "other-principal"
    elif mutation == "wrong_release":
        history["bindings"][-1]["release_mode"] = (
            "strong_binding" if runtime == "openclaw" else "restricted_allow_once"
        )
    elif mutation == "wrong_lease_link":
        history["leases"][-1]["consumption_id"] = "unrelated-consumption"
    elif mutation == "new_ack":
        ack = terminal.ack.model_dump(mode="json")
        ack["ack_token"] = "hmac-sha256:" + "f" * 64
        document["ack"] = save("ack.json", ack)
    elif mutation in {"wrong_authority", "wrong_ct"}:
        parent = terminal.parent.model_dump(mode="json")
        if mutation == "wrong_authority":
            parent["evidence"]["decision_authority"]["payload"][
                "event_id"
            ] = "wrong-event"
        else:
            parent["evidence"]["ct_transient_facts"]["payload"]["bundle"][
                "event_id"
            ] = "wrong-event"
        document["parent"] = save("parent.json", parent)
        history["audits"][-2] = parent
    elif mutation == "missing_parent":
        history["audits"] = [
            item
            for item in history["audits"]
            if item["audit_id"] != terminal.parent.audit_id
        ]
    elif mutation == "missing_ack_record":
        history["acknowledgements"] = []
    elif mutation == "parent_replaced":
        history["audits"][0]["summary"] = "Replaced prior policy history"
    elif mutation == "expired_at_consume":
        history["leases"][-1]["issued_at"] = terminal.ack.expires_at
    else:
        wire = terminal.receipt.model_dump(mode="json")
        if mutation == "wrong_receipt_kind":
            wire["metadata"]["outcome_kind"] = "pre_execution_deny"
        else:
            wire["metadata"]["activation_ack"]["issued_at"] = terminal.ack.expires_at
        document["receipt"] = save("receipt.json", wire)
    document["history"] = save("history.json", history)
    terminal.reference = save("terminal-evidence.json", document)
    with pytest.raises(AdmissionError, match="conformance_policy_terminal_invalid"):
        verify(tmp_path, replay, terminal)


def test_target_receipt_omitted_sidecar_is_rejected(tmp_path):
    replay = make_policy_replay(
        tmp_path / "policy", group="allow", category="file", evidence_root=tmp_path
    )
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    terminal.reference = None
    with pytest.raises(AdmissionError, match="conformance_policy_terminal_invalid"):
        verify(tmp_path, replay, terminal)


@pytest.mark.parametrize(
    "offset,accepted", [(0.001, True), (-0.001, False), (4, False)]
)
def test_server_capture_time_is_distinct_from_event_time(tmp_path, offset, accepted):
    from datetime import datetime, timedelta

    replay = make_policy_replay(
        tmp_path / "policy", group="allow", category="file", evidence_root=tmp_path
    )
    checked_at = (
        datetime.fromisoformat(replay.snapshot.evaluation_clock.evaluated_at)
        + timedelta(seconds=offset)
    ).isoformat()
    replay.replay["server_capture"]["checked_at"] = checked_at
    replay.row["replay"] = _save(tmp_path, "changed-policy-replay.json", replay.replay)
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    if accepted:
        assert verify(tmp_path, replay, terminal) == terminal.receipt
    else:
        with pytest.raises(AdmissionError):
            verify(tmp_path, replay, terminal)
