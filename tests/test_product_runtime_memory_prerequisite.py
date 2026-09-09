"""A real production proof replay of synthetic memory lifecycle inputs."""

from contextlib import contextmanager
from copy import deepcopy
import json

import pytest

from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.memory_prerequisite import verify_memory_prerequisite
from scripts.product_runtime.models import AdmissionError
from tests.product_runtime_memory_fixture import build_memory_prerequisite
from tests.test_product_runtime_policy_evidence import _save, make_policy_replay

pytestmark = pytest.mark.contract


@pytest.fixture(scope="module", params=["langgraph", "openclaw"])
def memory_case(tmp_path_factory, request):
    root = tmp_path_factory.mktemp("typed-memory-" + request.param)
    initial = make_policy_replay(
        root / "initial",
        runtime=request.param,
        group="allow",
        category="memory",
        evidence_root=root,
    )
    fixture = build_memory_prerequisite(root / "memory", initial, evidence_root=root)
    return root, fixture


def _verify(root, fixture, reference=None, read_row=None):
    return verify_memory_prerequisite(
        reference or fixture.reference,
        read_row=read_row or fixture.read.row,
        runtime=fixture.read.event.runtime,
        scope_id=fixture.read.scope_id,
        policy=fixture.read.policy,
        store=EvidenceStore(root),
        candidate_manifest_digest=fixture.read.replay["candidate_manifest_digest"],
        adapter_artifact_digest=fixture.read.replay["adapter_artifact_digest"],
    )


@contextmanager
def _restore(root):
    originals = {path: path.read_bytes() for path in root.rglob("*.json")}
    try:
        yield
    finally:
        for path, content in originals.items():
            if path.read_bytes() != content:
                path.write_bytes(content)


def _replace(root, reference, mutate):
    value = json.loads((root / reference["path"]).read_bytes())
    mutate(value)
    return _save(root, reference["path"], value)


def test_original_ask_receipt_proves_committed_memory_without_clean_promotion(
    memory_case,
):
    root, fixture = memory_case
    fact = _verify(root, fixture)
    assert fact == fixture.memory_fact
    assert fact.change_status == "committed"
    assert fact.trust_state == "quarantined"
    assert fixture.write.authority.selected_decision.decision == "ask"
    assert fixture.read.authority.selected_decision.decision == "allow"
    assert fixture.write.authority.policy_digest == fixture.read.authority.policy_digest


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_consumption",
        "wrong_scope",
        "wrong_candidate",
        "changed_value",
        "changed_namespace",
        "rejected_change",
        "changed_consumption",
        "changed_fingerprint",
        "replacement_ack",
        "receipt_without_ack",
        "changed_accepted_terminal",
        "source_value_drift",
        "clean_fact",
        "wrong_write_sequence",
    ],
)
def test_hash_consistent_memory_evidence_still_rejects_broken_proof(
    memory_case, mutation
):
    root, fixture = memory_case
    with _restore(root):
        document = deepcopy(fixture.document)
        read_row = deepcopy(fixture.read.row)
        if mutation == "missing_consumption":
            document.pop("consumption")
        elif mutation == "wrong_scope":
            document["scope_id"] = "another-isolated-scope"
        elif mutation == "wrong_candidate":
            document["candidate_manifest_digest"] = "sha256:" + "9" * 64
        elif mutation in {"changed_value", "changed_namespace", "rejected_change"}:
            key, value = {
                "changed_value": ("value_preview", "a different value"),
                "changed_namespace": ("namespace", "/another/memory.sqlite"),
                "rejected_change": ("status", "rejected"),
            }[mutation]
            document["change"] = _replace(
                root, document["change"], lambda data: data.update({key: value})
            )
        elif mutation in {"changed_consumption", "changed_fingerprint"}:
            key, value = (
                ("consumption_id", "another-consumption")
                if mutation == "changed_consumption"
                else ("authorization_fingerprint", "sha256:" + "9" * 64)
            )
            document["consumption"] = _replace(
                root, document["consumption"], lambda data: data.update({key: value})
            )
        elif mutation == "replacement_ack":
            document["ack"] = _replace(
                root,
                document["ack"],
                lambda data: data.update(ack_token="different-private-token"),
            )
        elif mutation == "receipt_without_ack":
            document["receipt"] = _replace(
                root,
                document["receipt"],
                lambda data: data["metadata"].update(activation_ack=None),
            )
        elif mutation == "changed_accepted_terminal":
            document["terminal"] = _replace(
                root,
                document["terminal"],
                lambda data: data["evidence"]["side_effects"].update(count=2),
            )
        elif mutation == "source_value_drift":
            from agentguard_core.actions.canonical_json import canonical_sha256

            def change_source(data):
                data["summary"] = json.dumps(
                    {"key": fixture.change.key, "value": "different"}
                )
                data["content_digest"] = canonical_sha256(data["summary"])

            document["context_source"] = _replace(
                root, document["context_source"], change_source
            )
        else:
            from agentguard_core.actions.canonical_json import canonical_sha256
            from agentguard_core.security_context import SecuritySnapshot
            from agentguard_core.security_context.snapshot import (
                snapshot_digest_projection,
            )

            def change_fact(data):
                fact = next(
                    item
                    for item in data["memory_facts"]
                    if item["change_id"] == fixture.change.change_id
                )
                if mutation == "clean_fact":
                    fact["trust_state"] = "clean"
                else:
                    fact["last_write_sequence"]["value"] = 1
                snapshot = SecuritySnapshot.model_validate(data)
                data["snapshot_digest"] = canonical_sha256(
                    snapshot_digest_projection(snapshot)
                )

            document["read_snapshot"] = _replace(
                root, document["read_snapshot"], change_fact
            )
            read_row["replay"] = _replace(
                root,
                read_row["replay"],
                lambda data: data.update(snapshot=document["read_snapshot"]),
            )
        reference = _save(root, fixture.reference["path"], document)
        with pytest.raises(
            AdmissionError, match="^conformance_memory_prerequisite_invalid$"
        ):
            _verify(root, fixture, reference, read_row)


def test_valid_read_of_other_key_cannot_borrow_first_write_sidecar(memory_case):
    """Both decisions replay correctly; the sidecar still belongs to another key."""
    from agentguard_core import GuardEvent
    from agentguard_core.actions.canonical_json import canonical_json, canonical_sha256
    from agentguard_core.actions.canonical_resources import (
        ResourceNormalizationInput,
        normalize_memory_resource,
    )
    from agentguard_core.security_context.snapshot import snapshot_digest_projection
    from guard_api.services.product_model_content import build_product_model_content
    from guard_api.services.product_tool_catalog import ProductToolCatalog
    from scripts.product_runtime.policy_evidence import (
        PolicyHistory,
        _HistoryStore,
        verify_policy_evidence,
    )
    from tests.test_product_runtime_policy_evidence import _assess_unit, _server_capture

    root, fixture = memory_case
    target = root / "unrelated-memory-read"
    row, replay, history = (
        deepcopy(fixture.read.row),
        deepcopy(fixture.read.replay),
        deepcopy(fixture.read.history),
    )
    event = GuardEvent.model_validate(row["event"])
    event.payload.arguments["key"] = "another-note"
    other_id = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="", target="another-note", memory_namespace=fixture.change.namespace
        )
    ).canonical_id
    # An explicitly synthetic second committed value is a legitimate Core read
    # input. Its user provenance does not assert that the first-write sidecar
    # created it; that is precisely the unrelated linkage rejected below.
    other = fixture.memory_fact.model_copy(
        update={
            "memory_id":other_id,
            "change_id":"synthetic-other-memory-write",
            "source_refs":["source:user:input"],
            "taints":[],
            "last_write_sequence":fixture.memory_fact.last_write_sequence.model_copy(update={"producer_binding_id":"synthetic-other-memory-write"}),
        }
    )
    # A B-only bounded evaluation window need not traverse A's original flows.
    # The A sidecar remains complete in its own separately verified history.
    history["events"] = [item for item in history["events"] if not item["event_id"].startswith("unit-memory-")]
    history["audits"] = [item for item in history["audits"] if not item["links"]["event_id"].startswith("unit-memory-")]
    history.update(approvals=[],bindings=[],leases=[])
    snapshot = fixture.read.snapshot.model_copy(update={
        "memory_facts":[fixture.memory_fact,other],
        "sources":[item for item in fixture.read.snapshot.sources if item.source_id in {"source:user:input","source:model:output"}],
        "flows":[item for item in fixture.read.snapshot.flows if item.target_ref in {"model_input:input","model_output:output"}],
    })
    snapshot = snapshot.model_copy(update={"snapshot_digest":canonical_sha256(snapshot_digest_projection(snapshot))})
    output = next(item for item in history["events"] if item["event_id"]=="output")
    projection = json.loads(output["payload"]["content_preview"])
    projection["tool_calls"][0]["args"]["key"] = "another-note"
    output["payload"]["content_preview"] = canonical_json(projection)
    catalog = ProductToolCatalog(str(root / replay["catalog"]["path"]),fixture.read.activation)
    product_secret = (root / replay["product_key"]["path"]).read_bytes()
    assessment_secret = (root / replay["assessment_key"]["path"]).read_bytes()
    records = _HistoryStore(PolicyHistory.model_validate(history),snapshot,fixture.read.activation,product_secret)
    parent = next(item for item in history["audits"] if item["audit_id"]=="audit:output")
    commitment = build_product_model_content(
        records,GuardEvent.model_validate(output),snapshot=snapshot,catalog=catalog,
        activation=fixture.read.activation,
        decision_authority_evidence={"decision_authority":parent["evidence"]["decision_authority"]},
    )
    parent["evidence"]["product_model_content"] = commitment.model_dump(mode="json")
    records = _HistoryStore(PolicyHistory.model_validate(history),snapshot,fixture.read.activation,product_secret)
    actual = _assess_unit(event,snapshot,catalog,fixture.read.activation,fixture.read.policy,records,assessment_secret)
    assert actual.authority.selected_decision.decision == "allow"
    assert actual.proof.memory_refs == (other_id,)
    def save(name,value):
        return _save(target,name,value,evidence_root=root)
    replay.update(
        server_capture=_server_capture(event,actual.authority,snapshot,row["policy_audit_id"],checked_at=replay["server_capture"]["checked_at"]),
        snapshot=save("snapshot.json",snapshot.model_dump(mode="json")),
        current_snapshot=save("current-snapshot.json",snapshot.model_dump(mode="json")),
        history=save("history.json",history),
        coverage=actual.outcome.coverage.model_dump(mode="json"),
        transient_facts=actual.transient.model_dump(mode="json"),
        product_data=actual.proof.model_dump(mode="json"),
    )
    row.update(event=event.model_dump(mode="json"),authority=actual.authority.model_dump(mode="json"),assessment=actual.outcome.assessment.model_dump(mode="json"),replay=save("replay.json",replay))
    rebuilt = verify_policy_evidence(
        row,runtime=fixture.read.event.runtime,scope_id=fixture.read.scope_id,
        policy=fixture.read.policy,store=EvidenceStore(root),
        candidate_manifest_digest=replay["candidate_manifest_digest"],
        adapter_artifact_digest=replay["adapter_artifact_digest"],
    )
    assert rebuilt == actual.authority
    document = deepcopy(fixture.document)
    document["read_snapshot"] = replay["snapshot"]
    with pytest.raises(AdmissionError,match="^conformance_memory_prerequisite_invalid$"):
        _verify(root,fixture,save("unrelated-prerequisite.json",document),row)
