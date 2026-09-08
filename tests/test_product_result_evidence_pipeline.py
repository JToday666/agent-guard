"""Real Core evidence serialization and audit persistence of server result proofs.

Parents are explicitly synthetic policies with real signed ACK/receipt ingestion.
No Provider, Host execution or candidate qualification is claimed here.
"""

from copy import deepcopy

import pytest

from agentguard_core import GuardDecision, PolicyBundle
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.decisions.shadow import (
    compute_assessment_digest,
    shadow_assess_with_coverage,
)
from agentguard_core.signals.models import EvidenceRef
from guard_api.services.product_model_content import (
    ProductModelContentUnavailable,
    _authority,
    read_product_tool_result,
    verify_product_tool_result,
)
from tests.test_product_tool_result_content import result_fixture

pytestmark = pytest.mark.integration


def _result_evidence(rig):
    proof = verify_product_tool_result(
        rig.harness.store, rig.result_event, rig.snapshot
    )
    policies = rig.harness.store.get_policy_snapshot()
    assert policies is not None
    outcome = shadow_assess_with_coverage(
        rig.result_event,
        policies,
        rig.snapshot,
        server_secret=rig.harness.fixture.server_secret,
    )
    # Phase A attaches this reserved reference only after the verifier above
    # authenticates the original action, model commitment, terminal and ACKs.
    reference = EvidenceRef(
        ref_id=f"product-result:{proof.event_id}",
        kind="guard_event",
        record_type="product_tool_result",
        record_id=proof.event_id,
        json_pointer="/evidence/product_tool_result",
        digest=proof.proof_digest,
        redaction_state="summary_only",
    )
    unrelated = reference.model_copy(
        update={"ref_id": "unrelated", "record_type": "unrelated_observation"}
    )
    assessment = outcome.assessment.model_copy(
        update={
            "evidence_refs": [*outcome.assessment.evidence_refs, reference, unrelated]
        }
    )
    assessment = assessment.model_copy(
        update={"assessment_digest": compute_assessment_digest(assessment)}
    )
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="allow",
        snapshot_id=rig.snapshot.snapshot_id,
        state_version=rig.snapshot.state_version,
        coverage=outcome.coverage,
        mode="active",
        selected_decision="allow",
    )
    return proof, reference, decision_evidence_v21_envelope(evidence)


def _record_result(rig, proof, envelope):
    template = rig.parent_builder(
        rig.result_event.event_id, "tool_result_produced", [], []
    )
    authority = _authority(template, "tool_result_produced")
    # Keep the synthetic selected authority bound to the actual Core evidence
    # rather than carrying the fixture's unrelated original assessment anchor.
    selected = envelope["decision_v21"]["payload"]
    authority = authority.model_copy(
        update={
            key: selected[key]
            for key in (
                "assessment_id",
                "assessment_digest",
                "snapshot_id",
                "snapshot_digest",
                "state_version",
            )
        }
    )
    authority_envelope = deepcopy(template.evidence["decision_authority"])
    authority_envelope["payload"] = authority.model_dump(mode="json")
    return rig.service.record_evaluation(
        rig.result_event,
        GuardDecision.model_validate(template.evidence["guard_decision"]),
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        audit_id=template.audit_id,
        v21_evidence=envelope,
        decision_authority=authority.decision_authority,
        decision_authority_evidence={"decision_authority": authority_envelope},
        product_tool_result=proof.model_dump(mode="json"),
        extra_metadata={
            "product_model_task": template.metadata["product_model_task"],
            "policy_digest": authority.policy_digest,
        },
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_selected_result_evidence_survives_core_builder_and_real_audit_store(
    tmp_path, runtime
):
    rig = result_fixture(tmp_path, runtime=runtime, message=True)
    proof, reference, envelope = _result_evidence(rig)
    assert envelope["decision_v21"]["payload"]["evidence_refs"] == [
        reference.model_dump(mode="json")
    ]
    record = _record_result(rig, proof, envelope)
    persisted = rig.harness.store.get_audit_event(record.audit_id)
    assert persisted is not None
    assert read_product_tool_result(persisted) == proof
    assert proof.parent_action_id != proof.native_call_id


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "digest", "event"])
def test_result_reader_still_rejects_missing_or_ambiguous_serialized_proof(
    tmp_path, mutation
):
    rig = result_fixture(tmp_path, message=True)
    proof, reference, envelope = _result_evidence(rig)
    refs = envelope["decision_v21"]["payload"]["evidence_refs"]
    assert refs == [reference.model_dump(mode="json")]
    if mutation == "missing":
        refs.clear()
    elif mutation == "duplicate":
        refs.append(deepcopy(refs[0]))
    elif mutation == "digest":
        refs[0]["digest"] = "sha256:" + "0" * 64
    else:
        refs[0]["record_id"] = "unrelated-event"
    before = len(rig.harness.store.audit_events)
    with pytest.raises(ProductModelContentUnavailable):
        _record_result(rig, proof, envelope)
    assert len(rig.harness.store.audit_events) == before
