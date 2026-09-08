"""Historical resource closure with synthetic policies and real ACK receipts.

No model, Host invocation, side effect or Product activation is claimed.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.canonical_resources import (
    RESOURCE_NORMALIZERS,
    ResourceNormalizationInput,
)
from agentguard_core.actions.product_tools import product_tool_resource_identity
from agentguard_core.security_context.product_data import VerifiedProductData
from guard_api.services.product_model_content import (
    ModelContentCommitment,
    ProductModelContentUnavailable,
    verify_product_model_content,
)
from tests.test_product_model_content import _ct, _fixture, _with_prior_model
from tests.test_v21_05_provenance import make_flow

pytestmark = pytest.mark.integration


def _replace_audit(store, record):
    store.audit_events_by_id[record.audit_id] = record
    store.audit_events[:] = [
        record if old.audit_id == record.audit_id else old for old in store.audit_events
    ]


def _history(tmp_path, *, linked=True):
    rig = _fixture(tmp_path, model_taints=())
    store = rig.harness.store
    original_proof = verify_product_model_content(
        store, rig.event, rig.snapshot, rig.tool
    )
    snapshot = _with_prior_model(rig)
    # Remove the fixture's direct model-to-current-user bridge. Only the
    # actual current resource may now lead back to the previous action.
    _replace_audit(store, rig.input)
    flows = [flow for flow in snapshot.flows if flow.flow_id != "prior-control"]
    scope = snapshot.scope.scope_digest
    prior_model = next(
        source
        for source in snapshot.sources
        if source.source_id == "source:model:prior-output"
    )
    prior_user = next(
        source for source in snapshot.sources if source.source_id == "source:user:prior"
    )
    resource = rig.tool.resource_inputs()[0]
    resource_ref = RESOURCE_NORMALIZERS[resource["kind"]](
        ResourceNormalizationInput(
            resource_id="fixture-resource",
            target=resource["target"],
            method=resource.get("method"),
        )
    ).canonical_id
    prior_action_id = "prior-action"
    tool_ref = product_tool_resource_identity(
        rig.tool.tool_name, rig.tool.descriptor_digest, rig.tool.semantics_digest
    )
    raw = original_proof.model_dump(mode="json", exclude={"proof_digest"})
    raw.update(
        event_id="prior-action-event",
        action_id=prior_action_id,
        model_source_ref=prior_model.source_id,
        model_output_event_id="prior-output",
        model_output_audit_id="audit:prior-output",
        source_refs=[prior_model.source_id, prior_user.source_id],
        direct_source_refs=[prior_model.source_id, prior_user.source_id],
        taints=["SENSITIVE"],
    )
    for binding in raw["bindings"]:
        binding.update(action_id=prior_action_id, source_ref=prior_model.source_id)
    prior_proof = VerifiedProductData.model_validate(raw)
    action_flows = [
        make_flow(
            "prior-action-data",
            prior_model.source_id,
            f"action:{prior_action_id}",
            relation="derived_from",
            taints=["SENSITIVE"],
        ),
        make_flow(
            "prior-action-tool",
            f"action:{prior_action_id}",
            tool_ref,
            relation="read_from",
            taints=[],
        ),
        make_flow(
            "prior-action-resource",
            f"action:{prior_action_id}",
            resource_ref if linked else resource_ref + ".unrelated",
            relation="written_to",
            taints=["SENSITIVE"],
        ),
    ]
    action_flows = [
        flow.model_copy(update={"scope_digest": scope}) for flow in action_flows
    ]
    parent = rig.parent_builder(
        "prior-action-event", "tool_call_proposed", [], action_flows
    )
    data = parent.model_dump(mode="json")
    data["links"]["action_id"] = prior_action_id
    data["evidence"]["product_action_data"] = prior_proof.model_dump(mode="json")
    data["evidence"]["decision_v21"]["payload"]["evidence_refs"] = [
        {
            "kind": "guard_event",
            "record_type": "product_action_data",
            "record_id": prior_proof.event_id,
            "json_pointer": "/evidence/product_action_data",
            "digest": prior_proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    parent = type(parent).model_validate(data)
    assert store.add_audit_event(parent)
    snapshot = snapshot.model_copy(update={"flows": (*flows, *action_flows)})
    return SimpleNamespace(
        rig=rig,
        snapshot=snapshot,
        parent=parent,
        resource_ref=resource_ref,
        tool_ref=tool_ref,
        action_flows=action_flows,
    )


def test_exact_current_resource_recovers_prior_model_and_all_control_taints(tmp_path):
    case = _history(tmp_path)
    rig = case.rig
    proof = verify_product_model_content(
        rig.harness.store, rig.event, case.snapshot, rig.tool
    )
    assert "source:model:prior-output" in proof.source_refs
    assert "source:user:prior" in proof.source_refs
    assert {
        "model_output:prior-output",
        "model_input:prior-input",
        "action:prior-action",
        case.resource_ref,
        case.tool_ref,
    } <= set(proof.artifact_refs)
    assert "SENSITIVE" in proof.taints and not proof.reviewable
    assert all(proof.covers_flow_endpoints(flow) for flow in case.action_flows)
    assert (
        next(
            source
            for source in case.snapshot.sources
            if source.source_id == "source:model:prior-output"
        ).trust
        == "unknown"
    )


def test_distinct_product_policy_cannot_reuse_an_action_identity_even_for_same_tool(
    tmp_path,
):
    case = _history(tmp_path)
    rig, store = case.rig, case.rig.harness.store
    raw = case.parent.model_dump(mode="json")
    duplicate_event = "second-event-same-action"
    raw.update(audit_id="audit:second-event-same-action")
    raw["links"]["event_id"] = duplicate_event
    raw["evidence"]["decision_authority"]["payload"]["event_id"] = duplicate_event
    proof_data = raw["evidence"]["product_action_data"]
    proof_data.pop("proof_digest")
    proof_data["event_id"] = duplicate_event
    proof = VerifiedProductData.model_validate(proof_data)
    raw["evidence"]["product_action_data"] = proof.model_dump(mode="json")
    ref = raw["evidence"]["decision_v21"]["payload"]["evidence_refs"][0]
    ref.update(record_id=duplicate_event, digest=proof.proof_digest)
    raw["evidence"]["ct_transient_facts"] = _ct(
        duplicate_event, case.snapshot.scope.scope_digest, [], case.action_flows
    )
    assert store.add_audit_event(type(case.parent).model_validate(raw))
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(store, rig.event, case.snapshot, rig.tool)


def test_shared_user_alone_cannot_admit_an_unrelated_model_branch(tmp_path):
    case = _history(tmp_path, linked=False)
    rig, store = case.rig, case.rig.harness.store
    parent = store.audit_events_by_id["audit:prior-output"]
    input_parent = store.audit_events_by_id["audit:prior-input"]
    replacements = {}
    for flow in case.snapshot.flows:
        if flow.flow_id in {"prior-input-flow", "prior-output-flow"}:
            replacements[flow.flow_id] = flow.model_copy(
                update={"source_ref": rig.user.source_id}
            )
    for item, phase in ((input_parent, "input"), (parent, "output")):
        data = item.model_dump(mode="json")
        data["evidence"]["ct_transient_facts"] = _ct(
            f"prior-{phase}",
            case.snapshot.scope.scope_digest,
            [rig.user]
            if phase == "input"
            else [
                next(
                    source
                    for source in case.snapshot.sources
                    if source.source_id == "source:model:prior-output"
                )
            ],
            [replacements[f"prior-{phase}-flow"]],
        )
        if phase == "output":
            commitment = deepcopy(data["evidence"]["product_model_content"])
            commitment.pop("commitment_digest")
            commitment["visible_source_refs"] = [rig.user.source_id]
            data["evidence"]["product_model_content"] = (
                ModelContentCommitment.model_validate(commitment).model_dump(
                    mode="json"
                )
            )
        _replace_audit(store, type(item).model_validate(data))
    snapshot = case.snapshot.model_copy(
        update={
            "flows": tuple(
                replacements.get(flow.flow_id, flow) for flow in case.snapshot.flows
            )
        }
    )
    proof = verify_product_model_content(store, rig.event, snapshot, rig.tool)
    assert "source:model:prior-output" not in proof.source_refs
    assert "model_output:prior-output" not in proof.artifact_refs
    assert "action:prior-action" not in proof.artifact_refs
    assert case.tool_ref not in proof.artifact_refs
    assert not proof.covers_control_flow(replacements["prior-output-flow"])


@pytest.mark.parametrize("missing", ["input", "output"])
def test_resource_ancestry_still_requires_both_accepted_model_receipts(
    tmp_path, missing
):
    case = _history(tmp_path)
    rig = case.rig
    del rig.harness.store.audit_events_by_id[
        f"audit_outcome_prior-{missing}_execution_completed"
    ]
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(
            rig.harness.store, rig.event, case.snapshot, rig.tool
        )


@pytest.mark.parametrize(
    "invalid",
    [
        "proof_digest",
        "assessment_ref",
        "action_identity",
        "foreign_scope",
        "foreign_flow",
    ],
)
def test_resource_history_requires_unchanged_same_scope_action_proof_and_flows(
    tmp_path, invalid
):
    case = _history(tmp_path)
    rig, store = case.rig, case.rig.harness.store
    data = case.parent.model_dump(mode="json")
    if invalid == "proof_digest":
        data["evidence"]["product_action_data"]["tool_descriptor_digest"] = (
            canonical_sha256("forged descriptor")
        )
    elif invalid == "assessment_ref":
        data["evidence"]["decision_v21"]["payload"]["evidence_refs"][0]["digest"] = (
            canonical_sha256("forged ref")
        )
    elif invalid == "action_identity":
        data["links"]["action_id"] = "another-action"
    elif invalid == "foreign_scope":
        data["metadata"]["product_model_task"]["scope_digest"] = canonical_sha256(
            "other scope"
        )
    else:
        flow = case.action_flows[-1].model_copy(
            update={"scope_digest": canonical_sha256("other scope")}
        )
        case.snapshot = case.snapshot.model_copy(
            update={"flows": (*case.snapshot.flows[:-1], flow)}
        )
    _replace_audit(store, type(case.parent).model_validate(data))
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(store, rig.event, case.snapshot, rig.tool)
