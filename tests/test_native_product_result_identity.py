"""Recorded result aliases: synthetic policies, real signed receipt ingestion."""

from __future__ import annotations

from copy import deepcopy

import pytest
from agentguard_core import RuntimeOutcomeReceipt
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.services.product_model_content import (
    ProductModelContentUnavailable,
    verify_product_model_content,
)
from tests.test_native_product_resource_history import _history, _replace_audit
from tests.test_product_model_content import _ct
from tests.test_v21_05_provenance import make_flow
from tests.test_v21_security_state_models import make_source_fact

pytestmark = pytest.mark.integration


def _result_case(tmp_path, *, linked=True, result_taints=("UNTRUSTED",)):
    case = _history(tmp_path, linked=linked)
    rig, store = case.rig, case.rig.harness.store
    scope = case.snapshot.scope.scope_digest
    source = make_source_fact(
        source_id=f"tool_result:{case.snapshot.scope.runtime_binding_id}:prior-action",
        scope_digest=scope,
        source_type="tool_result",
        trust="untrusted",
        authority="untrusted_claim",
        origin="observed",
        producer="adapter_unattributed",
        taints=list(result_taints),
    )
    returned = make_flow(
        "prior-returned",
        "action:prior-action",
        source.source_id,
        relation="returned_by",
        taints=[],
    ).model_copy(update={"scope_digest": scope, "origin": "deterministic"})
    parent = rig.parent_builder(
        "prior-result", "tool_result_produced", [source], [returned]
    )
    parent = parent.model_copy(
        update={"links": {**parent.links, "action_id": "prior-action"}}
    )
    assert store.add_audit_event(parent)
    wire = deepcopy(rig.receipt_wire)
    wire["audit_id"] = "audit_outcome_prior-result_execution_completed"
    wire["links"] = {
        key: value
        for key, value in {**parent.links, "policy_audit_id": parent.audit_id}.items()
        if key
        in {"event_id", "policy_audit_id", "decision_id", "action_id", "approval_id"}
        and value is not None
    }
    wire["evidence"]["result"]["disposition"] = "passed_through"
    rig.service.submit(
        RuntimeOutcomeReceipt.model_validate(wire),
        auth_context=rig.harness.auth_context,
    )
    case.snapshot = case.snapshot.model_copy(
        update={
            "sources": (*case.snapshot.sources, source),
            "flows": (*case.snapshot.flows, returned),
        }
    )
    case.source, case.returned, case.result_parent = source, returned, parent
    return case


def test_only_recorded_same_action_result_identity_is_added_without_a_false_cycle(
    tmp_path,
):
    case = _result_case(tmp_path)
    rig = case.rig
    proof = verify_product_model_content(
        rig.harness.store, rig.event, case.snapshot, rig.tool
    )
    assert case.source.source_id in proof.source_refs
    assert case.source.source_id not in proof.artifact_refs
    assert proof.covers_flow_endpoints(case.returned)
    assert "UNTRUSTED" in proof.taints
    assert case.source.trust == "untrusted"


def test_unrelated_action_result_is_not_added_or_required(tmp_path):
    case = _result_case(tmp_path, linked=False)
    rig = case.rig
    del rig.harness.store.audit_events_by_id[
        "audit_outcome_prior-result_execution_completed"
    ]
    proof = verify_product_model_content(
        rig.harness.store, rig.event, case.snapshot, rig.tool
    )
    assert case.source.source_id not in proof.source_refs
    assert not proof.covers_flow_endpoints(case.returned)


@pytest.mark.parametrize(
    "taint", ["SENSITIVE", "CREDENTIAL", "EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"]
)
def test_result_identity_carries_every_dangerous_taint_and_never_becomes_reviewable(
    tmp_path, taint
):
    case = _result_case(tmp_path, result_taints=("UNTRUSTED", taint))
    rig = case.rig
    proof = verify_product_model_content(
        rig.harness.store, rig.event, case.snapshot, rig.tool
    )
    assert {"UNTRUSTED", taint} <= set(proof.taints)
    assert not proof.reviewable


@pytest.mark.parametrize(
    "invalid",
    [
        "missing_receipt",
        "bad_ack_stamp",
        "unknown_source",
        "source_drift",
        "wrong_target",
        "possible_edge",
        "unobserved_edge",
        "extra_incoming",
        "flow_drift",
        "foreign_scope",
        "wrong_action",
        "duplicate_result",
    ],
)
def test_result_alias_refuses_missing_conflicting_or_unverified_evidence(
    tmp_path, invalid
):
    case = _result_case(tmp_path)
    rig, store = case.rig, case.rig.harness.store
    parent = case.result_parent
    if invalid == "missing_receipt":
        del store.audit_events_by_id["audit_outcome_prior-result_execution_completed"]
    elif invalid == "bad_ack_stamp":
        receipt = store.audit_events_by_id[
            "audit_outcome_prior-result_execution_completed"
        ].model_copy(deep=True)
        receipt.metadata["product_ack_validation"]["parent_authority_digest"] = (
            canonical_sha256("foreign parent")
        )
        _replace_audit(store, receipt)
    elif invalid == "duplicate_result":
        duplicate = parent.model_copy(
            update={"audit_id": "audit:conflicting-second-result"}
        )
        assert store.add_audit_event(duplicate)
    elif invalid == "extra_incoming":
        extra = make_flow(
            "other-result-input",
            rig.user.source_id,
            case.source.source_id,
            taints=["CREDENTIAL"],
        ).model_copy(update={"scope_digest": case.snapshot.scope.scope_digest})
        case.snapshot = case.snapshot.model_copy(
            update={"flows": (*case.snapshot.flows, extra)}
        )
    elif invalid == "source_drift":
        changed = case.source.model_copy(update={"producer": "changed-producer"})
        case.snapshot = case.snapshot.model_copy(
            update={"sources": (*case.snapshot.sources[:-1], changed)}
        )
    elif invalid == "flow_drift":
        changed = case.returned.model_copy(update={"producer": "changed-producer"})
        case.snapshot = case.snapshot.model_copy(
            update={"flows": (*case.snapshot.flows[:-1], changed)}
        )
    elif invalid == "wrong_action":
        parent = parent.model_copy(
            update={"links": {**parent.links, "action_id": "other-action"}}
        )
        # Keep the old action declaration but alter the original returned edge.
        changed = case.returned.model_copy(update={"source_ref": "action:other-action"})
        parent = parent.model_copy(
            update={
                "links": {**parent.links, "action_id": "prior-action"},
                "evidence": {
                    **parent.evidence,
                    "ct_transient_facts": _ct(
                        "prior-result",
                        case.snapshot.scope.scope_digest,
                        [case.source],
                        [changed],
                    ),
                },
            }
        )
        _replace_audit(store, parent)
    else:
        source, flow = case.source, case.returned
        if invalid == "unknown_source":
            source = source.model_copy(update={"trust": "unknown"})
        elif invalid == "wrong_target":
            source = source.model_copy(
                update={"source_id": source.source_id + ":other"}
            )
            flow = flow.model_copy(update={"target_ref": source.source_id})
        elif invalid == "possible_edge":
            flow = flow.model_copy(update={"strength": "possible"})
        elif invalid == "unobserved_edge":
            flow = flow.model_copy(update={"origin": "semantic_inferred"})
        else:
            source = source.model_copy(
                update={"scope_digest": canonical_sha256("foreign scope")}
            )
        parent = parent.model_copy(
            update={
                "evidence": {
                    **parent.evidence,
                    "ct_transient_facts": _ct(
                        "prior-result",
                        case.snapshot.scope.scope_digest,
                        [source],
                        [flow],
                    ),
                }
            }
        )
        _replace_audit(store, parent)
        case.snapshot = case.snapshot.model_copy(
            update={
                "sources": (*case.snapshot.sources[:-1], source),
                "flows": (*case.snapshot.flows[:-1], flow),
            }
        )
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(store, rig.event, case.snapshot, rig.tool)
