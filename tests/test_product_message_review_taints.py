"""Actual detector/CT wiring with synthetic Product proof, no Host qualification."""

from __future__ import annotations

import base64
from dataclasses import replace
from types import SimpleNamespace

import pytest
from agentguard_core.detectors.outbound import OutboundDetector
from agentguard_core.policies import PolicyBundle
from guard_api.security_state import SecurityStateService
from guard_api.security_state.fact_builder import build_transient_facts
from guard_api.services.ct_projection import (
    CtProjectionService,
    _product_message_review_only,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_product_fact_builder import fixture_case
from tests.test_v21_security_state_models import make_source_fact

pytestmark = pytest.mark.integration


def _project(case, results, *, product=True, wrong_proof=False):
    store = MemoryControlPlaneStore()
    settings = GuardApiSettings(
        ct_fact_projection_enabled=True,
        v21_shadow_server_secret=base64.urlsafe_b64encode(
            case.catalog.fixture.server_secret
        ).decode("ascii"),
    )
    service = CtProjectionService(
        settings=settings, store=store, state_service=SecurityStateService(store)
    )
    sources = tuple(
        make_source_fact(
            source_id=descriptor.source_id,
            scope_digest=descriptor.scope_digest,
            source_type=descriptor.source_type,
            trust=descriptor.trust,
            verification_state=descriptor.verification_state,
            authority=descriptor.fact_authority,
            producer=descriptor.producer,
            taints=list(descriptor.initial_taints),
        )
        for descriptor in case.inputs.upstream_descriptors.values()
    )
    proof = case.proof
    if wrong_proof:
        raw_proof = proof.model_dump(mode="json", exclude={"proof_digest"})
        raw_proof["event_id"] = "another-event"
        proof = type(proof).model_validate(raw_proof)
    materials = SimpleNamespace(
        detection_results=results,
        product_tool=case.tool if product else None,
        product_data=proof if product else None,
        product_result=None,
        task_id=case.ir.task_id,
        snapshot=SimpleNamespace(
            sources=sources,
            flows=(),
            memory_facts=(),
            task=SimpleNamespace(revision=1, principal_id=case.ir.principal_id),
            scope=SimpleNamespace(runtime_binding_id=case.ir.runtime_binding_id),
        ),
    )
    inputs = service._build_inputs(case.event, materials, case.ir.scope_digest)
    return inputs, build_transient_facts(event=case.event, inputs=inputs)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_actual_p005_review_remains_ask_without_inventing_sensitive_content(
    tmp_path, runtime
):
    case = fixture_case(tmp_path, runtime=runtime)
    results = OutboundDetector().evaluate(case.event, PolicyBundle())
    assert len(results) == 1 and results[0].decision == "ask"
    inputs, bundle = _project(case, results)
    assert not inputs.server_sensitive_evidence
    assert not bundle.degradations
    assert any(flow.relation == "sent_to" for flow in bundle.flow_facts)
    assert all(not flow.taints for flow in bundle.flow_facts)
    assert all(case.proof.covers_flow_endpoints(flow) for flow in bundle.flow_facts)
    assert all(
        flow.strength == "possible"
        for flow in bundle.flow_facts
        if flow.relation == "influenced_by"
    )
    assert results[0].decision == "ask"


@pytest.mark.parametrize(
    "taints", [("UNTRUSTED",), ("SENSITIVE",), ("CREDENTIAL", "SENSITIVE")]
)
def test_non_sensitive_message_text_retains_all_control_source_taints(tmp_path, taints):
    case = fixture_case(tmp_path, taints=taints)
    results = OutboundDetector().evaluate(case.event, PolicyBundle())
    inputs, bundle = _project(case, results)
    assert not inputs.server_sensitive_evidence
    assert not bundle.degradations
    assert bundle.flow_facts
    assert all(set(flow.taints) == set(taints) for flow in bundle.flow_facts)


@pytest.mark.parametrize("mode", ["legacy", "mismatched_product"])
def test_legacy_or_mismatched_proof_keeps_conservative_category_mapping(tmp_path, mode):
    case = fixture_case(tmp_path)
    results = OutboundDetector().evaluate(case.event, PolicyBundle())
    inputs, _ = _project(
        case,
        results,
        product=mode != "legacy",
        wrong_proof=mode == "mismatched_product",
    )
    assert inputs.server_sensitive_evidence


@pytest.mark.parametrize(
    "evidence_mutation",
    ["missing", "contradictory", "duplicate", "unknown", "recipient"],
)
def test_incomplete_or_conflicting_rule_evidence_cannot_remove_sensitive_bit(
    tmp_path, evidence_mutation
):
    case = fixture_case(tmp_path)
    (result,) = OutboundDetector().evaluate(case.event, PolicyBundle())
    evidence = list(result.rule_hit.evidence)
    if evidence_mutation == "missing":
        evidence.pop()
    elif evidence_mutation == "contradictory":
        evidence.append("sensitive_text_match=True")
    elif evidence_mutation == "duplicate":
        evidence.append("sensitive_text_match=False")
    elif evidence_mutation == "unknown":
        evidence[-1] = "sensitive_text_match=unknown"
    else:
        evidence[0] = "recipient=other"
    result = replace(
        result, rule_hit=result.rule_hit.model_copy(update={"evidence": evidence})
    )
    inputs, bundle = _project(case, [result])
    assert inputs.server_sensitive_evidence
    assert all("SENSITIVE" in flow.taints for flow in bundle.flow_facts)


@pytest.mark.parametrize("sensitive_mode", ["full_content", "explicit_flag"])
def test_actual_sensitive_detector_result_is_never_review_only(
    tmp_path, sensitive_mode
):
    case = fixture_case(tmp_path)
    payload = case.event.payload.model_copy(
        update=(
            {"content_preview": "ordinary text " * 400 + "password=fixture-marker"}
            if sensitive_mode == "full_content"
            else {"contains_sensitive_data": True}
        )
    )
    event = case.event.model_copy(update={"payload": payload})
    (result,) = OutboundDetector().evaluate(event, PolicyBundle())
    assert result.decision == "deny"
    assert not _product_message_review_only(event, result)
    # A policy override to ASK still carries real sensitive evidence.
    assert not _product_message_review_only(event, replace(result, decision="ask"))
    inputs, bundle = _project(case, [result])
    assert inputs.server_sensitive_evidence
    assert all("SENSITIVE" in flow.taints for flow in bundle.flow_facts)


@pytest.mark.parametrize(
    "category",
    [
        "sensitive_file_access",
        "file_exfiltration",
        "outbound_dlp",
        "credential_exposure",
    ],
)
def test_other_server_detections_still_add_their_sensitive_or_credential_bits(
    tmp_path, category
):
    case = fixture_case(tmp_path)
    (review,) = OutboundDetector().evaluate(case.event, PolicyBundle())
    other = replace(
        review,
        category=category,
        rule_hit=review.rule_hit.model_copy(
            update={"rule_id": "other-server-detector"}
        ),
    )
    inputs, bundle = _project(case, [review, other])
    assert not bundle.degradations
    assert inputs.server_credential_evidence is (category == "credential_exposure")
    assert all("SENSITIVE" in flow.taints for flow in bundle.flow_facts)
    if category == "credential_exposure":
        assert all("CREDENTIAL" in flow.taints for flow in bundle.flow_facts)
