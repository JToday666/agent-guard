"""Signed ACK/accepted receipt -> compiler -> CT -> actual Core assessment.

The original model policies/content are explicit synthetic server fixtures.
There is no Host/model execution, Provider call, or Active qualification claim.
Only the coverage observer is wrapped; its real computation is always executed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentguard_core.decisions import shadow as core_assessment
from agentguard_core.security_context.assessment_overlay import AssessmentTransientFacts
from guard_api.security_state.fact_builder import build_transient_facts
from guard_api.services.ct_projection import CtProjectionService
from guard_api.services.product_model_content import verify_product_model_content
from tests.test_product_model_content import _fixture

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("memory", [False, True])
@pytest.mark.parametrize("sensitive", [False, True])
@pytest.mark.parametrize("untrusted", [False, True])
def test_signed_parent_data_flows_through_actual_ct_and_core(
    tmp_path, monkeypatch, memory, sensitive, untrusted
):
    rig = _fixture(
        tmp_path,
        memory=memory,
        sensitive=sensitive,
        model_taints=("UNTRUSTED",) if untrusted else (),
    )
    rig.snapshot = rig.snapshot.model_copy(
        update={
            "sources": list(rig.snapshot.sources),
            "flows": list(rig.snapshot.flows),
            "memory_facts": list(rig.snapshot.memory_facts),
            "dirty_domains": list(rig.snapshot.dirty_domains),
        }
    )
    before = rig.snapshot.model_dump(mode="json")
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    service = object.__new__(CtProjectionService)
    service._server_secret = rig.harness.fixture.server_secret
    materials = SimpleNamespace(
        snapshot=rig.snapshot,
        detection_results=[],
        task_id=rig.snapshot.task.task_id,
        product_tool=rig.tool,
        product_data=proof,
        product_result=None,
    )
    inputs = service._build_inputs(
        rig.event, materials, rig.snapshot.scope.scope_digest
    )
    assert inputs.action_ir is not None and proof.matches_action(inputs.action_ir)
    bundle = build_transient_facts(event=rig.event, inputs=inputs)
    assert not bundle.degradations
    assert any(
        flow.relation == "influenced_by" and flow.strength == "possible"
        for flow in bundle.flow_facts
    )
    transient = AssessmentTransientFacts.model_validate(bundle.model_dump(mode="json"))
    observed = []
    real_coverage = core_assessment.compute_coverage

    def observe_coverage(*args, **kwargs):
        result = real_coverage(*args, **kwargs)
        observed.append(result)
        return result

    monkeypatch.setattr(core_assessment, "compute_coverage", observe_coverage)
    policies = rig.harness.store.get_policy_snapshot()
    assert policies is not None
    assessment = core_assessment.assess(
        rig.event,
        policies,
        rig.snapshot,
        server_secret=rig.harness.fixture.server_secret,
        transient_facts=transient,
        product_tool=rig.tool,
        product_data=proof,
    )
    assert len(observed) == 1
    coverage = observed[0]
    assert assessment.action_id == proof.action_id == inputs.action_ir.action_id
    assert (
        assessment.authorization_fingerprint
        == inputs.action_ir.authorization_fingerprint
    )
    assert {"source", "dataflow"} <= set(
        assessment.required_check_plan.required_domains
    )
    assert ("memory" in assessment.required_check_plan.required_domains) is memory
    assert coverage.source.status == "complete"
    persisted_untrusted = memory and untrusted
    assert coverage.dataflow.status == (
        "partial" if persisted_untrusted else "complete"
    )
    assert coverage.memory.status == (
        "partial" if persisted_untrusted else "complete" if memory else "not_applicable"
    )
    assert "v21-05:possible_flow_link" not in coverage.dataflow.reason_codes
    assert rig.snapshot.model_dump(mode="json") == before
    assert rig.model.trust == "unknown" and rig.model.authority == "model_judgment"
    assert rig.model.source_id in proof.direct_source_refs
    if memory:
        (fact,) = bundle.memory_facts
        assert fact.trust_state == ("tainted" if untrusted else "unknown")
        assert set(fact.taints) == set(proof.taints) | (
            {"PERSISTENT_UNTRUSTED"} if untrusted else set()
        )
        assert set(fact.source_refs) == {
            *proof.direct_source_refs,
            f"action:{proof.action_id}",
        }
    if sensitive or persisted_untrusted:
        if sensitive:
            assert {"CREDENTIAL", "SENSITIVE"} <= set(proof.taints)
            assert not proof.reviewable
        assert assessment.flow.status != "safe"
        assert assessment.disposition != "clear_allow"
    else:
        assert proof.taints == (("UNTRUSTED",) if untrusted else ())
        assert assessment.flow.status == "safe"
    (ref,) = [
        ref
        for ref in assessment.evidence_refs
        if ref.record_type == "product_action_data"
    ]
    assert ref.digest == proof.proof_digest
