"""Product context exclusion and scoped model observation parity."""

import pytest

from agentguard_core import PolicyBundle
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.security_context import AssessmentTransientFacts
from guard_api.services.context_builder import build_context_assembly
from guard_api.services.context_manifest import prepare_context_manifest
from tests.test_context_builder import _source, _event, _bundle, _task
from tests.test_v21_08_shadow_assessment import _snapshot
from tests.test_v21_action_ir_contract import _model_output_event

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("runtime", ["openclaw"])
@pytest.mark.parametrize("trust", ["trusted", "unknown"])
@pytest.mark.parametrize("sensitive", [False, True])
def test_unverified_runtime_system_remains_excluded_in_a_valid_manifest(
    runtime, trust, sensitive
):
    source = _source(
        "runtime:unverified-system",
        "runtime",
        "Unverified Host instructions",
        sequence_index=0,
        role="system",
        source_trust=trust,
        sensitive=sensitive,
    )
    event = _event([source])
    event.runtime = runtime
    snapshot = _snapshot().model_copy(update={"task": _task()})
    result = build_context_assembly(
        event=event,
        bundle=_bundle(event),
        snapshot=snapshot,
        product_runtime_isolation=True,
    )
    chunk = result.plan.chunks[0]
    assert (chunk.source_type, chunk.compartment, chunk.transform_state) == (
        "runtime",
        "untrusted_evidence",
        "excluded",
    )
    assert chunk.trust == "untrusted" and chunk.fact_authority == "untrusted_claim"
    assert "UNTRUSTED" in chunk.taints
    assert ("SENSITIVE" in chunk.taints) is sensitive
    assert prepare_context_manifest(event, result.plan) is not None


def _model_case(runtime):
    event = _model_output_event("product-output")
    event.runtime = runtime
    snapshot = _snapshot()
    snapshot = snapshot.model_copy(
        update={"scope": snapshot.scope.model_copy(update={"runtime": runtime})}
    )
    overlay = AssessmentTransientFacts(
        event_id=event.event_id, scope_digest=snapshot.scope.scope_digest
    )
    return event, snapshot, overlay


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_output_observation_is_explicit_and_preserves_legacy_default(runtime):
    event, snapshot, overlay = _model_case(runtime)
    common = dict(
        server_secret=b"fixture-secret",
        transient_facts=overlay,
        source_dataflow_not_required_actions=frozenset({"model_call"}),
        memory_not_required_actions=frozenset({"model_call"}),
    )
    old = shadow_assess_with_coverage(event, PolicyBundle(), snapshot, **common)
    product = shadow_assess_with_coverage(
        event, PolicyBundle(), snapshot, product_model_output_observation=True, **common
    )
    assert product.action_ir.impact == "low"
    assert not product.action_ir.effects.model_dump(exclude_defaults=True)
    assert (old.action_ir.impact == "low") is (runtime == "langgraph")
    required = set(product.assessment.required_check_plan.required_domains)
    assert not {"source", "dataflow", "memory"} & required
    assert {"task", "capability", "behavior"} <= required


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "missing", ["input_event", "overlay", "policy_marker", "snapshot"]
)
def test_product_observation_cannot_be_applied_to_input_or_incomplete_materials(
    runtime, missing
):
    event, snapshot, overlay = _model_case(runtime)
    if missing == "input_event":
        event.event_type = "model_input_prepared"
        event.payload.phase = "input"
        event.pre_execution = True
    with pytest.raises(ValueError, match="product_model_observation_invalid"):
        shadow_assess_with_coverage(
            event,
            PolicyBundle(),
            None if missing == "snapshot" else snapshot,
            server_secret=b"fixture-secret",
            product_model_output_observation=True,
            transient_facts=None if missing == "overlay" else overlay,
            source_dataflow_not_required_actions=frozenset()
            if missing == "policy_marker"
            else frozenset({"model_call"}),
        )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_explicit_memory_lineage_is_still_required_for_product_model(runtime):
    event, snapshot, overlay = _model_case(runtime)
    event.security_context.visible_source_refs = ("memory://fixture/key",)
    result = shadow_assess_with_coverage(
        event,
        PolicyBundle(),
        snapshot,
        server_secret=b"fixture-secret",
        product_model_output_observation=True,
        transient_facts=overlay,
        source_dataflow_not_required_actions=frozenset({"model_call"}),
        memory_not_required_actions=frozenset({"model_call"}),
    )
    assert "memory" in result.assessment.required_check_plan.required_domains
    assert result.assessment.disposition != "CLEAR_ALLOW"


@pytest.mark.parametrize(
    "runtime,product", [("langgraph", False), ("langgraph", True), ("openclaw", False)]
)
def test_non_product_oc_runtime_classification_is_unchanged(runtime, product):
    event = _event(
        [
            _source(
                "runtime:unknown",
                "runtime",
                "Host text",
                sequence_index=0,
                role="system",
                source_trust="unknown",
            )
        ]
    )
    event.runtime = runtime
    result = build_context_assembly(
        event=event,
        bundle=_bundle(event),
        snapshot=_snapshot().model_copy(update={"task": _task()}),
        product_runtime_isolation=product,
    )
    assert result.plan.chunks[0].compartment == "trusted_runtime_fact"
    assert result.plan.chunks[0].transform_state == "excluded"
