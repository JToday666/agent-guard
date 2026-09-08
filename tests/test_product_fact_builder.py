"""Scoped Product CT projection; signed catalog, synthetic parent evidence.

No model/tool invocation or Product Active qualification is claimed here.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context.facts import SourceFact
from agentguard_core.security_context.product_data import DataContentBinding
from guard_api.security_state.fact_authority import (
    ProducerIdentity,
    VerifiedSourceDescriptor,
)
from guard_api.security_state.fact_builder import FactBuildInputs, build_transient_facts
from guard_api.security_state.transient import (
    FACT_BUILDER_VERSION,
    LEGACY_FACT_BUILDER_VERSION,
    PRODUCT_FACT_BUILDER_VERSION,
    PRODUCT_FACT_PRODUCER,
    compute_bundle_digest,
    compute_overlay_digest,
    fact_builder_version_for_bundle,
)
from guard_api.services.ct_projection import (
    CtProjectionService,
    decode_ct_transient_facts,
)
from tests.support.product_tool_catalog import catalog_fixture
from tests.test_product_data_contract import MODEL, USER, proof
from tests.test_product_tool_catalog import action, event_for, resolve
from tests.test_ct_fact_builder import ct_inputs, ct_model_event
from tests.test_ct_fact_builder_write_path import _upstream_memory_fact

ANCESTOR = "source:web:ancestor"
UNRELATED = "source:web:unrelated-history"


def descriptor(ref, scope, *, taints=(), untrusted=False):
    model = ref == MODEL
    return VerifiedSourceDescriptor(
        source_id=ref,
        scope_digest=scope,
        source_type="model" if model else "web" if untrusted else "user",
        trust="unknown" if model else "untrusted" if untrusted else "trusted",
        verification_state="verified",
        producer="ct-fact-builder",
        fact_authority=(
            "model_judgment"
            if model
            else "untrusted_claim" if untrusted else "authoritative"
        ),
        initial_taints=taints,
    )


def fixture_case(
    tmp_path, *, name="message", runtime="langgraph", taints=(), untrusted=False
):
    catalog = catalog_fixture(tmp_path)
    event = event_for(catalog, name, runtime)
    event = event.model_copy(
        update={
            "security_context": event.security_context.model_copy(
                update={"visible_source_refs": (MODEL, USER)},
            )
        }
    )
    tool = resolve(catalog, event)
    ir = action(catalog, event, tool)
    resources = (*ir.resources, *ir.destinations)
    memory_refs = tuple(
        sorted({r.canonical_id for r in resources if r.kind == "memory"})
    )
    artifacts = tuple(
        sorted({r.canonical_id for r in resources if r.kind not in {"memory", "tool"}})
    )
    first_write = memory_refs[0] if name == "agentguard_memory_write" else None
    issued = proof(
        ir,
        tool_descriptor_digest=tool.descriptor_digest,
        input_schema_digest=tool.input_schema_digest,
        semantics_digest=tool.semantics_digest,
        source_refs=(MODEL, USER, ANCESTOR),
        direct_source_refs=(MODEL, USER),
        artifact_refs=artifacts,
        memory_refs=memory_refs,
        first_write_memory_ref=first_write,
        taints=taints,
        bindings=tuple(
            DataContentBinding(
                source_ref=MODEL,
                source_json_pointer="/tool_calls/0/args" + item.json_pointer,
                value_digest=canonical_sha256(item.value),
                action_id=ir.action_id,
                argument_pointer=item.json_pointer,
                sink_role=(
                    "content"
                    if item.json_pointer in {"/message", "/value", "/content"}
                    else "selector"
                ),
                resource_ref=first_write if item.json_pointer == "/value" else None,
            )
            for item in ir.canonical_arguments.items
        ),
    )
    inputs = FactBuildInputs(
        scope_digest=ir.scope_digest,
        producer_identity=ProducerIdentity(),
        action_ir=ir,
        product_data=issued,
        visible_refs=(MODEL, USER),
        upstream_descriptors={
            MODEL: descriptor(MODEL, ir.scope_digest),
            USER: descriptor(USER, ir.scope_digest),
            ANCESTOR: descriptor(
                ANCESTOR, ir.scope_digest, taints=taints, untrusted=untrusted
            ),
            UNRELATED: descriptor(
                UNRELATED,
                ir.scope_digest,
                taints=("CREDENTIAL", "SENSITIVE"),
                untrusted=True,
            ),
        },
        upstream_memory_facts={
            "memory:memory://unrelated/history": _upstream_memory_fact(
                trust_state="quarantined", taints=("CREDENTIAL",)
            )
        },
    )
    return SimpleNamespace(
        catalog=catalog, event=event, tool=tool, ir=ir, proof=issued, inputs=inputs
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("name", ["read", "write"])
def test_product_tool_transport_keeps_actual_resources_and_possible_control(
    tmp_path, runtime, name
):
    case = fixture_case(tmp_path, name=name, runtime=runtime)
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    assert not bundle.degradations
    (copy,) = [flow for flow in bundle.flow_facts if flow.relation == "derived_from"]
    assert (copy.source_ref, copy.target_ref, copy.strength) == (
        MODEL,
        f"action:{case.ir.action_id}",
        "exact",
    )
    resource_flows = [
        flow
        for flow in bundle.flow_facts
        if flow.relation in {"read_from", "written_to"}
    ]
    assert {flow.target_ref for flow in resource_flows} == {
        resource.canonical_id
        for resource in (*case.ir.resources, *case.ir.destinations)
    }
    assert all(
        flow.strength == "possible"
        for flow in bundle.flow_facts
        if flow.relation == "influenced_by"
    )
    assert all(case.proof.covers_flow_endpoints(flow) for flow in bundle.flow_facts)


def test_message_sensitive_control_ancestor_remains_on_actual_outbound_flow(tmp_path):
    case = fixture_case(tmp_path, taints=("CREDENTIAL", "SENSITIVE"))
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    assert not bundle.degradations
    (sent,) = [flow for flow in bundle.flow_facts if flow.relation == "sent_to"]
    assert set(sent.taints) == {"CREDENTIAL", "SENSITIVE"}
    assert not case.proof.reviewable
    assert all(
        set(flow.taints) == set(sent.taints) and flow.strength == "possible"
        for flow in bundle.flow_facts
        if flow.relation == "influenced_by"
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_verified_message_uses_actual_profile_sink_not_payload_alias(tmp_path, runtime):
    case = fixture_case(tmp_path, runtime=runtime)
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    assert not bundle.degradations
    (sent,) = [flow for flow in bundle.flow_facts if flow.relation == "sent_to"]
    assert sent.source_ref == MODEL
    assert sent.target_ref == case.ir.destinations[0].canonical_id
    assert sent.target_ref.startswith("http://127.0.0.1:")
    assert case.event.payload.recipient == "fixture-inbox"
    assert sent.strength == "exact" and sent.origin == "observed"
    control = [flow for flow in bundle.flow_facts if flow.relation == "influenced_by"]
    assert {flow.source_ref for flow in control} == {MODEL, USER}
    assert all(
        flow.strength == "possible" and flow.origin == "semantic_inferred"
        for flow in control
    )
    assert all(flow.producer == PRODUCT_FACT_PRODUCER for flow in bundle.flow_facts)
    assert not any(
        flow.source_ref in {USER, ANCESTOR} and flow.relation == "sent_to"
        for flow in bundle.flow_facts
    )


@pytest.mark.parametrize("taints", [(), ("SENSITIVE",), ("CREDENTIAL", "SENSITIVE")])
def test_memory_excludes_unrelated_history_retains_full_closure_taints(
    tmp_path, taints
):
    case = fixture_case(tmp_path, name="agentguard_memory_write", taints=taints)
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    assert not bundle.degradations
    (memory,) = bundle.memory_facts
    assert memory.memory_id == case.proof.first_write_memory_ref
    assert memory.trust_state == "unknown"
    assert memory.change_status == "proposed"
    assert set(memory.source_refs) == {MODEL, USER, f"action:{case.ir.action_id}"}
    assert set(memory.taints) == set(taints)
    assert not any(UNRELATED in flow.source_ref for flow in bundle.flow_facts)
    (persisted,) = [
        flow for flow in bundle.flow_facts if flow.relation == "persisted_to"
    ]
    assert (
        persisted.source_ref == MODEL
        and persisted.target_ref == f"memory:{memory.memory_id}"
    )
    assert persisted.strength == "exact" and set(persisted.taints) == set(taints)
    assert all(
        flow.strength == "possible"
        for flow in bundle.flow_facts
        if flow.relation == "influenced_by"
    )
    assert case.inputs.upstream_descriptors[MODEL].trust == "unknown"


@pytest.mark.parametrize("quarantined", [False, True])
def test_memory_untrusted_ancestor_is_never_cleaned(tmp_path, quarantined):
    case = fixture_case(
        tmp_path, name="agentguard_memory_write", taints=("UNTRUSTED",), untrusted=True
    )
    inputs = (
        case.inputs.model_copy(update={"memory_change_status": "quarantined"})
        if quarantined
        else case.inputs
    )
    bundle = build_transient_facts(event=case.event, inputs=inputs)
    assert not bundle.degradations
    (memory,) = bundle.memory_facts
    assert memory.trust_state == ("quarantined" if quarantined else "tainted")
    assert set(memory.taints) == {"UNTRUSTED", "PERSISTENT_UNTRUSTED"}


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_ir",
        "missing_source",
        "wrong_scope",
        "missing_taint",
        "missing_visible",
        "wrong_visible",
        "overwrite",
        "forged_model_trust",
    ],
)
def test_incomplete_or_mismatched_product_inputs_emit_no_partial_facts(
    tmp_path, mutation
):
    case = fixture_case(tmp_path, name="agentguard_memory_write")
    updates = {}
    if mutation == "wrong_ir":
        updates["action_ir"] = case.ir.model_copy(update={"action_id": "other"})
    elif mutation in {
        "missing_source",
        "wrong_scope",
        "missing_taint",
        "forged_model_trust",
    }:
        sources = dict(case.inputs.upstream_descriptors)
        if mutation == "missing_source":
            del sources[ANCESTOR]
        elif mutation == "wrong_scope":
            sources[ANCESTOR] = sources[ANCESTOR].model_copy(
                update={"scope_digest": canonical_sha256("other")}
            )
        elif mutation == "missing_taint":
            sources[ANCESTOR] = sources[ANCESTOR].model_copy(
                update={"initial_taints": ("SENSITIVE",)}
            )
        else:
            sources[MODEL] = sources[MODEL].model_copy(update={"trust": "trusted"})
        updates["upstream_descriptors"] = sources
    elif mutation == "overwrite":
        updates["upstream_memory_facts"] = {
            case.proof.first_write_memory_ref: _upstream_memory_fact().model_copy(
                update={"memory_id": case.proof.first_write_memory_ref}
            )
        }
    else:
        updates["visible_refs"] = None if mutation == "missing_visible" else (MODEL,)
    bundle = build_transient_facts(
        event=case.event, inputs=case.inputs.model_copy(update=updates)
    )
    assert bundle.degradations and not bundle.flow_facts and not bundle.memory_facts
    assert bundle.current_action is None


def envelope(bundle):
    service = object.__new__(CtProjectionService)
    payload = service.commit_envelope(
        bundle,
        source_record_id=f"ct-facts:{bundle.event_id}",
        projection_id="projection:test",
        base_state_version=0,
        projection_eligible=True,
    )
    return {"schema_version": "1.1", "payload": payload}


def test_product_version_and_exact_digests_survive_envelope_replay(tmp_path):
    case = fixture_case(tmp_path)
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    assert fact_builder_version_for_bundle(bundle) == PRODUCT_FACT_BUILDER_VERSION
    wire = envelope(bundle)
    assert wire["payload"]["fact_builder_version"] == PRODUCT_FACT_BUILDER_VERSION
    decoded = decode_ct_transient_facts(wire)
    assert decoded.kind == "full" and decoded.bundle == bundle
    assert bundle.bundle_digest == compute_bundle_digest(
        bundle, fact_builder_version=PRODUCT_FACT_BUILDER_VERSION
    )
    assert bundle.bundle_digest != compute_bundle_digest(
        bundle, fact_builder_version=FACT_BUILDER_VERSION
    )


@pytest.mark.parametrize(
    "mutation", ["wrong_version", "missing_marker", "mixed_marker", "digest"]
)
def test_product_envelope_rejects_version_marker_and_digest_substitution(
    tmp_path, mutation
):
    case = fixture_case(tmp_path)
    bundle = build_transient_facts(event=case.event, inputs=case.inputs)
    wire = envelope(bundle)
    if mutation == "wrong_version":
        wire["payload"]["fact_builder_version"] = FACT_BUILDER_VERSION
        digest = compute_bundle_digest(
            bundle, fact_builder_version=FACT_BUILDER_VERSION
        )
        wire["payload"]["bundle_digest"] = wire["payload"]["bundle"][
            "bundle_digest"
        ] = digest
    elif mutation == "digest":
        wire["payload"]["bundle_digest"] = canonical_sha256("substituted")
    else:
        flows = list(bundle.flow_facts)
        changed = range(len(flows)) if mutation == "missing_marker" else [0]
        for index in changed:
            flows[index] = flows[index].model_copy(
                update={"producer": "ct-fact-builder"}
            )
        changed_bundle = bundle.model_copy(update={"flow_facts": tuple(flows)})
        changed_bundle = changed_bundle.model_copy(
            update={
                "bundle_digest": compute_bundle_digest(
                    changed_bundle, fact_builder_version=PRODUCT_FACT_BUILDER_VERSION
                ),
                "overlay_digest": compute_overlay_digest(changed_bundle),
            }
        )
        wire["payload"]["bundle"] = changed_bundle.model_dump(mode="json")
        wire["payload"]["bundle_digest"] = changed_bundle.bundle_digest
        wire["payload"]["overlay_digest"] = changed_bundle.overlay_digest
    assert decode_ct_transient_facts(wire).kind == "invalid"


def test_old_bundles_keep_dump_and_versioned_replay():
    bundle = build_transient_facts(
        event=ct_model_event("input"), inputs=ct_inputs(visible_refs=())
    )
    dumped = bundle.model_dump(mode="json")
    assert "fact_builder_version" not in dumped
    assert fact_builder_version_for_bundle(bundle) == FACT_BUILDER_VERSION
    assert decode_ct_transient_facts(envelope(bundle)).kind == "full"
    legacy = deepcopy(envelope(bundle))
    legacy["schema_version"] = "1.0"
    legacy["payload"].pop("fact_builder_version")
    digest = compute_bundle_digest(
        bundle, fact_builder_version=LEGACY_FACT_BUILDER_VERSION
    )
    legacy["payload"]["bundle_digest"] = legacy["payload"]["bundle"][
        "bundle_digest"
    ] = digest
    assert decode_ct_transient_facts(legacy).kind == "full"


def test_server_ct_inputs_use_same_verified_ir_and_proof(tmp_path):
    case = fixture_case(tmp_path, name="agentguard_memory_write")
    service = object.__new__(CtProjectionService)
    service._server_secret = case.catalog.fixture.server_secret
    sources = [
        SourceFact(
            source_id=d.source_id,
            scope_digest=d.scope_digest,
            source_type=d.source_type,
            trust=d.trust,
            verification_state=d.verification_state,
            authority=d.fact_authority,
            origin="observed",
            producer=d.producer,
            taints=list(d.initial_taints),
            first_sequence=None,
            last_sequence=None,
            evidence_refs=[],
        )
        for d in case.inputs.upstream_descriptors.values()
    ]
    snapshot = SimpleNamespace(
        sources=sources,
        memory_facts=[],
        flows=[],
        task=SimpleNamespace(revision=1, principal_id=case.ir.principal_id),
        scope=SimpleNamespace(runtime_binding_id=case.ir.runtime_binding_id),
    )
    materials = SimpleNamespace(
        snapshot=snapshot,
        detection_results=[],
        task_id="task",
        product_tool=case.tool,
        product_data=case.proof,
    )
    actual = service._build_inputs(case.event, materials, case.ir.scope_digest)
    assert actual.product_data is case.proof
    assert actual.action_ir == case.ir
    assert set(actual.visible_refs) == {MODEL, USER}
    assert not build_transient_facts(event=case.event, inputs=actual).degradations
