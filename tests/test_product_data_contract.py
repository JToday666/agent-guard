"""Pure Core contract tests; evidence is synthetic, never Active qualification."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agentguard_core.actions.builder import build_action_ir
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.canonical_resources import (
    ResourceNormalizationInput,
    normalize_memory_resource,
)
from agentguard_core.actions.fingerprints import (
    authorization_fingerprint,
    audit_fingerprint,
)
from agentguard_core.actions.models import ToolResource
from agentguard_core.actions.normalize import normalize_arguments
from agentguard_core.actions.product_tools import product_tool_resource_identity
from agentguard_core.decisions.product import select_product_v21_authority
from agentguard_core.events import GuardEvent
from agentguard_core.security_context.product_data import (
    DataContentBinding,
    VerifiedProductData,
    PRODUCT_DATA_COVERAGE_VERSION,
)
from agentguard_core.security_context.projection.flow_verdict import (
    compute_flow_verdict_from_state,
)
from agentguard_core.security_context.projection.provenance_coverage import (
    source_coverage,
    dataflow_coverage,
    memory_coverage,
)
from agentguard_core.security_context.required_checks import (
    PolicyProfile,
    build_required_check_plan,
)
from tests.support.product_activation import build_test_product_activation
from tests.test_product_v21_core_selector import (
    _assessment,
    _coverage,
    _decision,
    _eligibility,
    POLICY_DIGEST,
)
from tests.test_v21_05_coverage import make_ctx
from tests.test_v21_05_provenance import empty_state, make_flow, make_memory
from tests.test_v21_security_state_models import make_source_fact

SCOPE = canonical_sha256("scope")
DESCRIPTOR = canonical_sha256("descriptor")
SEMANTICS = canonical_sha256("semantics")
MODEL = "source:model:evt_model_output"
USER = "source:user:task"
SECRET = b"synthetic-unit-test-key"


def test_actual_hmac_scope_digest_is_an_identity_not_a_content_hash():
    scope = "hmac-sha256:" + "a" * 64
    ir = action().model_copy(update={"scope_digest": scope})
    issued = proof(ir)
    assert issued.scope_digest == scope
    assert issued.matches_action(ir)
    assert not issued.matches_action(ir.model_copy(update={"scope_digest": SCOPE}))
    with pytest.raises(ValidationError):
        proof(ir, argument_digest=scope)


def test_proof_rejects_changed_actual_schema_even_with_same_descriptor_identity():
    ir = action()
    issued = proof(ir)
    changed = ir.model_copy(
        update={
            "resources": [
                ir.resources[0].model_copy(
                    update={"tool_schema_digest": canonical_sha256("different schema")},
                )
            ]
        }
    )
    assert not issued.matches_action(changed)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "taint",
        "source",
        "lifecycle",
        "change",
        "duplicate",
        "contradictory_clean",
    ],
)
def test_historical_memory_requires_complete_unchanged_dependency_state(mutation):
    ref = "memory://notes/old"
    parent = "action:old-write"
    issued = proof(memory_refs=(ref,), artifact_refs=(parent,))
    fact = make_memory(
        ref,
        change_id="change-original",
        change_status="committed",
        trust_state="clean",
        taints=[],
        source_refs=[USER, parent],
    )
    if mutation == "taint":
        fact = fact.model_copy(
            update={"trust_state": "tainted", "taints": ["CREDENTIAL"]}
        )
    elif mutation == "source":
        fact = fact.model_copy(update={"source_refs": ["source:unproved"]})
    elif mutation == "lifecycle":
        fact = fact.model_copy(update={"change_status": "proposed"})
    elif mutation == "change":
        fact = fact.model_copy(update={"change_id": None})
    elif mutation == "contradictory_clean":
        issued = proof(
            memory_refs=(ref,), artifact_refs=(parent,), taints=("UNTRUSTED",)
        )
        fact = fact.model_copy(update={"taints": ["UNTRUSTED"]})
    current = state().model_copy(
        update={"memory_index": [fact, fact] if mutation == "duplicate" else [fact]}
    )
    ctx = make_ctx(required=["memory"], stable_refs=(MODEL, USER)).model_copy(
        update={"product_data": issued}
    )
    assert memory_coverage(current, ctx).status == (
        "complete" if mutation is None else "partial"
    )


def action():
    event = GuardEvent.model_validate(
        {
            "event_id": "evt_action",
            "event_type": "tool_call_proposed",
            "runtime": "langgraph",
            "trace_id": "trace",
            "security_context": {
                "agent_id": "agent",
                "user_task": "create a report",
                "source_type": "model",
                "source_trust": "unknown",
            },
            "payload": {
                "tool": {
                    "name": "write",
                    "category": "file",
                    "kind": "file_write",
                    "call_id": "call_write",
                },
                "arguments": {"path": "report.txt", "content": "original model value"},
                "derived_resources": [],
            },
        }
    )
    original = build_action_ir(
        event,
        server_secret=SECRET,
        task_id="task",
        task_revision=1,
        scope_digest=SCOPE,
        principal_id="principal",
        runtime_binding_id="binding",
    )
    resource = ToolResource(
        resource_id="tool",
        canonical_id=product_tool_resource_identity("write", DESCRIPTOR, SEMANTICS),
        display_summary="isolated write",
        resolution_status="resolved",
        normalizer_version="product-tool-1",
        tool_name="write",
        tool_schema_digest=canonical_sha256("schema"),
        provider_binding_id="binding",
    )
    updated = original.model_copy(update={"resources": [resource]})
    return updated.model_copy(
        update={
            "authorization_fingerprint": authorization_fingerprint(SECRET, updated),
            "audit_fingerprint": audit_fingerprint(updated),
        }
    )


def proof(ir=None, **overrides):
    ir = ir or action()
    values = {
        "event_id": ir.event_id,
        "action_id": ir.action_id,
        "runtime": ir.runtime,
        "runtime_binding_id": ir.runtime_binding_id,
        "scope_digest": ir.scope_digest,
        "task_id": ir.task_id,
        "task_revision": ir.task_revision,
        "tool_name": ir.tool_name,
        "tool_descriptor_digest": DESCRIPTOR,
        "input_schema_digest": canonical_sha256("schema"),
        "semantics_digest": SEMANTICS,
        "argument_digest": ir.argument_digest,
        "model_source_ref": MODEL,
        "model_output_event_id": "evt_model_output",
        "model_output_audit_id": "audit_model_output",
        "model_output_digest": canonical_sha256("complete output"),
        "content_evidence_digest": canonical_sha256("confirmed original parent chain"),
        "required_argument_pointers": tuple(
            item.json_pointer for item in ir.canonical_arguments.items
        ),
        "bindings": tuple(
            DataContentBinding(
                source_ref=MODEL,
                source_json_pointer="/tool_calls/0/args" + item.json_pointer,
                value_digest=canonical_sha256(item.value),
                action_id=ir.action_id,
                argument_pointer=item.json_pointer,
                sink_role="content" if item.json_pointer == "/content" else "selector",
            )
            for item in ir.canonical_arguments.items
        ),
        "source_refs": (MODEL, USER),
        "direct_source_refs": (MODEL, USER),
        "memory_refs": (),
        "taints": (),
        "hostile_instruction": False,
        "closure_complete": True,
    }
    values.update(overrides)
    return VerifiedProductData.model_validate(values)


def state(*, taints=()):
    model = make_source_fact(source_id=MODEL).model_copy(
        update={
            "scope_digest": SCOPE,
            "source_type": "model",
            "authority": "model_judgment",
            "trust": "unknown",
            "taints": list(taints),
        }
    )
    user = make_source_fact(source_id=USER).model_copy(
        update={"scope_digest": SCOPE, "taints": []}
    )
    control = make_flow(
        "control",
        USER,
        "action:call_write",
        relation="influenced_by",
        strength="possible",
    ).model_copy(
        update={
            "scope_digest": SCOPE,
            "origin": "semantic_inferred",
            "taints": list(taints),
        }
    )
    copied = make_flow(
        "model_control",
        MODEL,
        "action:call_write",
        relation="influenced_by",
        strength="possible",
    ).model_copy(
        update={
            "scope_digest": SCOPE,
            "origin": "semantic_inferred",
            "taints": list(taints),
        }
    )
    resource = make_flow(
        "resource",
        "action:call_write",
        action().resources[0].canonical_id,
        relation="read_from",
    ).model_copy(update={"scope_digest": SCOPE, "taints": []})
    return empty_state().model_copy(
        update={
            "source_index": [model, user],
            "relevant_flows": [control, copied, resource],
        }
    )


def context(data=None, **overrides):
    return make_ctx(
        required=["source", "dataflow"], stable_refs=(MODEL, USER), **overrides
    ).model_copy(update={"product_data": data})


def test_proof_is_immutable_canonical_and_contains_no_original_values():
    value = proof()
    assert value.matches_action(action())
    assert value.integrity_valid()
    assert "original model value" not in value.model_dump_json()
    assert "report.txt" not in value.model_dump_json()
    assert proof(source_refs=(USER, MODEL)).proof_digest == value.proof_digest
    assert VerifiedProductData.model_validate_json(value.model_dump_json()) == value
    with pytest.raises(ValidationError):
        value.action_id = "different"


@pytest.mark.parametrize(
    "change",
    [
        {"closure_complete": False},
        {"model_source_ref": "source:model:other"},
        {"source_refs": (MODEL, MODEL)},
        {"required_argument_pointers": ("/content",)},
        {"bindings": ()},
        {"proof_digest": canonical_sha256("wrong")},
        {"memory_refs": ("memory:unknown",)},
        {"hostile_instruction": "false"},
        {"task_revision": True},
        {"extra": "raw value"},
        {"direct_source_refs": (USER,)},
        {"direct_source_refs": (MODEL, "unproved")},
    ],
)
def test_invalid_proof_is_rejected(change):
    with pytest.raises(ValidationError):
        proof(**change)


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_id", "other"),
        ("action_id", "other"),
        ("runtime", "openclaw"),
        ("runtime_binding_id", "other"),
        ("scope_digest", canonical_sha256("other")),
        ("task_id", "other"),
        ("task_revision", 2),
        ("tool_name", "read"),
        ("argument_digest", canonical_sha256("other")),
    ],
)
def test_proof_rejects_action_anchor_drift(field, value):
    assert not proof().matches_action(action().model_copy(update={field: value}))


def test_proof_rejects_descriptor_semantics_and_field_drift():
    ir = action()
    assert not proof(
        tool_descriptor_digest=canonical_sha256("other descriptor")
    ).matches_action(ir)
    assert not proof(
        semantics_digest=canonical_sha256("other semantics")
    ).matches_action(ir)
    binding = (
        proof()
        .bindings[0]
        .model_copy(update={"value_digest": canonical_sha256("substitution")})
    )
    assert not proof(bindings=(binding, proof().bindings[1])).matches_action(ir)
    assert (
        not proof()
        .model_copy(update={"memory_refs": ("memory://hidden/key",)})
        .integrity_valid()
    )


def test_model_identity_known_does_not_promote_unknown_trust():
    before = state().model_dump()
    assert source_coverage(state(), context()).status == "partial"
    verdict = source_coverage(state(), context(proof()))
    assert verdict.status == "complete"
    assert verdict.projector_version == PRODUCT_DATA_COVERAGE_VERSION
    assert state().model_dump() == before
    assert state().source_index[0].trust == "unknown"


@pytest.mark.parametrize(
    "change", ["missing", "scope", "producer", "authority", "taint", "unknown_web"]
)
def test_missing_or_inconsistent_source_proof_cannot_complete(change):
    current = state()
    model = current.source_index[0]
    if change == "missing":
        current = current.model_copy(update={"source_index": current.source_index[1:]})
    else:
        field, value = {
            "scope": ("scope_digest", canonical_sha256("other")),
            "producer": ("producer", ""),
            "authority": ("authority", "untrusted_claim"),
            "taint": ("taints", ["CREDENTIAL"]),
            "unknown_web": ("source_type", "web"),
        }[change]
        current = current.model_copy(
            update={
                "source_index": [
                    model.model_copy(update={field: value}),
                    current.source_index[1],
                ]
            }
        )
    assert source_coverage(current, context(proof())).status != "complete"
    assert dataflow_coverage(current, context(proof())).status != "complete"


def test_control_possible_is_preserved_while_complete_bytes_are_proved():
    current = state()
    before = current.model_dump()
    assert dataflow_coverage(current, context()).status == "partial"
    assert dataflow_coverage(current, context(proof())).status == "complete"
    assert (
        compute_flow_verdict_from_state(
            current, action(), dataflow_status="complete"
        ).status
        == "uncertain"
    )
    assert (
        compute_flow_verdict_from_state(
            current, action(), dataflow_status="complete", product_data=proof()
        ).status
        == "safe"
    )
    assert current.model_dump() == before
    assert current.relevant_flows[0].strength == "possible"


@pytest.mark.parametrize(
    "change", ["data_possible", "unproved_control", "scope", "missing_taint"]
)
def test_unproved_or_real_possible_data_remains_partial(change):
    current = state()
    field, value = {
        "data_possible": ("relation", "derived_from"),
        "unproved_control": ("source_ref", "source:missing"),
        "scope": ("scope_digest", canonical_sha256("other")),
        "missing_taint": ("taints", ["SENSITIVE"]),
    }[change]
    flows = [
        current.relevant_flows[0].model_copy(update={field: value}),
        *current.relevant_flows[1:],
    ]
    current = current.model_copy(update={"relevant_flows": flows})
    assert dataflow_coverage(current, context(proof())).status != "complete"
    assert (
        compute_flow_verdict_from_state(
            current, action(), dataflow_status="complete", product_data=proof()
        ).status
        != "safe"
    )


@pytest.mark.parametrize(
    "kwargs",
    [{"truncated": ("dataflow",)}, {"provider_available": {"flow_provider": False}}],
)
def test_complete_field_bindings_do_not_override_unavailable_or_truncated_state(kwargs):
    assert dataflow_coverage(state(), context(proof(), **kwargs)).status != "complete"


@pytest.mark.parametrize(
    "taint", ["CREDENTIAL", "SENSITIVE", "EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"]
)
def test_unsafe_dependency_cannot_become_reviewable(taint):
    value = proof(taints=(taint,))
    assert not value.reviewable
    result = compute_flow_verdict_from_state(
        state(taints=(taint,)), action(), dataflow_status="complete", product_data=value
    )
    if taint in {"CREDENTIAL", "SENSITIVE"}:
        assert result.status == "violation"
        assert result.strongest_strength == "possible"
    else:
        assert result.status != "safe"


@pytest.mark.parametrize("endpoint", ["source_ref", "target_ref"])
def test_unknown_exact_artifact_is_not_hidden_by_complete_argument_binding(endpoint):
    current = state()
    extra = current.relevant_flows[-1].model_copy(
        update={endpoint: "artifact:unproved"}
    )
    current = current.model_copy(
        update={"relevant_flows": [*current.relevant_flows, extra]}
    )
    assert dataflow_coverage(current, context(proof())).status == "partial"
    assert (
        compute_flow_verdict_from_state(
            current, action(), dataflow_status="complete", product_data=proof()
        ).status
        != "safe"
    )


def test_current_resource_requires_proved_canonical_artifact_identity():
    from agentguard_core.actions.canonical_resources import normalize_file_resource

    file = normalize_file_resource(
        ResourceNormalizationInput(resource_id="file", target="/isolated/report.txt")
    )
    ir = action().model_copy(update={"resources": [*action().resources, file]})
    assert not proof(ir).matches_action(ir)
    assert proof(ir, artifact_refs=(file.canonical_id,)).matches_action(ir)


def test_hidden_sensitive_or_hostile_proof_cannot_produce_safe():
    for value in (proof(taints=("CREDENTIAL",)), proof(hostile_instruction=True)):
        assert not value.reviewable
        assert (
            compute_flow_verdict_from_state(
                state(), action(), dataflow_status="complete", product_data=value
            ).status
            != "safe"
        )


def test_file_persistence_is_not_false_memory_but_memory_dependencies_stay_required():
    ir = action().model_copy(
        update={"effects": action().effects.model_copy(update={"persistence": True})}
    )
    policy = PolicyProfile(policy_revision="1", policy_digest=POLICY_DIGEST)
    old = build_required_check_plan(ir, policy)
    assert "memory" in old.required_domains
    fixed = build_required_check_plan(ir, policy, product_data=proof(ir))
    assert "memory" not in fixed.required_domains
    assert {"source", "dataflow"}.issubset(fixed.required_domains)
    assert old == build_required_check_plan(ir, policy)
    assert old.plan_id != fixed.plan_id
    dependency = proof(ir, memory_refs=("memory://notes/old",))
    assert (
        "memory"
        in build_required_check_plan(
            ir, policy, product_data=dependency
        ).required_domains
    )
    with pytest.raises(ValueError, match="product_data_action_mismatch"):
        build_required_check_plan(ir, policy, product_data=proof(event_id="other"))


def test_current_memory_resource_cannot_be_omitted_from_proof():
    memory = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="memory", target="key", memory_namespace="notes"
        )
    )
    ir = action().model_copy(update={"resources": [*action().resources, memory]})
    assert not proof(ir).matches_action(ir)
    value = proof(ir, memory_refs=(memory.canonical_id,))
    assert value.matches_action(ir)
    ctx = make_ctx(required=["memory"], stable_refs=(MODEL, USER)).model_copy(
        update={"product_data": value}
    )
    assert memory_coverage(state(), ctx).status == "unknown"
    current = state().model_copy(
        update={"memory_index": [make_memory("memory://notes/unrelated")]}
    )
    assert memory_coverage(current, ctx).status == "partial"
    current = current.model_copy(
        update={
            "memory_index": [make_memory(memory.canonical_id, trust_state="unknown")]
        }
    )
    assert memory_coverage(current, ctx).status == "partial"


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "historical",
        "existing_change",
        "missing_source",
        "missing_taint",
        "other_target",
    ],
)
def test_first_write_known_model_unknown_classification_only(invalid):
    memory = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="memory", target="key", memory_namespace="notes"
        )
    )
    original = action()
    normalized = normalize_arguments(
        {"key": "key", "value": "model generated value"}
    ).canonical
    tool = original.resources[0].model_copy(
        update={
            "tool_name": "agentguard_memory_write",
            "canonical_id": product_tool_resource_identity(
                "agentguard_memory_write", DESCRIPTOR, SEMANTICS
            ),
        }
    )
    ir = original.model_copy(
        update={
            "action_type": "memory_write",
            "tool_name": "agentguard_memory_write",
            "canonical_arguments": normalized,
            "argument_digest": normalized.argument_digest,
            "resources": [tool, memory],
        }
    )
    bindings = tuple(
        binding.model_copy(
            update={
                "sink_role": (
                    "content" if binding.argument_pointer == "/value" else "selector"
                ),
                "resource_ref": memory.canonical_id,
            }
        )
        for binding in proof(ir, memory_refs=(memory.canonical_id,)).bindings
    )
    value = proof(
        ir,
        memory_refs=(memory.canonical_id,),
        first_write_memory_ref=memory.canonical_id,
        bindings=bindings,
    )
    assert value.matches_action(ir)
    fact = make_memory(
        memory.canonical_id,
        change_status="proposed",
        trust_state="unknown",
        taints=[],
        source_refs=[MODEL, USER, f"action:{ir.action_id}"],
    )
    if invalid is not None:
        field, replacement = {
            "historical": ("change_status", "committed"),
            "existing_change": ("change_id", "old-change"),
            "missing_source": ("source_refs", [MODEL]),
            "missing_taint": ("taints", ["UNTRUSTED"]),
            "other_target": ("memory_id", "memory://notes/other"),
        }[invalid]
        fact = fact.model_copy(update={field: replacement})
    current = state().model_copy(update={"memory_index": [fact]})
    ctx = make_ctx(required=["memory"], stable_refs=(MODEL, USER)).model_copy(
        update={"product_data": value}
    )
    before = fact.model_dump()
    assert memory_coverage(current, ctx).status == (
        "complete" if invalid is None else "partial"
    )
    assert fact.model_dump() == before
    assert fact.trust_state == "unknown"


def test_transitive_source_does_not_need_to_be_repeated_in_direct_memory_refs():
    # The complete closure includes an ancestor, while the current event has
    # exactly its direct visible set. The producer's fact must use the latter.
    ancestor = "source:user:ancestor"
    value = proof(source_refs=(MODEL, USER, ancestor))
    current = state().model_copy(
        update={
            "source_index": [
                *state().source_index,
                make_source_fact(source_id=ancestor).model_copy(
                    update={"scope_digest": SCOPE, "taints": []}
                ),
            ]
        }
    )
    assert source_coverage(current, context(value)).status == "complete"
    assert value.direct_source_refs == tuple(sorted((MODEL, USER)))


@pytest.mark.parametrize(
    "runtime,release",
    [("langgraph", "strong_binding"), ("openclaw", "restricted_allow_once")],
)
@pytest.mark.parametrize(
    "taint", [None, "UNTRUSTED", "CREDENTIAL", "PERSISTENT_UNTRUSTED"]
)
def test_complete_ask_preserves_runtime_release_and_rejects_unsafe_closure(
    runtime, release, taint
):
    unsafe = taint not in {None, "UNTRUSTED"}
    fixture = build_test_product_activation(
        now=datetime(2026, 9, 1, tzinfo=timezone.utc), policy_digest=POLICY_DIGEST
    )
    entry = fixture.bundle.runtime_entry(runtime)
    assessment = _assessment("ask")
    # bindings have their own action anchor; construct an exact updated proof.
    value = proof(
        event_id=assessment.event_id,
        action_id=assessment.action_id,
        runtime=runtime,
        runtime_binding_id=entry.runtime_binding_id,
        taints=(taint,) if taint else (),
        bindings=tuple(
            binding.model_copy(update={"action_id": assessment.action_id})
            for binding in proof().bindings
        ),
    )
    result, directive = select_product_v21_authority(
        event_id=assessment.event_id,
        current_decision=_decision("allow"),
        raw_v21_decision=_decision("ask"),
        assessment=assessment,
        coverage=_coverage(),
        activation=fixture.bundle,
        runtime_entry=entry,
        eligibility=_eligibility(),
        snapshot_id="snapshot",
        state_version=1,
        scope_digest=SCOPE,
        event_type="tool_call_proposed",
        residual_boundaries=entry.residual_boundaries,
        product_data=value,
    )
    assert result.authority.source == "v21"
    assert directive.mode == ("forbidden" if unsafe else release)
    assert directive.residual_boundaries == (
        list(entry.residual_boundaries) if not unsafe and runtime == "openclaw" else []
    )
