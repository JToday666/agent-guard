"""Synthetic parent policies with real signed ACK issuance/receipt ingestion.

These are server evidence contracts, not real model or candidate qualification.
No Provider is called and the Memory store is deliberately a test fixture.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from agentguard_core import AuditEvent, GuardEvent, RuntimeOutcomeReceipt
from agentguard_core.actions.canonical_json import canonical_sha256, canonical_json
from agentguard_core.actions.product_tools import (
    bind_verified_product_tool,
    product_command_script_digest,
)
from guard_api.security_state.transient import (
    TransientSecurityFacts,
    compute_bundle_digest,
    compute_overlay_digest,
)
from guard_api.services.ct_projection import (
    CtProjectionService,
    ct_transient_facts_envelope,
)
from guard_api.services.product_model_content import (
    ProductModelContentUnavailable,
    build_product_model_content,
    verify_product_model_content,
)
from tests.test_product_activation_ack_receipt import _rig
from tests.test_v21_security_state_models import make_source_fact
from tests.test_v21_05_provenance import make_flow

pytestmark = pytest.mark.integration


def _ct(event_id, scope, sources, flows):
    bundle = TransientSecurityFacts(
        event_id=event_id,
        scope_digest=scope,
        source_facts=tuple(sources),
        flow_facts=tuple(flows),
    )
    bundle = bundle.model_copy(
        update={
            "bundle_digest": compute_bundle_digest(bundle),
            "overlay_digest": compute_overlay_digest(bundle),
        }
    )
    payload = CtProjectionService.commit_envelope(
        None,
        bundle,
        source_record_id=f"ct-facts:{event_id}",
        projection_id=f"projection:{event_id}",
        base_state_version=0,
        projection_eligible=True,
    )
    return ct_transient_facts_envelope(payload)["ct_transient_facts"]


def _fixture(
    tmp_path,
    *,
    memory=False,
    memory_read=False,
    sensitive=False,
    model_taints=("UNTRUSTED",),
    runtime="langgraph",
    message=False,
):
    harness, original, receipt_payload, service = _rig(tmp_path, runtime=runtime)
    phase = harness.pipeline.prepare_phase_a(
        harness.event(event_id="snapshot"), auth_context=harness.auth_context
    )
    assert phase is not None and phase.snapshot is not None
    snapshot = phase.snapshot
    user = make_source_fact(
        source_id="source:user:input",
        scope_digest=snapshot.scope.scope_digest,
        source_type="user",
        trust="trusted",
        authority="authoritative",
        taints=["SENSITIVE", "CREDENTIAL"] if sensitive else [],
        producer="model-content-fixture",
    )
    model = make_source_fact(
        source_id="source:model:output",
        scope_digest=snapshot.scope.scope_digest,
        source_type="model",
        trust="unknown",
        authority="model_judgment",
        taints=list(model_taints),
        producer="model-content-fixture",
    )
    input_flow = make_flow(
        "input-flow",
        user.source_id,
        "model_input:input",
        taints=[],
        relation="assembled_into",
    ).model_copy(update={"scope_digest": snapshot.scope.scope_digest})
    output_flow = make_flow(
        "output-flow",
        user.source_id,
        "model_output:output",
        taints=[],
        strength="possible",
        relation="influenced_by",
    ).model_copy(
        update={
            "scope_digest": snapshot.scope.scope_digest,
            "origin": "semantic_inferred",
        }
    )
    snapshot = snapshot.model_copy(
        update={
            "sources": (user, model),
            "flows": (input_flow, output_flow),
            "memory_facts": (),
            "dirty_domains": (),
        }
    )

    def parent(event_id, event_type, sources, flows):
        data = original.model_dump(mode="json")
        data.pop("integrity", None)
        data["audit_id"] = f"audit:{event_id}"
        data["event_type"] = event_type
        task = snapshot.task
        data["metadata"]["product_model_task"] = {
            "task_id": task.task_id,
            "task_revision": task.revision,
            "task_digest": task.task_digest,
            "scope_digest": task.scope_digest,
        }
        data["links"].update(event_id=event_id, action_id=f"action:{event_id}")
        authority = data["evidence"]["decision_authority"]["payload"]
        authority["event_id"] = event_id
        authority["event_type"] = event_type
        data["evidence"]["ct_transient_facts"] = _ct(
            event_id, snapshot.scope.scope_digest, sources, flows
        )
        return AuditEvent.model_validate(data)

    input_parent = parent("input", "model_input_prepared", [user], [input_flow])
    assert harness.store.add_audit_event(input_parent)
    output_parent = parent("output", "model_output_produced", [model], [output_flow])
    name = (
        "agentguard_memory_read"
        if memory_read
        else ("agentguard_memory_write" if memory else "write")
    )
    arguments = (
        {"key": "note", "value": "complete synthetic model content " + "x" * 3000}
        if memory
        else {
            "path": "report.txt",
            "content": "complete synthetic model content " + "x" * 3000,
        }
    )
    if memory_read:
        arguments = {"key": "note"}
    if message:
        name = "message"
        arguments = {
            "action": "send",
            "channel": "agentguard-fixture",
            "target": "fixture-inbox",
            "message": "complete synthetic message",
        }
    event = harness.event(event_id="action", call_id="call:generated").model_dump(
        mode="json"
    )
    event["security_context"].update(
        source_type="model",
        source_trust="unknown",
        visible_source_refs=[model.source_id, user.source_id],
    )
    event["metadata"]["product_model_content"] = {
        "model_output_audit_id": output_parent.audit_id,
        "model_source_ref": model.source_id,
        "call_id": "call:generated",
    }
    execution = {
        "root": str(tmp_path),
        "memory_namespace": str(tmp_path) + "/memory.sqlite",
        "inbox_url": "http://127.0.0.1:18431/inbox",
        "script_digest": product_command_script_digest(runtime),
    }
    if message:
        event["event_type"] = "message_send_proposed"
        event["metadata"]["product_tool_call"] = {
            "tool_name": name,
            "call_id": "call:generated",
        }
        event["payload"] = {
            "channel": arguments["channel"],
            "recipient": arguments["target"],
            "content_preview": arguments["message"],
            "contains_sensitive_data": False,
            "sanitized": False,
            "derived_resources": [],
        }
    elif memory:
        event["event_type"] = "memory_write_proposed"
        event["metadata"]["product_tool_call"] = {
            "tool_name": name,
            "call_id": "call:generated",
        }
        event["payload"] = {
            "action_id": "call:generated",
            "operation": "write",
            "will_persist": True,
            "requires_approval": False,
            "memory": {
                "key": "note",
                "source_trust": "unknown",
                "operation": "write",
                "namespace": execution["memory_namespace"],
                "value_preview": arguments["value"],
            },
            "destination_kind": "long_term_memory",
            "source_contains_untrusted": True,
            "instructional_content_detected": False,
            "derived_from_memory": False,
        }
    else:
        event["payload"] = {
            "tool": {"name": name, "call_id": "call:generated"},
            "arguments": arguments,
            "derived_resources": [],
        }
    event = GuardEvent.model_validate(event)
    tool = bind_verified_product_tool(
        event,
        runtime_binding_id=snapshot.scope.runtime_binding_id,
        inventory_digest=canonical_sha256("synthetic-inventory"),
        descriptor={"tool_id": name, "input_schema": {"type": "object"}},
        execution=execution,
    )
    catalog = SimpleNamespace(
        describe_tool=lambda *args, **kwargs: {
            "descriptor_digest": tool.descriptor_digest,
            "input_schema_digest": tool.input_schema_digest,
            "inventory_digest": tool.inventory_digest,
            "semantics_digest": tool.semantics_digest,
        }
    )
    projection = {
        "content": "bounded complete synthetic answer",
        "tool_calls": [
            {
                "name": name,
                "id": "call:generated",
                "args": arguments,
                "type": "tool_call",
            }
        ],
        "invalid_tool_calls": [],
    }
    output_event = harness.event(event_id="output").model_dump(mode="json")
    output_event.update(event_type="model_output_produced", pre_execution=False)
    output_event["metadata"]["product_model_input_audit_id"] = input_parent.audit_id
    output_event["security_context"].update(visible_source_refs=[user.source_id])
    output_event["payload"] = {
        "provider": "deterministic-test",
        "model": "synthetic",
        "phase": "output",
        "contains_instruction_like_text": False,
        "contains_sensitive_data": False,
        "sanitized": False,
        "content_preview": canonical_json(projection),
        "source_contains_untrusted": False,
        "instructional_content_detected": False,
    }
    output_event = GuardEvent.model_validate(output_event)
    commitment = build_product_model_content(
        harness.store,
        output_event,
        snapshot=snapshot,
        catalog=catalog,
        activation=harness.fixture.bundle,
        decision_authority_evidence={
            "decision_authority": output_parent.evidence["decision_authority"]
        },
    )
    assert commitment is not None
    output_parent = output_parent.model_copy(
        update={
            "evidence": {
                **output_parent.evidence,
                "product_model_content": commitment.model_dump(mode="json"),
            }
        }
    )
    assert harness.store.add_audit_event(output_parent)

    for record in (input_parent, output_parent):
        wire = copy.deepcopy(receipt_payload)
        if runtime == "openclaw":
            wire["evidence"]["execution"]["invoked_at"] = None
        wire["evidence"]["result"]["disposition"] = "passed_through"
        wire["audit_id"] = (
            f"audit_outcome_{record.links['event_id']}_execution_completed"
        )
        wire["links"] = {**record.links, "policy_audit_id": record.audit_id}
        # Audit policy includes optional links not in the frozen receipt schema.
        wire["links"] = {
            key: value
            for key, value in wire["links"].items()
            if key
            in {
                "event_id",
                "policy_audit_id",
                "decision_id",
                "action_id",
                "approval_id",
            }
            and value is not None
        }
        service.submit(
            RuntimeOutcomeReceipt.model_validate(wire),
            auth_context=harness.auth_context,
        )
    return SimpleNamespace(
        harness=harness,
        snapshot=snapshot,
        event=event,
        tool=tool,
        input=input_parent,
        output=output_parent,
        output_event=output_event,
        commitment=commitment,
        catalog=catalog,
        parent_builder=parent,
        receipt_wire=receipt_payload,
        service=service,
        model=model,
        user=user,
    )


def test_complete_content_proof_uses_original_signed_receipts_and_no_plaintext(
    tmp_path,
):
    rig = _fixture(tmp_path)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    assert proof.model_source_ref == rig.model.source_id
    assert proof.direct_source_refs == tuple(
        sorted((rig.user.source_id, rig.model.source_id))
    )
    assert set(proof.artifact_refs) >= {"model_output:output"}
    assert any(ref.startswith("file://") for ref in proof.artifact_refs)
    assert "complete synthetic model content" not in rig.output.model_dump_json()
    assert rig.harness.activation_ack_token not in proof.model_dump_json()
    assert rig.model.trust == "unknown" and "UNTRUSTED" in proof.taints


@pytest.mark.parametrize("parent", ["input", "output"])
@pytest.mark.parametrize(
    "field", ["missing", "stamp", "claims", "parent", "disposition"]
)
def test_missing_or_corrupt_original_receipt_rejects(tmp_path, parent, field):
    rig = _fixture(tmp_path)
    receipt_id = f"audit_outcome_{parent}_execution_completed"
    store = rig.harness.store
    receipt = store.audit_events_by_id[receipt_id]
    if field == "missing":
        del store.audit_events_by_id[receipt_id]
    else:
        data = receipt.model_dump(mode="json")
        if field == "stamp":
            data["metadata"].pop("product_ack_validation")
        if field == "claims":
            data["metadata"]["activation_ack"]["runtime_binding_id"] = "forged"
        if field == "parent":
            data["metadata"]["product_ack_validation"]["parent_authority_digest"] = (
                canonical_sha256("forged")
            )
        if field == "disposition":
            data["evidence"]["result"]["disposition"] = "quarantined"
        store.audit_events_by_id[receipt_id] = AuditEvent.model_validate(data)
    with pytest.raises(
        ProductModelContentUnavailable, match="^V21_PRODUCT_MODEL_CONTENT_UNAVAILABLE$"
    ):
        verify_product_model_content(store, rig.event, rig.snapshot, rig.tool)


@pytest.mark.parametrize(
    "change",
    ["arguments", "visible", "trusted", "unknown_producer", "unknown_artifact"],
)
def test_data_or_provenance_drift_cannot_become_complete(tmp_path, change):
    rig = _fixture(tmp_path)
    event = rig.event.model_copy(deep=True)
    snapshot = rig.snapshot
    if change == "arguments":
        event.payload.arguments["content"] += "tampered"
    if change == "visible":
        event.security_context.visible_source_refs = (rig.model.source_id,)
    if change == "trusted":
        event.security_context.source_trust = "trusted"
    if change == "unknown_producer":
        snapshot = snapshot.model_copy(
            update={
                "sources": (
                    rig.user,
                    rig.model.model_copy(update={"producer": "unknown"}),
                )
            }
        )
    if change == "unknown_artifact":
        flow = make_flow(
            "fake", "action:invented", "model_output:output", taints=[]
        ).model_copy(update={"scope_digest": snapshot.scope.scope_digest})
        snapshot = snapshot.model_copy(update={"flows": (*snapshot.flows, flow)})
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(rig.harness.store, event, snapshot, rig.tool)


@pytest.mark.parametrize(
    "change", ["duplicate", "truncated", "oversize", "missing_input"]
)
def test_output_commitment_requires_original_complete_canonical_content(
    tmp_path, change
):
    rig = _fixture(tmp_path)
    event = rig.output_event.model_copy(deep=True)
    if change == "duplicate":
        event.payload.content_preview = (
            '{"content":"x",' + event.payload.content_preview[1:]
        )
    if change == "truncated":
        event.payload.content_preview = event.payload.content_preview[:2000]
    if change == "oversize":
        event.payload.content_preview = "x" * (64 * 1024 + 1)
    if change == "missing_input":
        event.metadata.pop("product_model_input_audit_id")
    with pytest.raises(ProductModelContentUnavailable):
        build_product_model_content(
            rig.harness.store,
            event,
            snapshot=rig.snapshot,
            catalog=rig.catalog,
            activation=rig.harness.fixture.bundle,
            decision_authority_evidence={
                "decision_authority": rig.output.evidence["decision_authority"]
            },
        )


def test_first_write_cannot_overwrite_any_existing_memory_fact(tmp_path):
    from tests.test_v21_05_provenance import make_memory

    rig = _fixture(tmp_path, memory=True)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    assert proof.first_write_memory_ref is not None
    value_binding = next(
        item for item in proof.bindings if item.argument_pointer == "/value"
    )
    assert value_binding.resource_ref == proof.first_write_memory_ref
    for status in ("committed", "rolled_back", "quarantined"):
        memory = make_memory(
            proof.first_write_memory_ref, trust_state="unknown", change_status=status
        )
        snapshot = rig.snapshot.model_copy(update={"memory_facts": (memory,)})
        with pytest.raises(ProductModelContentUnavailable):
            verify_product_model_content(
                rig.harness.store, rig.event, snapshot, rig.tool
            )


def test_accepted_historical_receipts_do_not_need_a_fresh_ack(tmp_path):
    from datetime import datetime, timedelta

    rig = _fixture(tmp_path)
    from guard_api.runtime_status import activation_ack_token_digest

    issuance = rig.harness.store.get_product_activation_ack(
        activation_ack_token_digest(rig.harness.activation_ack_token)
    )
    rig.harness.store.revoke_product_activation_acks(
        issuance.identity(),
        revoked_at=(
            datetime.fromisoformat(rig.output.timestamp) + timedelta(days=1)
        ).isoformat(),
    )
    assert verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    ).closure_complete


def test_complete_ct_cycle_cannot_declare_an_invented_artifact(tmp_path):
    rig = _fixture(tmp_path)
    fake = make_flow(
        "invented", "action:invented", "model_output:output", taints=[]
    ).model_copy(update={"scope_digest": rig.snapshot.scope.scope_digest})
    cycle = make_flow(
        "cycle", "context:invented", "action:invented", taints=[]
    ).model_copy(update={"scope_digest": rig.snapshot.scope.scope_digest})
    cycle2 = make_flow(
        "cycle2", "action:invented", "context:invented", taints=[]
    ).model_copy(update={"scope_digest": rig.snapshot.scope.scope_digest})
    flows = (*rig.snapshot.flows[1:], fake, cycle, cycle2)
    updated = rig.output.model_copy(
        update={
            "evidence": {
                **rig.output.evidence,
                "ct_transient_facts": _ct(
                    "output", rig.snapshot.scope.scope_digest, [rig.model], flows
                ),
            }
        }
    )
    store = rig.harness.store
    store.audit_events_by_id[updated.audit_id] = updated
    store.audit_events[:] = [
        updated if record.audit_id == updated.audit_id else record
        for record in store.audit_events
    ]
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(
            store,
            rig.event,
            rig.snapshot.model_copy(
                update={"flows": (*rig.snapshot.flows, fake, cycle, cycle2)}
            ),
            rig.tool,
        )


def test_writer_rejects_same_action_substituted_proof_before_persistence(tmp_path):
    from agentguard_core import PolicyBundle
    from agentguard_core.actions import canonical_action_id
    from guard_api.services.evidence import build_audit_event
    from guard_api.services.product_model_content import (
        _authority,
        read_product_action_data,
    )
    from guard_api.services.redaction import sanitize_audit_event
    from agentguard_core.security_context.product_data import VerifiedProductData

    rig = _fixture(tmp_path)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    raw = rig.output.model_dump(mode="json")
    raw["event_type"] = rig.event.event_type
    raw["links"].update(
        event_id=rig.event.event_id, action_id=canonical_action_id(rig.event)
    )
    raw["evidence"]["decision_authority"]["payload"].update(
        event_id=rig.event.event_id, event_type=rig.event.event_type
    )
    parent = AuditEvent.model_validate(raw)
    authority = _authority(parent, rig.event.event_type)
    envelope = copy.deepcopy(parent.evidence["decision_v21"])
    envelope["payload"]["evidence_refs"] = [
        {
            "kind": "guard_event",
            "record_type": "product_action_data",
            "record_id": proof.event_id,
            "json_pointer": "/evidence/product_action_data",
            "digest": proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    kwargs = dict(
        policy_bundle=PolicyBundle(),
        policy_revision=1,
        v21_evidence={"decision_v21": envelope},
        decision_authority_evidence={
            "decision_authority": parent.evidence["decision_authority"]
        },
        decision_authority=authority.decision_authority,
    )
    built = build_audit_event(
        rig.event,
        authority.selected_decision,
        product_action_data=proof.model_dump(mode="json"),
        **kwargs,
    )
    assert (
        read_product_action_data(sanitize_audit_event(built)).proof_digest
        == proof.proof_digest
    )
    other = proof.model_dump(mode="json", exclude={"proof_digest"})
    other["content_evidence_digest"] = canonical_sha256("another valid closure")
    replacement = VerifiedProductData.model_validate(other)
    with pytest.raises(ProductModelContentUnavailable):
        build_audit_event(
            rig.event,
            authority.selected_decision,
            product_action_data=replacement.model_dump(mode="json"),
            **kwargs,
        )


def test_sensitive_ancestor_taint_is_retained_without_trusting_the_model(tmp_path):
    rig = _fixture(tmp_path, sensitive=True)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    assert {"SENSITIVE", "CREDENTIAL", "UNTRUSTED"} <= set(proof.taints)
    assert not proof.reviewable
    assert rig.model.trust == "unknown"


@pytest.mark.parametrize(
    "condition", ["missing", "committed", "unknown_source", "rolled_back"]
)
def test_current_memory_read_includes_value_sources_and_taints(tmp_path, condition):
    from agentguard_core.actions.canonical_resources import (
        normalize_memory_resource,
        ResourceNormalizationInput,
    )
    from tests.test_v21_05_provenance import make_memory

    rig = _fixture(tmp_path, memory_read=True)
    resource = rig.tool.resource_inputs()[0]
    target = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="memory",
            target=resource["target"],
            memory_namespace=resource["memory_namespace"],
        )
    ).canonical_id
    memory = make_memory(
        target,
        change_id="memory:accepted",
        trust_state="tainted",
        change_status="rolled_back" if condition == "rolled_back" else "committed",
        source_refs=(
            ["source:invented"]
            if condition == "unknown_source"
            else [rig.user.source_id]
        ),
        taints=["SENSITIVE"],
    )
    snapshot = rig.snapshot.model_copy(
        update={"memory_facts": () if condition == "missing" else (memory,)}
    )
    if condition == "committed":
        proof = verify_product_model_content(
            rig.harness.store, rig.event, snapshot, rig.tool
        )
        assert target in proof.memory_refs and "SENSITIVE" in proof.taints
    else:
        with pytest.raises(ProductModelContentUnavailable):
            verify_product_model_content(
                rig.harness.store, rig.event, snapshot, rig.tool
            )


def _with_prior_model(rig):
    from guard_api.services.product_model_content import (
        ModelContentCommitment,
        _authority,
    )

    store = rig.harness.store
    scope = rig.snapshot.scope.scope_digest
    prior_user = rig.user.model_copy(
        update={"source_id": "source:user:prior", "taints": ["SENSITIVE"]}
    )
    prior_model = rig.model.model_copy(
        update={"source_id": "source:model:prior-output"}
    )
    input_flow = make_flow(
        "prior-input-flow",
        prior_user.source_id,
        "model_input:prior-input",
        taints=["SENSITIVE"],
        relation="assembled_into",
    ).model_copy(update={"scope_digest": scope})
    output_flow = make_flow(
        "prior-output-flow",
        prior_user.source_id,
        "model_output:prior-output",
        taints=["SENSITIVE"],
        strength="possible",
        relation="influenced_by",
    ).model_copy(update={"scope_digest": scope, "origin": "semantic_inferred"})
    inp = rig.parent_builder(
        "prior-input", "model_input_prepared", [prior_user], [input_flow]
    )
    out = rig.parent_builder(
        "prior-output", "model_output_produced", [prior_model], [output_flow]
    )
    commitment = rig.commitment.model_dump(mode="json", exclude={"commitment_digest"})
    commitment.update(
        model_input_event_id="prior-input",
        model_input_audit_id=inp.audit_id,
        model_output_event_id="prior-output",
        model_output_authority_digest=canonical_sha256(
            _authority(out, "model_output_produced").model_dump(mode="json")
        ),
        visible_source_refs=[prior_user.source_id],
    )
    out = out.model_copy(
        update={
            "evidence": {
                **out.evidence,
                "product_model_content": ModelContentCommitment.model_validate(
                    commitment
                ).model_dump(mode="json"),
            }
        }
    )
    for parent in (inp, out):
        assert store.add_audit_event(parent)
        wire = copy.deepcopy(rig.receipt_wire)
        wire["audit_id"] = (
            f"audit_outcome_{parent.links['event_id']}_execution_completed"
        )
        wire["links"] = {
            key: value
            for key, value in {
                **parent.links,
                "policy_audit_id": parent.audit_id,
            }.items()
            if key
            in {
                "event_id",
                "policy_audit_id",
                "decision_id",
                "action_id",
                "approval_id",
            }
            and value is not None
        }
        wire["evidence"]["result"]["disposition"] = "passed_through"
        rig.service.submit(
            RuntimeOutcomeReceipt.model_validate(wire),
            auth_context=rig.harness.auth_context,
        )
    bridge = make_flow(
        "prior-control", prior_model.source_id, rig.user.source_id, taints=["UNTRUSTED"]
    ).model_copy(update={"scope_digest": scope})
    current = rig.input.model_copy(
        update={
            "evidence": {
                **rig.input.evidence,
                "ct_transient_facts": _ct(
                    "input", scope, [rig.user], [rig.snapshot.flows[0], bridge]
                ),
            }
        }
    )
    store.audit_events_by_id[current.audit_id] = current
    store.audit_events[:] = [
        current if item.audit_id == current.audit_id else item
        for item in store.audit_events
    ]
    return rig.snapshot.model_copy(
        update={
            "sources": (*rig.snapshot.sources, prior_user, prior_model),
            "flows": (*rig.snapshot.flows, input_flow, output_flow, bridge),
        }
    )


@pytest.mark.parametrize(
    "condition",
    ["valid", "missing_input_receipt", "missing_output_receipt", "false_commitment"],
)
def test_prior_model_source_needs_its_own_complete_accepted_chain(tmp_path, condition):
    rig = _fixture(tmp_path)
    snapshot = _with_prior_model(rig)
    store = rig.harness.store
    if condition.startswith("missing_"):
        parent = "prior-input" if "input" in condition else "prior-output"
        del store.audit_events_by_id[f"audit_outcome_{parent}_execution_completed"]
    if condition == "false_commitment":
        parent = store.audit_events_by_id["audit:prior-output"].model_copy(deep=True)
        parent.evidence["product_model_content"]["original_arguments_digest"] = (
            canonical_sha256("false")
        )
        store.audit_events_by_id[parent.audit_id] = parent
        store.audit_events[:] = [
            parent if item.audit_id == parent.audit_id else item
            for item in store.audit_events
        ]
    if condition == "valid":
        proof = verify_product_model_content(store, rig.event, snapshot, rig.tool)
        assert "source:model:prior-output" in proof.source_refs
        assert "model_output:prior-output" in proof.artifact_refs
        assert "SENSITIVE" in proof.taints
    else:
        with pytest.raises(ProductModelContentUnavailable):
            verify_product_model_content(store, rig.event, snapshot, rig.tool)


def test_cycle_between_known_committed_sources_is_rejected(tmp_path):
    rig = _fixture(tmp_path)
    snapshot = _with_prior_model(rig)
    store = rig.harness.store
    prior_user = next(
        source for source in snapshot.sources if source.source_id == "source:user:prior"
    )
    cycle = make_flow(
        "known-cycle", rig.user.source_id, prior_user.source_id, taints=[]
    ).model_copy(update={"scope_digest": snapshot.scope.scope_digest})
    parent = store.audit_events_by_id["audit:prior-input"]
    prior_flow = next(
        flow for flow in snapshot.flows if flow.flow_id == "prior-input-flow"
    )
    parent = parent.model_copy(
        update={
            "evidence": {
                **parent.evidence,
                "ct_transient_facts": _ct(
                    "prior-input",
                    snapshot.scope.scope_digest,
                    [prior_user],
                    [prior_flow, cycle],
                ),
            }
        }
    )
    store.audit_events_by_id[parent.audit_id] = parent
    store.audit_events[:] = [
        parent if record.audit_id == parent.audit_id else record
        for record in store.audit_events
    ]
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_model_content(
            store,
            rig.event,
            snapshot.model_copy(update={"flows": (*snapshot.flows, cycle)}),
            rig.tool,
        )


@pytest.mark.parametrize("value", ["deny", "ask"])
def test_retained_current_floor_keeps_hash_proof_without_model_qualification(
    tmp_path, value
):
    from agentguard_core import GuardDecision, PolicyBundle
    from agentguard_core.decisions.product import ProductDecisionAuthorityEvidenceV1
    from guard_api.services.evidence import build_audit_event
    from guard_api.services.product_model_content import (
        _authority,
        read_product_action_data,
    )
    from guard_api.services.redaction import sanitize_audit_event

    rig = _fixture(tmp_path)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    payload = copy.deepcopy(rig.output.evidence["decision_authority"]["payload"])
    decision = GuardDecision.model_validate(
        {**payload["selected_decision"], "decision": value, "approval_intent": None}
    )
    payload.update(
        event_id=rig.event.event_id,
        event_type=rig.event.event_type,
        current_decision=decision.model_dump(mode="json"),
        current_decision_digest=canonical_sha256(decision.model_dump(mode="json")),
        selected_decision=decision.model_dump(mode="json"),
        selected_decision_digest=canonical_sha256(decision.model_dump(mode="json")),
    )
    payload["decision_authority"]["legacy_floor_applied"] = True
    authority = ProductDecisionAuthorityEvidenceV1.model_validate(payload)
    envelope = copy.deepcopy(rig.output.evidence["decision_v21"])
    envelope["payload"]["evidence_refs"] = [
        {
            "kind": "guard_event",
            "record_type": "product_action_data",
            "record_id": proof.event_id,
            "json_pointer": "/evidence/product_action_data",
            "digest": proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    built = build_audit_event(
        rig.event,
        decision,
        policy_bundle=PolicyBundle(),
        policy_revision=1,
        v21_evidence={"decision_v21": envelope},
        decision_authority_evidence={
            "decision_authority": {
                "schema_version": "2.0",
                "payload": authority.model_dump(mode="json"),
            }
        },
        decision_authority=authority.decision_authority,
        product_action_data=proof.model_dump(mode="json"),
    )
    assert (
        read_product_action_data(sanitize_audit_event(built)).proof_digest
        == proof.proof_digest
    )
    assert built.decision == value
    with pytest.raises(ProductModelContentUnavailable):
        _authority(built, rig.event.event_type, require_allow=False)


@pytest.mark.parametrize("condition", ["sensitive", "missing", "rolled_back"])
def test_memory_source_identity_does_not_hide_the_same_memory_fact(tmp_path, condition):
    from agentguard_core.actions.canonical_resources import (
        normalize_memory_resource,
        ResourceNormalizationInput,
    )
    from tests.test_v21_05_provenance import make_memory

    rig = _fixture(tmp_path, memory_read=True)
    resource = rig.tool.resource_inputs()[0]
    target = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="memory",
            target=resource["target"],
            memory_namespace=resource["memory_namespace"],
        )
    ).canonical_id
    memory_source = make_source_fact(
        source_id=target,
        source_type="memory",
        trust="untrusted",
        scope_digest=rig.snapshot.scope.scope_digest,
        taints=[],
    )
    parent = rig.input.model_copy(
        update={
            "evidence": {
                **rig.input.evidence,
                "ct_transient_facts": _ct(
                    "input",
                    rig.snapshot.scope.scope_digest,
                    [rig.user, memory_source],
                    [rig.snapshot.flows[0]],
                ),
            }
        }
    )
    store = rig.harness.store
    store.audit_events_by_id[parent.audit_id] = parent
    store.audit_events[:] = [
        parent if record.audit_id == parent.audit_id else record
        for record in store.audit_events
    ]
    memory = make_memory(
        target,
        change_id="committed-value",
        change_status="rolled_back" if condition == "rolled_back" else "committed",
        taints=["SENSITIVE"],
        source_refs=[rig.user.source_id],
    )
    snapshot = rig.snapshot.model_copy(
        update={
            "sources": (*rig.snapshot.sources, memory_source),
            "memory_facts": () if condition == "missing" else (memory,),
        }
    )
    if condition == "sensitive":
        proof = verify_product_model_content(store, rig.event, snapshot, rig.tool)
        assert target in proof.memory_refs and target in proof.source_refs
        assert "SENSITIVE" in proof.taints
    else:
        with pytest.raises(ProductModelContentUnavailable):
            verify_product_model_content(store, rig.event, snapshot, rig.tool)
