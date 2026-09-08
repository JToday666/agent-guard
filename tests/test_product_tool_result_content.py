"""Server result proof contracts with synthetic policies and real signed ACK ingestion.

No Provider, Host execution, message dispatch or Product qualification is claimed.
"""

from copy import deepcopy

import pytest

from agentguard_core import GuardEvent, RuntimeOutcomeReceipt
from agentguard_core.actions import build_action_ir, canonical_action_id
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.security_state.fact_authority import ProducerIdentity
from guard_api.security_state.fact_builder import FactBuildInputs, build_transient_facts
from guard_api.security_state.transient import (
    PRODUCT_RESULT_FACT_BUILDER_VERSION,
    fact_builder_version_for_bundle,
)
from guard_api.services.product_model_content import (
    ProductModelContentUnavailable,
    _authority,
    _receipt,
    verify_product_model_content,
    verify_product_tool_result,
)
from tests.test_product_model_content import _fixture
from tests.test_restricted_product_receipt_api import restricted_rig  # noqa: F401
from tests.test_restricted_product_memory_receipt import _completed

pytestmark = pytest.mark.integration


def result_fixture(tmp_path, *, runtime="openclaw", message=False):
    rig = _fixture(tmp_path, runtime=runtime, message=message)
    proof = verify_product_model_content(
        rig.harness.store, rig.event, rig.snapshot, rig.tool
    )
    parent = rig.parent_builder(rig.event.event_id, rig.event.event_type, [], [])
    parent.links["action_id"] = canonical_action_id(rig.event)
    parent.evidence["guard_event"]["tool"] = {
        "name": rig.tool.tool_name,
        "call_id": rig.tool.call_id,
    }
    parent.metadata.update(
        action_name=rig.tool.tool_name,
        tool=rig.tool.tool_name,
        subject_id=canonical_action_id(rig.event),
    )
    parent.evidence["product_action_data"] = proof.model_dump(mode="json")
    parent.evidence["decision_v21"]["payload"]["evidence_refs"] = [
        {
            "kind": "guard_event",
            "record_type": "product_action_data",
            "record_id": proof.event_id,
            "json_pointer": "/evidence/product_action_data",
            "digest": proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    assert rig.harness.store.add_audit_event(parent)
    wire = deepcopy(rig.receipt_wire)
    wire["audit_id"] = f"audit_outcome_{rig.event.event_id}_execution_completed"
    wire["links"] = {
        key: value
        for key, value in parent.links.items()
        if key in {"event_id", "action_id", "decision_id", "approval_id"}
        and value is not None
    }
    wire["links"]["policy_audit_id"] = parent.audit_id
    wire["evidence"]["result"]["disposition"] = "passed_through"
    if runtime == "openclaw":
        wire["evidence"]["execution"]["invoked_at"] = None
    rig.service.submit(
        RuntimeOutcomeReceipt.model_validate(wire),
        auth_context=rig.harness.auth_context,
    )
    raw = rig.event.model_dump(mode="json")
    raw.update(
        event_id="result-event", event_type="tool_result_produced", pre_execution=False
    )
    raw["security_context"].update(
        source_type="tool_result",
        source_trust="untrusted",
        user_task=parent.evidence["guard_event"]["user_task"],
    )
    raw["metadata"] = {
        "task_id": rig.snapshot.task.task_id,
        "product_tool_result": {
            "action_event_id": rig.event.event_id,
            "action_policy_audit_id": parent.audit_id,
        },
    }
    content = "Complete actual-result fixture " + "x" * 3000
    raw["payload"] = {
        "tool": {"name": rig.tool.tool_name, "call_id": rig.tool.call_id},
        "result": {
            "content_preview": content,
            "content_type": "text/plain",
            "size_bytes": len(content.encode()),
        },
        "will_enter_context": True,
        "will_persist": True,
        "sanitized": False,
        "contains_sensitive_data": False,
        "contains_instruction_like_text": False,
    }
    rig.result_event = GuardEvent.model_validate(raw)
    rig.action_parent = parent
    rig.action_wire = wire
    return rig


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("message", [False, True])
def test_result_preserves_native_call_and_proves_its_distinct_original_action(
    tmp_path, runtime, message
):
    rig = result_fixture(tmp_path, runtime=runtime, message=message)
    proof = verify_product_tool_result(
        rig.harness.store, rig.result_event, rig.snapshot
    )
    assert proof.parent_action_id == canonical_action_id(rig.event)
    assert proof.native_call_id == rig.tool.call_id
    assert (proof.parent_action_id != proof.native_call_id) is message
    action = build_action_ir(
        rig.result_event,
        server_secret=b"fixture-secret",
        runtime_binding_id=rig.snapshot.scope.runtime_binding_id,
    )
    bundle = build_transient_facts(
        event=rig.result_event,
        inputs=FactBuildInputs(
            scope_digest=rig.snapshot.scope.scope_digest,
            producer_identity=ProducerIdentity(),
            action_ir=action,
            product_result=proof,
        ),
    )
    assert (
        fact_builder_version_for_bundle(bundle) == PRODUCT_RESULT_FACT_BUILDER_VERSION
    )
    assert bundle.source_facts[0].source_id.endswith(":" + rig.tool.call_id)
    assert bundle.flow_facts[0].source_ref == "action:" + proof.parent_action_id
    assert "UNTRUSTED" in bundle.source_facts[0].taints
    assert "Complete actual-result" not in proof.model_dump_json()
    assert (
        rig.action_wire["metadata"]["activation_ack"]["ack_token"]
        not in proof.model_dump_json()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "parent",
        "event",
        "scope",
        "runtime",
        "call",
        "name",
        "trust",
        "size",
        "oversized",
        "terminal",
        "ack_stamp",
        "commitment",
        "input_receipt",
        "output_receipt",
        "task_revision",
    ],
)
def test_unproven_or_changed_product_result_is_not_an_action_alias(tmp_path, mutation):
    rig = result_fixture(tmp_path, message=True)
    event = rig.result_event.model_copy(deep=True)
    snapshot = rig.snapshot
    store = rig.harness.store
    if mutation in {"parent", "event"}:
        event.metadata["product_tool_result"][
            "action_policy_audit_id" if mutation == "parent" else "action_event_id"
        ] = "wrong"
    elif mutation == "scope":
        snapshot = snapshot.model_copy(
            update={
                "scope": snapshot.scope.model_copy(
                    update={"scope_digest": "sha256:" + "f" * 64}
                )
            }
        )
    elif mutation == "runtime":
        event.runtime = "langgraph"
    elif mutation == "call":
        event.payload.tool.call_id = "wrong"
    elif mutation == "name":
        event.payload.tool.name = "write"
    elif mutation == "trust":
        event.security_context.source_trust = "trusted"
    elif mutation == "size":
        event.payload.result.size_bytes += 1
    elif mutation == "oversized":
        event.payload.result.content_preview = "x" * (65536 + 1)
        event.payload.result.size_bytes = 65537
    elif mutation == "terminal":
        store.audit_events_by_id.pop(rig.action_wire["audit_id"])
    elif mutation == "ack_stamp":
        store.audit_events_by_id[rig.action_wire["audit_id"]].metadata[
            "product_ack_validation"
        ]["parent_authority_digest"] = canonical_sha256("bad")
    elif mutation == "commitment":
        store.audit_events_by_id[rig.output.audit_id].evidence["product_model_content"][
            "call_id"
        ] = "wrong"
    elif mutation in {"input_receipt", "output_receipt"}:
        store.audit_events_by_id.pop(
            f"audit_outcome_{mutation.removesuffix('_receipt')}_execution_completed"
        )
    elif mutation == "task_revision":
        snapshot = snapshot.model_copy(
            update={
                "task": snapshot.task.model_copy(
                    update={"revision": snapshot.task.revision + 1}
                )
            }
        )
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_tool_result(store, event, snapshot)


def test_actual_restricted_terminal_reuses_consumption_ack_after_expiry(restricted_rig):  # noqa: F811
    harness, parent, wire, service, _, result = restricted_rig
    completed = _completed(wire)
    receipt = RuntimeOutcomeReceipt.model_validate(completed)
    service.submit(receipt, auth_context=harness.auth_context)
    prepared = harness.pipeline.prepare_phase_a(
        harness.event(event_id="snapshot"), auth_context=harness.auth_context
    )
    assert prepared is not None and prepared.snapshot is not None
    authority = _authority(
        parent, parent.event_type, require_allow=False, require_unfloored=False
    )
    token_digest = activation_ack_token_digest(
        receipt.metadata.activation_ack.ack_token
    )
    issuance = harness.store.get_product_activation_ack(token_digest)
    # Later revocation does not erase the accepted historical consume window.
    harness.store.product_activation_acks_v1[token_digest] = issuance.model_copy(
        update={"revoked_at": completed["timestamp"]}
    )
    assert (
        _receipt(
            harness.store, parent, authority, prepared.snapshot, action_terminal=True
        ).audit_id
        == receipt.audit_id
    )
    stored_lease = harness.store.execution_lease_records[result.lease.lease_id]
    stored_lease.action_id = "tampered"
    with pytest.raises(Exception):
        _receipt(
            harness.store, parent, authority, prepared.snapshot, action_terminal=True
        )


def stored_result(rig, *, checkpoint=True):
    from agentguard_core import GuardDecision, PolicyBundle
    from guard_api.services.ct_projection import (
        CtProjectionService,
        ct_transient_facts_envelope,
    )
    from guard_api.services.product_model_content import read_product_tool_result

    proof = verify_product_tool_result(
        rig.harness.store, rig.result_event, rig.snapshot
    )
    action = build_action_ir(
        rig.result_event,
        server_secret=b"fixture-secret",
        runtime_binding_id=rig.snapshot.scope.runtime_binding_id,
    )
    bundle = build_transient_facts(
        event=rig.result_event,
        inputs=FactBuildInputs(
            scope_digest=rig.snapshot.scope.scope_digest,
            producer_identity=ProducerIdentity(),
            action_ir=action,
            product_result=proof,
        ),
    )
    template = rig.parent_builder(
        rig.result_event.event_id, "tool_result_produced", [], []
    )
    envelope = deepcopy(template.evidence["decision_v21"])
    envelope["payload"]["evidence_refs"] = [
        {
            "ref_id": "result-proof-ref",
            "kind": "guard_event",
            "record_type": "product_tool_result",
            "record_id": proof.event_id,
            "json_pointer": "/evidence/product_tool_result",
            "digest": proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    commit = CtProjectionService.commit_envelope(
        None,
        bundle,
        source_record_id=f"ct-facts:{proof.event_id}",
        projection_id=f"projection:{proof.event_id}",
        base_state_version=0,
        projection_eligible=True,
    )
    decision = GuardDecision.model_validate(template.evidence["guard_decision"])
    authority = _authority(template, "tool_result_produced")
    record = rig.service.record_evaluation(
        rig.result_event,
        decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        audit_id=template.audit_id,
        v21_evidence={"decision_v21": envelope},
        decision_authority=authority.decision_authority,
        decision_authority_evidence={
            "decision_authority": template.evidence["decision_authority"]
        },
        ct_facts_evidence=ct_transient_facts_envelope(commit),
        product_tool_result=proof.model_dump(mode="json"),
        extra_metadata={
            "product_model_task": template.metadata["product_model_task"],
            "policy_digest": authority.policy_digest,
            "product_authority_initial_checked_at": template.metadata[
                "product_authority_initial_checked_at"
            ],
        },
    )
    assert read_product_tool_result(record) == proof
    if checkpoint:
        wire = deepcopy(rig.receipt_wire)
        wire["audit_id"] = f"audit_outcome_{proof.event_id}_execution_completed"
        wire["links"] = {
            key: value
            for key, value in record.links.items()
            if key in {"event_id", "action_id", "decision_id", "approval_id"}
            and value is not None
        }
        wire["links"]["policy_audit_id"] = record.audit_id
        wire["evidence"]["result"]["disposition"] = "passed_through"
        if rig.result_event.runtime == "openclaw":
            wire["evidence"]["execution"]["invoked_at"] = None
        rig.service.submit(
            RuntimeOutcomeReceipt.model_validate(wire),
            auth_context=rig.harness.auth_context,
        )
    snapshot = rig.snapshot.model_copy(
        update={
            "sources": (*rig.snapshot.sources, *bundle.source_facts),
            "flows": (*rig.snapshot.flows, *bundle.flow_facts),
        }
    )
    return record, proof, bundle, snapshot


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("message", [False, True])
def test_real_writer_preserves_typed_result_and_original_action_alias(
    tmp_path, runtime, message
):
    from guard_api.services.ct_projection import decode_ct_transient_facts
    from guard_api.services.product_model_content import _verified_action_result_source

    rig = result_fixture(tmp_path, runtime=runtime, message=message)
    record, proof, bundle, snapshot = stored_result(rig)
    assert decode_ct_transient_facts(record).kind == "full"
    source = _verified_action_result_source(
        rig.harness.store,
        [record],
        "action:" + proof.parent_action_id,
        rig.result_event,
        snapshot,
        {s.source_id: s for s in snapshot.sources},
    )
    assert source == bundle.source_facts[0]
    assert source.trust == "untrusted" and "UNTRUSTED" in source.taints
    assert record.links["action_id"] == rig.tool.call_id
    assert len(proof.result_digest) == 71


@pytest.mark.parametrize(
    "mutation",
    [
        "checkpoint",
        "parent_terminal",
        "parent_ack",
        "parent_lease",
        "scope",
        "source_hash",
        "flow_hash",
        "duplicate",
        "proof_ref",
        "proof_copy",
        "client_metadata",
    ],
)
def test_history_alias_requires_original_proof_and_own_checkpoint(tmp_path, mutation):
    from guard_api.services.product_model_content import _verified_action_result_source

    rig = result_fixture(tmp_path, message=True)
    record, proof, bundle, snapshot = stored_result(
        rig, checkpoint=mutation != "checkpoint"
    )
    records = [record]
    if mutation == "parent_terminal":
        rig.harness.store.audit_events_by_id.pop(rig.action_wire["audit_id"])
    elif mutation == "parent_ack":
        rig.harness.store.audit_events_by_id[rig.action_wire["audit_id"]].metadata[
            "product_ack_validation"
        ]["token_digest"] = "sha256:" + "0" * 64
    elif mutation == "parent_lease":
        # ALLOW cannot acquire an unrelated lease after the recorded result.
        record.evidence["product_tool_result"]["parent_action_id"] = "unrelated-action"
    elif mutation == "scope":
        snapshot = snapshot.model_copy(
            update={
                "scope": snapshot.scope.model_copy(
                    update={"scope_digest": "sha256:" + "f" * 64}
                )
            }
        )
    elif mutation == "source_hash":
        snapshot = snapshot.model_copy(
            update={
                "sources": (
                    *rig.snapshot.sources,
                    bundle.source_facts[0].model_copy(update={"taints": []}),
                )
            }
        )
    elif mutation == "flow_hash":
        snapshot = snapshot.model_copy(
            update={
                "flows": (
                    *rig.snapshot.flows,
                    bundle.flow_facts[0].model_copy(update={"taints": ["CREDENTIAL"]}),
                )
            }
        )
    elif mutation == "duplicate":
        records.append(record)
    elif mutation == "proof_ref":
        record.evidence["decision_v21"]["payload"]["evidence_refs"] = []
    elif mutation == "proof_copy":
        changed = proof.model_copy(update={"parent_action_id": "forged"})
        assert not changed.matches_event(rig.result_event)
        record.evidence["product_tool_result"] = changed.model_dump(mode="json")
    elif mutation == "client_metadata":
        record.metadata["product_tool_result"] = record.evidence.pop(
            "product_tool_result"
        )
    with pytest.raises(ProductModelContentUnavailable):
        _verified_action_result_source(
            rig.harness.store,
            records,
            "action:" + proof.parent_action_id,
            rig.result_event,
            snapshot,
            {s.source_id: s for s in snapshot.sources},
        )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_actual_failed_terminal_can_prove_a_bounded_native_error_result(
    tmp_path, runtime
):
    rig = result_fixture(tmp_path, runtime=runtime)
    rig.harness.store.audit_events_by_id.pop(rig.action_wire["audit_id"])
    wire = deepcopy(rig.action_wire)
    wire["audit_id"] = f"audit_outcome_{rig.event.event_id}_execution_failed"
    wire["metadata"]["outcome_kind"] = "execution_failed"
    wire["evidence"]["execution"].update(
        status="failed",
        error="bounded native error",
        tool_result_entered_context=False,
        persisted=False,
    )
    wire["evidence"]["result"].update(disposition="not_applicable", sanitized=None)
    rig.service.submit(
        RuntimeOutcomeReceipt.model_validate(wire),
        auth_context=rig.harness.auth_context,
    )
    proof = verify_product_tool_result(
        rig.harness.store, rig.result_event, rig.snapshot
    )
    assert proof.parent_terminal_audit_id == wire["audit_id"]


def test_conflicting_original_terminal_kinds_cannot_be_guessed(tmp_path):
    rig = result_fixture(tmp_path)
    completed = rig.harness.store.get_audit_event(rig.action_wire["audit_id"])
    failed_id = f"audit_outcome_{rig.event.event_id}_execution_failed"
    rig.harness.store.audit_events_by_id[failed_id] = completed.model_copy(
        update={"audit_id": failed_id}
    )
    with pytest.raises(ProductModelContentUnavailable):
        verify_product_tool_result(rig.harness.store, rig.result_event, rig.snapshot)


def test_result_proof_is_required_only_by_the_configured_product_composition(tmp_path):
    from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError

    rig = result_fixture(tmp_path)
    event = rig.result_event.model_copy(deep=True)
    event.metadata.pop("product_tool_result")
    pipeline = rig.harness.pipeline
    assert pipeline._product_result_materials(event, rig.snapshot) is None
    pipeline._product_tool_catalog = rig.catalog
    with pytest.raises(
        V21OfficialEvaluationUnavailableError,
        match="V21_PRODUCT_TOOL_RESULT_UNAVAILABLE",
    ):
        pipeline._product_result_materials(event, rig.snapshot)
    assert pipeline._product_result_materials(
        rig.result_event, rig.snapshot
    ).matches_event(rig.result_event)
