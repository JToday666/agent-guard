"""Synthetic offline replay fixtures; never candidate/host qualification reports."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentguard_core import (
    AuditEvent,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    RuntimeActivationEntryV1,
    V21SelectionEligibility,
    build_activation_ack,
    build_product_activation_bundle,
    build_residual_risk_acceptance,
    build_rollout_admission_record,
)
from agentguard_core.actions.canonical_json import canonical_sha256, canonical_json
from agentguard_core.actions.product_tools import product_model_visible_tools
from agentguard_core.authority.models import task_digest_projection
from agentguard_core.decisions.product import (
    build_product_decision_authority_evidence,
    select_product_v21_authority,
)
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.security_context.assessment_overlay import AssessmentTransientFacts
from agentguard_core.security_context import SecuritySnapshot
from agentguard_core.security_context.snapshot import snapshot_digest_projection
from agentguard_core.security_context.projection.capability import (
    GrantPolicyContext,
    compile_task_to_grants,
)
from guard_api.runtime_status import ProductActivationAckRecordV1
from guard_api.security_state.fact_builder import build_transient_facts
from guard_api.services.ct_projection import CtProjectionService
from guard_api.services.product_model_content import (
    build_product_model_content,
    verify_product_model_content,
)
from guard_api.services.product_tool_catalog import ProductToolCatalog
from scripts.product_runtime.conformance import policy_templates
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.models import AdmissionError
from scripts.product_runtime.policy_evidence import verify_policy_evidence
from tests.support import product_evaluation
from tests.support.product_tool_catalog import catalog_fixture, resign_catalog_document
from tests.test_product_model_content import _fixture

pytestmark = pytest.mark.unit
DIGEST = "sha256:" + "b" * 64
ARTIFACT = "sha256:" + "c" * 64


def _save(root, name, value, *, evidence_root=None):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(
        value
        if isinstance(value, bytes)
        else json.dumps(value, sort_keys=True).encode()
    )
    path.chmod(0o600)
    evidence_root = evidence_root or root
    return (
        EvidenceStore(evidence_root)
        .capture(path.relative_to(evidence_root).as_posix())
        .reference()
    )


def _rebind_authority(audit, activation):
    raw = audit.model_dump(mode="json")
    raw.pop("integrity", None)
    entry = activation.runtime_entry(audit.runtime)
    authority = raw["evidence"]["decision_authority"]["payload"]
    authority["profile_digest"] = entry.profile_digest
    authority["policy_digest"] = activation.policy_digest
    authority["dataset_digest"] = activation.dataset_digest
    authority["decision_authority"][
        "activation_ref_digest"
    ] = activation.activation_ref_digest
    authority["approval_release_directive"].update(
        activation_ref_digest=activation.activation_ref_digest,
        capability_digest=entry.capability_report_digest,
    )
    raw["decision_authority"] = authority["decision_authority"]
    return AuditEvent.model_validate(raw)


def _server_capture(event, authority, snapshot, audit_id, *, checked_at=None):
    return {
        "schema_version": "agentguard-product-policy-server-capture/1",
        "authority_kind": "synthetic_contract_fixture",
        "source": "guard_api_phase_b",
        "runtime": event.runtime,
        "checked_at": checked_at or snapshot.evaluation_clock.evaluated_at,
        "event_id": event.event_id,
        "policy_audit_id": audit_id,
        "event_digest": canonical_sha256(event.model_dump(mode="json")),
        "snapshot_digest": snapshot.snapshot_digest,
        "activation_ref_digest": authority.decision_authority.activation_ref_digest,
        "decision_authority_digest": canonical_sha256(
            authority.model_dump(mode="json")
        ),
    }


def _assess_unit(
    event, snapshot, catalog, activation, policy, records, assessment_secret
):
    tool = catalog.resolve(event, activation=activation)
    proof = verify_product_model_content(records, event, snapshot, tool)
    engine = GuardEngine()
    current, detections = engine.evaluate_with_results(event, policy)
    ct = object.__new__(CtProjectionService)
    ct._server_secret = assessment_secret
    inputs = ct._build_inputs(
        event,
        SimpleNamespace(
            snapshot=snapshot,
            detection_results=detections,
            task_id=snapshot.task.task_id,
            product_tool=tool,
            product_data=proof,
            product_result=None,
        ),
        snapshot.scope.scope_digest,
    )
    bundle = build_transient_facts(event=event, inputs=inputs)
    transient = AssessmentTransientFacts.model_validate(bundle.model_dump(mode="json"))
    outcome = shadow_assess_with_coverage(
        event,
        policy,
        snapshot,
        server_secret=assessment_secret,
        detection_results=detections,
        transient_facts=transient,
        product_tool=tool,
        product_data=proof,
    )
    entry = activation.runtime_entry(event.runtime)
    selection, directive = select_product_v21_authority(
        event_id=event.event_id,
        current_decision=current,
        raw_v21_decision=engine.finalize(outcome.assessment),
        assessment=outcome.assessment,
        coverage=outcome.coverage,
        activation=activation,
        runtime_entry=entry,
        eligibility=V21SelectionEligibility(
            **{key: True for key in V21SelectionEligibility.model_fields}
        ),
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        scope_digest=snapshot.scope.scope_digest,
        event_type=event.event_type,
        residual_boundaries=entry.residual_boundaries,
        product_data=proof,
    )
    authority = build_product_decision_authority_evidence(
        result=selection,
        directive=directive,
        assessment=outcome.assessment,
        activation=activation,
        runtime_entry=entry,
        event_type=event.event_type,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
    )
    return SimpleNamespace(
        event=event,
        snapshot=snapshot,
        proof=proof,
        tool=tool,
        bundle=bundle,
        transient=transient,
        outcome=outcome,
        authority=authority,
    )


def _terminal_unit(parent, wire_template, ack, issuance, *, wire_out=None):
    """Typed synthetic observation; the production receipt reader verifies it."""
    from agentguard_core import RuntimeOutcomeReceipt

    wire = deepcopy(wire_template)
    for key in (
        "trace_id",
        "case_id",
        "runtime",
        "decision",
        "risk_score",
        "severity",
        "blocked",
        "is_malicious",
        "rule_hits",
    ):
        wire[key] = getattr(parent, key)
    wire["audit_id"] = f"audit_outcome_{parent.links['event_id']}_execution_completed"
    wire["links"] = {
        key: value
        for key, value in parent.links.items()
        if key in {"event_id", "action_id", "decision_id", "approval_id"}
        and value is not None
    } | {"policy_audit_id": parent.audit_id}
    wire["metadata"]["activation_ack"] = ack.model_dump(mode="json")
    wire["evidence"]["result"]["disposition"] = "passed_through"
    if parent.runtime == "openclaw":
        wire["evidence"]["execution"]["invoked_at"] = None
    wire = RuntimeOutcomeReceipt.model_validate(wire).model_dump(mode="json")
    if wire_out is not None:
        # Retain the original private input before its accepted audit projection
        # strips the token. Never recreate transport bytes from redacted history.
        wire_out.append(deepcopy(wire))
    wire["metadata"]["activation_ack"] = ack.token_projection()
    wire["metadata"]["product_ack_validation"] = {
        "schema_version": "1.0",
        "token_digest": issuance.token_digest,
        "public_claims_digest": canonical_sha256(ack.token_projection()),
        "parent_authority_digest": canonical_sha256(
            parent.evidence["decision_authority"]["payload"]
        ),
    }
    return AuditEvent.model_validate(wire)


def _read_ancestor(
    rig,
    *,
    root,
    evidence_root,
    scope_id,
    candidate_manifest_digest,
    adapter_artifact_digest,
    snapshot,
    activation,
    catalog,
    policy,
    history,
    parents,
    event,
    output_event,
    ack,
    issuance,
    secret,
):
    """A synthetic read call/result passed into the next complete model turn."""
    from agentguard_core.actions import canonical_action_id
    from agentguard_core import product_decision_authority_envelope
    from agentguard_core.decisions.evidence_builder import (
        build_decision_evidence_v21,
        decision_evidence_v21_envelope,
    )
    from guard_api.services.product_model_content import verify_product_tool_result
    from scripts.product_runtime.policy_evidence import _HistoryStore, PolicyHistory
    from tests.test_product_model_content import _ct
    from tests.test_v21_05_provenance import make_flow

    script_name = "command-marker.txt"
    user = rig.user
    prior_model = rig.model.model_copy(
        update={"source_id": "source:model:unit-read-output", "taints": []}
    )
    prior_input_flow = make_flow(
        "prior-read-input-flow",
        user.source_id,
        "model_input:unit-read-input",
        taints=[],
        relation="assembled_into",
    ).model_copy(update={"scope_digest": snapshot.scope.scope_digest})
    prior_output_flow = make_flow(
        "prior-read-output-flow",
        user.source_id,
        "model_output:unit-read-output",
        taints=[],
        strength="possible",
        relation="influenced_by",
    ).model_copy(
        update={
            "scope_digest": snapshot.scope.scope_digest,
            "origin": "semantic_inferred",
        }
    )
    prior_snapshot = snapshot.model_copy(
        update={
            "sources": [user, prior_model],
            "flows": [prior_input_flow, prior_output_flow],
        }
    )
    prior_snapshot = prior_snapshot.model_copy(
        update={
            "snapshot_digest": canonical_sha256(
                snapshot_digest_projection(prior_snapshot)
            )
        }
    )
    previous_parents = []
    for identifier, kind, sources, flows in (
        ("unit-read-input", "model_input_prepared", [user], [prior_input_flow]),
        (
            "unit-read-output",
            "model_output_produced",
            [prior_model],
            [prior_output_flow],
        ),
    ):
        parent = _rebind_authority(
            rig.parent_builder(identifier, kind, sources, flows), activation
        )
        parent.metadata["product_model_task"]["task_digest"] = snapshot.task.task_digest
        previous_parents.append(parent)
    prior_audits = {parents[0].audit_id: parents[0]}
    for parent in previous_parents:
        prior_audits[parent.audit_id] = parent
        terminal = _terminal_unit(parent, rig.receipt_wire, ack, issuance)
        prior_audits[terminal.audit_id] = terminal
    prior_output = output_event.model_dump(mode="json")
    prior_output["event_id"] = "unit-read-output"
    prior_output["metadata"]["product_model_input_audit_id"] = previous_parents[
        0
    ].audit_id
    prior_output["payload"]["content_preview"] = canonical_json(
        {
            "content": "synthetic initial read planning",
            "tool_calls": [
                {
                    "name": "read",
                    "id": "unit-read-call",
                    "args": {"path": script_name},
                    "type": "tool_call",
                }
            ],
            "invalid_tool_calls": [],
        }
    )
    prior_output = GuardEvent.model_validate(prior_output)
    prior_event = event.model_dump(mode="json")
    prior_event["event_id"] = "unit-read-action"
    prior_event["metadata"]["product_model_content"] = {
        "model_output_audit_id": previous_parents[1].audit_id,
        "model_source_ref": prior_model.source_id,
        "call_id": "unit-read-call",
    }
    prior_event["security_context"]["visible_source_refs"] = [
        prior_model.source_id,
        user.source_id,
    ]
    prior_event["payload"] = {
        "tool": {
            "name": "read",
            "call_id": "unit-read-call",
            "category": "file",
            "kind": "file_read",
            "operation": "read",
        },
        "arguments": {"path": script_name},
        "derived_resources": [],
    }
    prior_event = GuardEvent.model_validate(prior_event)
    prior_history = deepcopy(history)
    prior_history["events"] = [prior_output.model_dump(mode="json")]
    prior_history["audits"] = [a.model_dump(mode="json") for a in prior_audits.values()]
    records = _HistoryStore(
        PolicyHistory.model_validate(prior_history), prior_snapshot, activation, secret
    )
    commitment = build_product_model_content(
        records,
        prior_output,
        snapshot=prior_snapshot,
        catalog=catalog,
        activation=activation,
        decision_authority_evidence={
            "decision_authority": previous_parents[1].evidence["decision_authority"]
        },
    )
    previous_parents[1].evidence["product_model_content"] = commitment.model_dump(
        mode="json"
    )
    prior_history["audits"] = [a.model_dump(mode="json") for a in prior_audits.values()]
    records = _HistoryStore(
        PolicyHistory.model_validate(prior_history), prior_snapshot, activation, secret
    )
    actual = _assess_unit(
        prior_event,
        prior_snapshot,
        catalog,
        activation,
        policy,
        records,
        base64.urlsafe_b64decode(product_evaluation._SHADOW_SECRET_B64),
    )
    assert actual.authority.selected_decision.decision == "allow"
    parent = rig.parent_builder(
        prior_event.event_id, prior_event.event_type, [], []
    ).model_dump(mode="json")
    parent.pop("integrity", None)
    parent["links"].update(
        action_id=canonical_action_id(prior_event),
        decision_id=actual.authority.selected_decision.decision_id,
    )
    decision = actual.authority.selected_decision
    for key in ("decision", "risk_score", "severity", "blocked", "reason", "rule_hits"):
        parent[key] = getattr(decision, key)
    parent["decision_authority"] = actual.authority.decision_authority.model_dump(
        mode="json"
    )
    parent["evidence"].update(product_decision_authority_envelope(actual.authority))
    parent["evidence"].update(
        decision_evidence_v21_envelope(
            build_decision_evidence_v21(
                actual.outcome.assessment,
                legacy_decision=actual.authority.current_decision.decision,
                snapshot_id=prior_snapshot.snapshot_id,
                state_version=prior_snapshot.state_version,
                coverage=actual.outcome.coverage,
                mode="active",
                selected_decision="allow",
            )
        )
    )
    parent["evidence"]["product_action_data"] = actual.proof.model_dump(mode="json")
    parent["evidence"]["guard_decision"] = decision.model_dump(mode="json")
    parent["evidence"]["guard_event"]["tool"] = {
        "name": "read",
        "call_id": "unit-read-call",
    }
    parent["evidence"]["ct_transient_facts"] = _ct(
        prior_event.event_id,
        snapshot.scope.scope_digest,
        actual.bundle.source_facts,
        actual.bundle.flow_facts,
    )
    parent["metadata"].update(
        action_name="read",
        tool="read",
        subject_id=canonical_action_id(prior_event),
        policy_digest=activation.policy_digest,
        product_authority_initial_checked_at=prior_snapshot.evaluation_clock.evaluated_at,
    )
    parent["metadata"]["product_model_task"]["task_digest"] = snapshot.task.task_digest
    parent = AuditEvent.model_validate(parent)
    raw_wires = []
    terminal = _terminal_unit(
        parent, rig.receipt_wire, ack, issuance, wire_out=raw_wires
    )
    raw_wire = raw_wires[0]
    start = None
    if event.runtime == "langgraph":
        from agentguard_langgraph_adapter.activation_ack import (
            ActivationAckV1 as SdkAck,
        )
        from agentguard_langgraph_adapter.event_models import PolicyDecision
        from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome
        from tests.product_runtime_start_fixture import build_policy_start

        sdk_decision = PolicyDecision.model_validate(
            actual.authority.selected_decision.model_dump(mode="json")
            | {
                "policy_audit_id": parent.audit_id,
                "decision_authority": actual.authority.decision_authority.model_dump(
                    mode="json"
                ),
                "approval_release_directive": actual.authority.approval_release_directive.model_dump(
                    mode="json"
                ),
            }
        )
        sdk_decision._evaluation_activation_ack = SdkAck.model_validate(
            ack.model_dump(mode="json")
        )
        raw_wire = build_runtime_outcome(
            prior_event,
            sdk_decision,
            execution_status="executed",
            invoked_at=prior_snapshot.evaluation_clock.evaluated_at,
            completed_at=prior_snapshot.evaluation_clock.evaluated_at,
        ).to_wire()
        start = build_policy_start(
            root / "prior-read-start",
            SimpleNamespace(
                event=prior_event,
                authority=actual.authority,
                ack=ack,
                scope_id=scope_id,
                replay={
                    "candidate_manifest_digest": candidate_manifest_digest,
                    "adapter_artifact_digest": adapter_artifact_digest,
                },
            ),
            parent,
            raw_wire,
            evidence_root=evidence_root,
        )
        raw_wire["links"]["parent_audit_id"] = start.start_audit_id
    from agentguard_core import RuntimeOutcomeReceipt
    from guard_api.services.product_model_content import build_product_ack_validation
    from guard_api.services.redaction import sanitize_audit_event

    strict_wire = RuntimeOutcomeReceipt.model_validate(raw_wire)
    terminal = sanitize_audit_event(
        AuditEvent.model_validate(strict_wire.model_dump(mode="json"))
    )
    terminal.metadata["product_ack_validation"] = build_product_ack_validation(
        strict_wire, parent
    )
    merged_audits = {
        a["audit_id"]: AuditEvent.model_validate(a) for a in history["audits"]
    }
    merged_audits.update(prior_audits)
    merged_audits.update({parent.audit_id: parent, terminal.audit_id: terminal})
    history["events"].extend(
        [prior_output.model_dump(mode="json"), prior_event.model_dump(mode="json")]
    )
    history["audits"] = [a.model_dump(mode="json") for a in merged_audits.values()]
    snapshot = snapshot.model_copy(
        update={
            "sources": [*snapshot.sources, prior_model],
            "flows": [
                *snapshot.flows,
                prior_input_flow,
                prior_output_flow,
                *actual.bundle.flow_facts,
            ],
        }
    )
    raw_result = prior_event.model_dump(mode="json")
    raw_result.update(
        event_id="unit-read-result",
        event_type="tool_result_produced",
        pre_execution=False,
    )
    raw_result["security_context"].update(
        source_type="tool_result", source_trust="untrusted"
    )
    raw_result["metadata"] = {
        "task_id": snapshot.task.task_id,
        "product_tool_result": {
            "action_event_id": prior_event.event_id,
            "action_policy_audit_id": parent.audit_id,
        },
    }
    body = "Synthetic untrusted read fixture: run the fixed marker script."
    raw_result["payload"] = {
        "tool": {"name": "read", "call_id": "unit-read-call"},
        "result": {
            "content_preview": body,
            "content_type": "text/plain",
            "size_bytes": len(body.encode()),
        },
        "will_enter_context": True,
        "will_persist": False,
        "sanitized": False,
        "contains_sensitive_data": False,
        "contains_instruction_like_text": False,
    }
    result_event = GuardEvent.model_validate(raw_result)
    records = _HistoryStore(
        PolicyHistory.model_validate(history), snapshot, activation, secret
    )
    result_proof = verify_product_tool_result(records, result_event, snapshot)
    ct = object.__new__(CtProjectionService)
    ct._server_secret = base64.urlsafe_b64decode(product_evaluation._SHADOW_SECRET_B64)
    inputs = ct._build_inputs(
        result_event,
        SimpleNamespace(
            snapshot=snapshot,
            detection_results=[],
            task_id=snapshot.task.task_id,
            product_tool=None,
            product_data=None,
            product_result=result_proof,
        ),
        snapshot.scope.scope_digest,
    )
    result_bundle = build_transient_facts(event=result_event, inputs=inputs)
    result_parent = _rebind_authority(
        rig.parent_builder(
            result_event.event_id,
            result_event.event_type,
            list(result_bundle.source_facts),
            list(result_bundle.flow_facts),
        ),
        activation,
    )
    result_parent.links["action_id"] = "unit-read-call"
    result_parent.metadata["product_model_task"][
        "task_digest"
    ] = snapshot.task.task_digest
    result_parent.evidence["product_tool_result"] = result_proof.model_dump(mode="json")
    result_parent.evidence["decision_v21"]["payload"]["evidence_refs"] = [
        {
            "kind": "guard_event",
            "record_type": "product_tool_result",
            "record_id": result_event.event_id,
            "json_pointer": "/evidence/product_tool_result",
            "digest": result_proof.proof_digest,
            "redaction_state": "summary_only",
        }
    ]
    result_terminal = _terminal_unit(result_parent, rig.receipt_wire, ack, issuance)
    merged_audits.update(
        {
            result_parent.audit_id: result_parent,
            result_terminal.audit_id: result_terminal,
        }
    )
    source = result_bundle.source_facts[0]
    extra_flows = [
        make_flow(
            "unit-read-to-input",
            source.source_id,
            "model_input:input",
            relation="assembled_into",
            taints=["UNTRUSTED"],
        ).model_copy(update={"scope_digest": snapshot.scope.scope_digest}),
        make_flow(
            "unit-read-to-output",
            source.source_id,
            "model_output:output",
            relation="influenced_by",
            strength="possible",
            taints=["UNTRUSTED"],
        ).model_copy(
            update={
                "scope_digest": snapshot.scope.scope_digest,
                "origin": "semantic_inferred",
            }
        ),
    ]
    snapshot = snapshot.model_copy(
        update={
            "sources": [*snapshot.sources, *result_bundle.source_facts],
            "flows": [*snapshot.flows, *result_bundle.flow_facts, *extra_flows],
        }
    )
    snapshot = snapshot.model_copy(
        update={
            "snapshot_digest": canonical_sha256(snapshot_digest_projection(snapshot))
        }
    )
    for parent_current, extra in zip(parents[1:], extra_flows, strict=True):
        original = next(
            a for a in history["audits"] if a["audit_id"] == parent_current.audit_id
        )
        from guard_api.services.ct_projection import decode_ct_transient_facts

        prior_ct = decode_ct_transient_facts(AuditEvent.model_validate(original)).bundle
        parent_current.evidence["ct_transient_facts"] = _ct(
            parent_current.links["event_id"],
            snapshot.scope.scope_digest,
            prior_ct.source_facts,
            (*prior_ct.flow_facts, extra),
        )
        merged_audits[parent_current.audit_id] = parent_current
    event = event.model_copy(deep=True)
    event.security_context.visible_source_refs = (
        *event.security_context.visible_source_refs,
        source.source_id,
    )
    output_event = output_event.model_copy(deep=True)
    output_event.security_context.visible_source_refs = (
        *output_event.security_context.visible_source_refs,
        source.source_id,
    )
    history["events"] = [
        raw for raw in history["events"] if raw["event_id"] != output_event.event_id
    ] + [output_event.model_dump(mode="json"), result_event.model_dump(mode="json")]
    history["audits"] = [a.model_dump(mode="json") for a in merged_audits.values()]
    records = _HistoryStore(
        PolicyHistory.model_validate(history), snapshot, activation, secret
    )
    commitment = build_product_model_content(
        records,
        output_event,
        snapshot=snapshot,
        catalog=catalog,
        activation=activation,
        decision_authority_evidence={
            "decision_authority": parents[-1].evidence["decision_authority"]
        },
    )
    parents[-1].evidence["product_model_content"] = commitment.model_dump(mode="json")
    merged_audits[parents[-1].audit_id] = parents[-1]
    history["audits"] = [a.model_dump(mode="json") for a in merged_audits.values()]
    actual.history = prior_history
    actual.parent = parent
    actual.result_parent = result_parent
    actual.start = start
    actual.raw_wire = raw_wire
    from agentguard_core import RuntimeOutcomeReceipt

    actual.receipt = RuntimeOutcomeReceipt.model_validate(raw_wire)
    actual.accepted = terminal
    return snapshot, event, history, actual


def _first_write_ids(rig):
    """Keep historical first-write model identities distinct from the read turn."""
    from tests.test_product_model_content import _ct
    from guard_api.services.ct_projection import decode_ct_transient_facts

    names = {
        "input": "unit-memory-write-input",
        "output": "unit-memory-write-output",
        "audit:input": "audit:unit-memory-write-input",
        "audit:output": "audit:unit-memory-write-output",
        "action:input": "action:unit-memory-write-input",
        "action:output": "action:unit-memory-write-output",
        "model_input:input": "model_input:unit-memory-write-input",
        "model_output:output": "model_output:unit-memory-write-output",
        "source:model:output": "source:model:unit-memory-write-output",
        "input-flow": "unit-memory-write-input-flow",
        "output-flow": "unit-memory-write-output-flow",
        "audit_outcome_input_execution_completed": "audit_outcome_unit-memory-write-input_execution_completed",
        "audit_outcome_output_execution_completed": "audit_outcome_unit-memory-write-output_execution_completed",
    }

    def rename(value):
        if isinstance(value, str):
            return names.get(value, value)
        if isinstance(value, list):
            return [rename(item) for item in value]
        if isinstance(value, dict):
            return {
                key: item if key == "phase" else rename(item)
                for key, item in value.items()
            }
        return value

    previous = rig.snapshot.model_copy(
        update={
            key: list(getattr(rig.snapshot, key))
            for key in ("sources", "flows", "memory_facts", "dirty_domains")
        }
    )
    rig.snapshot = SecuritySnapshot.model_validate(
        rename(previous.model_dump(mode="json"))
    )
    rig.model = next(
        source for source in rig.snapshot.sources if source.source_type == "model"
    )
    for name in ("input", "output"):
        before = getattr(rig, name)
        raw = rename(before.model_dump(mode="json"))
        facts = decode_ct_transient_facts(before).bundle
        sources = [
            source.model_validate(rename(source.model_dump(mode="json")))
            for source in facts.source_facts
        ]
        flows = [
            flow.model_validate(rename(flow.model_dump(mode="json")))
            for flow in facts.flow_facts
        ]
        raw["evidence"]["ct_transient_facts"] = _ct(
            raw["links"]["event_id"], rig.snapshot.scope.scope_digest, sources, flows
        )
        setattr(rig, name, AuditEvent.model_validate(raw))
    rig.event = GuardEvent.model_validate(rename(rig.event.model_dump(mode="json")))
    rig.output_event = GuardEvent.model_validate(
        rename(rig.output_event.model_dump(mode="json"))
    )
    for name in ("input", "output"):
        previous = rig.harness.store.audit_events_by_id.pop(
            f"audit_outcome_{name}_execution_completed"
        )
        changed = AuditEvent.model_validate(rename(previous.model_dump(mode="json")))
        rig.harness.store.audit_events_by_id[changed.audit_id] = changed


def _merge_first_write_history(snapshot, history, shared):
    """Carry the prior committed source/action identities into the read snapshot."""
    from guard_api.security_state.transient import TransientSecurityFacts

    transient = TransientSecurityFacts.model_validate(shared.replay["transient_facts"])

    def unique(rows, key):
        result = {}
        for row in rows:
            value = getattr(row, key)
            if value in result:
                assert result[value].model_dump(mode="json") == row.model_dump(
                    mode="json"
                )
            result[value] = row
        return list(result.values())

    snapshot = snapshot.model_copy(
        update={
            "sources": unique(
                [*shared.snapshot.sources, *transient.source_facts, *snapshot.sources],
                "source_id",
            ),
            "flows": unique(
                [*shared.snapshot.flows, *transient.flow_facts, *snapshot.flows],
                "flow_id",
            ),
        }
    )
    snapshot = snapshot.model_copy(
        update={
            "snapshot_digest": canonical_sha256(snapshot_digest_projection(snapshot))
        }
    )
    for key, identity in (
        ("events", "event_id"),
        ("audits", "audit_id"),
        ("approvals", "approval_id"),
        ("bindings", "approval_id"),
        ("leases", "lease_id"),
    ):
        combined = {}
        for row in [*shared.history[key], *history[key]]:
            if row[identity] in combined:
                assert combined[row[identity]] == row
            combined[row[identity]] = row
        history[key] = list(combined.values())
    acknowledgements = {}
    for row in [*shared.history["acknowledgements"], *history["acknowledgements"]]:
        identity = row["record"]["token_digest"]
        if identity in acknowledgements:
            assert acknowledgements[identity] == row
        acknowledgements[identity] = row
    history["acknowledgements"] = list(acknowledgements.values())
    return snapshot, history


def make_policy_replay(
    root: Path,
    *,
    runtime="langgraph",
    group="ask",
    category="file",
    candidate_manifest_digest=DIGEST,
    adapter_artifact_digest=ARTIFACT,
    scope_id=None,
    evidence_root=None,
    memory_first_write=False,
    memory_fact_override=None,
    shared_fixture=None,
):
    """Build full synthetic records, then execute real proof/CT/Core/selector code.

    The returned data is a unit fixture, not evidence that a model or Host ran.
    It is shared by the full admission unit test, which also labels that scope.
    """
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence_root = evidence_root or root

    def save(name, value):
        return _save(root, name, value, evidence_root=evidence_root)

    scope_id = scope_id or f"unit-{runtime}-{group}-{category}"
    source = root / "source"
    source.mkdir(mode=0o700)
    # Offline evidence exercises protocol readers, not the machine's wall clock.
    # Keep issuance and Phase A/B on one explicit instant; live HTTP/PG callers
    # continue using the harness's default real-time clock.
    fixture_time = datetime.now(timezone.utc)
    rig = _fixture(
        source,
        runtime=runtime,
        memory=category == "memory" and (group != "allow" or memory_first_write),
        memory_read=category == "memory"
        and group == "allow"
        and not memory_first_write,
        message=category == "message",
        model_taints=(),
        evaluation_clock=lambda: fixture_time,
    )
    if memory_first_write:
        _first_write_ids(rig)
    policy = PolicyBundle.model_validate(policy_templates()[group])
    if shared_fixture is None:
        data = catalog_fixture(
            root, policy_digest=canonical_sha256(policy.model_dump(mode="json"))
        )
        # A fixed, non-sensitive logical root keeps command detector coverage honest.
        # These unit descriptors do not execute a tool at this path.
        for catalog_row in data.document["runtimes"]:
            execution = catalog_row["execution"]
            execution["root"] = f"/srv/agentguard-unit/{runtime}/{group}/{category}"
            execution["memory_namespace"] = execution["root"] + "/memory.sqlite"
            if catalog_row["runtime"] == "langgraph":
                binding = canonical_sha256(
                    {
                        key: execution[key]
                        for key in ("root", "inbox_url", "script_digest")
                    }
                    | {
                        "source_id": "agentguard-langgraph-adapter:isolated-product-tools-v1"
                    }
                )
                for tool in catalog_row["inventory"]["tools"]:
                    tool["execution_binding_digest"] = binding
                catalog_row["inventory"]["model_visible_tools"] = (
                    product_model_visible_tools(catalog_row["inventory"]["tools"])
                )
        resign_catalog_document(data)
        secret = data.fixture.server_secret
        risk_values = data.bundle.residual_risk_acceptance.digest_projection() | {
            "candidate_artifact_digest": candidate_manifest_digest
        }
        risk = build_residual_risk_acceptance(server_secret=secret, **risk_values)
        admission_values = data.bundle.rollout_admission_record.digest_projection() | {
            "candidate_artifact_manifest_digest": candidate_manifest_digest
        }
        admission = build_rollout_admission_record(
            server_secret=secret, **admission_values
        )
        entries = []
        for entry in data.bundle.runtimes:
            value = entry.model_dump(mode="json")
            if entry.runtime == runtime:
                value["adapter_artifact_digest"] = adapter_artifact_digest
            if entry.runtime == "openclaw":
                value["residual_risk_acceptance_digest"] = risk.acceptance_ref_digest
            entries.append(RuntimeActivationEntryV1.model_validate(value))
        values = data.bundle.digest_projection() | {
            "candidate_artifact_manifest_digest": candidate_manifest_digest,
            "rollout_admission_record": admission,
            "rollout_admission_digest": admission.admission_ref_digest,
            "residual_risk_acceptance": risk,
            "runtimes": entries,
        }
        data.bundle = build_product_activation_bundle(server_secret=secret, **values)
        # Recompute profile projection after changing the unit adapter artifact.
        resign_catalog_document(data)
    else:
        data = shared_fixture.catalog_data
        secret = data.fixture.server_secret
    activation = data.bundle
    catalog = ProductToolCatalog(str(data.path), activation)
    entry = activation.runtime_entry(runtime)
    snapshot = rig.snapshot.model_copy(
        update={
            key: list(getattr(rig.snapshot, key))
            for key in ("sources", "flows", "memory_facts", "dirty_domains")
        }
    )
    snapshot = SecuritySnapshot.model_validate(snapshot.model_dump(mode="json"))
    if shared_fixture is not None:
        snapshot = snapshot.model_copy(
            update={
                "scope": shared_fixture.snapshot.scope,
                "evaluation_clock": shared_fixture.snapshot.evaluation_clock,
                "task": shared_fixture.snapshot.task,
            }
        )
    task = snapshot.task.model_copy(deep=True)
    task.task_summary = "Read fixture.txt; write output.txt; execute the fixed marker command; read and write the note memory; send a message to fixture-inbox@agentguard.invalid."
    task.action_constraints[0].action_types = [
        "tool_call",
        "model_call",
        "file_read",
        "file_write",
        "file_edit",
        "command_exec",
        "memory_read",
        "memory_write",
        "message_send",
    ]
    task = task.model_copy(update={"task_digest": task_digest_projection(task)})
    grants = compile_task_to_grants(
        task,
        GrantPolicyContext(
            policy_revision=snapshot.policy_revision,
            scope_digest=task.scope_digest,
            principal_id=task.principal_id,
        ),
    )
    snapshot = snapshot.model_copy(
        update={
            "task": task,
            "policy_digest": activation.policy_digest,
            "grants": grants,
        }
    )
    event = rig.event.model_dump(mode="json")
    event["timestamp"] = snapshot.evaluation_clock.evaluated_at
    call_id = "unit-memory-first-write-call" if memory_first_write else "call:generated"
    event["metadata"]["task_id"] = task.task_id
    event["metadata"]["product_model_content"]["call_id"] = call_id
    if memory_first_write:
        event["event_id"] = "unit-memory-first-write-action"
        event["metadata"]["product_tool_call"]["call_id"] = call_id
        event["payload"]["action_id"] = call_id
    event["security_context"]["user_task"] = task.task_summary
    arguments = rig.tool.arguments()
    if category == "file":
        name = "write" if group == "ask" else "read"
        arguments = (
            {"path": "output.txt", "content": "synthetic fixture output"}
            if group == "ask"
            else {"path": "fixture.txt" if group == "allow" else "private.txt"}
        )
    elif category == "command":
        name = "exec"
        arguments = {
            "command": (
                "python marker.py" if runtime == "langgraph" else "node marker.mjs"
            )
        }
    else:
        name = rig.tool.tool_name
    if category in {"file", "command"}:
        execution = next(
            row["execution"]
            for row in data.document["runtimes"]
            if row["runtime"] == runtime
        )
        kind = (
            "command_exec"
            if category == "command"
            else "file_write" if name == "write" else "file_read"
        )
        operation = (
            "execute"
            if category == "command"
            else "write" if name == "write" else "read"
        )
        target = (
            execution["root"]
            + "/"
            + ("marker.py" if runtime == "langgraph" else "marker.mjs")
            if category == "command"
            else execution["root"] + "/" + arguments["path"]
        )
        event["payload"] = {
            "tool": {
                "name": name,
                "call_id": call_id,
                "category": "code" if category == "command" else "file",
                "kind": kind,
                "operation": operation,
            },
            "arguments": arguments,
            "derived_resources": [
                {
                    "resource_type": "process" if category == "command" else "file",
                    "operation": operation,
                    "direction": "local",
                    "target": target,
                }
            ],
        }
    if category == "memory" and (group != "allow" or memory_first_write):
        event["payload"]["memory"]["namespace"] = next(
            row["execution"]["memory_namespace"]
            for row in data.document["runtimes"]
            if row["runtime"] == runtime
        )
    event = GuardEvent.model_validate(event)
    tool = catalog.resolve(event, activation=activation)
    if category == "memory" and group == "allow" and not memory_first_write:
        from agentguard_core.actions.canonical_resources import (
            normalize_memory_resource,
            ResourceNormalizationInput,
        )
        from tests.test_v21_05_provenance import make_memory

        resource = tool.resource_inputs()[0]
        target = normalize_memory_resource(
            ResourceNormalizationInput(
                resource_id="memory",
                target=resource["target"],
                memory_namespace=resource["memory_namespace"],
            )
        ).canonical_id
        # Actual accepted model writes remain quarantined in the memory lifecycle.
        # A known quarantined value can be read; its later context release stays blocked.
        memory = memory_fact_override or make_memory(
            target,
            change_id="unit-memory-first-write",
            trust_state="quarantined",
            change_status="committed",
            source_refs=[rig.user.source_id],
            taints=[],
        )
        snapshot = snapshot.model_copy(update={"memory_facts": [memory]})
    snapshot = snapshot.model_copy(
        update={
            "snapshot_digest": canonical_sha256(snapshot_digest_projection(snapshot))
        }
    )
    from tests.test_v21_05_provenance import make_flow

    context_id = "unit-memory-write-context" if memory_first_write else "unit-context"
    context_flow = make_flow(
        f"{context_id}-flow",
        rig.user.source_id,
        f"context:{context_id}",
        relation="assembled_into",
        taints=[],
    ).model_copy(update={"scope_digest": snapshot.scope.scope_digest})
    context = rig.parent_builder(
        context_id, "context_assembled", [rig.user], [context_flow]
    )
    parents = [
        _rebind_authority(audit, activation)
        for audit in (context, rig.input, rig.output)
    ]
    for parent in parents:
        parent.metadata["task_id"] = task.task_id
        parent.metadata["product_model_task"].update(
            task_id=task.task_id,
            task_revision=task.revision,
            task_digest=task.task_digest,
            scope_digest=task.scope_digest,
        )
        if shared_fixture is not None:
            parent.metadata["product_authority_initial_checked_at"] = (
                snapshot.evaluation_clock.evaluated_at
            )
    when = datetime.fromisoformat(snapshot.evaluation_clock.evaluated_at)
    ack = build_activation_ack(
        server_secret=secret,
        runtime=entry.runtime,
        runtime_version=entry.runtime_version,
        plugin_version=entry.plugin_version,
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        profile_id=entry.profile_id,
        activation_ref_digest=activation.activation_ref_digest,
        capability_digest=entry.capability_report_digest,
        host_inventory_digest=entry.host_inventory_digest,
        plugin_inventory_digest=entry.plugin_inventory_digest,
        plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
        tool_inventory_digest=entry.tool_inventory_digest,
        issued_at=(when - timedelta(seconds=10)).isoformat(),
        expires_at=(when + timedelta(seconds=100)).isoformat(),
    )
    if shared_fixture is not None:
        ack = shared_fixture.ack
    issuance = ProductActivationAckRecordV1.from_ack(
        ack, principal_id=entry.principal_id
    )
    # Keep only the complete same-scope model parents and their actual-shaped receipts.
    original_store = rig.harness.store
    audits = {}
    for parent in parents:
        audits[parent.audit_id] = parent
        if parent.event_type == "context_assembled":
            continue
        previous = original_store.get_audit_event(
            f"audit_outcome_{parent.links['event_id']}_execution_completed"
        ).model_dump(mode="json")
        previous.pop("integrity", None)
        authority = parent.evidence["decision_authority"]["payload"]
        previous["metadata"]["activation_ack"] = ack.token_projection()
        previous["metadata"]["product_ack_validation"] = {
            "schema_version": "1.0",
            "token_digest": issuance.token_digest,
            "public_claims_digest": canonical_sha256(ack.token_projection()),
            "parent_authority_digest": canonical_sha256(authority),
        }
        audits[previous["audit_id"]] = AuditEvent.model_validate(previous)
    original_store.audit_events_by_id.clear()
    original_store.audit_events_by_id.update(audits)
    # Proof reader uses the bounded API to resolve CT records, not just this map.
    from scripts.product_runtime.policy_evidence import _HistoryStore, PolicyHistory

    output_event = rig.output_event.model_dump(mode="json")
    projection = {
        "content": "complete synthetic unit answer",
        "tool_calls": [
            {"name": name, "id": call_id, "args": arguments, "type": "tool_call"}
        ],
        "invalid_tool_calls": [],
    }
    output_event["metadata"]["task_id"] = task.task_id
    output_event["payload"]["content_preview"] = canonical_json(projection)
    output_event = GuardEvent.model_validate(output_event)
    history = {
        "schema_version": "agentguard-product-policy-history/1",
        "authority_kind": "synthetic_contract_fixture",
        "scope_id": scope_id,
        "events": [output_event.model_dump(mode="json")],
        "audits": [a.model_dump(mode="json") for a in audits.values()],
        "acknowledgements": [
            {
                "ack": ack.model_dump(mode="json"),
                "record": issuance.model_dump(mode="json"),
            }
        ],
        "approvals": [],
        "bindings": [],
        "leases": [],
    }
    records = _HistoryStore(
        PolicyHistory.model_validate(history), snapshot, activation, secret
    )
    commitment = build_product_model_content(
        records,
        output_event,
        snapshot=snapshot,
        catalog=catalog,
        activation=activation,
        decision_authority_evidence={
            "decision_authority": parents[-1].evidence["decision_authority"]
        },
    )
    parents[-1].evidence["product_model_content"] = commitment.model_dump(mode="json")
    history["audits"] = [a.model_dump(mode="json") for a in audits.values()]
    if shared_fixture is not None and memory_fact_override is not None:
        snapshot, history = _merge_first_write_history(
            snapshot, history, shared_fixture
        )
    prior_read = None
    if category == "command" and group == "ask":
        snapshot, event, history, prior_read = _read_ancestor(
            rig,
            root=root,
            evidence_root=evidence_root,
            scope_id=scope_id,
            candidate_manifest_digest=candidate_manifest_digest,
            adapter_artifact_digest=adapter_artifact_digest,
            snapshot=snapshot,
            activation=activation,
            catalog=catalog,
            policy=policy,
            history=history,
            parents=parents,
            event=event,
            output_event=output_event,
            ack=ack,
            issuance=issuance,
            secret=secret,
        )
        tool = catalog.resolve(event, activation=activation)
    records = _HistoryStore(
        PolicyHistory.model_validate(history), snapshot, activation, secret
    )
    proof = verify_product_model_content(records, event, snapshot, tool)
    engine = GuardEngine()
    current, detections = engine.evaluate_with_results(event, policy)
    assessment_secret = base64.urlsafe_b64decode(product_evaluation._SHADOW_SECRET_B64)
    scope_secret = base64.urlsafe_b64decode(product_evaluation._TASK_SCOPE_KEY_B64)
    ct = object.__new__(CtProjectionService)
    ct._server_secret = assessment_secret
    inputs = ct._build_inputs(
        event,
        SimpleNamespace(
            snapshot=snapshot,
            detection_results=detections,
            task_id=task.task_id,
            product_tool=tool,
            product_data=proof,
            product_result=None,
        ),
        snapshot.scope.scope_digest,
    )
    bundle = build_transient_facts(event=event, inputs=inputs)
    transient = AssessmentTransientFacts.model_validate(bundle.model_dump(mode="json"))
    outcome = shadow_assess_with_coverage(
        event,
        policy,
        snapshot,
        server_secret=assessment_secret,
        detection_results=detections,
        transient_facts=transient,
        product_tool=tool,
        product_data=proof,
    )
    result, directive = select_product_v21_authority(
        event_id=event.event_id,
        current_decision=current,
        raw_v21_decision=engine.finalize(outcome.assessment),
        assessment=outcome.assessment,
        coverage=outcome.coverage,
        activation=activation,
        runtime_entry=entry,
        eligibility=V21SelectionEligibility(
            **{key: True for key in V21SelectionEligibility.model_fields}
        ),
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        scope_digest=snapshot.scope.scope_digest,
        event_type=event.event_type,
        residual_boundaries=entry.residual_boundaries,
        product_data=proof,
    )
    authority = build_product_decision_authority_evidence(
        result=result,
        directive=directive,
        assessment=outcome.assessment,
        activation=activation,
        runtime_entry=entry,
        event_type=event.event_type,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
    )
    target_audit_id = (
        "unit-memory-first-write-policy" if memory_first_write else "unit-target-policy"
    )
    replay = {
        "server_capture": _server_capture(event, authority, snapshot, target_audit_id),
        "schema_version": "agentguard-product-policy-replay/1",
        "authority_kind": "synthetic_contract_fixture",
        "execution_scope": "isolated_contract_fixture",
        "product_active_enabled": False,
        "external_provider_requests": 0,
        "runtime": runtime,
        "scope_id": scope_id,
        "candidate_manifest_digest": candidate_manifest_digest,
        "adapter_artifact_digest": adapter_artifact_digest,
        "activation": save("activation.json", activation.model_dump(mode="json")),
        "catalog": EvidenceStore(evidence_root)
        .capture(data.path.relative_to(evidence_root).as_posix())
        .reference(),
        "snapshot": save("snapshot.json", snapshot.model_dump(mode="json")),
        "current_snapshot": save(
            "current-snapshot.json", snapshot.model_dump(mode="json")
        ),
        "history": save("history.json", history),
        "product_key": save("product.key", secret),
        "assessment_key": save("assessment.key", assessment_secret),
        "scope_key": save("scope.key", scope_secret),
        "evaluation_ack": save("ack.json", ack.model_dump(mode="json")),
        "revoked_grant_ids": [],
        "coverage": outcome.coverage.model_dump(mode="json"),
        "transient_facts": transient.model_dump(mode="json"),
        "product_data": proof.model_dump(mode="json"),
    }
    replay["prior_actions"] = []
    if prior_read is not None:
        prior_replay = deepcopy(replay)
        prior_replay.update(
            server_capture=_server_capture(
                prior_read.event,
                prior_read.authority,
                prior_read.snapshot,
                prior_read.parent.audit_id,
            ),
            snapshot=save(
                "prior-read-snapshot.json", prior_read.snapshot.model_dump(mode="json")
            ),
            current_snapshot=save(
                "prior-read-current-snapshot.json",
                prior_read.snapshot.model_dump(mode="json"),
            ),
            history=save("prior-read-history.json", prior_read.history),
            coverage=prior_read.outcome.coverage.model_dump(mode="json"),
            transient_facts=prior_read.transient.model_dump(mode="json"),
            product_data=prior_read.proof.model_dump(mode="json"),
        )
        prior_row = {
            "event": prior_read.event.model_dump(mode="json"),
            "authority": prior_read.authority.model_dump(mode="json"),
            "assessment": prior_read.outcome.assessment.model_dump(mode="json"),
            "policy_audit_id": prior_read.parent.audit_id,
            "replay": save("prior-read-replay.json", prior_replay),
            "receipt": save("prior-read-receipt.json", prior_read.raw_wire),
            "accepted": save(
                "prior-read-accepted.json", prior_read.accepted.model_dump(mode="json")
            ),
            "start": (
                prior_read.start.reference if prior_read.start is not None else None
            ),
        }
        replay["prior_actions"] = [save("prior-read-row.json", prior_row)]
    row = {
        "event": event.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json"),
        "assessment": outcome.assessment.model_dump(mode="json"),
        "policy_audit_id": target_audit_id,
        "upstream_policy_audit_ids": [parent.audit_id for parent in parents],
        "memory_fact_id": "unit-memory-first-write",
        "replay": save("replay.json", replay),
    }
    return SimpleNamespace(
        root=root,
        row=row,
        event=event,
        authority=authority,
        assessment=outcome.assessment,
        product_data=proof,
        coverage=outcome.coverage,
        replay=replay,
        history=history,
        scope_digest=snapshot.scope.scope_digest,
        scope_id=scope_id,
        policy=policy,
        parents=parents,
        activation=activation,
        ack=ack,
        snapshot=snapshot,
        prior_read=prior_read,
        catalog_data=data,
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("group", ["allow", "ask", "deny"])
@pytest.mark.parametrize("category", ["file", "command", "memory", "message"])
def test_replay_uses_actual_core_and_selector(tmp_path, runtime, group, category):
    fixture = make_policy_replay(
        tmp_path, runtime=runtime, group=group, category=category
    )
    result = verify_policy_evidence(
        fixture.row,
        runtime=runtime,
        scope_id=fixture.scope_id,
        policy=fixture.policy,
        store=EvidenceStore(tmp_path),
        candidate_manifest_digest=DIGEST,
        adapter_artifact_digest=ARTIFACT,
    )
    assert result == fixture.authority
    assert result.selected_decision.decision == group
    assert result.decision_authority.source == "v21"
    assert result.decision_authority.mode == "active"
    assert result.decision_authority.selection_basis == "profile_all"
    if group != "deny":
        assert fixture.coverage.dataflow.status == "complete"
    if group == "ask":
        assert result.approval_release_directive.mode == (
            "strong_binding" if runtime == "langgraph" else "restricted_allow_once"
        )


def _rewrite(fixture, field, mutate):
    raw = json.loads((fixture.root / fixture.replay[field]["path"]).read_bytes())
    mutate(raw)
    fixture.replay[field] = _save(fixture.root, fixture.replay[field]["path"], raw)
    fixture.row["replay"] = _save(fixture.root, "replay.json", fixture.replay)


def _verify_fixture(fixture, **overrides):
    options = dict(
        runtime=fixture.event.runtime,
        scope_id=fixture.scope_id,
        policy=fixture.policy,
        store=EvidenceStore(fixture.root),
        candidate_manifest_digest=DIGEST,
        adapter_artifact_digest=ARTIFACT,
    )
    options.update(overrides)
    return verify_policy_evidence(fixture.row, **options)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_replay",
        "fake_assessment",
        "fake_legacy",
        "active",
        "coverage",
        "transient",
        "sealed_proof",
        "original_output",
        "missing_receipt",
        "revoked_ack",
        "unsigned_ack",
        "snapshot_digest",
        "stale_state",
        "grant_digest",
        "key_permission",
        "identity",
    ],
)
def test_changed_policy_material_cannot_be_rehashed_into_a_pass(
    tmp_path, runtime, mutation
):
    fixture = make_policy_replay(tmp_path, runtime=runtime)
    if mutation == "missing_replay":
        fixture.row.pop("replay")
    elif mutation == "fake_assessment":
        from agentguard_core.decisions.evidence import FastAssessment
        from agentguard_core.decisions.shadow import compute_assessment_digest

        assessment = FastAssessment.model_validate(
            fixture.row["assessment"]
        ).model_copy(update={"disposition": "ALLOW"})
        assessment = assessment.model_copy(
            update={"assessment_digest": compute_assessment_digest(assessment)}
        )
        fixture.row["assessment"] = assessment.model_dump(mode="json")
    elif mutation == "fake_legacy":
        fixture.row["authority"]["current_decision"][
            "reason"
        ] = "fabricated current policy"
    elif mutation == "active":
        fixture.replay["product_active_enabled"] = True
    elif mutation == "coverage":
        fixture.replay["coverage"]["dataflow"] = "partial"
    elif mutation == "transient":
        fixture.replay["transient_facts"]["flow_facts"] = []
    elif mutation == "sealed_proof":
        fixture.replay["product_data"]["taints"] = ["UNTRUSTED"]
    elif mutation == "original_output":

        def change(raw):
            payload = raw["events"][0]["payload"]
            projection = json.loads(payload["content_preview"])
            projection["tool_calls"][0]["args"][
                "content"
            ] = "different original content"
            payload["content_preview"] = canonical_json(projection)

        _rewrite(fixture, "history", change)
    elif mutation == "missing_receipt":
        _rewrite(
            fixture,
            "history",
            lambda raw: raw.update(
                audits=[
                    row
                    for row in raw["audits"]
                    if row["audit_id"] != "audit_outcome_output_execution_completed"
                ]
            ),
        )
    elif mutation == "revoked_ack":
        _rewrite(
            fixture,
            "history",
            lambda raw: raw["acknowledgements"][0]["record"].update(
                revoked_at=fixture.ack.issued_at
            ),
        )
    elif mutation == "unsigned_ack":
        _rewrite(
            fixture,
            "evaluation_ack",
            lambda raw: raw.update(ack_token="hmac-sha256:" + "0" * 64),
        )
    elif mutation == "snapshot_digest":
        _rewrite(fixture, "snapshot", lambda raw: raw.update(snapshot_digest=DIGEST))
    elif mutation == "stale_state":

        def change(raw):
            raw["state_version"] += 1
            raw["snapshot_digest"] = canonical_sha256(
                snapshot_digest_projection(SecuritySnapshot.model_validate(raw))
            )

        _rewrite(fixture, "current_snapshot", change)
    elif mutation == "grant_digest":

        def change(raw):
            raw["grants"][0]["grant_digest"] = DIGEST
            raw["snapshot_digest"] = canonical_sha256(
                snapshot_digest_projection(SecuritySnapshot.model_validate(raw))
            )

        _rewrite(fixture, "snapshot", change)
    elif mutation == "key_permission":
        (tmp_path / fixture.replay["product_key"]["path"]).chmod(0o644)
    elif mutation == "identity":
        fixture.row["event"]["security_context"]["agent_id"] = "different-agent"
    if "replay" in fixture.row:
        fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError) as failure:
        _verify_fixture(fixture)
    assert str(failure.value) == failure.value.code
    assert fixture.ack.ack_token not in str(failure.value)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_read",
        "missing_result",
        "changed_body",
        "changed_read_policy",
        "duplicate_prior",
    ],
)
def test_command_ask_requires_original_read_result_and_replayed_parent(
    tmp_path, runtime, mutation
):
    fixture = make_policy_replay(
        tmp_path, runtime=runtime, group="ask", category="command"
    )
    if mutation == "missing_read":
        fixture.replay["prior_actions"] = []
    elif mutation == "duplicate_prior":
        fixture.replay["prior_actions"] *= 2
    elif mutation in {"missing_result", "changed_body"}:

        def change(raw):
            if mutation == "missing_result":
                raw["events"] = [
                    row
                    for row in raw["events"]
                    if row["event_type"] != "tool_result_produced"
                ]
            else:
                result = next(
                    row
                    for row in raw["events"]
                    if row["event_type"] == "tool_result_produced"
                )["payload"]["result"]
                result["content_preview"] = "x" * result["size_bytes"]

        _rewrite(fixture, "history", change)
    else:
        ref = fixture.replay["prior_actions"][0]
        prior = json.loads((tmp_path / ref["path"]).read_bytes())
        prior["authority"]["selected_decision"]["reason"] = "fabricated read evaluation"
        fixture.replay["prior_actions"][0] = _save(tmp_path, ref["path"], prior)
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError):
        _verify_fixture(fixture)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "mutation", ["missing_raw", "public_ack_only", "wrong_accepted"]
)
def test_command_read_requires_original_private_terminal(tmp_path, runtime, mutation):
    fixture = make_policy_replay(
        tmp_path, runtime=runtime, group="ask", category="command"
    )
    prior = EvidenceStore(tmp_path).read_json(fixture.replay["prior_actions"][0]).data
    if mutation == "missing_raw":
        prior.pop("receipt")
    elif mutation == "public_ack_only":
        raw = EvidenceStore(tmp_path).read_json(prior["receipt"]).data
        raw["metadata"]["activation_ack"].pop("ack_token")
        prior["receipt"] = _save(tmp_path, "rewritten-raw.json", raw)
    else:
        accepted = EvidenceStore(tmp_path).read_json(prior["accepted"]).data
        accepted["summary"] = "Unrelated accepted read"
        prior["accepted"] = _save(tmp_path, "rewritten-accepted.json", accepted)
    fixture.replay["prior_actions"] = [_save(tmp_path, "rewritten-prior.json", prior)]
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError):
        _verify_fixture(fixture)


@pytest.mark.parametrize(
    "mutation", ["missing_start", "confirmation_failed", "unlinked_start"]
)
def test_command_read_cannot_omit_its_own_langgraph_start(tmp_path, mutation):
    fixture = make_policy_replay(
        tmp_path, runtime="langgraph", group="ask", category="command"
    )
    prior = EvidenceStore(tmp_path).read_json(fixture.replay["prior_actions"][0]).data
    assert fixture.prior_read.start is not None
    if mutation == "missing_start":
        prior["start"] = None
    else:
        document = EvidenceStore(tmp_path).read_json(prior["start"]).data
        key = "confirmation" if mutation == "confirmation_failed" else "wire"
        raw = EvidenceStore(tmp_path).read_json(document[key]).data
        if key == "confirmation":
            raw["response"]["ok"] = False
        else:
            raw["links"]["parent_audit_id"] = "unrelated-policy"
        document[key] = _save(tmp_path, "rewritten-start-material.json", raw)
        prior["start"] = _save(tmp_path, "rewritten-start.json", document)
    fixture.replay["prior_actions"] = [_save(tmp_path, "rewritten-prior.json", prior)]
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError):
        _verify_fixture(fixture)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_first_memory_write_remains_ask_with_allow_profile(tmp_path, runtime):
    fixture = make_policy_replay(
        tmp_path,
        runtime=runtime,
        group="allow",
        category="memory",
        memory_first_write=True,
    )
    assert fixture.event.event_type == "memory_write_proposed"
    assert fixture.snapshot.memory_facts == []
    assert _verify_fixture(fixture).selected_decision.decision == "ask"


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_event_before_refreshed_ack_uses_actual_server_capture_clock(tmp_path, runtime):
    fixture = make_policy_replay(tmp_path, runtime=runtime)
    event_clock = datetime.fromisoformat(fixture.snapshot.evaluation_clock.evaluated_at)
    issued = event_clock + timedelta(milliseconds=1)
    checked = event_clock + timedelta(milliseconds=2)
    secret = (tmp_path / fixture.replay["product_key"]["path"]).read_bytes()
    values = fixture.ack.token_projection()
    values.pop("schema_version")
    values.update(
        issued_at=issued.isoformat(),
        expires_at=(issued + timedelta(seconds=100)).isoformat(),
    )
    fresh = build_activation_ack(server_secret=secret, **values)
    record = ProductActivationAckRecordV1.from_ack(
        fresh, principal_id=fixture.snapshot.scope.principal_id
    )
    # Keep historical model input/output receipts on their own original ACK.
    fixture.history["acknowledgements"].append(
        {"ack": fresh.model_dump(mode="json"), "record": record.model_dump(mode="json")}
    )
    fixture.replay["history"] = _save(tmp_path, "history.json", fixture.history)
    fixture.replay["evaluation_ack"] = _save(
        tmp_path, "refreshed-ack.json", fresh.model_dump(mode="json")
    )
    fixture.replay["server_capture"]["checked_at"] = checked.isoformat()
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    result = _verify_fixture(fixture)
    assert result == fixture.authority
    assert fixture.snapshot.evaluation_clock.evaluated_at == fixture.event.timestamp
    assert event_clock < issued < checked
    fixture.replay["server_capture"]["checked_at"] = event_clock.isoformat()
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError):
        _verify_fixture(fixture)


@pytest.mark.parametrize(
    "field",
    [
        "event_id",
        "policy_audit_id",
        "event_digest",
        "snapshot_digest",
        "activation_ref_digest",
        "decision_authority_digest",
    ],
)
def test_server_capture_must_identify_the_original_policy(tmp_path, field):
    fixture = make_policy_replay(tmp_path)
    fixture.replay["server_capture"][field] = (
        DIGEST if field.endswith("digest") else "unrelated-policy-event"
    )
    fixture.row["replay"] = _save(tmp_path, "replay.json", fixture.replay)
    with pytest.raises(AdmissionError):
        _verify_fixture(fixture)
