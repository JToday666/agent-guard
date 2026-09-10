"""Typed synthetic first-write inputs; never host or operator qualification."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace

from agentguard_core import (
    AuditEvent,
    ContextSource,
    MemoryGuardChange,
    RuntimeOutcomeReceipt,
    product_decision_authority_envelope,
)
from agentguard_core.actions.canonical_json import canonical_json, canonical_sha256
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.security_context import ExecutionLease, GrantConsumption
from agentguard_core.signals.models import SequenceRef
from guard_api.models import ApprovalRequest
from guard_api.security_state.transient import TransientSecurityFacts
from guard_api.services.ct_projection import (
    CtProjectionService,
    ct_transient_facts_envelope,
)
from guard_api.services.evidence import build_audit_event
from guard_api.services.product_model_content import build_product_ack_validation
from guard_api.services.redaction import sanitize_audit_event
from guard_api.storage.base import EnforcementBindingRecord
from tests.test_product_runtime_admission import receipt_frames
from tests.test_product_runtime_policy_evidence import _save, make_policy_replay


def build_memory_prerequisite(
    root: Path,
    read_replay,
    *,
    evidence_root: Path,
):
    """Return a rebuilt read fixture plus its typed, same-policy first write.

    ``read`` replaces the caller's earlier memory ALLOW replay. ``reference``
    is attached both to its row and the observation's memory_prerequisite frame.
    This fixture does not claim that the synthetic human-shaped approval was
    actually operated; the surrounding report labels the synthetic scope.
    """
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime = read_replay.event.runtime
    shared = {
        "runtime": runtime,
        "group": "allow",
        "category": "memory",
        "candidate_manifest_digest": read_replay.replay["candidate_manifest_digest"],
        "adapter_artifact_digest": read_replay.replay["adapter_artifact_digest"],
        "scope_id": read_replay.scope_id,
        "evidence_root": evidence_root,
    }
    write = make_policy_replay(root / "first-write", memory_first_write=True, **shared)
    assert write.authority.selected_decision.decision == "ask"
    write.row["policy_audit_id"] = "unit-memory-first-write-policy"
    write.replay["server_capture"]["policy_audit_id"] = write.row["policy_audit_id"]
    authority = write.authority
    decision = authority.selected_decision
    evaluated = datetime.fromisoformat(write.snapshot.evaluation_clock.evaluated_at)

    def timestamp(offset):
        return (evaluated + timedelta(seconds=offset)).isoformat()

    change_id = "unit-memory-first-write"
    approval_id = "unit-memory-first-write-approval"
    consumption_id = "unit-memory-first-write-consumption"
    grant_id = "unit-memory-first-write-grant"
    action_id = write.assessment.action_id
    bundle = TransientSecurityFacts.model_validate(write.replay["transient_facts"])
    assert len(bundle.memory_facts) == 1
    committed = bundle.memory_facts[0].model_copy(
        update={
            "change_id": change_id,
            "change_status": "committed",
            "trust_state": "quarantined",
            "last_write_sequence": SequenceRef(
                domain="memory", producer_binding_id=change_id, value=2
            ),
        }
    )
    assert committed.trust_state != "clean"
    memory = write.event.payload.memory
    change = MemoryGuardChange(
        change_id=change_id,
        trace_id=write.event.trace_id,
        namespace=memory.namespace,
        key=memory.key,
        value_preview=memory.value_preview,
        source_trust="unknown",
        runtime=runtime,
        agent_id=write.event.security_context.agent_id,
        principal_id=write.snapshot.scope.principal_id,
        status="committed",
        created_at=timestamp(0),
        updated_at=timestamp(3),
        metadata={
            "event_id": write.event.event_id,
            "decision_id": decision.decision_id,
        },
    )
    ct = CtProjectionService.commit_envelope(
        None,
        bundle,
        source_record_id=f"ct-facts:{write.event.event_id}",
        projection_id=f"projection:{write.event.event_id}",
        base_state_version=write.snapshot.state_version,
        projection_eligible=True,
    )
    parent = build_audit_event(
        write.event,
        decision,
        policy_bundle=write.policy,
        policy_revision=None,
        approval_id=approval_id,
        memory_change_id=change_id,
        audit_id=write.row["policy_audit_id"],
        extra_metadata={
            "product_authority_initial_checked_at": timestamp(0),
            "product_model_task": {
                "task_id": write.snapshot.task.task_id,
                "task_revision": write.snapshot.task.revision,
                "task_digest": write.snapshot.task.task_digest,
                "scope_digest": write.snapshot.task.scope_digest,
            },
        },
        decision_authority=authority.decision_authority,
        decision_authority_evidence=product_decision_authority_envelope(authority),
        v21_evidence=decision_evidence_v21_envelope(
            build_decision_evidence_v21(
                write.assessment,
                legacy_decision=authority.current_decision.decision,
                snapshot_id=write.snapshot.snapshot_id,
                state_version=write.snapshot.state_version,
                coverage=write.coverage,
                mode="active",
                selected_decision="ask",
            )
        ),
        ct_facts_evidence=ct_transient_facts_envelope(ct),
        product_action_data=write.product_data.model_dump(mode="json"),
    )
    assert parent.links["action_id"] == action_id
    approval = ApprovalRequest(
        approval_id=approval_id,
        trace_id=write.event.trace_id,
        subject_id=action_id,
        subject_type="memory",
        action_id=action_id,
        action_name="agentguard_memory_write",
        requesting_principal_id=write.snapshot.scope.principal_id,
        runtime=runtime,
        agent_id=write.event.security_context.agent_id,
        status="resolved",
        decision="allow_once",
        resource=committed.memory_id,
        reason="Synthetic first-write protocol fixture",
        risk_score=decision.risk_score,
        severity=decision.severity,
        evidence={
            "decision_authority": authority.decision_authority.model_dump(mode="json"),
            "approval_release_directive": authority.approval_release_directive.model_dump(
                mode="json"
            ),
        },
        resolution_source="human",
        resolved_by="synthetic-unit-operator",
        resolution_reason="Unit protocol input; no actual operator confirmation",
        created_at=timestamp(0),
        expires_at=timestamp(90),
        resolved_at=timestamp(1),
    )
    binding = EnforcementBindingRecord(
        event_id=write.event.event_id,
        policy_audit_id=parent.audit_id,
        approval_id=approval_id,
        action_id=action_id,
        action_type="memory_write",
        authorization_fingerprint=write.assessment.authorization_fingerprint,
        runtime_binding_id=write.snapshot.scope.runtime_binding_id,
        scope_digest=write.scope_digest,
        principal_id=write.snapshot.scope.principal_id,
        runtime=runtime,
        agent_id=write.event.security_context.agent_id,
        policy_revision=write.snapshot.policy_revision,
        requires_execution_lease=True,
        grant_id=grant_id,
        created_at=timestamp(0),
        release_mode=authority.approval_release_directive.mode,
    )
    consumption = GrantConsumption(
        consumption_id=consumption_id,
        grant_id=grant_id,
        action_id=action_id,
        authorization_fingerprint=binding.authorization_fingerprint,
        sequence=None,
        evidence_refs=[],
    )
    lease = ExecutionLease(
        lease_id="unit-memory-first-write-lease",
        consumption_id=consumption_id,
        approval_id=approval_id,
        grant_id=grant_id,
        action_id=action_id,
        authorization_fingerprint=binding.authorization_fingerprint,
        runtime_binding_id=binding.runtime_binding_id,
        issued_at=timestamp(2),
        expires_at=timestamp(60),
        token_digest=canonical_sha256("synthetic unit lease token"),
        status="consumed",
        evidence_refs=[],
    )
    wire = json.loads(receipt_frames()[0][2]["wire"])
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
    wire.update(
        audit_id=f"audit_outcome_{write.event.event_id}_execution_completed",
        timestamp=timestamp(3),
    )
    wire["links"] = {
        key: parent.links[key]
        for key in ("event_id", "decision_id", "action_id", "approval_id")
    }
    wire["links"].update(
        policy_audit_id=parent.audit_id,
        lease_id=lease.lease_id,
        consumption_id=consumption_id,
    )
    wire["metadata"].update(
        agent_id=write.event.security_context.agent_id,
        activation_ack=write.ack.model_dump(mode="json"),
    )
    wire["evidence"]["execution"].update(
        completed_at=timestamp(3),
        invoked_at=timestamp(2) if runtime == "langgraph" else None,
        persisted=True if runtime == "openclaw" else None,
    )
    wire["evidence"]["side_effects"] = {
        "measurement_status": "measured",
        "count": 1,
        "summary": "Synthetic SQLite first write",
    }
    wire["evidence"]["result"]["disposition"] = "passed_through"
    wire["evidence"]["approval"] = {
        "approval_id": approval_id,
        "status": "allowed",
        "decision": "allow_once",
        "resolved_at": timestamp(1),
    }
    wire["evidence"]["enforcement"] = {
        "release_mode": binding.release_mode,
        "gate_state": "approval_released",
        "binding_check_status": "passed" if runtime == "langgraph" else "not_performed",
        "lease_consume_outcome": "consumed",
        "reason_codes": [
            (
                "rte-05:binding_exact"
                if runtime == "langgraph"
                else "v21:restricted_allow_once"
            ),
            "rte-05:lease_consumed",
        ],
    }
    start = None
    if runtime == "langgraph":
        from tests.product_runtime_start_fixture import build_policy_start

        start = build_policy_start(
            root / "start", write, parent, wire, evidence_root=evidence_root
        )
        wire["links"]["parent_audit_id"] = start.start_audit_id
        wire["resource_targets"] = start.start.resource_targets
    receipt = RuntimeOutcomeReceipt.model_validate(wire)
    terminal = sanitize_audit_event(
        AuditEvent.model_validate(receipt.model_dump(mode="json"))
    )
    terminal.metadata["product_ack_validation"] = build_product_ack_validation(
        receipt, parent
    )
    history = deepcopy(write.history)
    history["approvals"] = [approval.model_dump(mode="json")]
    history["bindings"] = [asdict(binding)]
    history["leases"] = [lease.model_dump(mode="json")]
    history["events"].append(write.event.model_dump(mode="json"))
    history["audits"].extend(
        [parent.model_dump(mode="json"), terminal.model_dump(mode="json")]
    )

    def save(name, value):
        return _save(root, name, value, evidence_root=evidence_root)

    write.replay["history"] = save("write-history.json", history)
    write.row["replay"] = save("write-replay.json", write.replay)
    write.history = history
    read_shared = SimpleNamespace(**vars(write))
    read_shared.snapshot = write.snapshot.model_copy(
        update={
            "evaluation_clock": write.snapshot.evaluation_clock.model_copy(
                update={"evaluated_at": timestamp(4)}
            )
        }
    )
    read = make_policy_replay(
        root / "read",
        shared_fixture=read_shared,
        memory_fact_override=committed,
        **shared,
    )
    read.row["memory_fact_id"] = committed.memory_id
    body = canonical_json({"key": change.key, "value": change.value_preview})
    source = ContextSource(
        source_id=committed.memory_id,
        source_type="memory",
        source_trust="unknown",
        role="tool",
        summary=body,
        content_digest=canonical_sha256(body),
        sequence_index=0,
    )
    document = {
        "schema_version": "agentguard-product-memory-prerequisite/1",
        "authority_kind": "synthetic_contract_fixture",
        "execution_scope": "isolated_contract_fixture",
        "runtime": runtime,
        "scope_id": read.scope_id,
        "candidate_manifest_digest": read.replay["candidate_manifest_digest"],
        "adapter_artifact_digest": read.replay["adapter_artifact_digest"],
        "write_policy": save("write-policy.json", write.row),
        "write_parent": save("write-parent.json", parent.model_dump(mode="json")),
        "terminal": save("terminal.json", terminal.model_dump(mode="json")),
        "receipt": save("receipt.json", receipt.model_dump(mode="json")),
        "ack": save("ack.json", write.ack.model_dump(mode="json")),
        "change": save("change.json", change.model_dump(mode="json")),
        "consumption": save("consumption.json", consumption.model_dump(mode="json")),
        "read_snapshot": read.replay["snapshot"],
        "context_source": save("context-source.json", source.model_dump(mode="json")),
        "start": start.reference if start else None,
    }
    reference = save("prerequisite.json", document)
    read.row["memory_prerequisite"] = reference
    return SimpleNamespace(
        reference=reference,
        document=document,
        read=read,
        write=write,
        parent=parent,
        terminal=terminal,
        receipt=receipt,
        ack=write.ack,
        approval=approval,
        binding=binding,
        lease=lease,
        consumption=consumption,
        change=change,
        memory_fact=committed,
        source=source,
        start=start,
    )
