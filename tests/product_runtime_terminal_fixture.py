"""Strict synthetic target outcomes, never native Host qualification records."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace

from agentguard_core import (
    AuditEvent,
    RuntimeOutcomeReceipt,
    product_decision_authority_envelope,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.security_context import ExecutionLease, GrantConsumption
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
from tests.test_product_runtime_policy_evidence import _save


def build_policy_terminal(root: Path, replay, *, evidence_root: Path):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def save(name, value):
        return _save(root, name, value, evidence_root=evidence_root)

    when = datetime.fromisoformat(replay.snapshot.evaluation_clock.evaluated_at)

    def timestamp(offset):
        return (when + timedelta(seconds=offset)).isoformat()

    authority, event = replay.authority, replay.event
    decision = authority.selected_decision
    runtime = event.runtime
    asking, denied = decision.decision == "ask", decision.decision == "deny"
    approval_id = "unit-target-approval" if asking else None
    bundle = TransientSecurityFacts.model_validate(replay.replay["transient_facts"])
    ct = CtProjectionService.commit_envelope(
        None,
        bundle,
        source_record_id=f"ct-facts:{event.event_id}",
        projection_id=f"projection:{event.event_id}",
        base_state_version=replay.snapshot.state_version,
        projection_eligible=True,
    )
    parent = build_audit_event(
        event,
        decision,
        policy_bundle=replay.policy,
        policy_revision=None,
        approval_id=approval_id,
        audit_id=replay.row["policy_audit_id"],
        extra_metadata={
            "product_authority_initial_checked_at": replay.replay["server_capture"][
                "checked_at"
            ],
            "product_model_task": {
                "task_id": replay.snapshot.task.task_id,
                "task_revision": replay.snapshot.task.revision,
                "task_digest": replay.snapshot.task.task_digest,
                "scope_digest": replay.scope_digest,
            },
        },
        decision_authority=authority.decision_authority,
        decision_authority_evidence=product_decision_authority_envelope(authority),
        v21_evidence=decision_evidence_v21_envelope(
            build_decision_evidence_v21(
                replay.assessment,
                legacy_decision=authority.current_decision.decision,
                snapshot_id=replay.snapshot.snapshot_id,
                state_version=replay.snapshot.state_version,
                coverage=replay.coverage,
                mode="active",
                selected_decision=decision.decision,
            )
        ),
        ct_facts_evidence=ct_transient_facts_envelope(ct),
        product_action_data=replay.product_data.model_dump(mode="json"),
    )
    action_id = parent.links["action_id"]
    approval = binding = lease = consumption = None
    if asking:
        approval = ApprovalRequest(
            approval_id=approval_id,
            trace_id=event.trace_id,
            subject_id=action_id,
            subject_type="action",
            action_id=action_id,
            action_name=replay.product_data.tool_name,
            requesting_principal_id=replay.snapshot.scope.principal_id,
            runtime=runtime,
            agent_id=event.security_context.agent_id,
            status="resolved",
            decision="allow_once",
            resource="synthetic isolated target",
            reason="Synthetic protocol input",
            risk_score=decision.risk_score,
            severity=decision.severity,
            evidence={
                "decision_authority": authority.decision_authority.model_dump(
                    mode="json"
                ),
                "approval_release_directive": authority.approval_release_directive.model_dump(
                    mode="json"
                ),
            },
            resolution_source="human",
            resolved_by="synthetic-unit-operator",
            resolution_reason="Unit input; no actual operator confirmation",
            created_at=timestamp(0),
            expires_at=timestamp(90),
            resolved_at=timestamp(1),
        )
        binding = EnforcementBindingRecord(
            event_id=event.event_id,
            policy_audit_id=parent.audit_id,
            approval_id=approval_id,
            action_id=action_id,
            action_type=(
                "memory_write"
                if event.event_type == "memory_write_proposed"
                else (
                    "message_send"
                    if event.event_type == "message_send_proposed"
                    else event.payload.tool.kind
                )
            ),
            authorization_fingerprint=replay.assessment.authorization_fingerprint,
            runtime_binding_id=replay.snapshot.scope.runtime_binding_id,
            scope_digest=replay.scope_digest,
            principal_id=replay.snapshot.scope.principal_id,
            runtime=runtime,
            agent_id=event.security_context.agent_id,
            policy_revision=replay.snapshot.policy_revision,
            requires_execution_lease=True,
            grant_id="unit-target-grant",
            created_at=timestamp(0),
            release_mode=authority.approval_release_directive.mode,
        )
        consumption = GrantConsumption(
            consumption_id="unit-target-consumption",
            grant_id=binding.grant_id,
            action_id=action_id,
            authorization_fingerprint=binding.authorization_fingerprint,
            sequence=None,
            evidence_refs=[],
        )
        lease = ExecutionLease(
            lease_id="unit-target-lease",
            consumption_id=consumption.consumption_id,
            approval_id=approval_id,
            grant_id=binding.grant_id,
            action_id=action_id,
            authorization_fingerprint=binding.authorization_fingerprint,
            runtime_binding_id=binding.runtime_binding_id,
            issued_at=timestamp(2),
            expires_at=timestamp(60),
            token_digest=canonical_sha256("synthetic target lease"),
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
    kind = "pre_execution_deny" if denied else "execution_completed"
    wire.update(
        audit_id=f"audit_outcome_{event.event_id}_{kind}", timestamp=timestamp(3)
    )
    wire["links"] = {
        key: parent.links[key] for key in ("event_id", "action_id", "decision_id")
    }
    wire["links"]["policy_audit_id"] = parent.audit_id
    if runtime == "langgraph":
        from agentguard_langgraph_adapter.runtime_receipts import _resource_targets

        wire["resource_targets"] = _resource_targets(event.model_dump(mode="json"))
    else:
        wire["resource_targets"] = list(event.security_context.derived_paths)
    wire["metadata"].update(
        agent_id=event.security_context.agent_id,
        activation_ack=replay.ack.model_dump(mode="json"),
        outcome_kind=kind,
    )
    wire["evidence"]["intervention"] = {
        "type": "deny" if denied else "approval_release" if asking else "allow",
        "reason": "Synthetic typed target observation",
    }
    wire["evidence"]["execution"].update(
        status="not_invoked" if denied else "executed",
        completed_at=timestamp(3),
        invoked_at=None if denied or runtime == "openclaw" else timestamp(2),
        persisted=event.event_type == "memory_write_proposed" and not denied,
    )
    wire["evidence"]["result"]["disposition"] = (
        "not_applicable"
        if denied
        else (
            "quarantined"
            if replay.product_data.tool_name == "agentguard_memory_read"
            else "passed_through"
        )
    )
    if replay.product_data.tool_name == "agentguard_memory_read":
        wire["evidence"]["execution"]["tool_result_entered_context"] = False
    wire["evidence"]["side_effects"] = {
        "measurement_status": "measured",
        "count": 0 if denied else 1,
        "summary": "Synthetic target fixture observation",
    }
    if asking:
        wire["links"].update(
            approval_id=approval_id,
            lease_id=lease.lease_id,
            consumption_id=consumption.consumption_id,
        )
        wire["evidence"]["approval"] = {
            "approval_id": approval_id,
            "status": "allowed",
            "decision": "allow_once",
            "resolved_at": timestamp(1),
        }
        wire["evidence"]["enforcement"] = {
            "release_mode": binding.release_mode,
            "gate_state": "approval_released",
            "binding_check_status": (
                "passed" if runtime == "langgraph" else "not_performed"
            ),
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
    if runtime == "openclaw":
        memory_written = event.event_type == "memory_write_proposed" and not denied
        wire["evidence"]["result"].update(
            disposition=(
                "not_applicable"
                if denied
                else "passed_through" if memory_written else "unknown"
            ),
            sanitized=False if denied or memory_written else None,
        )
        wire["evidence"]["execution"].update(
            invoked_at=None,
            tool_result_entered_context=False if denied else None,
            persisted=False if denied else True if memory_written else None,
        )
        wire["evidence"]["side_effects"].update(
            measurement_status="measured" if denied else "not_measured",
            count=0 if denied else None,
        )
        wire["evidence"]["approval"]["resolved_at"] = None
        node_time = (
            datetime.fromisoformat(wire["timestamp"])
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        wire["timestamp"] = node_time
        wire["evidence"]["execution"]["completed_at"] = node_time
    else:
        wire["evidence"]["execution"]["persisted"] = None
    start = None
    if runtime == "langgraph" and not denied:
        from tests.product_runtime_start_fixture import build_policy_start

        start = build_policy_start(
            root / "start", replay, parent, wire, evidence_root=evidence_root
        )
        wire["links"]["parent_audit_id"] = start.start_audit_id
    receipt = RuntimeOutcomeReceipt.model_validate(wire)
    terminal = sanitize_audit_event(
        AuditEvent.model_validate(receipt.model_dump(mode="json"))
    )
    terminal.metadata["product_ack_validation"] = build_product_ack_validation(
        receipt, parent
    )
    history = deepcopy(replay.history)
    # Shared-memory and command histories contain only previous actions.
    assert not any(item["event_id"] == event.event_id for item in history["events"])
    history["events"].append(event.model_dump(mode="json"))
    history["audits"].extend(
        [parent.model_dump(mode="json"), terminal.model_dump(mode="json")]
    )
    if asking:
        history["approvals"].append(approval.model_dump(mode="json"))
        history["bindings"].append(asdict(binding))
        history["leases"].append(lease.model_dump(mode="json"))
    document = {
        "schema_version": "agentguard-product-policy-terminal/1",
        "authority_kind": "synthetic_contract_fixture",
        "execution_scope": "isolated_contract_fixture",
        "runtime": runtime,
        "scope_id": replay.scope_id,
        "candidate_manifest_digest": replay.replay["candidate_manifest_digest"],
        "adapter_artifact_digest": replay.replay["adapter_artifact_digest"],
        "parent": save("parent.json", parent.model_dump(mode="json")),
        "receipt": save("receipt.json", wire),
        "accepted": save("accepted.json", terminal.model_dump(mode="json")),
        "ack": save("ack.json", replay.ack.model_dump(mode="json")),
        "history": save("history.json", history),
        "consumption": (
            save("consumption.json", consumption.model_dump(mode="json"))
            if asking
            else None
        ),
        "start": start.reference if start is not None else None,
    }
    reference = save("terminal-evidence.json", document)
    replay.row["terminal_evidence"] = reference
    return SimpleNamespace(
        reference=reference,
        document=document,
        parent=parent,
        receipt=receipt,
        terminal=terminal,
        ack=replay.ack,
        approval=approval,
        binding=binding,
        lease=lease,
        consumption=consumption,
        history=history,
        start=start,
    )
