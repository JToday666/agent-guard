"""Validate LangGraph's actual pre-invocation observation and confirmation."""

from __future__ import annotations

from typing import Any, Literal

from agentguard_core import ActivationAckV1, AuditEvent, RuntimeOutcomeReceipt
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.services.redaction import sanitize_audit_event

from .evidence import EvidenceStore
from .models import (
    AdmissionError,
    Digest,
    EvidenceRef,
    Identifier,
    StrictModel,
    read_model,
)
from .policy_evidence import PolicyReplay, _HistoryStore, _same, _time, _typed


class PolicyStart(StrictModel):
    schema_version: Literal["agentguard-product-policy-start/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    execution_scope: Literal["isolated_contract_fixture"]
    runtime: Literal["langgraph"]
    scope_id: Identifier
    candidate_manifest_digest: Digest
    adapter_artifact_digest: Digest
    wire: EvidenceRef
    accepted: EvidenceRef
    ack: EvidenceRef
    confirmation: EvidenceRef


class StartConfirmation(StrictModel):
    method: Literal["POST"]
    path: Literal["/v1/audit/events"]
    request_raw_sha256: Digest
    status: Literal[200]
    response: dict[str, Any]
    confirmed_at: str


def _require(value: object) -> None:
    if not value:
        raise AdmissionError("conformance_policy_start_invalid")


def verify_policy_start(
    reference: EvidenceRef | dict[str, Any],
    *,
    row: dict[str, Any],
    parent: AuditEvent,
    terminal: RuntimeOutcomeReceipt,
    replay: PolicyReplay,
    store: EvidenceStore,
    records: _HistoryStore,
) -> AuditEvent:
    try:
        return _verify(
            reference,
            row=row,
            parent=parent,
            terminal=terminal,
            replay=replay,
            store=store,
            records=records,
        )
    except Exception:
        raise AdmissionError("conformance_policy_start_invalid") from None


def _verify(reference, *, row, parent, terminal, replay, store, records):
    document = read_model(PolicyStart, store.read_json(reference).data)
    _require(
        (
            document.runtime,
            document.scope_id,
            document.candidate_manifest_digest,
            document.adapter_artifact_digest,
        )
        == (
            replay.runtime,
            replay.scope_id,
            replay.candidate_manifest_digest,
            replay.adapter_artifact_digest,
        )
    )
    _require(terminal.runtime == parent.runtime == "langgraph")
    _require(terminal.evidence.execution.status == "executed")
    _require(parent.decision in {"allow", "ask"})
    original = store.read_json(document.wire)
    # This is a generic observation, never a RuntimeOutcomeReceipt. The SDK's
    # private ACK belongs to its encrypted envelope, not this HTTP payload.
    start = AuditEvent.model_validate(original.data, strict=True)
    _require(start.record_type == "runtime_observation")
    accepted = _typed(AuditEvent, store.read_json(document.accepted).data)
    _same(
        sanitize_audit_event(start).model_dump(mode="json", exclude={"integrity"}),
        accepted.model_dump(mode="json", exclude={"integrity"}),
    )
    ack = _typed(ActivationAckV1, store.read_json(document.ack).data)
    _same(
        ack.model_dump(mode="json"),
        terminal.metadata.activation_ack.model_dump(mode="json"),
    )
    issuance = records.get_product_activation_ack(
        activation_ack_token_digest(ack.ack_token)
    )
    _require(issuance is not None)
    _same(issuance.ack_projection, ack.token_projection())
    event_id = row["event"]["event_id"]
    _require(start.audit_id == f"audit_commit_{event_id}")
    _require(start.trace_id == parent.trace_id == terminal.trace_id)
    _require(start.stage == start.event_type == "tool_call_committed")
    _require(start.schema_version == "0.4")
    _require(
        start.metadata
        == {
            "agent_id": terminal.metadata.agent_id,
            "observation_state": "action_intent",
        }
    )
    _require(
        start.decision is None
        and start.risk_score is None
        and start.severity is None
        and start.blocked is None
    )
    _require(
        not start.rule_hits and start.model_dump().get("decision_authority") is None
    )
    _same(start.resource_targets, terminal.resource_targets)
    event_data = row["event"]
    resources = event_data["payload"].get("derived_resources", [])
    targets = [item["target"] for item in resources if item.get("target")]
    targets.extend(event_data["security_context"].get("derived_paths", []))
    _same(start.resource_targets, list(dict.fromkeys(targets)))
    _require(terminal.links.parent_audit_id == start.audit_id)
    expected_links = terminal.links.model_dump(mode="json")
    expected_links["parent_audit_id"] = parent.audit_id
    _same(start.links, expected_links)
    _require(
        start.links["policy_audit_id"] == parent.audit_id == row["policy_audit_id"]
    )
    evidence = start.evidence
    _require(evidence is not None)
    assert evidence is not None
    _require(
        set(evidence)
        == {
            "intervention",
            "execution",
            "side_effects",
            "result",
            "approval",
        }
        | ({"enforcement"} if terminal.evidence.enforcement is not None else set())
    )
    _same(
        evidence["execution"],
        {
            "status": "unknown",
            "receipt_recorded": False,
            "invoked_at": None,
            "completed_at": None,
            "error": None,
            "tool_result_entered_context": None,
            "persisted": None,
        },
    )
    _same(
        evidence["side_effects"],
        {
            "measurement_status": "unknown",
            "count": None,
            "summary": "Invocation has not begun.",
        },
    )
    _same(
        evidence["result"],
        {"disposition": "unknown", "summary": None, "sanitized": None},
    )
    _same(evidence["approval"], terminal.evidence.approval.model_dump(mode="json"))
    enforcement = terminal.evidence.enforcement
    _same(
        evidence.get("enforcement"),
        enforcement.model_dump(mode="json") if enforcement else None,
    )
    _require(
        evidence["intervention"]["type"]
        == ("none" if parent.decision == "allow" else "approval_release")
    )
    confirmation = read_model(
        StartConfirmation, store.read_json(document.confirmation).data
    )
    _require(confirmation.request_raw_sha256 == original.file.raw_sha256)
    response = confirmation.response
    _require(set(response) == {"ok", "audit_id", "created", "idempotent_replay"})
    _require(response["ok"] is True and response["audit_id"] == start.audit_id)
    _require(
        type(response["created"]) is bool
        and type(response["idempotent_replay"]) is bool
    )
    _require(response["created"] != response["idempotent_replay"])
    started, confirmed = _time(start.timestamp), _time(confirmation.confirmed_at)
    invoked = _time(terminal.evidence.execution.invoked_at)
    _require(
        _time(ack.issued_at)
        <= started
        <= confirmed
        <= invoked
        <= _time(terminal.timestamp)
    )
    _require(invoked < _time(ack.expires_at))
    _require(_time(parent.metadata["product_authority_initial_checked_at"]) <= started)
    if issuance.revoked_at is not None:
        _require(_time(issuance.revoked_at) > confirmed)
    if parent.decision == "ask":
        lease = records.leases[terminal.links.lease_id]
        approval = records.approvals[terminal.links.approval_id]
        _require(_time(approval.resolved_at) <= _time(lease.issued_at) <= started)
        _require(invoked < _time(lease.expires_at))
    store.recheck_reads()
    return start
