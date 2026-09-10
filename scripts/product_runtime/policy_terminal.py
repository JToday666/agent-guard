"""Validate a target outcome against the real Product policy and private state."""

from __future__ import annotations

from typing import Any, Literal, cast

from agentguard_core import (
    ActivationAckV1,
    AuditEvent,
    GuardEvent,
    PolicyBundle,
    ProductActivationBundleV1,
    RuntimeOutcomeReceipt,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import GrantConsumption
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.services.audit import AuditService
from guard_api.services.ct_projection import decode_ct_transient_facts
from guard_api.services.product_model_content import (
    ACK_VALIDATION_KEY,
    _receipt,
    build_product_ack_validation,
)
from guard_api.services.redaction import sanitize_audit_event
from guard_api.storage.base import ControlPlaneStore
from guard_api.storage.memory import _lease_matches_binding

from .evidence import EvidenceStore
from .models import (
    AdmissionError,
    Digest,
    EvidenceRef,
    Identifier,
    Runtime,
    StrictModel,
    read_model,
)
from .policy_evidence import (
    PolicyHistory,
    PolicyReplay,
    _HistoryStore,
    _key,
    _same,
    _snapshot,
    _time,
    _typed,
    verify_policy_evidence,
)


class PolicyTerminal(StrictModel):
    schema_version: Literal["agentguard-product-policy-terminal/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    execution_scope: Literal["isolated_contract_fixture"]
    runtime: Runtime
    scope_id: Identifier
    candidate_manifest_digest: Digest
    adapter_artifact_digest: Digest
    parent: EvidenceRef
    receipt: EvidenceRef
    accepted: EvidenceRef
    ack: EvidenceRef
    history: EvidenceRef
    consumption: EvidenceRef | None
    start: EvidenceRef | None


def _require(value: object) -> None:
    if not value:
        raise AdmissionError("conformance_policy_terminal_invalid")


def verify_policy_terminal(
    reference: EvidenceRef | dict[str, Any],
    *,
    row: dict[str, Any],
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
) -> RuntimeOutcomeReceipt:
    try:
        return _verify(
            reference,
            row=row,
            runtime=runtime,
            scope_id=scope_id,
            policy=policy,
            store=store,
            candidate_manifest_digest=candidate_manifest_digest,
            adapter_artifact_digest=adapter_artifact_digest,
        )
    except Exception:
        # Private lease fingerprints and ACKs never escape a failed parse.
        raise AdmissionError("conformance_policy_terminal_invalid") from None


def _verify(
    reference: EvidenceRef | dict[str, Any],
    *,
    row: dict[str, Any],
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
) -> RuntimeOutcomeReceipt:
    document = read_model(PolicyTerminal, store.read_json(reference).data)
    _require(
        (
            document.runtime,
            document.scope_id,
            document.candidate_manifest_digest,
            document.adapter_artifact_digest,
        )
        == (runtime, scope_id, candidate_manifest_digest, adapter_artifact_digest)
    )
    authority = verify_policy_evidence(
        row,
        runtime=runtime,
        scope_id=scope_id,
        policy=policy,
        store=store,
        candidate_manifest_digest=candidate_manifest_digest,
        adapter_artifact_digest=adapter_artifact_digest,
    )
    replay = read_model(PolicyReplay, store.read_json(row["replay"]).data)
    product_key, scope_key = (
        _key(store, getattr(replay, key)) for key in ("product_key", "scope_key")
    )
    snapshot = _snapshot(store, replay.snapshot, policy, scope_key)
    activation = _typed(
        ProductActivationBundleV1, store.read_json(replay.activation).data
    )
    history = read_model(PolicyHistory, store.read_json(document.history).data)
    _require(history.scope_id == scope_id)
    records = _HistoryStore(history, snapshot, activation, product_key)
    original = read_model(PolicyHistory, store.read_json(replay.history).data)
    # Terminal collection can append records, never replace the policy's history.
    for key, identity in (
        ("events", "event_id"),
        ("audits", "audit_id"),
        ("approvals", "approval_id"),
        ("bindings", "approval_id"),
        ("leases", "lease_id"),
    ):
        current = {item[identity]: item for item in getattr(history, key)}
        for item in getattr(original, key):
            _same(current.get(item[identity]), item)
    for ack_record in original.acknowledgements:
        _require(ack_record in history.acknowledgements)
    event = _typed(GuardEvent, row["event"])
    _same(records.events[event.event_id].model_dump(mode="json"), row["event"])
    parent = _typed(AuditEvent, store.read_json(document.parent).data)
    # Node emits millisecond ISO timestamps ending in Z and omits optional
    # defaults. Preserve the raw evidence file, then use the API's receipt
    # parser for its supported canonicalization instead of requiring a dump
    # identical to the producer's JSON representation.
    wire = RuntimeOutcomeReceipt.model_validate(
        store.read_json(document.receipt).data, strict=True
    )
    accepted = _typed(AuditEvent, store.read_json(document.accepted).data)
    ack = _typed(ActivationAckV1, store.read_json(document.ack).data)
    _require(parent.audit_id == row["policy_audit_id"])
    _require(
        records.audits[parent.audit_id] == parent
        and records.audits[accepted.audit_id] == accepted
    )
    _same(
        parent.evidence["decision_authority"]["payload"],
        authority.model_dump(mode="json"),
    )
    _same(
        parent.evidence["guard_decision"],
        authority.selected_decision.model_dump(mode="json"),
    )
    _same(parent.evidence["product_action_data"], replay.product_data)
    ct = decode_ct_transient_facts(parent)
    _require(ct.kind == "full" and ct.bundle is not None)
    assert ct.bundle is not None
    _same(ct.bundle.model_dump(mode="json"), replay.transient_facts)
    _require(parent.links.get("event_id") == event.event_id == authority.event_id)
    _require(parent.links.get("action_id") == row["assessment"]["action_id"])
    _require(parent.links.get("decision_id") == authority.selected_decision.decision_id)
    _require(wire.metadata.activation_ack is not None)
    assert wire.metadata.activation_ack is not None
    _same(
        ack.model_dump(mode="json"),
        wire.metadata.activation_ack.model_dump(mode="json"),
    )
    issued = records.get_product_activation_ack(
        activation_ack_token_digest(ack.ack_token)
    )
    _require(issued is not None)
    assert issued is not None
    _same(issued.ack_projection, ack.token_projection())
    entry = activation.runtime_entry(cast(Any, runtime))
    _require(
        (
            ack.runtime,
            ack.runtime_binding_id,
            ack.agent_id,
            ack.profile_id,
            ack.activation_ref_digest,
            ack.capability_digest,
            issued.principal_id,
        )
        == (
            runtime,
            snapshot.scope.runtime_binding_id,
            event.security_context.agent_id,
            authority.profile_id,
            activation.activation_ref_digest,
            entry.capability_report_digest,
            snapshot.scope.principal_id,
        )
    )
    _same(
        parent.decision_authority, authority.decision_authority.model_dump(mode="json")
    )
    normalized = sanitize_audit_event(
        AuditEvent.model_validate(wire.model_dump(mode="json"))
    )
    normalized.metadata[ACK_VALIDATION_KEY] = build_product_ack_validation(wire, parent)
    _same(
        normalized.model_dump(mode="json", exclude={"integrity"}),
        accepted.model_dump(mode="json", exclude={"integrity"}),
    )
    service = AuditService(store=cast(ControlPlaneStore, records))
    _require(service._validate_runtime_outcome_parent(wire) == parent)
    service._validate_runtime_outcome_authority(wire, parent)
    initial = _time(parent.metadata["product_authority_initial_checked_at"])
    _require(initial == _time(replay.server_capture.checked_at))
    _require(
        _time(snapshot.evaluation_clock.evaluated_at)
        <= initial
        <= _time(wire.timestamp)
    )
    _require(
        _time(activation.issued_at) <= initial < _time(activation.expires_at)
        and initial < _time(entry.expires_at)
    )
    anchor = initial
    decision = authority.selected_decision.decision
    if runtime == "langgraph" and decision != "deny":
        from .policy_start import verify_policy_start

        _require(document.start is not None)
        assert document.start is not None
        verify_policy_start(
            document.start,
            row=row,
            parent=parent,
            terminal=wire,
            replay=replay,
            store=store,
            records=records,
        )
    else:
        _require(document.start is None and wire.links.parent_audit_id is None)
    if decision == "ask":
        _require(document.consumption is not None)
        _require(wire.links.approval_id is not None and wire.links.lease_id is not None)
        assert wire.links.approval_id is not None and wire.links.lease_id is not None
        consumption = _typed(
            GrantConsumption, store.read_json(document.consumption).data
        )
        binding = records.bindings.get(wire.links.approval_id)
        lease = records.leases.get(wire.links.lease_id)
        approval = records.approvals.get(wire.links.approval_id)
        _require(binding is not None and lease is not None and approval is not None)
        assert binding is not None and lease is not None and approval is not None
        _require(
            binding.authorization_fingerprint
            == row["assessment"]["authorization_fingerprint"]
        )
        _require(binding.action_id == row["assessment"]["action_id"])
        _require(_lease_matches_binding(lease, binding, consumption))
        _require(
            consumption.consumed_uses == 1
            and consumption.consumption_id == wire.links.consumption_id
        )
        anchor = _time(lease.issued_at)
        _require(
            initial
            <= _time(approval.created_at)
            <= _time(approval.resolved_at)
            <= anchor
            <= _time(wire.timestamp)
        )
        _require(
            anchor < _time(approval.expires_at) and anchor < _time(lease.expires_at)
        )
        if wire.evidence.execution.invoked_at is not None:
            _require(
                anchor
                <= _time(wire.evidence.execution.invoked_at)
                < _time(lease.expires_at)
            )
    else:
        _require(
            document.consumption is None
            and wire.links.approval_id is None
            and wire.links.lease_id is None
            and wire.evidence.enforcement is None
        )
    _require(_time(ack.issued_at) <= anchor < _time(ack.expires_at))
    _require(issued.revoked_at is None or anchor < _time(issued.revoked_at))
    _require(anchor <= _time(wire.timestamp))
    if decision == "deny":
        _require(
            wire.metadata.outcome_kind == "pre_execution_deny"
            and wire.evidence.execution.status == "not_invoked"
            and wire.evidence.execution.invoked_at is None
            and wire.evidence.result.disposition == "not_applicable"
        )
    else:
        _require(
            wire.metadata.outcome_kind == "execution_completed"
            and wire.evidence.execution.status == "executed"
            and wire.evidence.result.disposition
            in (
                {"passed_through", "modified", "quarantined", "unknown"}
                if runtime == "openclaw"
                else {"passed_through", "modified", "quarantined"}
            )
        )
        _require(
            _receipt(
                cast(ControlPlaneStore, records),
                parent,
                authority,
                snapshot,
                action_terminal=True,
            )
            is not None
        )
    if runtime == "openclaw":
        _require(wire.evidence.execution.invoked_at is None)
        _same(wire.resource_targets, event.security_context.derived_paths)
    _require(
        canonical_sha256(parent.evidence["decision_authority"]["payload"])
        == accepted.metadata[ACK_VALIDATION_KEY]["parent_authority_digest"]
    )
    store.recheck_reads()
    return wire
