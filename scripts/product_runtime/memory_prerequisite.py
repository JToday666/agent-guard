"""Verify a committed first write before accepting the memory-read ALLOW case.

These are isolated contract records, not claims of native host execution. The
conformance consumer separately checks the recorded host call and SQLite bytes.
The production memory proof reader owns approval, receipt and trust semantics.
"""

from __future__ import annotations

from typing import Any, Literal, cast

from agentguard_core import (
    ActivationAckV1,
    AuditEvent,
    ContextSource,
    GuardEvent,
    MemoryGuardChange,
    PolicyBundle,
    ProductActivationBundleV1,
    RuntimeOutcomeReceipt,
)
from agentguard_core.decisions.product import verify_activation_ack_token
from agentguard_core.actions.product_tools import product_tool_arguments
from agentguard_core.security_context import GrantConsumption, MemoryFact
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.security_state.delta_builder import MEMORY_TRANSITION_REVISIONS
from guard_api.services.ct_projection import decode_ct_transient_facts
from guard_api.services.evidence import _should_quarantine_memory_change
from guard_api.services.product_memory import (
    is_product_memory_completion,
    verify_product_memory_source,
)
from guard_api.services.product_model_content import (
    ACK_VALIDATION_KEY,
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


class MemoryPrerequisite(StrictModel):
    schema_version: Literal["agentguard-product-memory-prerequisite/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    execution_scope: Literal["isolated_contract_fixture"]
    runtime: Runtime
    scope_id: Identifier
    candidate_manifest_digest: Digest
    adapter_artifact_digest: Digest
    write_policy: EvidenceRef
    write_parent: EvidenceRef
    terminal: EvidenceRef
    receipt: EvidenceRef
    ack: EvidenceRef
    change: EvidenceRef
    consumption: EvidenceRef
    read_snapshot: EvidenceRef
    context_source: EvidenceRef
    start: EvidenceRef | None


def _require(value: object) -> None:
    if not value:
        raise AdmissionError("conformance_memory_prerequisite_invalid")


class _MemoryRecords(_HistoryStore):
    change: MemoryGuardChange

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None:
        return self.change if self.change.change_id == change_id else None


def verify_memory_prerequisite(
    reference: EvidenceRef | dict[str, Any],
    *,
    read_row: dict[str, Any],
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
) -> MemoryFact:
    """Recompute the original ASK and validate its immutable accepted outcome."""
    try:
        return _verify(
            reference,
            read_row=read_row,
            runtime=runtime,
            scope_id=scope_id,
            policy=policy,
            store=store,
            candidate_manifest_digest=candidate_manifest_digest,
            adapter_artifact_digest=adapter_artifact_digest,
        )
    except Exception:
        # Pydantic and production readers may otherwise expose private ACKs.
        raise AdmissionError("conformance_memory_prerequisite_invalid") from None


def _verify(
    reference: EvidenceRef | dict[str, Any],
    *,
    read_row: dict[str, Any],
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
) -> MemoryFact:
    document = read_model(MemoryPrerequisite, store.read_json(reference).data)
    _require(
        (
            document.runtime,
            document.scope_id,
            document.candidate_manifest_digest,
            document.adapter_artifact_digest,
        )
        == (runtime, scope_id, candidate_manifest_digest, adapter_artifact_digest)
    )
    write_row = store.read_json(document.write_policy).data
    _require(isinstance(write_row, dict))
    authority = verify_policy_evidence(
        write_row,
        runtime=runtime,
        scope_id=scope_id,
        policy=policy,
        store=store,
        candidate_manifest_digest=candidate_manifest_digest,
        adapter_artifact_digest=adapter_artifact_digest,
    )
    _require(
        authority.event_type == "memory_write_proposed"
        and authority.selected_decision.decision == "ask"
    )
    write = read_model(PolicyReplay, store.read_json(write_row["replay"]).data)
    read = read_model(PolicyReplay, store.read_json(read_row["replay"]).data)
    read_authority = verify_policy_evidence(
        read_row,
        runtime=runtime,
        scope_id=scope_id,
        policy=policy,
        store=store,
        candidate_manifest_digest=candidate_manifest_digest,
        adapter_artifact_digest=adapter_artifact_digest,
    )
    _require(read_authority.selected_decision.decision == "allow")
    product_key, scope_key = (
        _key(store, getattr(write, name)) for name in ("product_key", "scope_key")
    )
    before = _snapshot(store, write.snapshot, policy, scope_key)
    after = _snapshot(store, document.read_snapshot, policy, scope_key)
    _same(after.model_dump(mode="json"), store.read_json(read.snapshot).data)
    _same(before.scope.model_dump(mode="json"), after.scope.model_dump(mode="json"))
    assert before.task is not None and after.task is not None
    _same(before.task.model_dump(mode="json"), after.task.model_dump(mode="json"))
    _same(store.read_json(write.catalog).data, store.read_json(read.catalog).data)
    _same(store.read_json(write.activation).data, store.read_json(read.activation).data)
    _require(after.state_version >= before.state_version)
    activation = _typed(
        ProductActivationBundleV1, store.read_json(write.activation).data
    )
    history = read_model(PolicyHistory, store.read_json(write.history).data)
    _require(history.scope_id == scope_id)
    records = _MemoryRecords(history, before, activation, product_key)
    change = _typed(MemoryGuardChange, store.read_json(document.change).data)
    records.change = change
    parent = _typed(AuditEvent, store.read_json(document.write_parent).data)
    terminal = _typed(AuditEvent, store.read_json(document.terminal).data)
    # The immutable file is the original HTTP body. Core accepts and normalizes
    # Node's millisecond-Z timestamps; never rewrite that body to match a dump.
    wire = RuntimeOutcomeReceipt.model_validate(
        store.read_json(document.receipt).data, strict=True
    )
    ack = _typed(ActivationAckV1, store.read_json(document.ack).data)
    _require(verify_activation_ack_token(ack, server_secret=product_key))
    _require(
        records.get_product_activation_ack(activation_ack_token_digest(ack.ack_token))
        is not None
    )
    _require(wire.metadata.activation_ack is not None)
    assert wire.metadata.activation_ack is not None
    _same(
        ack.model_dump(mode="json"),
        wire.metadata.activation_ack.model_dump(mode="json"),
    )
    _require(parent.audit_id == write_row["policy_audit_id"])
    _require(
        _time(parent.metadata["product_authority_initial_checked_at"])
        == _time(write.server_capture.checked_at)
    )
    _same(
        parent.evidence["decision_authority"]["payload"],
        authority.model_dump(mode="json"),
    )
    _same(parent.evidence["product_action_data"], write.product_data)
    original_ct = decode_ct_transient_facts(parent)
    _require(original_ct.kind == "full" and original_ct.bundle is not None)
    assert original_ct.bundle is not None
    _same(original_ct.bundle.model_dump(mode="json"), write.transient_facts)
    _require(parent.links.get("event_id") == authority.event_id)
    _require(parent.links.get("action_id") == write_row["assessment"]["action_id"])
    _require(parent.links.get("decision_id") == authority.selected_decision.decision_id)
    _require(parent.links.get("memory_change_id") == change.change_id)
    for item in (parent, terminal):
        previous = records.audits.get(item.audit_id)
        _require(previous is None or previous == item)
        records.audits[item.audit_id] = item
    existing = records.get_policy_evaluation_by_event_id(authority.event_id)
    _require(existing is None or existing == parent)
    records.policies[parent.audit_id] = parent
    if runtime == "langgraph":
        from .policy_start import verify_policy_start

        _require(document.start is not None)
        verify_policy_start(
            document.start,
            row=write_row,
            parent=parent,
            terminal=wire,
            replay=write,
            store=store,
            records=records,
        )
    else:
        _require(document.start is None)
    accepted = sanitize_audit_event(
        AuditEvent.model_validate(wire.model_dump(mode="json"))
    )
    accepted.metadata[ACK_VALIDATION_KEY] = build_product_ack_validation(wire, parent)
    _same(
        accepted.model_dump(mode="json", exclude={"integrity"}),
        terminal.model_dump(mode="json", exclude={"integrity"}),
    )
    _require(is_product_memory_completion(wire, parent))
    _require(change.status == "committed" and change.operation == "write")
    _require(
        (change.runtime, change.principal_id, change.agent_id, change.trace_id)
        == (
            runtime,
            after.scope.principal_id,
            wire.metadata.agent_id,
            after.scope.trace_id,
        )
    )
    _require(
        change.metadata.get("event_id") == wire.links.event_id
        and change.metadata.get("decision_id") == wire.links.decision_id
    )
    event = _typed(GuardEvent, write_row["event"])
    _require(change.agent_id == event.security_context.agent_id)
    _require(
        _time(before.evaluation_clock.evaluated_at)
        <= _time(change.created_at)
        <= _time(change.updated_at)
        <= _time(after.evaluation_clock.evaluated_at)
    )
    _require(wire.evidence.execution.completed_at is not None)
    _require(
        _time(change.created_at)
        <= _time(wire.evidence.execution.completed_at)
        <= _time(change.updated_at)
    )
    consumption = _typed(GrantConsumption, store.read_json(document.consumption).data)
    _require(wire.links.lease_id is not None and wire.links.approval_id is not None)
    assert wire.links.lease_id is not None and wire.links.approval_id is not None
    lease = records.leases.get(wire.links.lease_id)
    binding = records.bindings.get(wire.links.approval_id)
    _require(lease is not None and binding is not None)
    assert lease is not None and binding is not None
    _require(_lease_matches_binding(lease, binding, consumption))
    _require(
        binding.authorization_fingerprint
        == write_row["assessment"]["authorization_fingerprint"]
    )
    _require(binding.action_type == "memory_write")
    approval = records.approvals.get(binding.approval_id)
    _require(approval is not None and approval.resolved_at is not None)
    assert approval is not None and approval.resolved_at is not None
    _require(
        _time(approval.resolved_at)
        <= _time(lease.issued_at)
        <= _time(wire.evidence.execution.completed_at)
    )
    _require(_time(lease.issued_at) < _time(approval.expires_at))
    _require(_time(lease.issued_at) < _time(lease.expires_at))
    _require(
        wire.links.consumption_id == consumption.consumption_id
        and consumption.consumed_uses == 1
    )
    matches = [
        fact for fact in after.memory_facts if fact.change_id == change.change_id
    ]
    _require(len(matches) == 1)
    fact = matches[0]
    _require(fact.memory_id == read_row["memory_fact_id"])
    read_name, _, read_arguments = product_tool_arguments(
        _typed(GuardEvent, read_row["event"])
    )
    _require(read_name == read.product_data["tool_name"] == "agentguard_memory_read")
    _require(read_arguments["key"] == change.key)
    _require(read.product_data["memory_refs"] == [fact.memory_id])
    if _should_quarantine_memory_change(change):
        _require(fact.trust_state == "quarantined")
    originals = [
        item
        for item in original_ct.bundle.memory_facts
        if item.memory_id == fact.memory_id
    ]
    _require(len(originals) == 1)
    _require(set(fact.taints) == set(originals[0].taints))
    _require(all(item.memory_id != fact.memory_id for item in before.memory_facts))
    sequence = fact.last_write_sequence
    _require(
        sequence is not None
        and sequence.domain == "memory"
        and sequence.producer_binding_id == change.change_id
        and sequence.value == MEMORY_TRANSITION_REVISIONS["committed"]
    )
    source = _typed(ContextSource, store.read_json(document.context_source).data)
    _require(
        verify_product_memory_source(
            store=cast(ControlPlaneStore, records),
            source=source,
            memory_fact=fact,
            snapshot=after,
        )
    )
    store.recheck_reads()
    return fact
