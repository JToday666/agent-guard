"""Advance existing memory lifecycle only after an accepted Product outcome.

This bridge adds no memory facts or trust authority. The evaluation already
created the exact change; its existing lifecycle service owns transitions and
post-commit CT projection. Receipt replay repairs a crash between these commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import TYPE_CHECKING

from agentguard_core import (
    AuditEvent,
    ProductDecisionAuthorityEvidenceV1,
    RuntimeOutcomeReceipt,
    ContextSource,
    MemoryGuardChange,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.canonical_resources import (
    ResourceNormalizationInput,
    normalize_memory_resource,
)
from agentguard_core.security_context import MemoryFact, SecuritySnapshot
from agentguard_core.security_context.product_data import VerifiedProductData

from guard_api.storage.base import ControlPlaneStore, MemoryChangeTransitionError
from guard_api.auth import AuthContext

from .competition import parse_decision_authority_evidence_payload

if TYPE_CHECKING:
    from .memory import MemoryGuardService


def _memory_proof(parent: AuditEvent, change: MemoryGuardChange) -> VerifiedProductData:
    """Bind stored memory bytes to the original compiler-owned commitments."""
    from .product_model_content import read_product_action_data

    proof = read_product_action_data(parent)
    memory_id = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="", target=change.key, memory_namespace=change.namespace
        )
    ).canonical_id
    bindings = {item.argument_pointer: item for item in proof.bindings}
    value = bindings.get("/value")
    key = bindings.get("/key")
    if (
        proof.runtime not in {"langgraph", "openclaw"}
        or proof.runtime != change.runtime
        or proof.first_write_memory_ref != memory_id
        or change.source_trust != "unknown"
        or value is None
        or value.resource_ref != memory_id
        or value.sink_role != "content"
        or value.value_digest != canonical_sha256(change.value_preview)
        or key is None
        or key.value_digest != canonical_sha256(change.key)
    ):
        raise ValueError("V21_PRODUCT_MEMORY_CONTENT_BINDING_INVALID")
    return proof


def _accepted_ack_matches(
    store: ControlPlaneStore,
    terminal: AuditEvent,
    authority: ProductDecisionAuthorityEvidenceV1,
    runtime_binding_id: str,
    principal_id: str,
) -> bool:
    """Read the immutable server validation stamp, without re-aging old ACKs."""
    from .product_model_content import ACK_VALIDATION_KEY

    stamp = terminal.metadata.get(ACK_VALIDATION_KEY)
    if not isinstance(stamp, dict) or set(stamp) != {
        "schema_version",
        "token_digest",
        "public_claims_digest",
        "parent_authority_digest",
    }:
        return False
    token_digest = stamp.get("token_digest")
    if not isinstance(token_digest, str):
        return False
    issuance = store.get_product_activation_ack(token_digest)
    if issuance is None:
        return False
    public = terminal.metadata.get("activation_ack")
    if not isinstance(public, dict):
        return False
    public = {key: value for key, value in public.items() if key != "ack_token"}
    return bool(
        stamp["schema_version"] == "1.0"
        and stamp["parent_authority_digest"]
        == canonical_sha256(authority.model_dump(mode="json"))
        and stamp["public_claims_digest"] == canonical_sha256(issuance.ack_projection)
        and public == issuance.ack_projection
        and issuance.principal_id == principal_id
        and public.get("runtime_binding_id") == runtime_binding_id
        and public.get("activation_ref_digest")
        == authority.decision_authority.activation_ref_digest
        and public.get("capability_digest")
        == authority.approval_release_directive.capability_digest
    )


def verify_product_memory_source(
    *,
    store: ControlPlaneStore,
    source: ContextSource,
    memory_fact: MemoryFact,
    snapshot: SecuritySnapshot,
) -> bool:
    """Bind the full native SQLite read value to its accepted original write.

    The existing change stores the native event's complete value_preview. Its
    digest is derived here from that server-owned value, never from a caller's
    alleged old/new hash. This does not elevate the fact's existing trust.
    """
    try:
        from .ct_projection import decode_ct_transient_facts

        if (
            source.source_type != "memory"
            or source.role not in {"user", "tool"}
            or memory_fact not in snapshot.memory_facts
            or memory_fact.change_status != "committed"
            or memory_fact.change_id is None
            or snapshot.scope.runtime != "langgraph"
            or source.source_id
            not in {memory_fact.memory_id, f"memory:{memory_fact.memory_id}"}
            or len(source.summary.encode("utf-8")) > 64 * 1024
            or canonical_sha256(source.summary) != source.content_digest
        ):
            return False

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate memory result field")
                result[key] = value
            return result

        body = json.loads(source.summary, object_pairs_hook=unique_object)
        change = store.get_memory_change(memory_fact.change_id)
        if (
            type(body) is not dict
            or set(body) != {"key", "value"}
            or type(body["key"]) is not str
            or type(body["value"]) is not str
            or change is None
            or change.status != "committed"
            or change.runtime != snapshot.scope.runtime
            or change.principal_id != snapshot.scope.principal_id
            or change.operation != "write"
            or body["key"] != change.key
            or canonical_sha256(body["value"]) != canonical_sha256(change.value_preview)
            or normalize_memory_resource(
                ResourceNormalizationInput(
                    resource_id="",
                    target=change.key,
                    memory_namespace=change.namespace,
                )
            ).canonical_id
            != memory_fact.memory_id
        ):
            return False
        event_id = change.metadata.get("event_id")
        if not isinstance(event_id, str):
            return False
        parent = store.get_policy_evaluation_by_event_id(event_id)
        terminal = store.get_audit_event(
            f"audit_outcome_{event_id}_execution_completed"
        )
        if parent is None or terminal is None:
            return False
        envelope = (parent.evidence or {}).get("decision_authority")
        authority = parse_decision_authority_evidence_payload(
            {"decision_authority": envelope}
        )
        proof = _memory_proof(parent, change)
        decoded = decode_ct_transient_facts(parent)
        originals = (
            [
                item
                for item in decoded.bundle.memory_facts
                if item.memory_id == memory_fact.memory_id
            ]
            if decoded.bundle is not None
            else []
        )
        return bool(
            isinstance(authority, ProductDecisionAuthorityEvidenceV1)
            and authority.runtime == "langgraph"
            and authority.event_type == parent.event_type == "memory_write_proposed"
            and authority.approval_release_directive.scope_digest
            == snapshot.scope.scope_digest
            and decoded.kind == "full"
            and decoded.bundle is not None
            and decoded.bundle.scope_digest == snapshot.scope.scope_digest
            and proof.scope_digest == snapshot.scope.scope_digest
            and proof.runtime_binding_id == snapshot.scope.runtime_binding_id
            and len(originals) == 1
            and set(originals[0].source_refs) == set(memory_fact.source_refs)
            and set(originals[0].taints).issubset(memory_fact.taints)
            and memory_fact.trust_state != "clean"
            and parent.links.get("memory_change_id") == change.change_id
            and terminal.record_type == "runtime_outcome"
            and terminal.runtime == "langgraph"
            and terminal.metadata.get("outcome_kind") == "execution_completed"
            and (terminal.evidence or {}).get("execution", {}).get("status")
            == "executed"
            and terminal.links.get("event_id") == event_id
            and terminal.links.get("policy_audit_id") == parent.audit_id
            and terminal.links.get("action_id") == parent.links.get("action_id")
            and terminal.metadata.get("agent_id") == change.agent_id
            and _accepted_ack_matches(
                store,
                terminal,
                authority,
                snapshot.scope.runtime_binding_id,
                snapshot.scope.principal_id,
            )
        )
    except Exception:
        # Incomplete or conflicting proof excludes the source; no raw content
        # or stored authority is reflected into a runtime diagnostic.
        return False


def is_product_memory_completion(
    receipt: RuntimeOutcomeReceipt, parent: AuditEvent
) -> bool:
    """Select only the already validated original memory action terminal."""
    if not (
        receipt.runtime == parent.runtime
        and receipt.runtime in {"langgraph", "openclaw"}
        and parent.record_type == "policy_evaluation"
        and parent.event_type == "memory_write_proposed"
        and receipt.metadata.outcome_kind == "execution_completed"
        and receipt.evidence.execution.status == "executed"
        and receipt.metadata.activation_ack is not None
    ):
        return False
    envelope = (parent.evidence or {}).get("decision_authority")
    if envelope is None:
        return False
    # Audit ingestion has already strictly parsed and verified this envelope.
    evidence = parse_decision_authority_evidence_payload(
        {"decision_authority": envelope}
    )
    if (
        not isinstance(evidence, ProductDecisionAuthorityEvidenceV1)
        or evidence.runtime != parent.runtime
        or evidence.event_type != parent.event_type
        or evidence.event_id != receipt.links.event_id
        or evidence.selected_decision.decision != parent.decision
    ):
        return False
    if receipt.runtime == "langgraph":
        return receipt.evidence.execution.invoked_at is not None
    # C1 reports only an actual after-hook outcome, never an authoritative
    # invocation timestamp. Release/unknown/failed/quarantined are not commits.
    if (
        receipt.evidence.execution.invoked_at is not None
        or receipt.evidence.execution.persisted is not True
        or receipt.evidence.result.disposition != "passed_through"
    ):
        return False
    if evidence.selected_decision.decision == "allow":
        return (
            receipt.evidence.enforcement is None
            and receipt.links.approval_id is None
            and receipt.links.lease_id is None
            and evidence.approval_release_directive.mode == "not_applicable"
        )
    enforcement = receipt.evidence.enforcement
    return (
        evidence.selected_decision.decision == "ask"
        and evidence.approval_release_directive.mode == "restricted_allow_once"
        and enforcement is not None
        and enforcement.release_mode == "restricted_allow_once"
        and enforcement.gate_state == "approval_released"
        and enforcement.binding_check_status == "not_performed"
        and enforcement.lease_consume_outcome == "consumed"
        and receipt.links.lease_id is not None
        and receipt.links.consumption_id is not None
        and receipt.evidence.approval.status == "allowed"
        and receipt.evidence.approval.decision == "allow_once"
    )


@dataclass(frozen=True, slots=True)
class ProductMemoryReceiptBridge:
    memory_service: MemoryGuardService = field(repr=False)

    def apply(
        self,
        receipt: RuntimeOutcomeReceipt,
        parent: AuditEvent,
        *,
        auth_context: AuthContext | None,
    ) -> None:
        if not is_product_memory_completion(receipt, parent):
            return
        service = self.memory_service
        stored = service.store.get_audit_event(receipt.audit_id)
        ack = receipt.metadata.activation_ack
        change_id = parent.links.get("memory_change_id")
        change = service.get(change_id) if isinstance(change_id, str) else None
        if (
            stored is None
            or stored.record_type != "runtime_outcome"
            or stored.links != receipt.links.model_dump(mode="json")
            or stored.metadata.get("outcome_kind") != "execution_completed"
            or (stored.evidence or {}).get("execution", {}).get("status") != "executed"
            or ack is None
            or change is None
            or change.operation != "write"
            or change.runtime != receipt.runtime
            or change.agent_id != receipt.metadata.agent_id
            or auth_context is None
            or change.principal_id != auth_context.principal_id
            or change.trace_id != receipt.trace_id
            or change.metadata.get("event_id") != receipt.links.event_id
            or change.metadata.get("decision_id") != receipt.links.decision_id
            or parent.audit_id != receipt.links.policy_audit_id
            or parent.links.get("event_id") != receipt.links.event_id
            or parent.links.get("action_id") != receipt.links.action_id
        ):
            raise ValueError("V21_PRODUCT_MEMORY_RECEIPT_BINDING_INVALID")
        if receipt.runtime == "openclaw":
            accepted_execution = (stored.evidence or {}).get("execution", {})
            if (
                accepted_execution.get("invoked_at") is not None
                or accepted_execution.get("persisted") is not True
                or (stored.evidence or {}).get("result", {}).get("disposition")
                != "passed_through"
                or (stored.evidence or {}).get("enforcement")
                != (
                    receipt.evidence.enforcement.model_dump(mode="json")
                    if receipt.evidence.enforcement
                    else None
                )
            ):
                raise ValueError("V21_PRODUCT_MEMORY_RECEIPT_BINDING_INVALID")
        proof = _memory_proof(parent, change)
        from .product_model_content import (
            ACK_VALIDATION_KEY,
            build_product_ack_validation,
        )

        if proof.runtime_binding_id != ack.runtime_binding_id or stored.metadata.get(
            ACK_VALIDATION_KEY
        ) != build_product_ack_validation(receipt, parent):
            raise ValueError("V21_PRODUCT_MEMORY_RECEIPT_BINDING_INVALID")
        # A later explicit rejection/rollback remains authoritative. Historical
        # delivery must never reactivate it, even when its earlier receipt was
        # delayed until after the operator transition.
        if change.status in {"rejected", "rolled_back"}:
            if service.projection_service is not None:
                service.projection_service.project_memory_transition(change)
            return
        try:
            service.commit(change.change_id, operator_id=auth_context.principal_id)
        except MemoryChangeTransitionError:
            # Respect an operator transition racing the accepted receipt.
            current = service.get(change.change_id)
            if current is None or current.status not in {"rejected", "rolled_back"}:
                raise
            if service.projection_service is not None:
                service.projection_service.project_memory_transition(current)
