"""Private Product approval checks shared by grant registration and consumption."""

from __future__ import annotations

from agentguard_core import ActivationAckV1, ProductDecisionAuthorityEvidenceV1

from guard_api.models import ApprovalRequest
from guard_api.storage.base import ControlPlaneStore, EnforcementBindingRecord

from .competition import parse_decision_authority_evidence_payload


def read_product_approval_authority(
    store: ControlPlaneStore,
    binding: EnforcementBindingRecord,
    approval: ApprovalRequest,
) -> ProductDecisionAuthorityEvidenceV1 | None:
    """Accept only the persisted policy's exact mode and private approval link.

    Absence remains compatible for an old strong binding. Restricted grants
    always require a typed Product parent; caller metadata cannot select them.
    """
    parent = store.get_policy_evaluation_by_event_id(binding.event_id)
    envelope = (parent.evidence or {}).get("decision_authority") if parent else None
    authority = (
        parse_decision_authority_evidence_payload({"decision_authority": envelope})
        if envelope is not None
        else None
    )
    if not isinstance(authority, ProductDecisionAuthorityEvidenceV1):
        if binding.release_mode != "strong_binding":
            raise ValueError("restricted approval requires Product authority")
        return None
    directive = authority.approval_release_directive
    if not (
        parent is not None
        and parent.record_type == "policy_evaluation"
        and parent.audit_id == binding.policy_audit_id
        and parent.decision == authority.selected_decision.decision == "ask"
        and parent.links.get("event_id") == authority.event_id == binding.event_id
        and parent.links.get("approval_id")
        == approval.approval_id
        == binding.approval_id
        and parent.links.get("action_id") == approval.action_id == binding.action_id
        and parent.trace_id == approval.trace_id
        and parent.runtime == authority.runtime == binding.runtime == approval.runtime
        and binding.agent_id == approval.agent_id
        and binding.principal_id == approval.requesting_principal_id
        and binding.requires_execution_lease is True
        and directive.mode == binding.release_mode
        and directive.scope_digest == binding.scope_digest
        and approval.evidence.get("decision_authority")
        == authority.decision_authority.model_dump(mode="json")
        and approval.evidence.get("approval_release_directive")
        == directive.model_dump(mode="json")
        and "allow_once" in approval.decision_options
        and (
            binding.release_mode != "restricted_allow_once"
            or (
                binding.runtime == "openclaw"
                and directive.required_runtime_profile == "C1"
                and directive.action_binding == "best_effort_host"
                and directive.receipt_requirement == "required_durable"
            )
        )
    ):
        raise ValueError("Product approval authority does not match private binding")
    return authority


def require_product_release_ack(
    authority: ProductDecisionAuthorityEvidenceV1,
    binding: EnforcementBindingRecord,
    ack: ActivationAckV1 | None,
) -> None:
    """Bind a fresh release ACK to the original policy, including after restart."""
    directive = authority.approval_release_directive
    if not (
        ack is not None
        and ack.runtime == authority.runtime == binding.runtime
        and ack.agent_id == binding.agent_id
        and ack.runtime_binding_id == binding.runtime_binding_id
        and ack.profile_id == authority.profile_id
        and ack.activation_ref_digest == directive.activation_ref_digest
        and ack.capability_digest == directive.capability_digest
    ):
        raise ValueError("Product release ACK does not match approval authority")
