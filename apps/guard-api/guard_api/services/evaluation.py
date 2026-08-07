"""Guard evaluation orchestration service."""

from __future__ import annotations

from agentguard_core import (
    ActionCritic,
    AuditEvent,
    GuardDecision,
    GuardEvent,
    MemoryEventPayload,
    MemoryGuardChange,
    evaluate as core_evaluate,
)

from guard_api.models import (
    ApprovalRequest,
    EvaluationApproval,
    GuardEvaluationResponse,
)
from guard_api.storage.integrity import canonical_sha256

from .approval import ApprovalService
from .audit import AuditService
from .memory import MemoryGuardService
from .policy import PolicyService


class EvaluationConflictError(ValueError):
    """Raised when the same event_id is re-evaluated with different content."""


class EvaluationService:
    def __init__(
        self,
        *,
        policy_service: PolicyService,
        audit_service: AuditService,
        approval_service: ApprovalService,
        memory_guard_service: MemoryGuardService | None = None,
        action_critic: ActionCritic | None = None,
    ) -> None:
        self.policy_service = policy_service
        self.audit_service = audit_service
        self.approval_service = approval_service
        self.memory_guard_service = memory_guard_service
        self.action_critic = action_critic or ActionCritic()

    def evaluate(
        self, event: GuardEvent, *, requesting_principal_id: str
    ) -> GuardEvaluationResponse:
        request_digest = canonical_sha256(event.model_dump(mode="json"))
        existing = self.audit_service.store.get_policy_evaluation_by_event_id(
            event.event_id
        )
        if existing is not None:
            if existing.links.get("request_digest") == request_digest:
                return self._rebuild_response(existing)
            raise EvaluationConflictError(event.event_id)
        snapshot_record = self.policy_service.current_snapshot_record()
        if snapshot_record is not None:
            bundle = snapshot_record.policy_bundle
        else:
            bundle = self.policy_service.current_snapshot()
        decision = core_evaluate(event, bundle)
        critic_review = self.action_critic.review(event, decision)
        approval = self.approval_service.create_for_decision(
            event,
            decision,
            requesting_principal_id=requesting_principal_id,
        )
        approval = self.approval_service.auto_review_with_llm(approval)
        memory_change = self._record_memory_change(event, decision)
        extra_links: dict[str, str] = {
            "request_digest": request_digest,
            "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
        }
        if snapshot_record is not None:
            extra_links["policy_revision"] = str(snapshot_record.revision)
        self.audit_service.record_evaluation(
            event,
            decision,
            approval_id=approval.approval_id if approval is not None else None,
            critic_review=critic_review,
            memory_change_id=(
                memory_change.change_id if memory_change is not None else None
            ),
            extra_links=extra_links,
            decision_dump=decision.model_dump(mode="json"),
        )
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
        )

    def _rebuild_response(self, audit: AuditEvent) -> GuardEvaluationResponse:
        decision = GuardDecision.model_validate(audit.metadata["guard_decision"])
        approval: ApprovalRequest | None = None
        approval_id = audit.links.get("approval_id")
        if approval_id:
            approval = self.approval_service.get_approval(approval_id)
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
        )

    def _approval_summary(
        self, approval: ApprovalRequest | None
    ) -> EvaluationApproval | None:
        if approval is None:
            return None
        return EvaluationApproval(
            approval_id=approval.approval_id,
            status=approval.status,
            decision_options=approval.decision_options,
            decision=approval.decision,
            resolution_source=approval.resolution_source,
            resolved_by=approval.resolved_by,
            resolution_reason=approval.resolution_reason,
            llm_review=approval.llm_review,
        )

    def _record_memory_change(
        self, event: GuardEvent, decision: GuardDecision
    ) -> MemoryGuardChange | None:
        if self.memory_guard_service is None or not isinstance(
            event.payload, MemoryEventPayload
        ):
            return None
        memory = event.payload.memory
        if memory.operation.lower() != "write" or not event.payload.will_persist:
            return None
        return self.memory_guard_service.propose(
            MemoryGuardChange(
                trace_id=event.trace_id,
                namespace=memory.namespace,
                key=memory.key,
                value_preview=memory.value_preview,
                operation=memory.operation,
                source_trust=memory.source_trust,
                metadata={
                    "event_id": event.event_id,
                    "decision_id": decision.decision_id,
                    "decision": decision.decision,
                    "requires_approval": event.payload.requires_approval,
                },
            )
        )
