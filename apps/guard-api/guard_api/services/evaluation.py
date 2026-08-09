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
from sqlalchemy.exc import IntegrityError

from guard_api.models import (
    ApprovalRequest,
    EvaluationApproval,
    GuardEvaluationResponse,
)
from guard_api.storage.base import parse_audit_timestamp
from guard_api.storage.integrity import canonical_sha256

from .approval import ApprovalService
from .audit import AuditService
from .memory import MemoryGuardService
from .policy import PolicyService


class EvaluationConflictError(ValueError):
    """Raised when the same event_id is re-evaluated with different content."""


def _stored_request_digest(audit: AuditEvent) -> object:
    """Return the canonical request digest from the 0.4 audit contract."""

    return audit.metadata.get("request_digest")


def _stored_decision_dump(audit: AuditEvent) -> object:
    """Return the canonical decision snapshot from the 0.4 audit contract."""

    evidence = audit.evidence
    if isinstance(evidence, dict):
        dump = evidence.get("guard_decision")
        if dump is not None:
            return dump
    return None


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
        # Validate temporal identity before detectors or any approval/memory side
        # effects run; persistence uses the same parser for defense in depth.
        parse_audit_timestamp(event.timestamp)
        request_digest = canonical_sha256(event.model_dump(mode="json"))
        # 审批、memory change 和审计写入都属于一次评估的副作用。同 event_id
        # 必须在副作用发生前串行化；Memory 使用进程锁，PostgreSQL 使用
        # crash-safe session advisory lock。进入锁后重新读取，保证并发重试只
        # 回放已经提交的权威结果，不创建孤立审批。
        with self.audit_service.store.policy_evaluation_guard(event.event_id):
            replayed = self._replay_or_conflict(
                self.audit_service.store.get_policy_evaluation_by_event_id(
                    event.event_id
                ),
                request_digest,
                event.event_id,
            )
            if replayed is not None:
                return replayed
            return self._evaluate_once(
                event,
                request_digest=request_digest,
                requesting_principal_id=requesting_principal_id,
            )

    def _evaluate_once(
        self,
        event: GuardEvent,
        *,
        request_digest: str,
        requesting_principal_id: str,
    ) -> GuardEvaluationResponse:
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
        # §9.9：links 只放稳定 ID；digest 经 metadata 传入 writer。
        try:
            audit_event = self.audit_service.record_evaluation(
                event,
                decision,
                policy_bundle=bundle,
                policy_revision=(
                    snapshot_record.revision if snapshot_record is not None else None
                ),
                approval_id=approval.approval_id if approval is not None else None,
                critic_review=critic_review,
                memory_change_id=(
                    memory_change.change_id if memory_change is not None else None
                ),
                extra_metadata={
                    "request_digest": request_digest,
                    "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
                },
                decision_dump=decision.model_dump(mode="json"),
            )
        except IntegrityError:
            # 并发下同 event_id 的写入先入链（部分唯一索引冲突）：
            # 重读并比较规范化请求摘要，同内容回放、异内容 409。
            replayed = self._replay_or_conflict(
                self.audit_service.store.get_policy_evaluation_by_event_id(
                    event.event_id
                ),
                request_digest,
                event.event_id,
            )
            if replayed is not None:
                return replayed
            raise
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
            policy_audit_id=audit_event.audit_id,
        )

    def _replay_or_conflict(
        self,
        existing: AuditEvent | None,
        request_digest: str,
        event_id: str,
    ) -> GuardEvaluationResponse | None:
        if existing is None:
            return None
        if _stored_request_digest(existing) == request_digest:
            # AuditEvent 已经是权威幂等结果；重试仍需执行确定性 provenance
            # upsert，以修复此前 audit 成功而图写入失败的部分状态。
            self.audit_service.repair_provenance(existing)
            return self._rebuild_response(existing)
        raise EvaluationConflictError(event_id)

    def _rebuild_response(self, audit: AuditEvent) -> GuardEvaluationResponse:
        raw_decision = _stored_decision_dump(audit)
        if raw_decision is None:
            raise EvaluationConflictError(audit.links.get("event_id", ""))
        decision = GuardDecision.model_validate(raw_decision)
        approval: ApprovalRequest | None = None
        approval_id = audit.links.get("approval_id")
        if approval_id:
            approval = self.approval_service.get_approval(approval_id)
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
            policy_audit_id=audit.audit_id,
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
