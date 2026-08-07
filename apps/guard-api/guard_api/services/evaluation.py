"""Guard evaluation orchestration service."""

from __future__ import annotations

import time

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
from guard_api.storage.integrity import canonical_sha256

from .approval import ApprovalService
from .audit import AuditService
from .memory import MemoryGuardService
from .policy import PolicyService

# memory store 下等待在途评估入链的最长时间（秒）。
_RESERVATION_WAIT_SECONDS = 5.0
_RESERVATION_POLL_INTERVAL = 0.02


class EvaluationConflictError(ValueError):
    """Raised when the same event_id is re-evaluated with different content."""


def _stored_request_digest(audit: AuditEvent) -> object:
    """先新后旧双读：0.4 记录存 metadata，PR #92/#93 旧记录存 links。"""

    digest = audit.metadata.get("request_digest")
    if digest is None:
        digest = audit.links.get("request_digest")
    return digest


def _stored_decision_dump(audit: AuditEvent) -> object:
    """先新后旧双读：0.4 记录存 evidence，旧记录存 metadata。"""

    evidence = audit.evidence
    if isinstance(evidence, dict):
        dump = evidence.get("guard_decision")
        if dump is not None:
            return dump
    return audit.metadata.get("guard_decision")


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
        # 快路径预检：已入链的评估零成本重放，不再调用 Core、不重复创建审批。
        replayed = self._replay_or_conflict(
            self.audit_service.store.get_policy_evaluation_by_event_id(
                event.event_id
            ),
            request_digest,
            event.event_id,
        )
        if replayed is not None:
            return replayed
        # 写入前占位：memory 在哈希链锁内原子判定；PostgreSQL 恒 True，
        # 真实约束由部分唯一索引（migration 0007）在写入时承担。
        if not self.audit_service.store.reserve_policy_evaluation(event.event_id):
            return self._await_committed_replay(event.event_id, request_digest)
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
            return self._rebuild_response(existing)
        raise EvaluationConflictError(event_id)

    def _await_committed_replay(
        self, event_id: str, request_digest: str
    ) -> GuardEvaluationResponse:
        # memory store 中在途评估持有占位直至入链；有界等待其落盘后
        # 回放或报冲突，与 PostgreSQL “写入即权威”的索引语义对齐。
        deadline = time.monotonic() + _RESERVATION_WAIT_SECONDS
        while True:
            existing = self.audit_service.store.get_policy_evaluation_by_event_id(
                event_id
            )
            if existing is not None:
                if _stored_request_digest(existing) == request_digest:
                    return self._rebuild_response(existing)
                raise EvaluationConflictError(event_id)
            if time.monotonic() >= deadline:
                raise EvaluationConflictError(event_id)
            time.sleep(_RESERVATION_POLL_INTERVAL)

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
