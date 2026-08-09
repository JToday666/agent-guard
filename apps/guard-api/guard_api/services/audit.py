"""Audit persistence and provenance service."""

from __future__ import annotations

from dataclasses import asdict

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
)

from guard_api.storage.base import ControlPlaneStore

from .evidence import build_audit_event
from .provenance import ProvenanceWriter
from .redaction import sanitize_audit_event


class PolicyEvaluationWriteForbiddenError(ValueError):
    """Raised when an inbound record explicitly claims record_type=policy_evaluation.

    契约 §12.1：POST /v1/audit/events 不得重复提交 Guard API 已经写入的
    policy_evaluation；该记录只能由 POST /v1/guard/evaluate 内部唯一写入（§10）。
    record_type=None 的 0.3 兼容记录不受影响。
    """


class AuditService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        provenance_writer: ProvenanceWriter | None = None,
    ) -> None:
        self.store = store
        self.provenance_writer = provenance_writer or ProvenanceWriter(store=store)

    def submit(self, event: AuditEvent) -> dict[str, str | bool]:
        # §12.1 守卫：仅拒显式声明 policy_evaluation 的入站记录。
        if event.record_type == "policy_evaluation":
            raise PolicyEvaluationWriteForbiddenError(event.audit_id)
        event = sanitize_audit_event(event)
        is_new = self.store.add_audit_event(event)
        persisted = self.store.get_audit_event(event.audit_id) or event
        # 同内容重试也执行确定性 upsert，用于修复首次请求在 audit 已提交后
        # provenance 写入失败形成的可检测部分状态。
        self.provenance_writer.record_audit_event(persisted)
        # §12.3：首次写入与同内容重试都返回 200，用 created/idempotent_replay 区分。
        return {
            "ok": True,
            "audit_id": event.audit_id,
            "created": is_new,
            "idempotent_replay": not is_new,
        }

    def record_evaluation(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        policy_bundle: PolicyBundle,
        policy_revision: int | None,
        approval_id: str | None = None,
        critic_review: ActionCriticReview | None = None,
        memory_change_id: str | None = None,
        extra_metadata: dict[str, object] | None = None,
        decision_dump: dict[str, object] | None = None,
    ) -> AuditEvent:
        audit_event = build_audit_event(
            event,
            decision,
            policy_bundle=policy_bundle,
            policy_revision=policy_revision,
            approval_id=approval_id,
            critic_review_id=(
                critic_review.review_id if critic_review is not None else None
            ),
            memory_change_id=memory_change_id,
            extra_metadata=extra_metadata,
            decision_dump=decision_dump,
        )
        audit_event = sanitize_audit_event(audit_event)
        self.store.add_audit_event(audit_event)
        persisted = self.store.get_audit_event(audit_event.audit_id) or audit_event
        if critic_review is not None:
            self.store.add_action_critic_review(critic_review)
        approval = (
            self.store.get_approval(approval_id) if approval_id is not None else None
        )
        self.provenance_writer.record_audit_event(
            persisted,
            approval=approval,
            critic_review=critic_review,
        )
        return persisted

    def repair_provenance(self, event: AuditEvent) -> None:
        approval_id = event.links.get("approval_id")
        approval = self.store.get_approval(approval_id) if approval_id else None
        critic_review: ActionCriticReview | None = None
        critic_review_id = event.links.get("critic_review_id")
        if critic_review_id:
            critic_review = next(
                (
                    review
                    for review in self.store.list_action_critic_reviews(event.trace_id)
                    if review.review_id == critic_review_id
                ),
                None,
            )
        self.provenance_writer.record_audit_event(
            event,
            approval=approval,
            critic_review=critic_review,
        )

    def integrity(self) -> dict[str, object]:
        return asdict(self.store.verify_audit_integrity())
