"""Audit persistence and provenance service."""

from __future__ import annotations

from dataclasses import asdict

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
    RuntimeOutcomeReceipt,
)
from pydantic import ValidationError

from guard_api.storage.base import ControlPlaneStore
from guard_api.storage.integrity import CANONICALIZATION

from .audit_checkpoint import (
    AuditCheckpointService,
    disabled_audit_anchor_status,
)
from .evidence import build_audit_event
from .provenance import ProvenanceWriter
from .redaction import sanitize_audit_event


class PolicyEvaluationWriteForbiddenError(ValueError):
    """Raised when an inbound record explicitly claims record_type=policy_evaluation.

    契约 §12.1：POST /v1/audit/events 不得重复提交 Guard API 已经写入的
    policy_evaluation；该记录只能由 POST /v1/guard/evaluate 内部唯一写入（§10）。
    record_type=None 的 0.3 兼容记录不受影响。
    """


class RuntimeOutcomeReceiptError(ValueError):
    """Raised when a runtime receipt is invalid or conflicts with its parent."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuditService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        provenance_writer: ProvenanceWriter | None = None,
        checkpoint_service: AuditCheckpointService | None = None,
    ) -> None:
        self.store = store
        self.provenance_writer = provenance_writer or ProvenanceWriter(store=store)
        self.checkpoint_service = checkpoint_service

    def prepare_submission(
        self,
        event: AuditEvent,
        *,
        raw_payload: dict[str, object] | None = None,
    ) -> AuditEvent:
        """Apply the strict producer contract before authorization/persistence."""

        if event.record_type != "runtime_outcome":
            return event
        candidate = (
            raw_payload if raw_payload is not None else event.model_dump(mode="json")
        )
        try:
            return RuntimeOutcomeReceipt.model_validate(candidate)
        except ValidationError:
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_INVALID") from None

    def submit(self, event: AuditEvent) -> dict[str, str | bool]:
        # §12.1 守卫：仅拒显式声明 policy_evaluation 的入站记录。
        if event.record_type == "policy_evaluation":
            raise PolicyEvaluationWriteForbiddenError(event.audit_id)
        if event.record_type == "runtime_outcome":
            receipt = (
                event
                if isinstance(event, RuntimeOutcomeReceipt)
                else self.prepare_submission(event)
            )
            if not isinstance(receipt, RuntimeOutcomeReceipt):  # pragma: no cover
                raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_INVALID")
            self._validate_runtime_outcome_parent(receipt)
            event = AuditEvent.model_validate(receipt.model_dump(mode="json"))
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

    def _validate_runtime_outcome_parent(self, receipt: RuntimeOutcomeReceipt) -> None:
        parent = self.store.get_audit_event(receipt.links.policy_audit_id)
        if parent is None or parent.record_type != "policy_evaluation":
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_PARENT_NOT_FOUND")
        expected = {
            "trace_id": parent.trace_id,
            "case_id": parent.case_id,
            "runtime": parent.runtime,
            "event_id": parent.links.get("event_id"),
            "decision_id": parent.links.get("decision_id"),
            "action_id": parent.links.get("action_id"),
            "approval_id": parent.links.get("approval_id"),
            "decision": parent.decision,
            "risk_score": parent.risk_score,
            "severity": parent.severity,
            "blocked": parent.blocked,
            "is_malicious": parent.is_malicious,
            "agent_id": parent.metadata.get("agent_id"),
            "rule_hits": parent.rule_hits,
        }
        actual = {
            "trace_id": receipt.trace_id,
            "case_id": receipt.case_id,
            "runtime": receipt.runtime,
            "event_id": receipt.links.event_id,
            "decision_id": receipt.links.decision_id,
            "action_id": receipt.links.action_id,
            "approval_id": receipt.links.approval_id,
            "decision": receipt.decision,
            "risk_score": receipt.risk_score,
            "severity": receipt.severity,
            "blocked": receipt.blocked,
            "is_malicious": receipt.is_malicious,
            "agent_id": receipt.metadata.agent_id,
            "rule_hits": receipt.rule_hits,
        }
        if actual != expected:
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_PARENT_MISMATCH")

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
        v21_evidence: dict[str, object] | None = None,
    ) -> AuditEvent:
        """写入 policy_evaluation 审计记录。

        ``v21_evidence``：V21-08 shadow 旁路信封透传（None 时与现状逐字节
        一致）；写入位置为同一条记录的 ``evidence.decision_v21``，不新增
        第二条审计记录（11_决策记录_V21-08前置.md D4）。
        """

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
            v21_evidence=v21_evidence,
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
        chain_status = self.store.verify_audit_integrity()
        anchor_status = (
            self.checkpoint_service.inspect(chain_status)
            if self.checkpoint_service is not None
            else disabled_audit_anchor_status()
        )
        return {
            **asdict(chain_status),
            "canonicalization": CANONICALIZATION,
            "anchor": asdict(anchor_status),
        }
