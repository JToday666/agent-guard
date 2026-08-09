"""Human and LLM approval service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agentguard_core import GuardDecision, GuardEvent

from guard_api.llm_approval import LlmApprovalReviewer
from guard_api.models import ApprovalRequest, LlmApprovalReview, LlmApprovalReviewInput
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ControlPlaneStore

from .evidence import _approval_evidence, describe_guard_event
from .provenance import ProvenanceWriter
from .redaction import (
    SUMMARY_TEXT_LIMIT,
    bound_redacted_value,
    scrub_text,
    truncate_text,
)


class ApprovalService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        settings: GuardApiSettings,
        llm_reviewer: LlmApprovalReviewer | None = None,
        provenance_writer: ProvenanceWriter | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.llm_reviewer = llm_reviewer
        self.provenance_writer = provenance_writer or ProvenanceWriter(store=store)

    def create_for_decision(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        requesting_principal_id: str,
    ) -> ApprovalRequest | None:
        if decision.decision != "ask" or decision.approval_intent is None:
            return None
        description = describe_guard_event(event)
        resource = decision.approval_intent.resource.strip()
        if not resource and description.resource_targets:
            resource = description.resource_targets[0]
        safe_resource = bound_redacted_value(resource, text_limit=SUMMARY_TEXT_LIMIT)
        safe_action_name = truncate_text(
            scrub_text(description.action_name), SUMMARY_TEXT_LIMIT
        )
        approval = ApprovalRequest(
            trace_id=event.trace_id,
            subject_id=description.subject_id,
            subject_type=description.subject_type,
            action_id=description.action_id,
            action_name=safe_action_name,
            tool_call_id=description.subject_id,
            requesting_principal_id=requesting_principal_id,
            runtime=event.runtime,
            agent_id=event.security_context.agent_id,
            tool=safe_action_name,
            resource=safe_resource if isinstance(safe_resource, str) else "",
            reason=truncate_text(scrub_text(decision.reason), SUMMARY_TEXT_LIMIT),
            risk_score=decision.risk_score,
            severity=decision.severity,
            evidence=_approval_evidence(event, decision, description),
            decision_options=decision.approval_intent.options,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(seconds=self.settings.approval_ttl_seconds)
            ).isoformat(),
        )
        return self.store.create_approval(approval)

    def auto_review_with_llm(
        self, approval: ApprovalRequest | None
    ) -> ApprovalRequest | None:
        if approval is None or not self.settings.llm_approval_enabled:
            return approval
        if self.llm_reviewer is None:
            return self._record_llm_review(
                approval,
                LlmApprovalReview(
                    status="error",
                    error="LLM approval configuration is incomplete.",
                ),
            )
        try:
            review = LlmApprovalReview.model_validate(
                self.llm_reviewer.review(LlmApprovalReviewInput.from_approval(approval))
            )
        except Exception as exc:
            return self._record_llm_review(
                approval,
                LlmApprovalReview(
                    status="error",
                    error=_llm_review_error(exc),
                ),
            )

        if review.decision == "deny":
            return self.resolve_approval(
                approval.approval_id,
                "deny",
                resolution_source="llm",
                resolved_by="llm-approval",
                resolution_reason=review.reason,
                llm_review=review.model_copy(update={"status": "resolved"}),
            )
        if review.decision == "allow_once" and _llm_can_allow_once(approval):
            return self.resolve_approval(
                approval.approval_id,
                "allow_once",
                resolution_source="llm",
                resolved_by="llm-approval",
                resolution_reason=review.reason,
                llm_review=review.model_copy(update={"status": "resolved"}),
            )
        return self._record_llm_review(
            approval, review.model_copy(update={"status": "kept_pending"})
        )

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return self.store.list_pending_approvals()

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.store.get_approval(approval_id)

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        resolution_source: str = "human",
        resolved_by: str | None = None,
        resolution_reason: str | None = None,
        llm_review: LlmApprovalReview | None = None,
    ) -> ApprovalRequest:
        resolved = self.store.resolve_approval(
            approval_id,
            decision,
            resolution_source=resolution_source,
            resolved_by=resolved_by,
            resolution_reason=resolution_reason,
            llm_review=llm_review,
        )
        self.provenance_writer.update_approval(resolved)
        return resolved

    def _record_llm_review(
        self, approval: ApprovalRequest, review: LlmApprovalReview
    ) -> ApprovalRequest:
        updated = approval.model_copy(update={"llm_review": review})
        stored = self.store.create_approval(updated)
        self.provenance_writer.update_approval(stored)
        return stored


def _llm_can_allow_once(approval: ApprovalRequest) -> bool:
    if "allow_once" not in approval.decision_options:
        return False
    return approval.severity.lower() in {"low", "medium"}


def _llm_review_error(exc: Exception) -> str:
    message = str(exc).strip()
    if len(message) > 240:
        message = f"{message[:240]}..."
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__
