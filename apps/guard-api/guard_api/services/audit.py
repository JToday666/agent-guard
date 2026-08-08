"""Audit persistence and provenance service."""

from __future__ import annotations

from dataclasses import asdict

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
)

from guard_api.storage.base import AuditEventFilters, ControlPlaneStore

from .evidence import build_audit_event
from .redaction import sanitize_audit_event


class PolicyEvaluationWriteForbiddenError(ValueError):
    """Raised when an inbound record explicitly claims record_type=policy_evaluation.

    契约 §12.1：POST /v1/audit/events 不得重复提交 Guard API 已经写入的
    policy_evaluation；该记录只能由 POST /v1/guard/evaluate 内部唯一写入（§10）。
    record_type=None 的 0.3 兼容记录不受影响。
    """


class AuditService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def submit(self, event: AuditEvent) -> dict[str, str | bool]:
        # §12.1 守卫：仅拒显式声明 policy_evaluation 的入站记录。
        if event.record_type == "policy_evaluation":
            raise PolicyEvaluationWriteForbiddenError(event.audit_id)
        event = sanitize_audit_event(event)
        is_new = self.store.add_audit_event(event)
        if is_new:
            self._record_audit_provenance(event)
        # §12.3：首次写入与同内容重试都返回 200，用 created/idempotent_replay 区分。
        return {
            "ok": True,
            "audit_id": event.audit_id,
            "created": is_new,
            "idempotent_replay": not is_new,
        }

    def list_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
        return self.store.list_audit_events(filters)

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
        if critic_review is not None:
            self.store.add_action_critic_review(critic_review)
        self._record_evaluation_provenance(
            event, decision, audit_event, critic_review=critic_review
        )
        return audit_event

    def integrity(self) -> dict[str, object]:
        return asdict(self.store.verify_audit_integrity())

    def _record_audit_provenance(self, event: AuditEvent) -> None:
        audit_node = ProvenanceNode(
            node_id=f"audit:{event.audit_id}",
            trace_id=event.trace_id,
            kind="audit",
            ref_id=event.audit_id,
            label=event.event_type,
            timestamp=event.timestamp,
            metadata={"runtime": event.runtime, "stage": event.stage},
        )
        self.store.add_provenance_node(audit_node)
        source_id = event.links.get("config_audit_event_id") or event.links.get(
            "event_id"
        )
        if source_id is None:
            return
        source_kind = "config_audit" if event.event_type == "config_audit" else "event"
        source_node = ProvenanceNode(
            node_id=f"{source_kind}:{source_id}",
            trace_id=event.trace_id,
            kind=source_kind,
            ref_id=source_id,
            label=event.event_type,
            timestamp=event.timestamp,
            metadata={"runtime": event.runtime, "stage": event.stage},
        )
        self.store.add_provenance_node(source_node)
        self.store.add_provenance_edge(
            ProvenanceEdge(
                edge_id=f"edge:{source_node.node_id}:{audit_node.node_id}",
                trace_id=event.trace_id,
                source_node_id=source_node.node_id,
                target_node_id=audit_node.node_id,
                relation="recorded_as",
            )
        )

    def _record_evaluation_provenance(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        audit_event: AuditEvent,
        *,
        critic_review: ActionCriticReview | None = None,
    ) -> None:
        event_node = ProvenanceNode(
            node_id=f"event:{event.event_id}",
            trace_id=event.trace_id,
            kind="event",
            ref_id=event.event_id,
            label=event.event_type,
            timestamp=event.timestamp,
            metadata={"runtime": event.runtime},
        )
        decision_node = ProvenanceNode(
            node_id=f"decision:{decision.decision_id}",
            trace_id=event.trace_id,
            kind="decision",
            ref_id=decision.decision_id,
            label=decision.decision,
            metadata={"severity": decision.severity, "risk_score": decision.risk_score},
        )
        audit_node = ProvenanceNode(
            node_id=f"audit:{audit_event.audit_id}",
            trace_id=event.trace_id,
            kind="audit",
            ref_id=audit_event.audit_id,
            label=audit_event.event_type,
            timestamp=audit_event.timestamp,
            metadata={"runtime": audit_event.runtime, "stage": audit_event.stage},
        )
        self.store.add_provenance_node(event_node)
        self.store.add_provenance_node(decision_node)
        self.store.add_provenance_node(audit_node)
        if critic_review is not None:
            critic_node = ProvenanceNode(
                node_id=f"action_critic:{critic_review.review_id}",
                trace_id=event.trace_id,
                kind="action_critic",
                ref_id=critic_review.review_id,
                label=critic_review.verdict,
                timestamp=critic_review.created_at,
                metadata={
                    "reviewer": critic_review.reviewer,
                    "confidence": critic_review.confidence,
                    "degraded": critic_review.degraded,
                },
            )
            self.store.add_provenance_node(critic_node)
        self.store.add_provenance_edge(
            ProvenanceEdge(
                edge_id=f"edge:{event.event_id}:{decision.decision_id}",
                trace_id=event.trace_id,
                source_node_id=event_node.node_id,
                target_node_id=decision_node.node_id,
                relation="evaluated_to",
            )
        )
        self.store.add_provenance_edge(
            ProvenanceEdge(
                edge_id=f"edge:{decision.decision_id}:{audit_event.audit_id}",
                trace_id=event.trace_id,
                source_node_id=decision_node.node_id,
                target_node_id=audit_node.node_id,
                relation="recorded_as",
            )
        )
        if critic_review is not None:
            self.store.add_provenance_edge(
                ProvenanceEdge(
                    edge_id=f"edge:{decision.decision_id}:{critic_review.review_id}",
                    trace_id=event.trace_id,
                    source_node_id=decision_node.node_id,
                    target_node_id=f"action_critic:{critic_review.review_id}",
                    relation="reviewed_by",
                )
            )
