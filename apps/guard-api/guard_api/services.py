"""Guard API / Control Plane service layer."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from agentguard_core import (
    AuditEvent,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
    ToolCallPayload,
    evaluate as core_evaluate,
)
from agentguard_core.resources import derive_resources

from guard_api.models import ApprovalRequest, EvaluationApproval, GuardEvaluationResponse
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditEventFilters,
    ControlPlaneStore,
    EvalMetricFilters,
    EvalMetrics,
    PolicySnapshotRecord,
)


@dataclass(frozen=True, slots=True)
class EventDescription:
    action_id: str
    action_name: str
    resource_targets: list[str]
    summary: str
    metadata: dict[str, str]


class PolicyService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore | None = None,
        policy_bundle: PolicyBundle | None = None,
        policy_provider: Callable[[], PolicyBundle] | None = None,
    ) -> None:
        if policy_bundle is not None and policy_provider is not None:
            raise ValueError("PolicyService accepts either policy_bundle or policy_provider, not both")
        self.store = store
        self.policy_bundle = policy_bundle or PolicyBundle()
        self.policy_provider = policy_provider

    def current_snapshot(self) -> PolicyBundle:
        if self.store is not None:
            snapshot = self.store.get_policy_snapshot()
            if snapshot is not None:
                return snapshot
        if self.policy_provider is not None:
            return self.policy_provider()
        return self.policy_bundle

    def save_snapshot(self, policy_bundle: PolicyBundle, *, updated_by: str = "system") -> PolicyBundle:
        if self.store is not None:
            return self.store.save_policy_snapshot(policy_bundle, updated_by=updated_by).policy_bundle
        self.policy_bundle = policy_bundle
        return policy_bundle

    def list_history(self, *, limit: int = 100) -> list[PolicySnapshotRecord]:
        if self.store is None:
            return []
        return self.store.list_policy_snapshot_history(limit=limit)


class AuditService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def submit(self, event: AuditEvent) -> dict[str, str | bool]:
        self.store.add_audit_event(event)
        return {"ok": True, "audit_id": event.audit_id}

    def list_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
        return self.store.list_audit_events(filters)

    def record_evaluation(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        approval_id: str | None = None,
    ) -> AuditEvent:
        audit_event = build_audit_event(event, decision, approval_id=approval_id)
        self.store.add_audit_event(audit_event)
        return audit_event


class ApprovalService:
    def __init__(self, *, store: ControlPlaneStore, settings: GuardApiSettings) -> None:
        self.store = store
        self.settings = settings

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
        approval = ApprovalRequest(
            trace_id=event.trace_id,
            tool_call_id=description.action_id,
            requesting_principal_id=requesting_principal_id,
            runtime=event.runtime,
            agent_id=event.security_context.agent_id,
            tool=description.action_name,
            resource=decision.approval_intent.resource,
            reason=decision.reason,
            risk_score=decision.risk_score,
            severity=decision.severity,
            decision_options=decision.approval_intent.options,
            expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=self.settings.approval_nonce_ttl_seconds)
            ).isoformat(),
        )
        return self.store.create_approval(approval)

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        pending: list[ApprovalRequest] = []
        for approval in self.store.list_pending_approvals():
            if self._is_expired(approval):
                self.store.expire_approval(approval.approval_id)
                continue
            pending.append(approval)
        return pending

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        approval = self.store.get_approval(approval_id)
        if approval is None:
            return None
        return self._with_expired_status(approval)

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        approval = self.get_approval(approval_id)
        if approval is not None and approval.status == "expired":
            approval.decision = "deny"
            return approval
        return self.store.resolve_approval(approval_id, decision)

    def _with_expired_status(self, approval: ApprovalRequest) -> ApprovalRequest:
        if self._is_expired(approval):
            return self.store.expire_approval(approval.approval_id)
        return approval

    def _is_expired(self, approval: ApprovalRequest) -> bool:
        if approval.status != "pending" or approval.expires_at is None:
            return False
        try:
            expires_at = datetime.fromisoformat(approval.expires_at)
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at < datetime.now(timezone.utc)


class MetricService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        return self.store.eval_metrics(filters)


class TraceService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def get_trace(self, trace_id: str) -> dict[str, object]:
        return {
            "trace_id": trace_id,
            "audit_events": [
                event.model_dump(mode="json")
                for event in self.store.list_audit_events(AuditEventFilters(trace_id=trace_id, limit=1000))
            ],
            "approvals": [
                approval.model_dump(mode="json") for approval in self.store.list_approvals(trace_id=trace_id)
            ],
            "metrics": self.store.eval_metrics(EvalMetricFilters(trace_id=trace_id)),
        }


class EvaluationService:
    def __init__(
        self,
        *,
        policy_service: PolicyService,
        audit_service: AuditService,
        approval_service: ApprovalService,
    ) -> None:
        self.policy_service = policy_service
        self.audit_service = audit_service
        self.approval_service = approval_service

    def evaluate(self, event: GuardEvent, *, requesting_principal_id: str) -> GuardEvaluationResponse:
        decision = core_evaluate(event, self.policy_service.current_snapshot())
        approval = self.approval_service.create_for_decision(
            event,
            decision,
            requesting_principal_id=requesting_principal_id,
        )
        self.audit_service.record_evaluation(
            event,
            decision,
            approval_id=approval.approval_id if approval is not None else None,
        )
        return GuardEvaluationResponse(
            decision=decision,
            approval=(
                EvaluationApproval(
                    approval_id=approval.approval_id,
                    status=approval.status,
                    decision_options=approval.decision_options,
                )
                if approval is not None
                else None
            ),
        )


def build_audit_event(
    event: GuardEvent,
    decision: GuardDecision,
    *,
    approval_id: str | None = None,
) -> AuditEvent:
    description = describe_guard_event(event)
    links = {"event_id": event.event_id, "decision_id": decision.decision_id}
    if approval_id is not None:
        links["approval_id"] = approval_id
    return AuditEvent(
        trace_id=event.trace_id,
        case_id=event.case_id,
        runtime=event.runtime,
        event_type=event.event_type,
        attack_type=event.attack_type,
        is_malicious=event.is_malicious,
        summary=description.summary,
        decision=decision.decision,
        risk_score=decision.risk_score,
        severity=decision.severity,
        blocked=decision.blocked,
        resource_targets=description.resource_targets,
        rule_hits=[hit.rule_id for hit in decision.rule_hits],
        reason=decision.reason,
        links=links,
        latency_ms=decision.latency_ms,
        metadata=description.metadata,
    )


def describe_guard_event(event: GuardEvent) -> EventDescription:
    resources = derive_resources(event)
    resource_targets = [resource.target for resource in resources if resource.target]
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        action_id = payload.tool.call_id
        action_name = payload.tool.name
        return EventDescription(
            action_id=action_id,
            action_name=action_name,
            resource_targets=resource_targets,
            summary=f"Agent attempted to call {action_name}",
            metadata={
                "event_type": event.event_type,
                "action_id": action_id,
                "action_name": action_name,
                "tool": payload.tool.name,
                "tool_call_id": payload.tool.call_id,
            },
        )

    action_id = event.event_id
    action_name = event.event_type
    metadata = {
        "event_type": event.event_type,
        "action_id": action_id,
        "action_name": action_name,
    }
    payload_tool = getattr(payload, "tool", None)
    if payload_tool is not None:
        metadata["source_tool"] = payload_tool.name
        metadata["source_tool_call_id"] = payload_tool.call_id
    payload_phase = getattr(payload, "phase", None)
    if payload_phase is not None:
        metadata["phase"] = payload_phase
    payload_model = getattr(payload, "model", None)
    if payload_model is not None:
        metadata["model"] = payload_model
    payload_channel = getattr(payload, "channel", None)
    if payload_channel is not None:
        metadata["channel"] = payload_channel
    payload_recipient = getattr(payload, "recipient", None)
    if payload_recipient is not None:
        metadata["recipient"] = payload_recipient
    payload_memory = getattr(payload, "memory", None)
    if payload_memory is not None:
        metadata["memory_namespace"] = payload_memory.namespace
        metadata["memory_key"] = payload_memory.key

    return EventDescription(
        action_id=action_id,
        action_name=action_name,
        resource_targets=resource_targets,
        summary=f"Agent evaluated {action_name}",
        metadata=metadata,
    )
