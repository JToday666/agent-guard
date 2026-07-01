"""Guard API / Control Plane service layer."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from agentguard_core import (
    ActionCritic,
    ActionCriticReview,
    AuditEvent,
    ConfigAuditEvent,
    ConfigAuditResult,
    GuardDecision,
    GuardEvent,
    MemoryEventPayload,
    MemoryGuardChange,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
    ToolCallPayload,
    evaluate as core_evaluate,
    evaluate_config_audit,
    utc_now_iso,
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
    subject_id: str
    subject_type: str
    action_id: str
    action_name: str
    resource_targets: list[str]
    summary: str
    metadata: dict[str, object]


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
        self._record_audit_provenance(event)
        return {"ok": True, "audit_id": event.audit_id}

    def list_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
        return self.store.list_audit_events(filters)

    def record_evaluation(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        approval_id: str | None = None,
        critic_review: ActionCriticReview | None = None,
        memory_change_id: str | None = None,
    ) -> AuditEvent:
        audit_event = build_audit_event(
            event,
            decision,
            approval_id=approval_id,
            critic_review_id=critic_review.review_id if critic_review is not None else None,
            memory_change_id=memory_change_id,
        )
        self.store.add_audit_event(audit_event)
        if critic_review is not None:
            self.store.add_action_critic_review(critic_review)
        self._record_evaluation_provenance(event, decision, audit_event, critic_review=critic_review)
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
        source_id = event.links.get("config_audit_event_id") or event.links.get("event_id")
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


class ConfigAuditService:
    def __init__(self, *, store: ControlPlaneStore, audit_service: AuditService | None = None) -> None:
        self.store = store
        self.audit_service = audit_service or AuditService(store=store)

    def evaluate(self, event: ConfigAuditEvent) -> ConfigAuditResult:
        result = evaluate_config_audit(event)
        for finding in result.findings:
            self.store.add_config_audit_finding(event, finding)
        self.audit_service.submit(_config_audit_event(event, result))
        return result


class MemoryGuardService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def propose(self, change: MemoryGuardChange) -> MemoryGuardChange:
        status = "quarantined" if _should_quarantine_memory_change(change) else "proposed"
        proposed = change.model_copy(update={"status": status, "updated_at": utc_now_iso()})
        return self.store.create_memory_change(proposed)

    def commit(self, change_id: str) -> MemoryGuardChange:
        return self.store.update_memory_change_status(change_id, "committed")

    def rollback(self, change_id: str) -> MemoryGuardChange:
        return self.store.update_memory_change_status(change_id, "rolled_back")


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
            subject_id=description.subject_id,
            subject_type=description.subject_type,
            action_id=description.action_id,
            action_name=description.action_name,
            tool_call_id=description.subject_id,
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

    def runtime_metrics(self, *, runtime: str | None = None, limit: int = 1000) -> dict[str, object]:
        events = self.store.list_audit_events(AuditEventFilters(runtime=runtime, limit=limit))
        by_runtime: dict[str, dict[str, object]] = {}
        hook_activity: dict[str, int] = {}
        for event in events:
            bucket = by_runtime.setdefault(
                event.runtime,
                {
                    "event_count": 0,
                    "allow_count": 0,
                    "deny_count": 0,
                    "ask_count": 0,
                    "blocked_count": 0,
                    "average_latency_ms": None,
                    "_latency_values": [],
                    "last_event_at": event.timestamp,
                },
            )
            bucket["event_count"] = int(bucket["event_count"]) + 1
            bucket[f"{event.decision}_count"] = int(bucket[f"{event.decision}_count"]) + 1
            if event.blocked or event.decision in {"deny", "ask"}:
                bucket["blocked_count"] = int(bucket["blocked_count"]) + 1
            if event.latency_ms is not None:
                bucket["_latency_values"].append(event.latency_ms)  # type: ignore[union-attr]
            if event.timestamp > str(bucket["last_event_at"]):
                bucket["last_event_at"] = event.timestamp
            hook_name = _event_hook_name(event)
            if hook_name is not None:
                hook_activity[hook_name] = hook_activity.get(hook_name, 0) + 1

        for bucket in by_runtime.values():
            latency_values = bucket.pop("_latency_values")
            bucket["average_latency_ms"] = (
                sum(latency_values) / len(latency_values) if latency_values else None
            )

        statuses = {
            adapter_id: status
            for adapter_id, status in self.store.list_adapter_statuses().items()
            if runtime is None or status.get("runtime") == runtime or adapter_id == runtime
        }
        event_count = len(events)
        blocked_count = sum(1 for event in events if event.blocked or event.decision in {"deny", "ask"})
        latency_values = [event.latency_ms for event in events if event.latency_ms is not None]
        return {
            "runtime": runtime,
            "event_count": event_count,
            "allow_count": sum(1 for event in events if event.decision == "allow"),
            "deny_count": sum(1 for event in events if event.decision == "deny"),
            "ask_count": sum(1 for event in events if event.decision == "ask"),
            "blocked_count": blocked_count,
            "block_rate": (blocked_count / event_count) if event_count else None,
            "average_latency_ms": (sum(latency_values) / len(latency_values)) if latency_values else None,
            "by_runtime": by_runtime,
            "hook_activity": dict(sorted(hook_activity.items())),
            "adapters": statuses,
            "active_adapter_count": sum(1 for status in statuses.values() if status.get("loaded") is True),
        }


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

    def get_provenance(self, trace_id: str) -> dict[str, object]:
        nodes, edges = self.store.list_provenance(trace_id)
        return {
            "trace_id": trace_id,
            "nodes": [node.model_dump(mode="json") for node in nodes],
            "edges": [edge.model_dump(mode="json") for edge in edges],
        }


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

    def evaluate(self, event: GuardEvent, *, requesting_principal_id: str) -> GuardEvaluationResponse:
        decision = core_evaluate(event, self.policy_service.current_snapshot())
        critic_review = self.action_critic.review(event, decision)
        approval = self.approval_service.create_for_decision(
            event,
            decision,
            requesting_principal_id=requesting_principal_id,
        )
        memory_change = self._record_memory_change(event, decision)
        self.audit_service.record_evaluation(
            event,
            decision,
            approval_id=approval.approval_id if approval is not None else None,
            critic_review=critic_review,
            memory_change_id=memory_change.change_id if memory_change is not None else None,
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

    def _record_memory_change(self, event: GuardEvent, decision: GuardDecision) -> MemoryGuardChange | None:
        if self.memory_guard_service is None or not isinstance(event.payload, MemoryEventPayload):
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


def build_audit_event(
    event: GuardEvent,
    decision: GuardDecision,
    *,
    approval_id: str | None = None,
    critic_review_id: str | None = None,
    memory_change_id: str | None = None,
) -> AuditEvent:
    description = describe_guard_event(event)
    links = {"event_id": event.event_id, "decision_id": decision.decision_id}
    if approval_id is not None:
        links["approval_id"] = approval_id
    if critic_review_id is not None:
        links["critic_review_id"] = critic_review_id
    if memory_change_id is not None:
        links["memory_change_id"] = memory_change_id
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
        metadata=_merge_metadata(
            _security_context_metadata(event),
            event.metadata,
            description.metadata,
        ),
    )


def _config_audit_event(event: ConfigAuditEvent, result: ConfigAuditResult) -> AuditEvent:
    worst = _worst_finding_severity(result.findings)
    risk_score = {"low": 15, "medium": 45, "high": 80, "critical": 95}[worst]
    return AuditEvent(
        trace_id=str(event.metadata.get("trace_id") or event.event_id),
        runtime=event.runtime,
        stage=event.action,
        event_type="config_audit",
        summary=f"Configuration audit for {event.target_type}:{event.target_id}",
        decision="deny" if result.decision == "block" else "allow",
        risk_score=risk_score,
        severity=worst,
        blocked=result.decision == "block",
        resource_targets=[event.target_id],
        rule_hits=[finding.category for finding in result.findings],
        reason=result.reason,
        links={"config_audit_event_id": event.event_id},
        metadata=_merge_metadata(
            event.metadata,
            {
                "target_type": event.target_type,
                "target_id": event.target_id,
                "finding_count": len(result.findings),
            },
        ),
    )


def _worst_finding_severity(findings: list[object]) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    worst = "low"
    for finding in findings:
        severity = getattr(finding, "severity", "low")
        if severity in rank and rank[severity] > rank[worst]:
            worst = severity
    return worst


def _should_quarantine_memory_change(change: MemoryGuardChange) -> bool:
    preview = change.value_preview.lower()
    if change.source_trust != "trusted":
        return True
    return any(marker in preview for marker in ("secret", "token", "password", "always send"))


def _event_hook_name(event: AuditEvent) -> str | None:
    hook_name = event.metadata.get("openclaw_hook") or event.metadata.get("hook_name")
    if isinstance(hook_name, str) and hook_name:
        return hook_name
    if event.event_type == "runtime_observation" and event.stage:
        return event.stage
    return None


def _security_context_metadata(event: GuardEvent) -> dict[str, object]:
    context = event.security_context
    metadata: dict[str, object] = {}
    scalar_fields = (
        "user_task",
        "source_type",
        "source_trust",
        "channel",
        "sender_id",
        "run_id",
        "agent_id",
        "current_step",
        "model_intent",
    )
    for field_name in scalar_fields:
        value = getattr(context, field_name)
        if value not in (None, ""):
            metadata[field_name] = value
    if context.derived_paths:
        metadata["derived_paths"] = list(context.derived_paths)
    if context.context_sources:
        metadata["context_sources"] = list(context.context_sources)
    return metadata


def _merge_metadata(*items: dict[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    for item in items:
        for key, value in item.items():
            if value in (None, ""):
                continue
            metadata[key] = value
    return metadata


def describe_guard_event(event: GuardEvent) -> EventDescription:
    resources = derive_resources(event)
    resource_targets = [resource.target for resource in resources if resource.target]
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        action_id = payload.tool.call_id
        action_name = payload.tool.name
        return EventDescription(
            subject_id=action_id,
            subject_type="tool_call",
            action_id=action_id,
            action_name=action_name,
            resource_targets=resource_targets,
            summary=f"Agent attempted to call {action_name}",
            metadata={
                "event_type": event.event_type,
                "subject_id": action_id,
                "subject_type": "tool_call",
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
        "subject_id": action_id,
        "subject_type": event.event_type,
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
    payload_provider = getattr(payload, "provider", None)
    if payload_provider is not None:
        metadata["provider"] = payload_provider
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
        subject_id=action_id,
        subject_type=event.event_type,
        action_id=action_id,
        action_name=action_name,
        resource_targets=resource_targets,
        summary=f"Agent evaluated {action_name}",
        metadata=metadata,
    )
