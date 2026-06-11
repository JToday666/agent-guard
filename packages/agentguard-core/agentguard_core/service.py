"""Formal AgentGuard Core service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from time import perf_counter

from .detectors import Detector, OutboundDetector, SensitiveResourceDetector, TaskMismatchDetector, derive_resources
from .models import ApprovalRequest, AuditEvent, PolicyDecision, ToolCallEvent
from .policy import build_policy_decision
from .settings import CoreSettings
from .storage.base import CoreStore
from .storage.postgres import PostgresCoreStore


class AgentGuardCore:
    def __init__(
        self,
        *,
        store: CoreStore | None = None,
        settings: CoreSettings | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self.settings = settings or CoreSettings()
        self.store = store or PostgresCoreStore(self.settings.database_url)
        self.detectors = detectors or [
            SensitiveResourceDetector(),
            OutboundDetector(),
            TaskMismatchDetector(),
        ]

    def initialize(self) -> None:
        self.store.initialize()

    def health_check(self) -> bool:
        return self.store.health_check()

    def evaluate_tool_call(
        self,
        event: ToolCallEvent,
        *,
        requesting_principal_id: str = "cred_adapter_main",
    ) -> PolicyDecision:
        started_at = perf_counter()
        detections = []
        for detector in self.detectors:
            detections.extend(detector.evaluate(event))
        decision = build_policy_decision(detections, started_at=started_at)
        if decision.decision == "ask":
            approval = self._create_approval(event, decision, requesting_principal_id=requesting_principal_id)
            decision.approval = {
                "approval_id": approval.approval_id,
                "status": approval.status,
                "decision_options": approval.decision_options,
            }
        self.store.add_audit_event(self._build_audit_event(event, decision))
        return decision

    def submit_audit_event(self, event: AuditEvent) -> dict[str, str | bool]:
        self.store.add_audit_event(event)
        return {"ok": True, "audit_id": event.audit_id}

    def list_audit_events(self) -> list[AuditEvent]:
        return self.store.list_audit_events()

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

    def eval_metrics(self) -> dict[str, int | float | None]:
        events = self.store.list_audit_events()
        blocked = [event for event in events if event.decision in {"deny", "ask"} or event.blocked]
        labeled_benign = [event for event in events if event.is_malicious is False]
        labeled_malicious = [event for event in events if event.is_malicious is True]
        false_positives = [event for event in labeled_benign if event.decision in {"deny", "ask"} or event.blocked]
        false_negatives = [
            event for event in labeled_malicious if event.decision == "allow" and not event.blocked
        ]
        latency_values = [event.latency_ms for event in events if event.latency_ms is not None]
        return {
            "event_count": len(events),
            "allow_count": sum(1 for event in events if event.decision == "allow"),
            "deny_count": sum(1 for event in events if event.decision == "deny"),
            "ask_count": sum(1 for event in events if event.decision == "ask"),
            "blocked_count": len(blocked),
            "block_rate": (len(blocked) / len(events)) if events else None,
            "fpr": (len(false_positives) / len(labeled_benign)) if labeled_benign else None,
            "fnr": (len(false_negatives) / len(labeled_malicious)) if labeled_malicious else None,
            "average_latency_ms": (sum(latency_values) / len(latency_values)) if latency_values else None,
        }

    def _create_approval(
        self,
        event: ToolCallEvent,
        decision: PolicyDecision,
        *,
        requesting_principal_id: str,
    ) -> ApprovalRequest:
        resources = derive_resources(event)
        resource = resources[0].target if resources else ""
        approval = ApprovalRequest(
            trace_id=event.trace_id,
            tool_call_id=event.tool.call_id,
            requesting_principal_id=requesting_principal_id,
            runtime=event.runtime,
            agent_id=event.security_context.agent_id,
            tool=event.tool.name,
            resource=resource,
            reason=decision.reason,
            risk_score=decision.risk_score,
            severity=decision.severity,
            expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=self.settings.approval_nonce_ttl_seconds)
            ).isoformat(),
        )
        return self.store.create_approval(approval)

    def _build_audit_event(self, event: ToolCallEvent, decision: PolicyDecision) -> AuditEvent:
        resources = derive_resources(event)
        links = {"event_id": event.event_id, "decision_id": decision.decision_id}
        if decision.approval is not None:
            approval_id = decision.approval.get("approval_id")
            if approval_id:
                links["approval_id"] = str(approval_id)
        return AuditEvent(
            trace_id=event.trace_id,
            case_id=event.case_id,
            runtime=event.runtime,
            event_type=event.event_type,
            attack_type=event.attack_type,
            is_malicious=event.is_malicious,
            summary=f"Agent attempted to call {event.tool.name}",
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            resource_targets=[resource.target for resource in resources if resource.target],
            rule_hits=[hit.rule_id for hit in decision.rule_hits],
            reason=decision.reason,
            links=links,
            latency_ms=decision.latency_ms,
            metadata={"tool": event.tool.name, "tool_call_id": event.tool.call_id},
        )

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
