"""Formal AgentGuard Core service."""

from __future__ import annotations

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
        return decision

    def submit_audit_event(self, event: AuditEvent) -> dict[str, str | bool]:
        self.store.add_audit_event(event)
        return {"ok": True, "audit_id": event.audit_id}

    def list_audit_events(self) -> list[AuditEvent]:
        return self.store.list_audit_events()

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return self.store.list_pending_approvals()

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.store.get_approval(approval_id)

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        return self.store.resolve_approval(approval_id, decision)

    def eval_metrics(self) -> dict[str, int | float | None]:
        events = self.store.list_audit_events()
        blocked = [event for event in events if event.decision in {"deny", "ask"} or event.blocked]
        return {
            "event_count": len(events),
            "blocked_count": len(blocked),
            "block_rate": (len(blocked) / len(events)) if events else None,
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
        )
        return self.store.create_approval(approval)

