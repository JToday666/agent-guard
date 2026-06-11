"""In-memory store used by tests and local smoke runs."""

from __future__ import annotations

from dataclasses import dataclass, field

from agentguard_core.models import ApprovalRequest, AuditEvent, utc_now_iso


@dataclass(slots=True)
class MemoryCoreStore:
    audit_events: list[AuditEvent] = field(default_factory=list)
    approvals: dict[str, ApprovalRequest] = field(default_factory=dict)

    def add_audit_event(self, event: AuditEvent) -> None:
        self.audit_events.append(event)

    def list_audit_events(self) -> list[AuditEvent]:
        return list(reversed(self.audit_events))

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        self.approvals[approval.approval_id] = approval
        return approval

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return [item for item in self.approvals.values() if item.status == "pending"]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.approvals.get(approval_id)

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        approval = self.approvals[approval_id]
        approval.status = "resolved"
        approval.decision = decision  # type: ignore[assignment]
        approval.resolved_at = utc_now_iso()
        self.approvals[approval_id] = approval
        return approval

