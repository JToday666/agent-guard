"""Storage protocol for Core audit and approval data."""

from __future__ import annotations

from typing import Protocol

from agentguard_core.models import ApprovalRequest, AuditEvent


class CoreStore(Protocol):
    def add_audit_event(self, event: AuditEvent) -> None:
        ...

    def list_audit_events(self) -> list[AuditEvent]:
        ...

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        ...

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        ...

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        ...

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        ...

