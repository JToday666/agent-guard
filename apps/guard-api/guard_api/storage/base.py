"""Storage protocol for Guard API / Control Plane state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentguard_core import AuditEvent

from guard_api.models import ApprovalRequest


@dataclass(frozen=True, slots=True)
class AuditEventFilters:
    trace_id: str | None = None
    case_id: str | None = None
    runtime: str | None = None
    decision: str | None = None
    limit: int = 500


@dataclass(frozen=True, slots=True)
class EvalMetricFilters:
    trace_id: str | None = None
    case_id: str | None = None
    runtime: str | None = None
    decision: str | None = None


@dataclass(frozen=True, slots=True)
class StoredLaunchCode:
    code_hash: str
    expires_at: str
    used_at: str | None = None


@dataclass(frozen=True, slots=True)
class StoredBrowserSession:
    session_hash: str
    csrf_token: str
    expires_at: str
    revoked_at: str | None = None


@dataclass(frozen=True, slots=True)
class StoredApprovalNonce:
    nonce_hash: str
    approval_id: str
    session_hash: str
    tool_call_id: str
    expires_at: str
    used_at: str | None = None


EvalMetrics = dict[str, int | float | None]


class ControlPlaneStore(Protocol):
    def initialize(self) -> None:
        ...

    def health_check(self) -> bool:
        ...

    def add_audit_event(self, event: AuditEvent) -> None:
        ...

    def list_audit_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
        ...

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        ...

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        ...

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        ...

    def list_approvals(self, trace_id: str | None = None) -> list[ApprovalRequest]:
        ...

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        ...

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        ...

    def expire_approval(self, approval_id: str) -> ApprovalRequest:
        ...

    def create_launch_code(self, code_hash: str, expires_at: str) -> StoredLaunchCode:
        ...

    def consume_launch_code(self, code_hash: str, used_at: str) -> StoredLaunchCode | None:
        ...

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession:
        ...

    def get_browser_session(self, session_hash: str) -> StoredBrowserSession | None:
        ...

    def revoke_browser_session(self, session_hash: str, revoked_at: str) -> None:
        ...

    def create_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        tool_call_id: str,
        expires_at: str,
    ) -> StoredApprovalNonce:
        ...

    def consume_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        tool_call_id: str,
        used_at: str,
    ) -> StoredApprovalNonce | None:
        ...
