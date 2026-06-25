"""In-memory Control Plane store used by tests and local smoke runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from agentguard_core import AuditEvent, PolicyBundle, utc_now_iso

from guard_api.models import ApprovalRequest
from guard_api.storage.base import (
    AuditEventFilters,
    EvalMetricFilters,
    EvalMetrics,
    PolicySnapshotRecord,
    StoredApprovalNonce,
    StoredBrowserSession,
    StoredLaunchCode,
)


@dataclass(slots=True)
class MemoryControlPlaneStore:
    audit_events: list[AuditEvent] = field(default_factory=list)
    approvals: dict[str, ApprovalRequest] = field(default_factory=dict)
    launch_codes: dict[str, StoredLaunchCode] = field(default_factory=dict)
    browser_sessions: dict[str, StoredBrowserSession] = field(default_factory=dict)
    approval_nonces: dict[str, StoredApprovalNonce] = field(default_factory=dict)
    policy_snapshot: PolicySnapshotRecord | None = None
    policy_snapshot_history: list[PolicySnapshotRecord] = field(default_factory=list)
    policy_snapshot_lock: Any = field(default_factory=Lock, init=False, repr=False)

    def initialize(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def add_audit_event(self, event: AuditEvent) -> None:
        self.audit_events.append(event)

    def list_audit_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
        filters = filters or AuditEventFilters()
        events = _filter_audit_events(list(reversed(self.audit_events)), filters)
        return events[: _bounded_limit(filters.limit)]

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        events = _filter_audit_events(list(reversed(self.audit_events)), filters or EvalMetricFilters())
        return _aggregate_metrics(events)

    def get_policy_snapshot(self) -> PolicyBundle | None:
        if self.policy_snapshot is None:
            return None
        return self.policy_snapshot.policy_bundle

    def save_policy_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord:
        with self.policy_snapshot_lock:
            revision = (self.policy_snapshot.revision + 1) if self.policy_snapshot is not None else 1
            record = PolicySnapshotRecord(
                revision=revision,
                policy_bundle=policy_bundle,
                updated_at=utc_now_iso(),
                updated_by=updated_by,
            )
            self.policy_snapshot = record
            self.policy_snapshot_history.append(record)
            return record

    def list_policy_snapshot_history(self, limit: int = 100) -> list[PolicySnapshotRecord]:
        return list(reversed(self.policy_snapshot_history))[: _bounded_limit(limit)]

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        self.approvals[approval.approval_id] = approval
        return approval

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return [item for item in self.approvals.values() if item.status == "pending"]

    def list_approvals(self, trace_id: str | None = None) -> list[ApprovalRequest]:
        approvals = list(self.approvals.values())
        if trace_id is not None:
            approvals = [item for item in approvals if item.trace_id == trace_id]
        return sorted(approvals, key=lambda item: item.created_at)

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.approvals.get(approval_id)

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        approval = self.approvals[approval_id]
        approval.status = "resolved"
        approval.decision = decision  # type: ignore[assignment]
        approval.resolved_at = utc_now_iso()
        self.approvals[approval_id] = approval
        return approval

    def expire_approval(self, approval_id: str) -> ApprovalRequest:
        approval = self.approvals[approval_id]
        approval.status = "expired"
        approval.decision = "deny"
        self.approvals[approval_id] = approval
        return approval

    def create_launch_code(self, code_hash: str, expires_at: str) -> StoredLaunchCode:
        launch_code = StoredLaunchCode(code_hash=code_hash, expires_at=expires_at)
        self.launch_codes[code_hash] = launch_code
        return launch_code

    def consume_launch_code(self, code_hash: str, used_at: str) -> StoredLaunchCode | None:
        launch_code = self.launch_codes.get(code_hash)
        if launch_code is None or launch_code.used_at is not None:
            return None
        consumed = StoredLaunchCode(code_hash=code_hash, expires_at=launch_code.expires_at, used_at=used_at)
        self.launch_codes[code_hash] = consumed
        return consumed

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession:
        session = StoredBrowserSession(session_hash=session_hash, csrf_token=csrf_token, expires_at=expires_at)
        self.browser_sessions[session_hash] = session
        return session

    def get_browser_session(self, session_hash: str) -> StoredBrowserSession | None:
        return self.browser_sessions.get(session_hash)

    def revoke_browser_session(self, session_hash: str, revoked_at: str) -> None:
        session = self.browser_sessions.get(session_hash)
        if session is None:
            return
        self.browser_sessions[session_hash] = StoredBrowserSession(
            session_hash=session.session_hash,
            csrf_token=session.csrf_token,
            expires_at=session.expires_at,
            revoked_at=revoked_at,
        )

    def create_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
        expires_at: str,
    ) -> StoredApprovalNonce:
        approval_subject_id = _approval_subject_id(subject_id=subject_id, tool_call_id=tool_call_id)
        nonce = StoredApprovalNonce(
            nonce_hash=nonce_hash,
            approval_id=approval_id,
            session_hash=session_hash,
            subject_id=approval_subject_id,
            tool_call_id=tool_call_id or approval_subject_id,
            expires_at=expires_at,
        )
        self.approval_nonces[nonce_hash] = nonce
        return nonce

    def consume_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
        used_at: str,
    ) -> StoredApprovalNonce | None:
        approval_subject_id = _approval_subject_id(subject_id=subject_id, tool_call_id=tool_call_id)
        nonce = self.approval_nonces.get(nonce_hash)
        if (
            nonce is None
            or nonce.used_at is not None
            or nonce.approval_id != approval_id
            or nonce.session_hash != session_hash
            or nonce.subject_id != approval_subject_id
        ):
            return None
        consumed = StoredApprovalNonce(
            nonce_hash=nonce.nonce_hash,
            approval_id=nonce.approval_id,
            session_hash=nonce.session_hash,
            subject_id=nonce.subject_id,
            tool_call_id=nonce.tool_call_id,
            expires_at=nonce.expires_at,
            used_at=used_at,
        )
        self.approval_nonces[nonce_hash] = consumed
        return consumed


def _filter_audit_events(
    events: list[AuditEvent],
    filters: AuditEventFilters | EvalMetricFilters,
) -> list[AuditEvent]:
    if filters.trace_id is not None:
        events = [event for event in events if event.trace_id == filters.trace_id]
    if filters.case_id is not None:
        events = [event for event in events if event.case_id == filters.case_id]
    if filters.runtime is not None:
        events = [event for event in events if event.runtime == filters.runtime]
    if filters.decision is not None:
        events = [event for event in events if event.decision == filters.decision]
    return events


def _aggregate_metrics(events: list[AuditEvent]) -> EvalMetrics:
    blocked = [event for event in events if event.decision in {"deny", "ask"} or event.blocked]
    labeled_benign = [event for event in events if event.is_malicious is False]
    labeled_malicious = [event for event in events if event.is_malicious is True]
    false_positives = [event for event in labeled_benign if event.decision in {"deny", "ask"} or event.blocked]
    false_negatives = [event for event in labeled_malicious if event.decision == "allow" and not event.blocked]
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


def _bounded_limit(limit: int) -> int:
    return max(1, min(limit, 1000))


def _approval_subject_id(*, subject_id: str | None, tool_call_id: str | None) -> str:
    approval_subject_id = subject_id or tool_call_id
    if approval_subject_id is None:
        raise ValueError("approval nonce requires subject_id or tool_call_id")
    return approval_subject_id
