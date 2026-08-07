"""Storage protocol for Guard API / Control Plane state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentguard_core import (
    AuditEvent,
    ActionCriticReview,
    ConfigAuditEvent,
    ConfigAuditFinding,
    MemoryGuardChange,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
)

from guard_api.models import (
    AdapterStatusRecord,
    ApprovalRequest,
    ConfigAuditFindingRecord,
    CredentialRecord,
    EvaluationRun,
    LlmApprovalReview,
)


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
    subject_id: str
    tool_call_id: str
    expires_at: str
    used_at: str | None = None


@dataclass(frozen=True, slots=True)
class PolicySnapshotRecord:
    revision: int
    policy_bundle: PolicyBundle
    updated_at: str
    updated_by: str


EvalMetrics = dict[str, int | float | None]


@dataclass(frozen=True, slots=True)
class AuditIntegrityStatus:
    valid: bool
    event_count: int
    head_hash: str | None
    first_broken_audit_id: str | None = None


class AuditIdConflictError(ValueError):
    """Raised when the same audit_id is re-submitted with different content."""


class ControlPlaneStore(Protocol):
    def initialize(self) -> None: ...

    def health_check(self) -> bool: ...

    def add_audit_event(self, event: AuditEvent) -> bool: ...

    def list_audit_events(
        self, filters: AuditEventFilters | None = None
    ) -> list[AuditEvent]: ...

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None: ...

    def reserve_policy_evaluation(self, event_id: str) -> bool: ...

    def verify_audit_integrity(self) -> AuditIntegrityStatus: ...

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics: ...

    def add_provenance_node(self, node: ProvenanceNode) -> ProvenanceNode: ...

    def add_provenance_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge: ...

    def list_provenance(
        self, trace_id: str
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]: ...

    def add_config_audit_finding(
        self,
        event: ConfigAuditEvent,
        finding: ConfigAuditFinding,
    ) -> ConfigAuditFinding: ...

    def list_config_audit_findings(
        self,
        *,
        trace_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[ConfigAuditFindingRecord]: ...

    def save_evaluation_run(self, run: EvaluationRun | dict) -> dict: ...

    def get_latest_evaluation_run(self) -> dict | None: ...

    def get_evaluation_run(self, run_id: str) -> dict | None: ...

    def list_evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
    ) -> list[dict]: ...

    def save_adapter_status(
        self, adapter_id: str, status: AdapterStatusRecord | dict
    ) -> dict: ...

    def get_adapter_status(self, adapter_id: str) -> dict | None: ...

    def list_adapter_statuses(self) -> dict[str, dict]: ...

    def create_credential(
        self, credential: CredentialRecord | dict
    ) -> CredentialRecord: ...

    def get_credential_by_token_hash(
        self, token_hash: str
    ) -> CredentialRecord | None: ...

    def list_credentials(self) -> list[CredentialRecord]: ...

    def revoke_credential(
        self, credential_id: str, revoked_at: str
    ) -> CredentialRecord: ...

    def add_action_critic_review(
        self, review: ActionCriticReview
    ) -> ActionCriticReview: ...

    def list_action_critic_reviews(self, trace_id: str) -> list[ActionCriticReview]: ...

    def create_memory_change(self, change: MemoryGuardChange) -> MemoryGuardChange: ...

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None: ...

    def update_memory_change_status(
        self, change_id: str, status: str
    ) -> MemoryGuardChange: ...

    def get_policy_snapshot(self) -> PolicyBundle | None: ...

    def save_policy_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord: ...

    def list_policy_snapshot_history(
        self, limit: int = 100
    ) -> list[PolicySnapshotRecord]: ...

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest: ...

    def list_pending_approvals(self) -> list[ApprovalRequest]: ...

    def list_approvals(self, trace_id: str | None = None) -> list[ApprovalRequest]: ...

    def get_approval(self, approval_id: str) -> ApprovalRequest | None: ...

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        resolution_source: str | None = None,
        resolved_by: str | None = None,
        resolution_reason: str | None = None,
        llm_review: LlmApprovalReview | None = None,
    ) -> ApprovalRequest: ...

    def expire_approval(self, approval_id: str) -> ApprovalRequest: ...

    def create_launch_code(
        self, code_hash: str, expires_at: str
    ) -> StoredLaunchCode: ...

    def consume_launch_code(
        self, code_hash: str, used_at: str
    ) -> StoredLaunchCode | None: ...

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession: ...

    def get_browser_session(self, session_hash: str) -> StoredBrowserSession | None: ...

    def revoke_browser_session(self, session_hash: str, revoked_at: str) -> None: ...

    def create_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
        expires_at: str,
    ) -> StoredApprovalNonce: ...

    def consume_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
        used_at: str,
    ) -> StoredApprovalNonce | None: ...
