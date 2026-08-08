"""In-memory Control Plane store used by tests and local smoke runs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Iterator

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    ConfigAuditEvent,
    ConfigAuditFinding,
    MemoryGuardChange,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
    utc_now_iso,
)

from guard_api.models import (
    AdapterStatusRecord,
    ApprovalRequest,
    ConfigAuditFindingRecord,
    CredentialRecord,
    EvaluationRun,
    LlmApprovalReview,
)
from guard_api.storage.base import (
    AuditEventFilters,
    AuditIdConflictError,
    AuditIntegrityStatus,
    AuditWindowQuery,
    EvalMetricFilters,
    EvalMetrics,
    PolicySnapshotRecord,
    ProvenanceEndpointMissingError,
    StoredApprovalNonce,
    StoredBrowserSession,
    StoredLaunchCode,
    merge_provenance_edge,
    merge_provenance_node,
    within_evaluated_range,
)
from guard_api.storage.integrity import (
    attach_audit_integrity,
    read_audit_integrity,
    verify_audit_chain,
)
from guard_api.services.metric_rules import aggregate_policy_metrics


@dataclass(slots=True)
class MemoryControlPlaneStore:
    audit_events: list[AuditEvent] = field(default_factory=list)
    provenance_nodes: dict[str, ProvenanceNode] = field(default_factory=dict)
    provenance_edges: dict[str, ProvenanceEdge] = field(default_factory=dict)
    config_audit_findings: list[dict[str, Any]] = field(default_factory=list)
    evaluation_runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    adapter_statuses: dict[str, dict[str, Any]] = field(default_factory=dict)
    credentials: dict[str, CredentialRecord] = field(default_factory=dict)
    action_critic_reviews: dict[str, ActionCriticReview] = field(default_factory=dict)
    memory_changes: dict[str, MemoryGuardChange] = field(default_factory=dict)
    approvals: dict[str, ApprovalRequest] = field(default_factory=dict)
    launch_codes: dict[str, StoredLaunchCode] = field(default_factory=dict)
    browser_sessions: dict[str, StoredBrowserSession] = field(default_factory=dict)
    approval_nonces: dict[str, StoredApprovalNonce] = field(default_factory=dict)
    policy_snapshot: PolicySnapshotRecord | None = None
    policy_snapshot_history: list[PolicySnapshotRecord] = field(default_factory=list)
    audit_integrity_lock: Any = field(default_factory=Lock, init=False, repr=False)
    provenance_lock: Any = field(default_factory=Lock, init=False, repr=False)
    policy_evaluation_lock: Any = field(default_factory=Lock, init=False, repr=False)
    policy_snapshot_lock: Any = field(default_factory=Lock, init=False, repr=False)
    audit_events_by_id: dict[str, AuditEvent] = field(default_factory=dict)

    def initialize(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def add_audit_event(self, event: AuditEvent) -> bool:
        with self.audit_integrity_lock:
            existing = self.audit_events_by_id.get(event.audit_id)
            if existing is not None:
                if _audit_content_matches(existing, event):
                    return False
                raise AuditIdConflictError(event.audit_id)
            prev = (
                read_audit_integrity(self.audit_events[-1])
                if self.audit_events
                else None
            )
            event_with_integrity = attach_audit_integrity(
                event,
                sequence=len(self.audit_events) + 1,
                prev_hash=prev.event_hash if prev is not None else None,
            )
            self.audit_events.append(event_with_integrity)
            self.audit_events_by_id[event.audit_id] = event_with_integrity
            return True

    def get_audit_event(self, audit_id: str) -> AuditEvent | None:
        with self.audit_integrity_lock:
            return self.audit_events_by_id.get(audit_id)

    def list_audit_events(
        self, filters: AuditEventFilters | None = None
    ) -> list[AuditEvent]:
        filters = filters or AuditEventFilters()
        events = _filter_audit_events(list(reversed(self.audit_events)), filters)
        return events[: _bounded_limit(filters.limit)]

    def read_audit_events_bounded(self, query: AuditWindowQuery) -> list[AuditEvent]:
        # 链内 sequence 即位序（sequence = index + 1），位序切片即上界读取：
        # sequence <= upper，且 after_sequence 存在时 sequence < after_sequence。
        with self.audit_integrity_lock:
            head_sequence = len(self.audit_events)
            upper = (
                head_sequence if query.upper_sequence is None else query.upper_sequence
            )
            end = upper
            if query.after_sequence is not None:
                end = min(end, query.after_sequence - 1)
            events = [
                event
                for event in self.audit_events[: max(end, 0)]
                if _matches_window_filters(event, query)
            ]
        return list(reversed(events))[: query.limit]

    def verify_audit_integrity(self) -> AuditIntegrityStatus:
        with self.audit_integrity_lock:
            return verify_audit_chain(list(self.audit_events))

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None:
        with self.audit_integrity_lock:
            for event in self.audit_events:
                if _is_policy_evaluation_for(event, event_id):
                    return event
        return None

    @contextmanager
    def policy_evaluation_guard(self, event_id: str) -> Iterator[None]:
        """Serialize evaluation side effects before the policy audit is committed.

        The in-memory backend deliberately uses one process-wide evaluation lock.
        Evaluation throughput is not a local-test bottleneck, and the simple lock
        keeps approval, memory-change and audit creation consistent with the
        PostgreSQL per-event advisory lock.
        """

        del event_id
        with self.policy_evaluation_lock:
            yield

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        # 按入链顺序传入，共享聚合器对重复逻辑键保留最早入链记录（§19.1）。
        events = _filter_audit_events(
            list(self.audit_events), filters or EvalMetricFilters()
        )
        return aggregate_policy_metrics(events)

    def add_provenance_node(self, node: ProvenanceNode) -> ProvenanceNode:
        with self.provenance_lock:
            existing = self.provenance_nodes.get(node.node_id)
            merged = node if existing is None else merge_provenance_node(existing, node)
            self.provenance_nodes[node.node_id] = merged
            return merged

    def get_provenance_node(self, node_id: str) -> ProvenanceNode | None:
        with self.provenance_lock:
            return self.provenance_nodes.get(node_id)

    def add_provenance_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        with self.provenance_lock:
            source = self.provenance_nodes.get(edge.source_node_id)
            target = self.provenance_nodes.get(edge.target_node_id)
            if (
                source is None
                or target is None
                or source.trace_id != edge.trace_id
                or target.trace_id != edge.trace_id
            ):
                raise ProvenanceEndpointMissingError(edge.edge_id)
            existing = self.provenance_edges.get(edge.edge_id)
            merged = edge if existing is None else merge_provenance_edge(existing, edge)
            self.provenance_edges[edge.edge_id] = merged
            return merged

    def list_provenance(
        self, trace_id: str
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]:
        with self.provenance_lock:
            nodes = [
                node
                for node in self.provenance_nodes.values()
                if node.trace_id == trace_id
            ]
            edges = [
                edge
                for edge in self.provenance_edges.values()
                if edge.trace_id == trace_id
            ]
        nodes.sort(key=lambda node: (node.timestamp, node.node_id))
        edges.sort(key=lambda edge: (edge.timestamp, edge.edge_id))
        return nodes, edges

    def add_config_audit_finding(
        self,
        event: ConfigAuditEvent,
        finding: ConfigAuditFinding,
    ) -> ConfigAuditFinding:
        self.config_audit_findings.append(
            {
                "event": event.model_dump(mode="json"),
                "finding": finding.model_dump(mode="json"),
            }
        )
        return finding

    def list_config_audit_findings(
        self,
        *,
        trace_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[ConfigAuditFindingRecord]:
        rows = [_config_finding_record(row) for row in self.config_audit_findings]
        if trace_id is not None:
            rows = [row for row in rows if row.trace_id == trace_id]
        if target_id is not None:
            rows = [row for row in rows if row.target_id == target_id]
        if target_type is not None:
            rows = [row for row in rows if row.target_type == target_type]
        if severity is not None:
            rows = [row for row in rows if row.finding.severity == severity]
        rows.sort(key=lambda row: (row.timestamp, row.finding.finding_id), reverse=True)
        return rows[: _bounded_limit(limit)]

    def save_evaluation_run(
        self, run: EvaluationRun | dict[str, Any]
    ) -> dict[str, Any]:
        payload = EvaluationRun.model_validate(run).model_dump(mode="json")
        self.evaluation_runs[payload["run_id"]] = payload
        return payload

    def get_latest_evaluation_run(self) -> dict[str, Any] | None:
        if not self.evaluation_runs:
            return None
        return max(
            self.evaluation_runs.values(),
            key=lambda run: (str(run["run_at"]), str(run["run_id"])),
        )

    def get_evaluation_run(self, run_id: str) -> dict[str, Any] | None:
        return self.evaluation_runs.get(run_id)

    def list_evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = list(self.evaluation_runs.values())
        if dataset_id is not None:
            rows = [run for run in rows if run.get("dataset_id") == dataset_id]
        if dataset_version is not None:
            rows = [
                run for run in rows if run.get("dataset_version") == dataset_version
            ]
        rows.sort(
            key=lambda run: (str(run["run_at"]), str(run["run_id"])), reverse=True
        )
        return rows[: _bounded_limit(limit)]

    def save_adapter_status(
        self, adapter_id: str, status: AdapterStatusRecord | dict[str, Any]
    ) -> dict[str, Any]:
        payload = AdapterStatusRecord.model_validate(status).model_dump(mode="json")
        self.adapter_statuses[adapter_id] = payload
        return payload

    def get_adapter_status(self, adapter_id: str) -> dict[str, Any] | None:
        return self.adapter_statuses.get(adapter_id)

    def list_adapter_statuses(self) -> dict[str, dict[str, Any]]:
        return dict(self.adapter_statuses)

    def create_credential(
        self, credential: CredentialRecord | dict[str, Any]
    ) -> CredentialRecord:
        record = CredentialRecord.model_validate(credential)
        self.credentials[record.credential_id] = record
        return record

    def get_credential_by_token_hash(self, token_hash: str) -> CredentialRecord | None:
        for credential in self.credentials.values():
            if credential.token_hash == token_hash and credential.revoked_at is None:
                return credential
        return None

    def list_credentials(self) -> list[CredentialRecord]:
        return sorted(
            self.credentials.values(), key=lambda credential: credential.created_at
        )

    def revoke_credential(
        self, credential_id: str, revoked_at: str
    ) -> CredentialRecord:
        credential = self.credentials[credential_id]
        revoked = credential.model_copy(update={"revoked_at": revoked_at})
        self.credentials[credential_id] = revoked
        return revoked

    def add_action_critic_review(
        self, review: ActionCriticReview
    ) -> ActionCriticReview:
        self.action_critic_reviews[review.review_id] = review
        return review

    def list_action_critic_reviews(self, trace_id: str) -> list[ActionCriticReview]:
        reviews = [
            review
            for review in self.action_critic_reviews.values()
            if review.trace_id == trace_id
        ]
        return sorted(reviews, key=lambda review: (review.created_at, review.review_id))

    def create_memory_change(self, change: MemoryGuardChange) -> MemoryGuardChange:
        self.memory_changes[change.change_id] = change
        return change

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None:
        return self.memory_changes.get(change_id)

    def update_memory_change_status(
        self, change_id: str, status: str
    ) -> MemoryGuardChange:
        current = self.memory_changes[change_id]
        updated = current.model_copy(
            update={"status": status, "updated_at": utc_now_iso()}
        )
        self.memory_changes[change_id] = updated
        return updated

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
            revision = (
                (self.policy_snapshot.revision + 1)
                if self.policy_snapshot is not None
                else 1
            )
            record = PolicySnapshotRecord(
                revision=revision,
                policy_bundle=policy_bundle,
                updated_at=utc_now_iso(),
                updated_by=updated_by,
            )
            self.policy_snapshot = record
            self.policy_snapshot_history.append(record)
            return record

    def list_policy_snapshot_history(
        self, limit: int = 100
    ) -> list[PolicySnapshotRecord]:
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

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        resolution_source: str | None = None,
        resolved_by: str | None = None,
        resolution_reason: str | None = None,
        llm_review: LlmApprovalReview | None = None,
    ) -> ApprovalRequest:
        approval = self.approvals[approval_id]
        approval.status = "resolved"
        approval.decision = decision  # type: ignore[assignment]
        approval.resolved_at = utc_now_iso()
        if resolution_source is not None:
            approval.resolution_source = resolution_source  # type: ignore[assignment]
        if resolved_by is not None:
            approval.resolved_by = resolved_by
        if resolution_reason is not None:
            approval.resolution_reason = resolution_reason
        if llm_review is not None:
            approval.llm_review = llm_review  # type: ignore[assignment]
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

    def consume_launch_code(
        self, code_hash: str, used_at: str
    ) -> StoredLaunchCode | None:
        launch_code = self.launch_codes.get(code_hash)
        if launch_code is None or launch_code.used_at is not None:
            return None
        consumed = StoredLaunchCode(
            code_hash=code_hash, expires_at=launch_code.expires_at, used_at=used_at
        )
        self.launch_codes[code_hash] = consumed
        return consumed

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession:
        session = StoredBrowserSession(
            session_hash=session_hash, csrf_token=csrf_token, expires_at=expires_at
        )
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
        approval_subject_id = _approval_subject_id(
            subject_id=subject_id, tool_call_id=tool_call_id
        )
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
        approval_subject_id = _approval_subject_id(
            subject_id=subject_id, tool_call_id=tool_call_id
        )
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


def _audit_content_matches(existing: AuditEvent, incoming: AuditEvent) -> bool:
    from guard_api.storage.integrity import _canonical_json_bytes

    return _canonical_json_bytes(
        existing.model_dump(mode="json", exclude={"integrity"})
    ) == _canonical_json_bytes(incoming.model_dump(mode="json", exclude={"integrity"}))


def _is_policy_evaluation_for(event: AuditEvent, event_id: str) -> bool:
    if event.links.get("event_id") != event_id:
        return False
    if "decision_id" not in event.links:
        return False
    return event.record_type in (None, "policy_evaluation")


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


def _matches_window_filters(event: AuditEvent, query: AuditWindowQuery) -> bool:
    if query.trace_id is not None and event.trace_id != query.trace_id:
        return False
    if query.case_id is not None and event.case_id != query.case_id:
        return False
    if query.runtime is not None and event.runtime != query.runtime:
        return False
    if query.decision is not None and event.decision != query.decision:
        return False
    return within_evaluated_range(
        event.timestamp, query.evaluated_from, query.evaluated_to
    )


def _bounded_limit(limit: int) -> int:
    return max(1, min(limit, 1000))


def _config_finding_record(row: dict[str, Any]) -> ConfigAuditFindingRecord:
    event = ConfigAuditEvent.model_validate(row["event"])
    finding = ConfigAuditFinding.model_validate(row["finding"])
    return ConfigAuditFindingRecord(
        runtime=event.runtime,
        target_type=event.target_type,
        target_id=event.target_id,
        trace_id=str(event.metadata.get("trace_id") or event.event_id),
        event_id=event.event_id,
        timestamp=event.timestamp,
        finding=finding,
    )


def _approval_subject_id(*, subject_id: str | None, tool_call_id: str | None) -> str:
    approval_subject_id = subject_id or tool_call_id
    if approval_subject_id is None:
        raise ValueError("approval nonce requires subject_id or tool_call_id")
    return approval_subject_id
