"""In-memory Control Plane store used by tests and local smoke runs."""

from __future__ import annotations

import hmac as hmac_module
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from threading import Lock, RLock
from typing import Any, Callable, Iterator, cast

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    ConfigAuditEvent,
    ConfigAuditFinding,
    MemoryGuardChange,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
    memory_change_can_transition,
    utc_now_iso,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import (
    CapabilityGrant,
    ExecutionLease,
    GrantConsumption,
)

from guard_api.models import (
    AdapterStatusRecord,
    ApprovalRequest,
    ConfigAuditFindingRecord,
    CredentialRecord,
    EvaluationRun,
    LlmApprovalReview,
)
from guard_api.runtime_status import (
    ProductRuntime,
    ProductRuntimeStatusIdentityV1,
    ProductRuntimeStatusV2,
)
from guard_api.storage.base import (
    ApprovalExecutionLeaseExpiredError,
    ApprovalExecutionLeaseStateInvalidError,
    ApprovalExecutionLeaseUnavailableError,
    ApprovalLeaseAuthorizationError,
    ApprovalLeaseConsumeCommand,
    ApprovalLeaseConsumptionConflictError,
    ApprovalLeaseExpiredError,
    ApprovalLeaseNotConsumableError,
    ApprovalLeaseNotFoundError,
    ApprovalStateConflictError,
    AuditEventFilters,
    AuditIdConflictError,
    AuditIntegrityStatus,
    AuditWindowQuery,
    CtProvenanceBatchConflictError,
    EnforcementBindingConflictError,
    EnforcementBindingRecord,
    EvaluationRunConflictError,
    GrantConsumptionResult,
    MAX_REBUILD_INPUT_LIMIT,
    MemoryChangeAlreadyExistsError,
    MemoryChangeTransitionError,
    MemoryTransitionResult,
    PolicyRevisionConflictError,
    PolicySnapshotRecord,
    ProductAuthorityCredentialUnavailableError,
    ProjectionDigestConflictError,
    ProjectionIdentityRecord,
    ProvenanceEndpointMissingError,
    SecurityStateRecord,
    StateVersionConflictError,
    StoredBrowserSession,
    StoredLaunchCode,
    TaskFactRecord,
    TaskRevisionConflictError,
    classify_audit_record_type,
    memory_change_is_replay_match,
    merge_provenance_edge,
    merge_provenance_node,
    parse_audit_timestamp,
    within_evaluated_range,
)
from guard_api.storage.integrity import (
    attach_audit_integrity,
    read_audit_integrity,
    verify_audit_chain,
)
from guard_api.security_state.lease_service import (
    GrantConsumptionConflictError,
    GrantExpiredError,
    GrantFingerprintMismatchError,
    GrantNotRegisteredError,
    GrantRevokedError,
    GrantScopeMismatchError,
    GrantUsesExhaustedError,
    LeaseExpiredError,
    LeaseRevokedError,
    LeaseStoreError,
    LeaseTokenMismatchError,
    LeaseTransitionError,
    lease_token_digest,
    validate_intent_payload,
)

_GRANT_RUNTIME_STATUSES = ("active", "expired", "revoked")


def _ct_flow_id(edge: ProvenanceEdge) -> str | None:
    metadata = edge.metadata
    if (
        metadata.get("contract") != "ct-provenance/1.0"
        or metadata.get("kind") != "edge"
    ):
        return None
    flow_id = metadata.get("flow_id")
    return flow_id if isinstance(flow_id, str) and flow_id else None


def _derive_consumption_id(grant_id: str, action_id: str) -> str:
    """consumption_id 确定性派生（受限 JCS sha256，禁 uuid）。"""
    suffix = canonical_sha256(
        {"action_id": action_id, "grant_id": grant_id}
    ).removeprefix("sha256:")
    return f"consumption:{suffix}"


def _derive_lease_id(consumption_id: str) -> str:
    """lease_id 确定性派生（受限 JCS sha256，禁 uuid）。"""
    suffix = canonical_sha256({"consumption_id": consumption_id}).removeprefix(
        "sha256:"
    )
    return f"lease:{suffix}"


def _system_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _binding_semantic_payload(record: EnforcementBindingRecord) -> tuple[Any, ...]:
    """Immutable binding facts; only the later registration link is excluded."""

    return (
        record.event_id,
        record.policy_audit_id,
        record.approval_id,
        record.action_id,
        record.action_type,
        record.authorization_fingerprint,
        record.runtime_binding_id,
        record.scope_digest,
        record.principal_id,
        record.runtime,
        record.agent_id,
        record.policy_revision,
        record.requires_execution_lease,
        record.created_at,
    )


def _safe_compare(left: str, right: str) -> bool:
    return hmac_module.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


@dataclass(slots=True)
class MemoryControlPlaneStore:
    audit_events: list[AuditEvent] = field(default_factory=list)
    provenance_nodes: dict[str, ProvenanceNode] = field(default_factory=dict)
    provenance_edges: dict[str, ProvenanceEdge] = field(default_factory=dict)
    config_audit_findings: list[dict[str, Any]] = field(default_factory=list)
    evaluation_runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    adapter_statuses: dict[str, dict[str, Any]] = field(default_factory=dict)
    product_runtime_statuses_v2: dict[
        tuple[str, str, str, str], tuple[int, ProductRuntimeStatusV2]
    ] = field(default_factory=dict)
    product_runtime_status_write_sequence: int = 0
    credentials: dict[str, CredentialRecord] = field(default_factory=dict)
    action_critic_reviews: dict[str, ActionCriticReview] = field(default_factory=dict)
    memory_changes: dict[str, MemoryGuardChange] = field(default_factory=dict)
    approvals: dict[str, ApprovalRequest] = field(default_factory=dict)
    enforcement_bindings: dict[str, EnforcementBindingRecord] = field(
        default_factory=dict
    )
    launch_codes: dict[str, StoredLaunchCode] = field(default_factory=dict)
    browser_sessions: dict[str, StoredBrowserSession] = field(default_factory=dict)
    policy_snapshot: PolicySnapshotRecord | None = None
    policy_snapshot_history: list[PolicySnapshotRecord] = field(default_factory=list)
    task_facts: dict[str, list[TaskFactRecord]] = field(default_factory=dict)
    security_states: dict[str, SecurityStateRecord] = field(default_factory=dict)
    projection_records: dict[
        tuple[str, str, str, int, str], ProjectionIdentityRecord
    ] = field(default_factory=dict)
    # V21-06 capability/lease 权威存储（C5：lease 只存本 store，不进
    # OnlineSecurityState）；migration 0016 三表的 memory 对应物。
    capability_grants: dict[str, dict[str, Any]] = field(default_factory=dict)
    grant_consumption_records: dict[str, GrantConsumption] = field(default_factory=dict)
    execution_lease_records: dict[str, ExecutionLease] = field(default_factory=dict)
    audit_clock: Callable[[], datetime] = field(default=_system_utc_now, repr=False)
    audit_integrity_lock: Any = field(default_factory=RLock, init=False, repr=False)
    provenance_lock: Any = field(default_factory=RLock, init=False, repr=False)
    policy_evaluation_lock: Any = field(default_factory=Lock, init=False, repr=False)
    evaluation_run_lock: Any = field(default_factory=Lock, init=False, repr=False)
    product_runtime_status_lock: Any = field(
        default_factory=RLock, init=False, repr=False
    )
    # Product evaluation holds these authority locks while re-entering the
    # public typed getters for its two exact validations.  They therefore must
    # be re-entrant; compatibility callers retain the same mutual exclusion.
    policy_snapshot_lock: Any = field(default_factory=RLock, init=False, repr=False)
    task_fact_lock: Any = field(default_factory=RLock, init=False, repr=False)
    security_state_lock: Any = field(default_factory=RLock, init=False, repr=False)
    approval_lease_lock: Any = field(default_factory=RLock, init=False, repr=False)
    memory_change_lock: Any = field(default_factory=RLock, init=False, repr=False)
    action_critic_lock: Any = field(default_factory=RLock, init=False, repr=False)
    audit_events_by_id: dict[str, AuditEvent] = field(default_factory=dict)
    audit_ingested_at_by_id: dict[str, datetime] = field(default_factory=dict)

    def initialize(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def add_audit_event(self, event: AuditEvent) -> bool:
        parse_audit_timestamp(event.timestamp)
        ingested_at = self.audit_clock()
        if ingested_at.tzinfo is None:
            raise ValueError("audit ingestion clock must include a timezone")
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
            self.audit_ingested_at_by_id[event.audit_id] = ingested_at
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
                if _matches_window_filters(
                    event,
                    query,
                    ingested_at=self.audit_ingested_at_by_id[event.audit_id],
                )
            ]
        return list(reversed(events))[: query.limit]

    def capture_audit_snapshot(self) -> tuple[int, datetime]:
        with self.audit_integrity_lock:
            captured_at = self.audit_clock()
            if captured_at.tzinfo is None:
                raise ValueError("audit ingestion clock must include a timezone")
            return len(self.audit_events), captured_at

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
    def evaluation_transaction(self, event_id: str) -> Iterator[None]:
        """Atomically apply one evaluation to the in-memory reference store."""

        del event_id
        with (
            self.policy_evaluation_lock,
            self.audit_integrity_lock,
            self.provenance_lock,
            self.approval_lease_lock,
            self.memory_change_lock,
            self.action_critic_lock,
        ):
            snapshot = {
                "audit_events": deepcopy(self.audit_events),
                "audit_events_by_id": deepcopy(self.audit_events_by_id),
                "audit_ingested_at_by_id": deepcopy(self.audit_ingested_at_by_id),
                "provenance_nodes": deepcopy(self.provenance_nodes),
                "provenance_edges": deepcopy(self.provenance_edges),
                "approvals": deepcopy(self.approvals),
                "enforcement_bindings": deepcopy(self.enforcement_bindings),
                "memory_changes": deepcopy(self.memory_changes),
                "action_critic_reviews": deepcopy(self.action_critic_reviews),
            }
            try:
                yield
            except BaseException:
                self.audit_events[:] = snapshot["audit_events"]
                self.audit_events_by_id.clear()
                self.audit_events_by_id.update(snapshot["audit_events_by_id"])
                self.audit_ingested_at_by_id.clear()
                self.audit_ingested_at_by_id.update(snapshot["audit_ingested_at_by_id"])
                self.provenance_nodes.clear()
                self.provenance_nodes.update(snapshot["provenance_nodes"])
                self.provenance_edges.clear()
                self.provenance_edges.update(snapshot["provenance_edges"])
                self.approvals.clear()
                self.approvals.update(snapshot["approvals"])
                self.enforcement_bindings.clear()
                self.enforcement_bindings.update(snapshot["enforcement_bindings"])
                self.memory_changes.clear()
                self.memory_changes.update(snapshot["memory_changes"])
                self.action_critic_reviews.clear()
                self.action_critic_reviews.update(snapshot["action_critic_reviews"])
                raise

    @contextmanager
    def product_evaluation_transaction(
        self,
        event_id: str,
        *,
        task_id: str,
        scope_digest: str,
        runtime_ids: tuple[ProductRuntime, ProductRuntime],
        credential_id: str,
        credential_token_hash: str,
    ) -> Iterator[None]:
        """Freeze Product authority and atomically stage its evaluation.

        The in-memory backend is the executable reference for the PostgreSQL
        lock contract.  Authority containers are included in the rollback
        image as a defence against a future in-transaction writer; the normal
        Product path only reads them, except for its projection reservation.
        """

        if runtime_ids != ("langgraph", "openclaw"):
            raise ValueError("Product authority requires both runtimes in order")
        if not all(
            isinstance(value, str) and value
            for value in (
                event_id,
                task_id,
                scope_digest,
                credential_id,
                credential_token_hash,
            )
        ):
            raise ValueError("Product authority fence identities must be non-empty")

        with (
            self.policy_evaluation_lock,
            self.product_runtime_status_lock,
            self.policy_snapshot_lock,
            self.task_fact_lock,
            self.security_state_lock,
            self.audit_integrity_lock,
            self.provenance_lock,
            self.approval_lease_lock,
            self.memory_change_lock,
            self.action_critic_lock,
        ):
            credential = self.credentials.get(credential_id)
            if (
                credential is None
                or credential.token_hash != credential_token_hash
                or credential.revoked_at is not None
            ):
                raise ProductAuthorityCredentialUnavailableError(
                    "Product credential is missing, changed, or revoked"
                )
            snapshot = {
                "audit_events": deepcopy(self.audit_events),
                "audit_events_by_id": deepcopy(self.audit_events_by_id),
                "audit_ingested_at_by_id": deepcopy(self.audit_ingested_at_by_id),
                "provenance_nodes": deepcopy(self.provenance_nodes),
                "provenance_edges": deepcopy(self.provenance_edges),
                "approvals": deepcopy(self.approvals),
                "enforcement_bindings": deepcopy(self.enforcement_bindings),
                "memory_changes": deepcopy(self.memory_changes),
                "action_critic_reviews": deepcopy(self.action_critic_reviews),
                "policy_snapshot": deepcopy(self.policy_snapshot),
                "policy_snapshot_history": deepcopy(self.policy_snapshot_history),
                "task_facts": deepcopy(self.task_facts),
                "security_states": deepcopy(self.security_states),
                "projection_records": deepcopy(self.projection_records),
                "product_runtime_statuses_v2": deepcopy(
                    self.product_runtime_statuses_v2
                ),
                "product_runtime_status_write_sequence": (
                    self.product_runtime_status_write_sequence
                ),
                "adapter_statuses": deepcopy(self.adapter_statuses),
                "credentials": deepcopy(self.credentials),
            }
            try:
                yield
            except BaseException:
                self.audit_events[:] = snapshot["audit_events"]
                self.audit_events_by_id.clear()
                self.audit_events_by_id.update(snapshot["audit_events_by_id"])
                self.audit_ingested_at_by_id.clear()
                self.audit_ingested_at_by_id.update(snapshot["audit_ingested_at_by_id"])
                self.provenance_nodes.clear()
                self.provenance_nodes.update(snapshot["provenance_nodes"])
                self.provenance_edges.clear()
                self.provenance_edges.update(snapshot["provenance_edges"])
                self.approvals.clear()
                self.approvals.update(snapshot["approvals"])
                self.enforcement_bindings.clear()
                self.enforcement_bindings.update(snapshot["enforcement_bindings"])
                self.memory_changes.clear()
                self.memory_changes.update(snapshot["memory_changes"])
                self.action_critic_reviews.clear()
                self.action_critic_reviews.update(snapshot["action_critic_reviews"])
                self.policy_snapshot = snapshot["policy_snapshot"]
                self.policy_snapshot_history[:] = snapshot["policy_snapshot_history"]
                self.task_facts.clear()
                self.task_facts.update(snapshot["task_facts"])
                self.security_states.clear()
                self.security_states.update(snapshot["security_states"])
                self.projection_records.clear()
                self.projection_records.update(snapshot["projection_records"])
                self.product_runtime_statuses_v2.clear()
                self.product_runtime_statuses_v2.update(
                    snapshot["product_runtime_statuses_v2"]
                )
                self.product_runtime_status_write_sequence = snapshot[
                    "product_runtime_status_write_sequence"
                ]
                self.adapter_statuses.clear()
                self.adapter_statuses.update(snapshot["adapter_statuses"])
                self.credentials.clear()
                self.credentials.update(snapshot["credentials"])
                raise

    @contextmanager
    def security_state_transaction(self, scope_digest: str) -> Iterator[None]:
        """Atomically reconcile one in-memory state/projection scope."""

        if not isinstance(scope_digest, str) or not scope_digest:
            raise ValueError("scope_digest must be non-empty")
        with self.security_state_lock:
            states_snapshot = deepcopy(self.security_states)
            projections_snapshot = deepcopy(self.projection_records)
            try:
                yield
            except BaseException:
                self.security_states.clear()
                self.security_states.update(states_snapshot)
                self.projection_records.clear()
                self.projection_records.update(projections_snapshot)
                raise

    @contextmanager
    def memory_change_transaction(self, change_id: str) -> Iterator[None]:
        """状态转换与转换审计要么一起可见，要么一起回滚。

        锁序与 evaluation_transaction 的前缀对齐（审计链 → provenance →
        记忆变更），避免与评测事务交叉倒置死锁；持锁期间外部读不到
        「状态已改、审计未入链」的中间态，异常时恢复快照。
        """

        del change_id
        with (
            self.audit_integrity_lock,
            self.provenance_lock,
            self.memory_change_lock,
        ):
            # 各容器内元素只会被替换或追加、不会就地变更，浅拷贝即可回滚。
            snapshot = {
                "memory_changes": dict(self.memory_changes),
                "audit_events": list(self.audit_events),
                "audit_events_by_id": dict(self.audit_events_by_id),
                "audit_ingested_at_by_id": dict(self.audit_ingested_at_by_id),
                "provenance_nodes": dict(self.provenance_nodes),
                "provenance_edges": dict(self.provenance_edges),
            }
            try:
                yield
            except BaseException:
                self.memory_changes.clear()
                self.memory_changes.update(snapshot["memory_changes"])
                self.audit_events[:] = snapshot["audit_events"]
                self.audit_events_by_id.clear()
                self.audit_events_by_id.update(snapshot["audit_events_by_id"])
                self.audit_ingested_at_by_id.clear()
                self.audit_ingested_at_by_id.update(snapshot["audit_ingested_at_by_id"])
                self.provenance_nodes.clear()
                self.provenance_nodes.update(snapshot["provenance_nodes"])
                self.provenance_edges.clear()
                self.provenance_edges.update(snapshot["provenance_edges"])
                raise

    @contextmanager
    def runtime_outcome_transaction(self, approval_id: str | None) -> Iterator[None]:
        """Serialize receipt first-write authority with lease consumption.

        The lock order matches ``evaluation_transaction``.  The approval lock
        is also the consume CAS lock, so a weak no-lease receipt cannot pass its
        authority check and then race a consume before entering the audit chain.
        """

        del approval_id
        with self.audit_integrity_lock, self.approval_lease_lock:
            yield

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

    def write_ct_provenance_batch(
        self,
        nodes: list[ProvenanceNode],
        edges: list[ProvenanceEdge],
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]:
        """Atomically materialize one bounded CT subgraph."""

        with self.provenance_lock:
            next_nodes = dict(self.provenance_nodes)
            next_edges = dict(self.provenance_edges)
            written_nodes: list[ProvenanceNode] = []
            written_edges: list[ProvenanceEdge] = []
            for node in sorted(nodes, key=lambda item: item.node_id):
                existing = next_nodes.get(node.node_id)
                merged = (
                    node if existing is None else merge_provenance_node(existing, node)
                )
                next_nodes[node.node_id] = merged
                written_nodes.append(merged)

            known_flows: dict[tuple[str, str], str] = {}
            for existing in next_edges.values():
                flow_id = _ct_flow_id(existing)
                if flow_id is not None:
                    known_flows[(existing.trace_id, flow_id)] = existing.edge_id
            for edge in sorted(edges, key=lambda item: item.edge_id):
                flow_id = _ct_flow_id(edge)
                if flow_id is None:
                    raise CtProvenanceBatchConflictError(edge.edge_id)
                identity = (edge.trace_id, flow_id)
                existing_flow_edge = known_flows.get(identity)
                if (
                    existing_flow_edge is not None
                    and existing_flow_edge != edge.edge_id
                ):
                    raise CtProvenanceBatchConflictError(f"{edge.trace_id}:{flow_id}")
                source = next_nodes.get(edge.source_node_id)
                target = next_nodes.get(edge.target_node_id)
                if (
                    source is None
                    or target is None
                    or source.trace_id != edge.trace_id
                    or target.trace_id != edge.trace_id
                ):
                    raise ProvenanceEndpointMissingError(edge.edge_id)
                existing = next_edges.get(edge.edge_id)
                merged = (
                    edge if existing is None else merge_provenance_edge(existing, edge)
                )
                next_edges[edge.edge_id] = merged
                known_flows[identity] = edge.edge_id
                written_edges.append(merged)
            self.provenance_nodes.clear()
            self.provenance_nodes.update(next_nodes)
            self.provenance_edges.clear()
            self.provenance_edges.update(next_edges)
            return written_nodes, written_edges

    def list_provenance(
        self,
        trace_id: str,
        *,
        node_limit: int | None = None,
        edge_limit: int | None = None,
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
        if node_limit is not None:
            nodes = nodes[: _bounded_collection_limit(node_limit)]
            node_ids = {node.node_id for node in nodes}
            edges = [
                edge
                for edge in edges
                if edge.source_node_id in node_ids and edge.target_node_id in node_ids
            ]
        if edge_limit is not None:
            edges = edges[: _bounded_collection_limit(edge_limit)]
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
        run_id = payload["run_id"]
        with self.evaluation_run_lock:
            existing = self.evaluation_runs.get(run_id)
            if existing is not None:
                if existing == payload:
                    return dict(existing)
                raise EvaluationRunConflictError(run_id)
            self.evaluation_runs[run_id] = payload
        return dict(payload)

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
        self,
        adapter_id: str,
        status: AdapterStatusRecord | dict[str, Any],
        *,
        preserve_heartbeat: bool = False,
    ) -> dict[str, Any]:
        payload = AdapterStatusRecord.model_validate(status).model_dump(mode="json")
        with self.product_runtime_status_lock:
            if preserve_heartbeat:
                existing = self.adapter_statuses.get(adapter_id)
                payload["last_heartbeat_at"] = (
                    existing.get("last_heartbeat_at") if existing is not None else None
                )
                payload = AdapterStatusRecord.model_validate(payload).model_dump(
                    mode="json"
                )
            self.adapter_statuses[adapter_id] = deepcopy(payload)
        return deepcopy(payload)

    def get_adapter_status(self, adapter_id: str) -> dict[str, Any] | None:
        with self.product_runtime_status_lock:
            payload = self.adapter_statuses.get(adapter_id)
            return deepcopy(payload) if payload is not None else None

    def list_adapter_statuses(self) -> dict[str, dict[str, Any]]:
        with self.product_runtime_status_lock:
            return deepcopy(self.adapter_statuses)

    def save_product_runtime_status(
        self, status: ProductRuntimeStatusV2 | dict[str, Any]
    ) -> ProductRuntimeStatusV2:
        record = ProductRuntimeStatusV2.model_validate(status)
        stored = deepcopy(record)
        identity = stored.identity()
        key = (
            identity.runtime,
            identity.agent_id,
            identity.runtime_binding_id,
            identity.profile_id,
        )
        legacy_payload = stored.to_legacy_adapter_status().model_dump(mode="json")
        with self.product_runtime_status_lock:
            self.product_runtime_status_write_sequence += 1
            self.product_runtime_statuses_v2[key] = (
                self.product_runtime_status_write_sequence,
                stored,
            )
            self.adapter_statuses[identity.runtime] = deepcopy(legacy_payload)
        return deepcopy(stored)

    def get_product_runtime_status(
        self, identity: ProductRuntimeStatusIdentityV1 | dict[str, Any]
    ) -> ProductRuntimeStatusV2 | None:
        exact = ProductRuntimeStatusIdentityV1.model_validate(identity)
        key = (
            exact.runtime,
            exact.agent_id,
            exact.runtime_binding_id,
            exact.profile_id,
        )
        with self.product_runtime_status_lock:
            row = self.product_runtime_statuses_v2.get(key)
            return deepcopy(row[1]) if row is not None else None

    def list_product_runtime_statuses(
        self, *, runtime: ProductRuntime | None = None, limit: int = 100
    ) -> list[ProductRuntimeStatusV2]:
        if runtime is not None and runtime not in {"langgraph", "openclaw"}:
            raise ValueError("runtime must be langgraph or openclaw")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 500
        ):
            raise ValueError("limit must be an integer between 1 and 500")
        with self.product_runtime_status_lock:
            rows = [
                (write_sequence, record)
                for key, (
                    write_sequence,
                    record,
                ) in self.product_runtime_statuses_v2.items()
                if runtime is None or key[0] == runtime
            ]
            rows.sort(key=lambda row: row[0], reverse=True)
            return [deepcopy(record) for _, record in rows[:limit]]

    def create_credential(
        self, credential: CredentialRecord | dict[str, Any]
    ) -> CredentialRecord:
        record = CredentialRecord.model_validate(credential)
        with self.approval_lease_lock:
            self.credentials[record.credential_id] = record
            return record

    def get_credential_by_token_hash(self, token_hash: str) -> CredentialRecord | None:
        with self.approval_lease_lock:
            for credential in self.credentials.values():
                if (
                    credential.token_hash == token_hash
                    and credential.revoked_at is None
                ):
                    return credential
        return None

    def list_credentials(self) -> list[CredentialRecord]:
        with self.approval_lease_lock:
            return sorted(
                self.credentials.values(), key=lambda credential: credential.created_at
            )

    def revoke_credential(
        self, credential_id: str, revoked_at: str
    ) -> CredentialRecord:
        with self.approval_lease_lock:
            credential = self.credentials[credential_id]
            revoked = credential.model_copy(update={"revoked_at": revoked_at})
            self.credentials[credential_id] = revoked
            return revoked

    def add_action_critic_review(
        self, review: ActionCriticReview
    ) -> ActionCriticReview:
        with self.action_critic_lock:
            self.action_critic_reviews[review.review_id] = review
            return review

    def list_action_critic_reviews(self, trace_id: str) -> list[ActionCriticReview]:
        with self.action_critic_lock:
            reviews = [
                review
                for review in self.action_critic_reviews.values()
                if review.trace_id == trace_id
            ]
        return sorted(reviews, key=lambda review: (review.created_at, review.review_id))

    def create_memory_change(self, change: MemoryGuardChange) -> MemoryGuardChange:
        # 存在即拒绝：锁内判定，绝不覆盖既有记录；完全一致才幂等返回。
        with self.memory_change_lock:
            existing = self.memory_changes.get(change.change_id)
            if existing is not None:
                if memory_change_is_replay_match(existing, change):
                    return existing
                raise MemoryChangeAlreadyExistsError(change.change_id)
            self.memory_changes[change.change_id] = change
            return change

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None:
        with self.memory_change_lock:
            return self.memory_changes.get(change_id)

    def update_memory_change_status(
        self, change_id: str, status: str
    ) -> MemoryTransitionResult:
        with self.memory_change_lock:
            current = self.memory_changes[change_id]
            if current.status == status:
                # 同态重复转换为幂等重放，直接返回当前记录。
                return MemoryTransitionResult(
                    change=current, applied=False, previous_status=current.status
                )
            if not memory_change_can_transition(current.status, status):
                raise MemoryChangeTransitionError(change_id, current.status, status)
            updated = current.model_copy(
                update={"status": status, "updated_at": utc_now_iso()}
            )
            self.memory_changes[change_id] = updated
            return MemoryTransitionResult(
                change=updated, applied=True, previous_status=current.status
            )

    def get_policy_snapshot(self) -> PolicyBundle | None:
        if self.policy_snapshot is None:
            return None
        return self.policy_snapshot.policy_bundle

    def get_policy_snapshot_record(self) -> PolicySnapshotRecord | None:
        return self.policy_snapshot

    def save_policy_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        expected_revision: int,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord:
        with self.policy_snapshot_lock:
            current_revision = (
                self.policy_snapshot.revision if self.policy_snapshot is not None else 0
            )
            if expected_revision != current_revision:
                raise PolicyRevisionConflictError(
                    expected_revision=expected_revision,
                    current_revision=current_revision,
                )
            revision = current_revision + 1
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

    def create_task_fact(self, record: TaskFactRecord) -> TaskFactRecord:
        # 追加式 CAS：锁内判定 head revision，旧 revision 永不覆盖。
        task_id = record.task_fact.task_id
        with self.task_fact_lock:
            revisions = self.task_facts.get(task_id, [])
            current_revision = revisions[-1].task_fact.revision if revisions else 0
            if record.expected_revision != current_revision:
                raise TaskRevisionConflictError(
                    expected_revision=record.expected_revision,
                    current_revision=current_revision,
                )
            self.task_facts[task_id] = [*revisions, record]
            return record

    def get_task_fact(
        self, task_id: str, revision: int | None = None
    ) -> TaskFactRecord | None:
        with self.task_fact_lock:
            revisions = self.task_facts.get(task_id)
            if not revisions:
                return None
            if revision is None:
                return revisions[-1]
            for record in revisions:
                if record.task_fact.revision == revision:
                    return record
            return None

    def list_task_fact_revisions(self, task_id: str) -> list[TaskFactRecord]:
        with self.task_fact_lock:
            return list(self.task_facts.get(task_id, []))

    def get_security_state(self, scope_digest: str) -> SecurityStateRecord | None:
        with self.security_state_lock:
            record = self.security_states.get(scope_digest)
            return deepcopy(record) if record is not None else None

    def cas_security_state(
        self,
        scope_digest: str,
        expected_state_version: int,
        record: SecurityStateRecord,
    ) -> bool:
        # 追加式 CAS：锁内判定当前 state_version（无记录为 0），
        # 版本不匹配抛 StateVersionConflictError，旧版本永不覆盖。
        with self.security_state_lock:
            existing = self.security_states.get(scope_digest)
            current_version = existing.state_version if existing is not None else 0
            if expected_state_version != current_version:
                raise StateVersionConflictError(
                    expected_state_version=expected_state_version,
                    current_state_version=current_version,
                )
            self.security_states[scope_digest] = deepcopy(record)
            return True

    def mark_security_state_dirty(self, scope_digest: str, domains: list[str]) -> None:
        # state_version 保持不变：dirty 标记不影响 CAS 锚点；
        # state 不存在时创建 version=0 的空态脏记录。
        from agentguard_core.security_context import (
            PROJECTOR_VERSION,
            OnlineSecurityState,
            StateWatermarks,
        )
        from agentguard_core.signals.models import CoverageDomain

        merged_str = sorted(set(domains))
        merged_domains = cast("list[CoverageDomain]", merged_str)
        with self.security_state_lock:
            existing = self.security_states.get(scope_digest)
            if existing is None:
                # F1 双口径同步：payload 内的 dirty_domains 与列同时写入。
                empty_state = OnlineSecurityState(
                    watermarks=StateWatermarks(
                        committed_sequence=None,
                        projected_sequence=None,
                        runtime_receipt_sequence=None,
                        memory_sequence=None,
                        gaps=[],
                    ),
                    dirty_domains=merged_domains,
                )
                self.security_states[scope_digest] = SecurityStateRecord(
                    scope_digest=scope_digest,
                    state_version=0,
                    canonical_payload=empty_state.model_dump(mode="json"),
                    dirty=True,
                    dirty_domains=merged_str,
                    projector_version=PROJECTOR_VERSION,
                    updated_at=utc_now_iso(),
                )
                return
            merged = sorted(set(existing.dirty_domains) | set(merged_str))
            # F1 双口径同步：把 dirty 域并入 canonical_payload 的
            # dirty_domains（payload 是 model_dump(mode="json") 口径，
            # 改后仍可 model_validate 读回），否则 projector 从 payload
            # 重建状态后回写会静默清除失败事实。
            payload_state = OnlineSecurityState.model_validate(
                existing.canonical_payload
            )
            payload_state = payload_state.model_copy(
                update={
                    "dirty_domains": sorted(
                        set(payload_state.dirty_domains) | set(merged)
                    )
                }
            )
            self.security_states[scope_digest] = SecurityStateRecord(
                scope_digest=existing.scope_digest,
                state_version=existing.state_version,
                canonical_payload=payload_state.model_dump(mode="json"),
                dirty=True,
                dirty_domains=merged,
                projector_version=existing.projector_version,
                updated_at=utc_now_iso(),
            )

    def record_projection(
        self, record: ProjectionIdentityRecord
    ) -> tuple[ProjectionIdentityRecord, bool]:
        # 幂等三分支：新身份写入；同身份同 digest no-op；同身份异 digest 拒绝。
        key = (
            record.scope_digest,
            record.source_record_type,
            record.source_record_id,
            record.source_revision,
            record.projector_version,
        )
        with self.security_state_lock:
            existing = self.projection_records.get(key)
            if existing is not None:
                if existing.delta_digest == record.delta_digest:
                    return deepcopy(existing), False
                raise ProjectionDigestConflictError(
                    projection_key="|".join(
                        [
                            record.scope_digest,
                            record.source_record_type,
                            record.source_record_id,
                            str(record.source_revision),
                            record.projector_version,
                        ]
                    ),
                    existing_digest=existing.delta_digest,
                    incoming_digest=record.delta_digest,
                )
            self.projection_records[key] = deepcopy(record)
            return record, True

    def get_projection(
        self,
        scope_digest: str,
        source_record_type: str,
        source_record_id: str,
        source_revision: int,
        projector_version: str,
    ) -> ProjectionIdentityRecord | None:
        key = (
            scope_digest,
            source_record_type,
            source_record_id,
            source_revision,
            projector_version,
        )
        with self.security_state_lock:
            record = self.projection_records.get(key)
            return deepcopy(record) if record is not None else None

    def list_rebuild_inputs(
        self, scope_digest: str, *, limit: int
    ) -> list[ProjectionIdentityRecord]:
        with self.security_state_lock:
            rows = [
                record
                for key, record in self.projection_records.items()
                if key[0] == scope_digest
            ]
            rows.sort(key=lambda item: item.applied_state_version)
            return [deepcopy(record) for record in rows[: _bounded_limit(limit)]]

    # RTE-05 private binding and approval-bound lease authority.  One reentrant
    # lock covers credential, approval, binding, grant, consumption, and lease
    # state so readers never observe a partially registered/consumed chain.

    def save_enforcement_binding(
        self, record: EnforcementBindingRecord
    ) -> EnforcementBindingRecord:
        if not record.requires_execution_lease:
            raise EnforcementBindingConflictError(
                "rte-05:binding_conflict", "private binding is invalid"
            )
        with self.approval_lease_lock:
            collisions = [
                existing
                for existing in self.enforcement_bindings.values()
                if existing.approval_id == record.approval_id
                or existing.event_id == record.event_id
                or existing.policy_audit_id == record.policy_audit_id
            ]
            if collisions:
                existing = collisions[0]
                if len(collisions) != 1 or _binding_semantic_payload(
                    existing
                ) != _binding_semantic_payload(record):
                    raise EnforcementBindingConflictError(
                        "rte-05:binding_conflict",
                        "private binding identity conflicts with stored facts",
                    )
                return deepcopy(existing)
            if record.grant_id is not None:
                raise EnforcementBindingConflictError(
                    "rte-05:binding_conflict",
                    "new private binding cannot be pre-registered",
                )
            self.enforcement_bindings[record.approval_id] = deepcopy(record)
            return deepcopy(record)

    def get_enforcement_binding(
        self, approval_id: str
    ) -> EnforcementBindingRecord | None:
        with self.approval_lease_lock:
            record = self.enforcement_bindings.get(approval_id)
            return deepcopy(record) if record is not None else None

    def approval_execution_was_consumed(self, approval_id: str) -> bool:
        with self.approval_lease_lock:
            binding = self.enforcement_bindings.get(approval_id)
            if binding is None or binding.grant_id is None:
                return False

            grant = self.capability_grants.get(binding.grant_id)
            grant_consumed = bool(
                grant is not None and grant.get("remaining_uses") == 0
            )
            consumption_id = _derive_consumption_id(
                binding.grant_id,
                binding.action_id,
            )
            consumption = self.grant_consumption_records.get(consumption_id)
            lease = self.execution_lease_records.get(_derive_lease_id(consumption_id))
            exact_pair_exists = bool(
                consumption is not None
                and lease is not None
                and _lease_matches_binding(lease, binding, consumption)
            )
            return grant_consumed or exact_pair_exists

    def register_approval_grant(
        self,
        binding: EnforcementBindingRecord,
        grant: CapabilityGrant,
    ) -> EnforcementBindingRecord:
        with self.approval_lease_lock:
            grants_snapshot = deepcopy(self.capability_grants)
            bindings_snapshot = deepcopy(self.enforcement_bindings)
            try:
                stored = self.enforcement_bindings.get(binding.approval_id)
                if stored is None:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:binding_unavailable",
                        "private binding is not available",
                    )
                if _binding_semantic_payload(stored) != _binding_semantic_payload(
                    binding
                ):
                    raise EnforcementBindingConflictError(
                        "rte-05:binding_conflict",
                        "private binding conflicts with stored facts",
                    )
                approval = self.approvals.get(stored.approval_id)
                if approval is None:
                    raise ApprovalLeaseNotFoundError(
                        "rte-05:approval_not_found", "approval is not available"
                    )
                now = self.audit_clock()
                if (
                    now.tzinfo is None
                    or parse_audit_timestamp(approval.expires_at) <= now
                    or approval.status != "resolved"
                    or approval.decision != "allow_once"
                    or approval.resolution_source != "human"
                ):
                    raise ApprovalLeaseNotConsumableError(
                        "rte-05:approval_not_consumable",
                        "approval is not consumable",
                    )
                if not _grant_matches_binding(grant, stored, approval):
                    raise EnforcementBindingConflictError(
                        "rte-05:grant_registration_conflict",
                        "runtime grant conflicts with private binding",
                    )

                registration_digest = canonical_sha256(grant.model_dump(mode="json"))
                existing = self.capability_grants.get(grant.grant_id)
                if existing is not None:
                    existing_fingerprint = existing.get("authorization_fingerprint")
                    if (
                        existing.get("registration_digest") != registration_digest
                        or existing.get("scope_digest") != grant.scope_digest
                        or existing.get("expires_at") != grant.expires_at
                        or not isinstance(existing_fingerprint, str)
                        or not _safe_compare(
                            existing_fingerprint,
                            binding.authorization_fingerprint,
                        )
                    ):
                        raise EnforcementBindingConflictError(
                            "rte-05:grant_registration_conflict",
                            "runtime grant registration conflicts with stored facts",
                        )
                else:
                    self.capability_grants[grant.grant_id] = {
                        "grant_id": grant.grant_id,
                        "scope_digest": grant.scope_digest,
                        "remaining_uses": grant.remaining_uses,
                        "expires_at": grant.expires_at,
                        "authorization_fingerprint": (
                            grant.exact_authorization_fingerprint
                        ),
                        "status": "active",
                        "registration_digest": registration_digest,
                    }

                if stored.grant_id not in (None, grant.grant_id):
                    raise EnforcementBindingConflictError(
                        "rte-05:grant_registration_conflict",
                        "private binding is already registered differently",
                    )
                registered = replace(stored, grant_id=grant.grant_id)
                self.enforcement_bindings[stored.approval_id] = registered
                return deepcopy(registered)
            except BaseException:
                self.capability_grants.clear()
                self.capability_grants.update(grants_snapshot)
                self.enforcement_bindings.clear()
                self.enforcement_bindings.update(bindings_snapshot)
                raise

    def consume_approval_execution_lease(
        self, command: ApprovalLeaseConsumeCommand
    ) -> GrantConsumptionResult:
        with self.approval_lease_lock:
            grants_snapshot = deepcopy(self.capability_grants)
            consumptions_snapshot = deepcopy(self.grant_consumption_records)
            leases_snapshot = deepcopy(self.execution_lease_records)
            try:
                now = self.audit_clock()
                if now.tzinfo is None:
                    raise ApprovalExecutionLeaseStateInvalidError(
                        "rte-05:state_invalid", "authority clock is invalid"
                    )

                # credential -> approval -> binding -> grant -> consumption -> lease
                credential = self.credentials.get(command.credential_id)
                if credential is None or not _credential_authorizes_binding(
                    credential, command, now
                ):
                    raise ApprovalLeaseAuthorizationError(
                        "rte-05:authorization_denied",
                        "credential or bound identity is not authorized",
                    )

                approval = self.approvals.get(command.approval_id)
                if approval is None:
                    raise ApprovalLeaseNotFoundError(
                        "rte-05:approval_not_found", "approval is not available"
                    )
                approval_expires_at = parse_audit_timestamp(approval.expires_at)
                if (
                    approval.status != "resolved"
                    or approval.decision != "allow_once"
                    or approval.resolution_source != "human"
                ):
                    raise ApprovalLeaseNotConsumableError(
                        "rte-05:approval_not_consumable",
                        "approval is not consumable",
                    )

                binding = self.enforcement_bindings.get(command.approval_id)
                if binding is None or not binding.requires_execution_lease:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:binding_unavailable",
                        "private binding is not available",
                    )
                if not _binding_approval_invariants_match(binding, approval):
                    raise ApprovalExecutionLeaseStateInvalidError(
                        "rte-05:state_invalid",
                        "private approval authority state is inconsistent",
                    )
                if not _command_identity_matches(binding, command):
                    raise ApprovalLeaseAuthorizationError(
                        "rte-05:authorization_denied",
                        "credential or bound identity is not authorized",
                    )
                if binding.action_id != command.action_id or not _safe_compare(
                    binding.authorization_fingerprint,
                    command.authorization_fingerprint,
                ):
                    raise ApprovalLeaseConsumptionConflictError(
                        "rte-05:consumption_conflict",
                        "request conflicts with the private binding",
                    )
                if binding.grant_id is None:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:grant_unavailable",
                        "runtime grant registration is not complete",
                    )

                grant = self.capability_grants.get(binding.grant_id)
                if grant is None:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:grant_unavailable",
                        "runtime grant registration is not complete",
                    )
                if not _registered_grant_matches_binding(grant, binding):
                    raise ApprovalExecutionLeaseStateInvalidError(
                        "rte-05:state_invalid",
                        "private approval authority state is inconsistent",
                    )
                grant_expires_at = parse_audit_timestamp(str(grant["expires_at"]))

                consumption_id = _derive_consumption_id(
                    binding.grant_id, binding.action_id
                )
                existing = self.grant_consumption_records.get(consumption_id)
                if existing is not None:
                    if not _safe_compare(
                        existing.authorization_fingerprint,
                        command.authorization_fingerprint,
                    ):
                        raise ApprovalLeaseConsumptionConflictError(
                            "rte-05:consumption_conflict",
                            "request conflicts with prior consumption",
                        )
                    lease_id = _derive_lease_id(consumption_id)
                    lease = self.execution_lease_records.get(lease_id)
                    if lease is None or not _lease_matches_binding(
                        lease, binding, existing
                    ):
                        raise ApprovalExecutionLeaseStateInvalidError(
                            "rte-05:state_invalid",
                            "private execution lease state is inconsistent",
                        )
                    if (
                        approval_expires_at <= now
                        or lease.status == "expired"
                        or (parse_audit_timestamp(lease.expires_at) <= now)
                    ):
                        raise ApprovalExecutionLeaseExpiredError(
                            "rte-05:execution_lease_expired",
                            "execution lease has expired",
                        )
                    if grant["status"] != "active" or grant_expires_at <= now:
                        raise ApprovalLeaseNotConsumableError(
                            "rte-05:approval_not_consumable",
                            "approval grant is not consumable",
                        )
                    if lease.status != "consumed" or not _safe_compare(
                        lease.token_digest,
                        lease_token_digest(command.lease_token),
                    ):
                        raise ApprovalLeaseConsumptionConflictError(
                            "rte-05:consumption_conflict",
                            "request conflicts with prior consumption",
                        )
                    return GrantConsumptionResult(
                        consumption=deepcopy(existing),
                        lease=deepcopy(lease),
                        lease_token=command.lease_token,
                        replayed=True,
                    )

                if approval_expires_at <= now or grant_expires_at <= now:
                    raise ApprovalLeaseExpiredError(
                        "rte-05:approval_expired", "approval has expired"
                    )
                if grant["status"] != "active":
                    raise ApprovalLeaseNotConsumableError(
                        "rte-05:approval_not_consumable",
                        "approval grant is not consumable",
                    )
                if int(grant["remaining_uses"]) != 1:
                    raise ApprovalLeaseConsumptionConflictError(
                        "rte-05:consumption_conflict",
                        "approval grant has already been consumed",
                    )
                lease_expires_at = parse_audit_timestamp(command.expires_at)
                if (
                    lease_expires_at <= now
                    or lease_expires_at > approval_expires_at
                    or lease_expires_at > grant_expires_at
                ):
                    raise ApprovalExecutionLeaseStateInvalidError(
                        "rte-05:state_invalid",
                        "execution lease expiry is outside authority bounds",
                    )

                grant["remaining_uses"] = 0
                consumption = GrantConsumption(
                    consumption_id=consumption_id,
                    grant_id=binding.grant_id,
                    action_id=binding.action_id,
                    authorization_fingerprint=binding.authorization_fingerprint,
                    sequence=None,
                    evidence_refs=[],
                )
                lease = ExecutionLease(
                    lease_id=_derive_lease_id(consumption_id),
                    consumption_id=consumption_id,
                    approval_id=binding.approval_id,
                    grant_id=binding.grant_id,
                    action_id=binding.action_id,
                    authorization_fingerprint=binding.authorization_fingerprint,
                    runtime_binding_id=binding.runtime_binding_id,
                    issued_at=now.astimezone(timezone.utc).isoformat(),
                    expires_at=lease_expires_at.astimezone(timezone.utc).isoformat(),
                    token_digest=lease_token_digest(command.lease_token),
                    status="consumed",
                    evidence_refs=[],
                )
                self.grant_consumption_records[consumption_id] = consumption
                self.execution_lease_records[lease.lease_id] = lease
                return GrantConsumptionResult(
                    consumption=deepcopy(consumption),
                    lease=deepcopy(lease),
                    lease_token=command.lease_token,
                    replayed=False,
                )
            except BaseException:
                self.capability_grants.clear()
                self.capability_grants.update(grants_snapshot)
                self.grant_consumption_records.clear()
                self.grant_consumption_records.update(consumptions_snapshot)
                self.execution_lease_records.clear()
                self.execution_lease_records.update(leases_snapshot)
                raise

    # V21-06 capability/lease 权威存储实现（C4：单锁内同序
    # 读-校验-写，语义与 postgres 单事务一致；C5：lease 不进
    # OnlineSecurityState）。行锁序固定 grant→consumption→lease。

    def seed_capability_grant_runtime(
        self,
        *,
        grant_id: str,
        scope_digest: str,
        remaining_uses: int,
        expires_at: str | None = None,
        authorization_fingerprint: str | None = None,
        status: str = "active",
    ) -> dict[str, Any]:
        """注册 grant 运行时行（权威写入入口；Phase 2 projector 复用）。"""
        if status not in _GRANT_RUNTIME_STATUSES:
            raise ValueError(f"unsupported grant status: {status!r}")
        if remaining_uses < 0:
            raise ValueError("remaining_uses must be >= 0")
        with self.approval_lease_lock:
            if grant_id in self.capability_grants:
                raise ValueError(f"grant already registered: {grant_id}")
            row = {
                "grant_id": grant_id,
                "scope_digest": scope_digest,
                "remaining_uses": remaining_uses,
                "expires_at": expires_at,
                "authorization_fingerprint": authorization_fingerprint,
                "status": status,
            }
            self.capability_grants[grant_id] = row
            return deepcopy(row)

    def get_capability_grant_runtime(self, grant_id: str) -> dict[str, Any] | None:
        """读 grant 运行时行（消费后 remaining_uses 校验/Phase 2 读路径）。"""
        with self.approval_lease_lock:
            row = self.capability_grants.get(grant_id)
            return deepcopy(row) if row is not None else None

    def consume_grant(
        self, scope_digest: str, intent_payload: dict[str, Any]
    ) -> GrantConsumptionResult:
        validate_intent_payload(intent_payload)
        grant_id = str(intent_payload["grant_id"])
        action_id = str(intent_payload["action_id"])
        fingerprint = str(intent_payload["authorization_fingerprint"])
        with self.approval_lease_lock:
            # 1) grant 行（锁序第一）：存在性 + scope 绑定。
            grant = self.capability_grants.get(grant_id)
            if grant is None:
                raise GrantNotRegisteredError(
                    "v21-06:grant_not_registered",
                    f"grant {grant_id!r} is not registered",
                )
            if grant["scope_digest"] != scope_digest:
                raise GrantScopeMismatchError(
                    "v21-06:grant_scope_mismatch",
                    "grant scope_digest does not match the request scope",
                )
            # 2) consumption（锁序第二）：UNIQUE(grant_id, action_id)
            #    幂等重放分支必须先于 remaining_uses 校验（重试时用量已归零）。
            consumption_id = _derive_consumption_id(grant_id, action_id)
            existing = self.grant_consumption_records.get(consumption_id)
            if existing is not None:
                if not hmac_module.compare_digest(
                    existing.authorization_fingerprint.encode("utf-8"),
                    fingerprint.encode("utf-8"),
                ):
                    raise GrantConsumptionConflictError(
                        "v21-06:consumption_conflict",
                        "double-spend attempt: same (grant_id, action_id) "
                        "with a different authorization_fingerprint",
                    )
                lease_id = _derive_lease_id(consumption_id)
                lease = self.execution_lease_records.get(lease_id)
                if lease is None:
                    raise LeaseStoreError(
                        "v21-06:lease_missing",
                        "consumption exists but its execution lease is missing",
                    )
                # F1：终态校验先于 expires_at —— revoked/expired 状态的
                # lease 不得被幂等重放绕过（撤销/过期语义 fail-closed）。
                if lease.status == "revoked":
                    raise LeaseRevokedError(
                        "v21-06:execution_lease_revoked",
                        "same-key retry after lease revocation must not "
                        "replay a revoked lease",
                    )
                if lease.status == "expired":
                    raise LeaseExpiredError(
                        "v21-06:execution_lease_expired",
                        "same-key retry after lease expiry must not issue a new lease",
                    )
                if parse_audit_timestamp(lease.expires_at) <= _system_utc_now():
                    raise LeaseExpiredError(
                        "v21-06:execution_lease_expired",
                        "same-key retry after lease expiry must not issue a new lease",
                    )
                # F3：重放返回前恒定时间校验调用方 token 与存储
                # token_digest 一致，伪造 token 的重放拒绝。
                caller_token = str(intent_payload["lease_token"])
                if not hmac_module.compare_digest(
                    lease_token_digest(caller_token).encode("utf-8"),
                    lease.token_digest.encode("utf-8"),
                ):
                    raise LeaseTokenMismatchError(
                        "v21-06:lease_token_mismatch",
                        "replay token digest does not match the stored "
                        "lease token digest",
                    )
                return GrantConsumptionResult(
                    consumption=deepcopy(existing),
                    lease=deepcopy(lease),
                    lease_token=caller_token,
                    replayed=True,
                )
            # 3) grant 校验：revoked / expiry / fingerprint / remaining。
            if grant["status"] == "revoked":
                raise GrantRevokedError(
                    "v21-06:grant_revoked",
                    f"grant {grant_id!r} is revoked",
                )
            grant_expires_at = grant["expires_at"]
            if grant["status"] == "expired" or (
                grant_expires_at is not None
                and parse_audit_timestamp(grant_expires_at) <= _system_utc_now()
            ):
                raise GrantExpiredError(
                    "v21-06:grant_expired",
                    f"grant {grant_id!r} is expired",
                )
            expected_fingerprint = grant["authorization_fingerprint"]
            if expected_fingerprint is not None and not (
                hmac_module.compare_digest(
                    expected_fingerprint.encode("utf-8"),
                    fingerprint.encode("utf-8"),
                )
            ):
                raise GrantFingerprintMismatchError(
                    "v21-06:grant_fingerprint_mismatch",
                    "authorization_fingerprint does not match the grant",
                )
            if int(grant["remaining_uses"]) <= 0:
                raise GrantUsesExhaustedError(
                    "v21-06:grant_uses_exhausted",
                    f"grant {grant_id!r} has no remaining uses",
                )
            # 4) 行级 CAS 扣减（单锁内条件更新，rowcount==1 语义）。
            grant["remaining_uses"] = int(grant["remaining_uses"]) - 1
            # 5) 写 GrantConsumption（明文 token 不落库）。
            consumption = GrantConsumption(
                consumption_id=consumption_id,
                grant_id=grant_id,
                action_id=action_id,
                authorization_fingerprint=fingerprint,
                sequence=None,
                evidence_refs=[],
            )
            self.grant_consumption_records[consumption_id] = consumption
            # 6) 写 ExecutionLease（只存 token_digest）。
            lease = ExecutionLease(
                lease_id=_derive_lease_id(consumption_id),
                consumption_id=consumption_id,
                approval_id=str(intent_payload["approval_id"]),
                grant_id=grant_id,
                action_id=action_id,
                authorization_fingerprint=fingerprint,
                runtime_binding_id=str(intent_payload["runtime_binding_id"]),
                issued_at=str(intent_payload["issued_at"]),
                expires_at=str(intent_payload["expires_at"]),
                token_digest=lease_token_digest(str(intent_payload["lease_token"])),
                status="consumed",
                evidence_refs=[],
            )
            self.execution_lease_records[lease.lease_id] = lease
            return GrantConsumptionResult(
                consumption=deepcopy(consumption),
                lease=deepcopy(lease),
                lease_token=str(intent_payload["lease_token"]),
                replayed=False,
            )

    def get_execution_lease(
        self, scope_digest: str, lease_ref: str
    ) -> ExecutionLease | None:
        with self.approval_lease_lock:
            lease = self.execution_lease_records.get(lease_ref)
            if lease is None:
                for candidate in self.execution_lease_records.values():
                    if candidate.token_digest == lease_ref:
                        lease = candidate
                        break
            if lease is None:
                return None
            grant = self.capability_grants.get(lease.grant_id)
            if grant is None or grant["scope_digest"] != scope_digest:
                return None
            return deepcopy(lease)

    def expire_or_revoke_lease(
        self, scope_digest: str, lease_id: str, reason: str
    ) -> ExecutionLease:
        # F9：与 postgres 对齐错误优先级 —— 先验 reason 合法性再查终态。
        if reason == "expired":
            target = "expired"
        elif reason == "revoked":
            target = "revoked"
        else:
            raise LeaseTransitionError(
                "v21-06:unsupported_lease_transition",
                f"lease transition reason must be 'expired' or 'revoked', "
                f"got {reason!r}",
            )
        with self.approval_lease_lock:
            lease = self.execution_lease_records.get(lease_id)
            if lease is None:
                raise KeyError(lease_id)
            grant = self.capability_grants.get(lease.grant_id)
            if grant is None or grant["scope_digest"] != scope_digest:
                raise KeyError(lease_id)
            if lease.status in ("expired", "revoked"):
                return deepcopy(lease)
            updated = lease.model_copy(update={"status": target})
            self.execution_lease_records[lease_id] = updated
            return deepcopy(updated)

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        with self.approval_lease_lock:
            existing = self.approvals.get(approval.approval_id)
            if existing is not None:
                current = _with_effective_approval_status(existing)
                if current.status != "pending":
                    return current.model_copy(deep=True)
                stored = approval.model_copy(
                    update={
                        "status": current.status,
                        "decision": current.decision,
                        "resolution_source": current.resolution_source,
                        "resolved_by": current.resolved_by,
                        "resolution_reason": current.resolution_reason,
                        "created_at": current.created_at,
                        "expires_at": current.expires_at,
                        "resolved_at": current.resolved_at,
                    },
                    deep=True,
                )
            else:
                stored = approval.model_copy(deep=True)
            self.approvals[approval.approval_id] = stored
            return _with_effective_approval_status(stored)

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        with self.approval_lease_lock:
            approvals = [
                _with_effective_approval_status(item)
                for item in self.approvals.values()
            ]
        return sorted(
            (item for item in approvals if item.status == "pending"),
            key=lambda item: item.created_at,
        )

    def list_approvals(
        self,
        trace_id: str | None = None,
        *,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        with self.approval_lease_lock:
            approvals = [
                _with_effective_approval_status(item)
                for item in self.approvals.values()
            ]
        if trace_id is not None:
            approvals = [item for item in approvals if item.trace_id == trace_id]
        ordered = sorted(approvals, key=lambda item: item.created_at)
        if limit is not None:
            return ordered[: _bounded_collection_limit(limit)]
        return ordered

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        with self.approval_lease_lock:
            approval = self.approvals.get(approval_id)
            if approval is None:
                return None
            return _with_effective_approval_status(approval)

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
        with self.approval_lease_lock:
            approval = self.approvals[approval_id]
            current = _with_effective_approval_status(approval)
            if current.status != "pending":
                raise ApprovalStateConflictError(approval_id, current.status)
            updates: dict[str, Any] = {
                "status": "resolved",
                "decision": decision,
                "resolved_at": utc_now_iso(),
            }
            if resolution_source is not None:
                updates["resolution_source"] = resolution_source
            if resolved_by is not None:
                updates["resolved_by"] = resolved_by
            if resolution_reason is not None:
                updates["resolution_reason"] = resolution_reason
            if llm_review is not None:
                updates["llm_review"] = llm_review
            resolved = current.model_copy(update=updates, deep=True)
            self.approvals[approval_id] = resolved
            return resolved.model_copy(deep=True)

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


def _audit_content_matches(existing: AuditEvent, incoming: AuditEvent) -> bool:
    from guard_api.storage.integrity import canonical_json_bytes

    return canonical_json_bytes(
        existing.model_dump(mode="json", exclude={"integrity"})
    ) == canonical_json_bytes(incoming.model_dump(mode="json", exclude={"integrity"}))


def _is_policy_evaluation_for(event: AuditEvent, event_id: str) -> bool:
    if event.links.get("event_id") != event_id:
        return False
    if "decision_id" not in event.links:
        return False
    return event.record_type in (None, "policy_evaluation")


def _filter_audit_events(
    events: list[AuditEvent],
    filters: AuditEventFilters,
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


def _matches_window_filters(
    event: AuditEvent,
    query: AuditWindowQuery,
    *,
    ingested_at: datetime,
) -> bool:
    if (
        query.record_type is not None
        and classify_audit_record_type(event) != query.record_type
    ):
        return False
    if query.ingested_as_of is not None and ingested_at > query.ingested_as_of:
        return False
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
    return max(1, min(limit, MAX_REBUILD_INPUT_LIMIT))


def _bounded_collection_limit(limit: int) -> int:
    return max(1, min(limit, 5000))


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


def _with_effective_approval_status(
    approval: ApprovalRequest, *, now: datetime | None = None
) -> ApprovalRequest:
    current = approval.model_copy(deep=True)
    if current.status != "pending" or current.expires_at is None:
        return current
    try:
        expires_at = datetime.fromisoformat(current.expires_at)
    except ValueError:
        return current
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= (now or datetime.now(timezone.utc)):
        return current.model_copy(update={"status": "expired", "decision": "deny"})
    return current


def _grant_matches_binding(
    grant: CapabilityGrant,
    binding: EnforcementBindingRecord,
    approval: ApprovalRequest,
) -> bool:
    fingerprint = grant.exact_authorization_fingerprint
    return bool(
        grant.source_type == "human_approval"
        and grant.source_ref == f"approval:{binding.approval_id}"
        and grant.scope_digest == binding.scope_digest
        and grant.subject_principal_id == binding.principal_id
        and grant.subject_agent_id == binding.agent_id
        and grant.action_types == [binding.action_type]
        and fingerprint is not None
        and _safe_compare(fingerprint, binding.authorization_fingerprint)
        and grant.usage_limit == 1
        and grant.remaining_uses == 1
        and not grant.delegable
        and not grant.revoked
        and grant.expires_at == approval.expires_at
        and grant.policy_revision == binding.policy_revision
    )


def _registered_grant_matches_binding(
    grant: dict[str, Any],
    binding: EnforcementBindingRecord,
) -> bool:
    fingerprint = grant.get("authorization_fingerprint")
    return bool(
        grant.get("grant_id") == binding.grant_id
        and grant.get("scope_digest") == binding.scope_digest
        and isinstance(fingerprint, str)
        and _safe_compare(fingerprint, binding.authorization_fingerprint)
        and isinstance(grant.get("expires_at"), str)
        and isinstance(grant.get("registration_digest"), str)
    )


def _credential_authorizes_binding(
    credential: CredentialRecord,
    command: ApprovalLeaseConsumeCommand,
    now: datetime,
) -> bool:
    if credential.credential_id != command.credential_id:
        return False
    if not _safe_compare(credential.token_hash, command.credential_token_hash):
        return False
    if credential.revoked_at is not None:
        return False
    if credential.expires_at is not None:
        try:
            if parse_audit_timestamp(credential.expires_at) <= now:
                return False
        except ValueError:
            return False
    return bool(
        credential.principal_type == "component"
        and credential.role == "adapter"
        and "approval:wait" in credential.scopes
        and credential.principal_id == command.principal_id
        and credential.runtime == command.runtime
        and credential.agent_id == command.agent_id
    )


def _binding_approval_invariants_match(
    binding: EnforcementBindingRecord,
    approval: ApprovalRequest,
) -> bool:
    return bool(
        binding.approval_id == approval.approval_id
        and binding.principal_id == approval.requesting_principal_id
        and binding.runtime == approval.runtime
        and binding.agent_id == approval.agent_id
        and binding.action_id == approval.action_id
    )


def _command_identity_matches(
    binding: EnforcementBindingRecord,
    command: ApprovalLeaseConsumeCommand,
) -> bool:
    return bool(
        binding.approval_id == command.approval_id
        and binding.principal_id == command.principal_id
        and binding.runtime == command.runtime
        and binding.agent_id == command.agent_id
    )


def _lease_matches_binding(
    lease: ExecutionLease,
    binding: EnforcementBindingRecord,
    consumption: GrantConsumption,
) -> bool:
    return bool(
        lease.consumption_id == consumption.consumption_id
        and lease.approval_id == binding.approval_id
        and lease.grant_id == binding.grant_id == consumption.grant_id
        and lease.action_id == binding.action_id == consumption.action_id
        and _safe_compare(
            lease.authorization_fingerprint,
            binding.authorization_fingerprint,
        )
        and _safe_compare(
            consumption.authorization_fingerprint,
            binding.authorization_fingerprint,
        )
        and lease.runtime_binding_id == binding.runtime_binding_id
    )
