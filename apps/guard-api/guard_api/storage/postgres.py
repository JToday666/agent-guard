"""PostgreSQL-backed Guard API / Control Plane store."""

from __future__ import annotations

import hashlib
import hmac as hmac_module
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, cast

from alembic import command
from alembic.config import Config
from sqlalchemy import CursorResult, create_engine, desc, func, select, text, update
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    Index,
    Integer,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

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
from agentguard_core.authority import TaskFact
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
from guard_api.storage.sqlalchemy_models import (
    action_critic_reviews,
    adapter_statuses,
    approval_requests,
    audit_integrity_heads,
    audit_events,
    browser_sessions,
    capability_grant_runtime,
    config_audit_findings,
    credentials,
    evaluation_runs,
    enforcement_bindings,
    launch_codes,
    memory_guard_changes,
    metadata,
    policy_snapshot_history,
    policy_snapshots,
    provenance_edges,
    provenance_nodes,
    task_facts,
)

_GRANT_RUNTIME_STATUSES = ("active", "expired", "revoked")

_POLICY_SNAPSHOT_ADVISORY_LOCK_ID = 427001030001
_AUDIT_INTEGRITY_ADVISORY_LOCK_ID = 427001030002
_AUDIT_CHAIN_ID = "default"


def _compat_strip_legacy_policy_bundle_fields(payload: Any) -> Any:
    """存量策略快照的遗留字段兼容处理。

    早期版本的 PolicyBundle 包含 default_enforcement_mode 字段，快照保存时全量
    dump，已写入 policy_snapshots / policy_snapshot_history 的 payload_json。
    该字段删除后，PolicyBundle 的 extra="forbid" 会使存量行回读失败，因此回读
    前先剥离遗留字段，保持对存量数据的读取兼容。

    当确认生产环境快照表 payload_json 中已无 default_enforcement_mode 存量行
    （例如完成一次全量重写保存）后，可移除本函数及调用点。
    """
    if isinstance(payload, dict):
        payload.pop("default_enforcement_mode", None)
    return payload


def _lock_provenance_identity(session: Session, kind: str, stable_id: str) -> None:
    lock_id = int.from_bytes(
        hashlib.sha256(f"provenance:{kind}:{stable_id}".encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
    )


def _ct_flow_id(edge: ProvenanceEdge) -> str | None:
    metadata = edge.metadata
    if (
        metadata.get("contract") != "ct-provenance/1.0"
        or metadata.get("kind") != "edge"
    ):
        return None
    flow_id = metadata.get("flow_id")
    return flow_id if isinstance(flow_id, str) and flow_id else None


def _lock_task_identity(session: Session, task_id: str) -> None:
    """按 task_id 加事务级 advisory lock，串行化同一任务的 revision CAS。"""

    lock_id = int.from_bytes(
        hashlib.sha256(f"task_fact:{task_id}".encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
    )


def _lock_security_state_scope(session: Session, scope_digest: str) -> None:
    """按 scope_digest 加事务级 advisory lock，串行化同一 scope 的 state CAS（V21-04）。"""

    lock_id = int.from_bytes(
        hashlib.sha256(f"security_state:{scope_digest}".encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
    )


def _lock_grant_identity(session: Session, grant_id: str) -> None:
    """按 grant_id 加事务级 advisory lock，串行化同一 grant 的原子消费（V21-06）。

    与 provenance/task/security_state 同范式：
    ``pg_advisory_xact_lock(sha256("grant:" + grant_id)[:8])``。
    """

    lock_id = int.from_bytes(
        hashlib.sha256(f"grant:{grant_id}".encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
    )


def _lock_binding_identities(
    session: Session, record: EnforcementBindingRecord
) -> None:
    """Serialize all three unique binding identities in stable lock order."""

    lock_ids = {
        int.from_bytes(
            hashlib.sha256(f"binding:{kind}:{value}".encode("utf-8")).digest()[:8],
            byteorder="big",
            signed=True,
        )
        for kind, value in (
            ("approval", record.approval_id),
            ("event", record.event_id),
            ("policy_audit", record.policy_audit_id),
        )
    }
    for lock_id in sorted(lock_ids):
        session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": lock_id},
        )


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


# V21-04 security state 表元数据（与迁移 0015_security_state 对齐）。
security_states = Table(
    "security_states",
    metadata,
    Column("scope_digest", Text, primary_key=True),
    Column("state_version", Integer, nullable=False),
    Column("canonical_payload", JSONB, nullable=False),
    Column("dirty", Boolean, nullable=False),
    Column("dirty_domains", JSONB, nullable=False),
    Column("projector_version", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
    CheckConstraint(
        "state_version >= 0",
        name="ck_security_states_state_version_non_negative",
    ),
)

# V21-06 capability/lease table metadata (migration 0016) is shared through
# sqlalchemy_models; RTE-05 migration 0017 adds registration_digest there.

grant_consumptions = Table(
    "grant_consumptions",
    metadata,
    Column("consumption_id", Text, primary_key=True),
    Column("grant_id", Text, nullable=False),
    Column("action_id", Text, nullable=False),
    Column("authorization_fingerprint", Text, nullable=False),
    Column("consumed_at", Text, nullable=False),
    # F10：与 migration 0016 对齐的 FK 元数据。
    ForeignKeyConstraint(
        ["grant_id"],
        ["capability_grant_runtime.grant_id"],
        name="fk_grant_consumptions_grant_id",
    ),
    UniqueConstraint(
        "grant_id", "action_id", name="uq_grant_consumptions_grant_action"
    ),
)

execution_leases = Table(
    "execution_leases",
    metadata,
    Column("lease_id", Text, primary_key=True),
    Column("token_digest", Text, nullable=False),
    Column("consumption_id", Text, nullable=False),
    Column("approval_id", Text, nullable=False),
    Column("grant_id", Text, nullable=False),
    Column("action_id", Text, nullable=False),
    Column("authorization_fingerprint", Text, nullable=False),
    Column("runtime_binding_id", Text, nullable=False),
    Column("issued_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("status", Text, nullable=False),
    # F10：与 migration 0016 对齐的 FK 元数据。
    ForeignKeyConstraint(
        ["consumption_id"],
        ["grant_consumptions.consumption_id"],
        name="fk_execution_leases_consumption_id",
    ),
    UniqueConstraint("token_digest", name="uq_execution_leases_token_digest"),
    CheckConstraint(
        "status IN ('consumed', 'expired', 'revoked')",
        name="ck_execution_leases_status",
    ),
    Index(
        "ix_execution_leases_consumption_id",
        "consumption_id",
    ),
)

projection_records = Table(
    "projection_records",
    metadata,
    Column("scope_digest", Text, primary_key=True),
    Column("source_record_type", Text, primary_key=True),
    Column("source_record_id", Text, primary_key=True),
    Column("source_revision", Integer, primary_key=True),
    Column("projector_version", Text, primary_key=True),
    Column("delta_digest", Text, nullable=False),
    Column("delta_payload", JSONB, nullable=False),
    Column("applied_state_version", Integer, nullable=False),
    Column("created_at", Text, nullable=False),
    CheckConstraint(
        "source_record_type IN ("
        "'policy_evaluation', 'runtime_outcome', 'approval', "
        "'memory_transition', 'policy_revision', 'runtime_observation')",
        name="ck_projection_records_source_record_type",
    ),
    CheckConstraint(
        "applied_state_version > 0",
        name="ck_projection_records_applied_state_version_positive",
    ),
    Index(
        "ix_projection_records_scope_applied_version",
        "scope_digest",
        "applied_state_version",
    ),
)


def _grant_consumption_from_row(row: Any) -> GrantConsumption:
    """grant_consumptions 行 → 冻结模型（consumed_at 仅落库，不入模型）。"""
    return GrantConsumption(
        consumption_id=str(row["consumption_id"]),
        grant_id=str(row["grant_id"]),
        action_id=str(row["action_id"]),
        authorization_fingerprint=str(row["authorization_fingerprint"]),
        sequence=None,
        evidence_refs=[],
    )


def _execution_lease_from_row(row: Any) -> ExecutionLease:
    """execution_leases 行 → 冻结模型（只存 token_digest，明文不落库）。"""
    return ExecutionLease(
        lease_id=str(row["lease_id"]),
        consumption_id=str(row["consumption_id"]),
        approval_id=str(row["approval_id"]),
        grant_id=str(row["grant_id"]),
        action_id=str(row["action_id"]),
        authorization_fingerprint=str(row["authorization_fingerprint"]),
        runtime_binding_id=str(row["runtime_binding_id"]),
        issued_at=str(row["issued_at"]),
        expires_at=str(row["expires_at"]),
        token_digest=str(row["token_digest"]),
        status=cast("Literal['consumed', 'expired', 'revoked']", str(row["status"])),
        evidence_refs=[],
    )


@dataclass(slots=True)
class PostgresControlPlaneStore:
    database_url: str
    _engine: Engine = field(init=False, repr=False)
    _session_factory: sessionmaker[Session] = field(init=False, repr=False)
    _active_store_session: ContextVar[Session | None] = field(
        default_factory=lambda: ContextVar(
            "agentguard_active_store_session", default=None
        ),
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.database_url = _normalize_database_url(self.database_url)
        self._engine = create_engine(self.database_url, pool_pre_ping=True)
        self._session_factory = sessionmaker(bind=self._engine)

    def initialize(self) -> None:
        command.upgrade(self._alembic_config(), "head")

    def health_check(self) -> bool:
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def add_audit_event(self, event: AuditEvent) -> bool:
        occurred_at = parse_audit_timestamp(event.timestamp)
        with self._write_session() as session:
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _AUDIT_INTEGRITY_ADVISORY_LOCK_ID},
            )
            existing = session.execute(
                select(audit_events.c.audit_id).where(
                    audit_events.c.audit_id == event.audit_id
                )
            ).scalar_one_or_none()
            if existing is not None:
                stored_payload = session.execute(
                    select(audit_events.c.payload_json).where(
                        audit_events.c.audit_id == event.audit_id
                    )
                ).scalar_one()
                from guard_api.storage.integrity import canonical_json_bytes

                stored_content = canonical_json_bytes(
                    {k: v for k, v in stored_payload.items() if k != "integrity"}
                )
                incoming_content = canonical_json_bytes(
                    event.model_dump(mode="json", exclude={"integrity"})
                )
                if stored_content == incoming_content:
                    return False
                raise AuditIdConflictError(event.audit_id)
            head = (
                session.execute(
                    select(
                        audit_integrity_heads.c.sequence,
                        audit_integrity_heads.c.event_hash,
                    )
                    .where(audit_integrity_heads.c.chain_id == _AUDIT_CHAIN_ID)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            sequence = int(head["sequence"]) + 1 if head is not None else 1
            prev_hash = (
                str(head["event_hash"])
                if head is not None and head["event_hash"] is not None
                else None
            )
            event_with_integrity = attach_audit_integrity(
                event,
                sequence=sequence,
                prev_hash=prev_hash,
            )
            integrity = read_audit_integrity(event_with_integrity)
            if integrity is None:
                raise RuntimeError("audit integrity metadata was not attached")
            payload = event_with_integrity.model_dump(mode="json")
            session.execute(
                pg_insert(audit_events).values(
                    audit_id=event.audit_id,
                    payload_json=payload,
                    occurred_at=occurred_at,
                    record_type=classify_audit_record_type(event),
                    trace_id=event.trace_id,
                    case_id=event.case_id,
                    runtime=event.runtime,
                    decision=event.decision,
                    event_id=event.links.get("event_id"),
                    decision_id=event.links.get("decision_id"),
                    is_malicious=event.is_malicious,
                    latency_ms=event.latency_ms,
                    chain_id=_AUDIT_CHAIN_ID,
                    sequence=integrity.sequence,
                    prev_hash=integrity.prev_hash,
                    event_hash=integrity.event_hash,
                )
            )
            head_stmt = pg_insert(audit_integrity_heads).values(
                chain_id=_AUDIT_CHAIN_ID,
                sequence=integrity.sequence,
                event_hash=integrity.event_hash,
                updated_at=func.statement_timestamp(),
            )
            head_stmt = head_stmt.on_conflict_do_update(
                index_elements=[audit_integrity_heads.c.chain_id],
                set_={
                    "sequence": head_stmt.excluded.sequence,
                    "event_hash": head_stmt.excluded.event_hash,
                    "updated_at": head_stmt.excluded.updated_at,
                },
            )
            session.execute(head_stmt)
            return True

    def get_audit_event(self, audit_id: str) -> AuditEvent | None:
        stmt = select(audit_events.c.payload_json).where(
            audit_events.c.audit_id == audit_id
        )
        with self._read_session() as session:
            row = session.execute(stmt).scalar_one_or_none()
        return AuditEvent.model_validate(row) if row is not None else None

    def list_audit_events(
        self, filters: AuditEventFilters | None = None
    ) -> list[AuditEvent]:
        filters = filters or AuditEventFilters()
        stmt = (
            select(audit_events.c.payload_json)
            .where(*_audit_filter_conditions(filters))
            .order_by(desc(audit_events.c.sequence))
            .limit(_bounded_limit(filters.limit))
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [AuditEvent.model_validate(row) for row in rows]

    def read_audit_events_bounded(self, query: AuditWindowQuery) -> list[AuditEvent]:
        # sequence 固化一致性快照；正式列承载过滤条件，避免 JSONB 解包和
        # Python 全表过滤。索引负责常用 trace/runtime/case/decision 与时间 cohort。
        conditions: list[Any] = [audit_events.c.chain_id == _AUDIT_CHAIN_ID]
        if query.after_sequence is not None:
            conditions.append(audit_events.c.sequence < query.after_sequence)
        conditions.extend(_window_filter_conditions(query))
        with self._session_factory() as session:
            with session.begin():
                upper = query.upper_sequence
                if upper is None:
                    upper = session.execute(
                        select(audit_integrity_heads.c.sequence).where(
                            audit_integrity_heads.c.chain_id == _AUDIT_CHAIN_ID
                        )
                    ).scalar_one_or_none()
                if upper is None:
                    return []
                stmt = (
                    select(audit_events.c.payload_json)
                    .where(audit_events.c.sequence <= upper, *conditions)
                    .order_by(desc(audit_events.c.sequence))
                    .limit(query.limit)
                )
                rows = session.execute(stmt).scalars().all()
        return [AuditEvent.model_validate(row) for row in rows]

    def capture_audit_snapshot(self) -> tuple[int, datetime]:
        head_sequence = (
            select(audit_integrity_heads.c.sequence)
            .where(audit_integrity_heads.c.chain_id == _AUDIT_CHAIN_ID)
            .scalar_subquery()
        )
        stmt = select(
            func.coalesce(head_sequence, 0),
            func.statement_timestamp(),
        )
        with self._session_factory() as session:
            row = session.execute(stmt).one()
        return int(row[0]), row[1]

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None:
        stmt = (
            select(audit_events.c.payload_json)
            .where(
                audit_events.c.event_id == event_id,
                audit_events.c.decision_id.is_not(None),
                audit_events.c.record_type == "policy_evaluation",
            )
            .order_by(audit_events.c.sequence.asc(), audit_events.c.audit_id.asc())
            .limit(1)
        )
        with self._read_session() as session:
            row = session.execute(stmt).scalars().first()
        return AuditEvent.model_validate(row) if row is not None else None

    @contextmanager
    def evaluation_transaction(self, event_id: str) -> Iterator[None]:
        """Commit every evaluation fact atomically under a per-event lock."""

        lock_id = int.from_bytes(
            hashlib.sha256(f"evaluation:{event_id}".encode("utf-8")).digest()[:8],
            byteorder="big",
            signed=True,
        )
        if self._active_store_session.get() is not None:
            raise RuntimeError("nested evaluation transactions are not supported")
        with self._session_factory.begin() as session:
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
            )
            token = self._active_store_session.set(session)
            try:
                yield
            finally:
                self._active_store_session.reset(token)

    @contextmanager
    def memory_change_transaction(self, change_id: str) -> Iterator[None]:
        """状态转换与转换审计共用同一事务，避免「状态已改、链上无记录」。

        复用 evaluation_transaction 的会话加入机制：上下文内的所有
        _read_session/_write_session 调用（含 add_audit_event 的链写入与
        provenance 写入）都汇入同一 session，随本事务一次性提交或回滚。
        审计链咨询锁仍由 add_audit_event 在事务内获取；与评测事务的
        锁序（per-event 锁 → 审计链锁）不存在交叉倒置，不会死锁。
        """

        del change_id
        if self._active_store_session.get() is not None:
            raise RuntimeError("nested store write transactions are not supported")
        with self._session_factory.begin() as session:
            token = self._active_store_session.set(session)
            try:
                yield
            finally:
                self._active_store_session.reset(token)

    def verify_audit_integrity(self) -> AuditIntegrityStatus:
        stmt = (
            select(audit_events.c.payload_json)
            .where(audit_events.c.chain_id == _AUDIT_CHAIN_ID)
            .order_by(audit_events.c.sequence.asc(), audit_events.c.audit_id.asc())
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return verify_audit_chain(AuditEvent.model_validate(row) for row in rows)

    def add_provenance_node(self, node: ProvenanceNode) -> ProvenanceNode:
        with self._write_session() as session:
            _lock_provenance_identity(session, "node", node.node_id)
            row = session.execute(
                select(provenance_nodes.c.payload_json).where(
                    provenance_nodes.c.node_id == node.node_id
                )
            ).scalar_one_or_none()
            merged = (
                node
                if row is None
                else merge_provenance_node(ProvenanceNode.model_validate(row), node)
            )
            payload = merged.model_dump(mode="json")
            stmt = pg_insert(provenance_nodes).values(
                node_id=merged.node_id,
                trace_id=merged.trace_id,
                kind=merged.kind,
                ref_id=merged.ref_id,
                payload_json=payload,
                created_at=_database_datetime(merged.timestamp),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[provenance_nodes.c.node_id],
                set_={
                    "payload_json": stmt.excluded.payload_json,
                    "created_at": stmt.excluded.created_at,
                },
            )
            session.execute(stmt)
        return merged

    def get_provenance_node(self, node_id: str) -> ProvenanceNode | None:
        stmt = select(provenance_nodes.c.payload_json).where(
            provenance_nodes.c.node_id == node_id
        )
        with self._read_session() as session:
            row = session.execute(stmt).scalar_one_or_none()
        return ProvenanceNode.model_validate(row) if row is not None else None

    def add_provenance_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        with self._write_session() as session:
            _lock_provenance_identity(session, "edge", edge.edge_id)
            endpoint_count = session.execute(
                select(func.count())
                .select_from(provenance_nodes)
                .where(
                    provenance_nodes.c.node_id.in_(
                        [edge.source_node_id, edge.target_node_id]
                    ),
                    provenance_nodes.c.trace_id == edge.trace_id,
                )
            ).scalar_one()
            expected_count = 1 if edge.source_node_id == edge.target_node_id else 2
            if int(endpoint_count) != expected_count:
                raise ProvenanceEndpointMissingError(edge.edge_id)
            row = session.execute(
                select(provenance_edges.c.payload_json).where(
                    provenance_edges.c.edge_id == edge.edge_id
                )
            ).scalar_one_or_none()
            merged = (
                edge
                if row is None
                else merge_provenance_edge(ProvenanceEdge.model_validate(row), edge)
            )
            payload = merged.model_dump(mode="json")
            stmt = pg_insert(provenance_edges).values(
                edge_id=merged.edge_id,
                trace_id=merged.trace_id,
                source_node_id=merged.source_node_id,
                target_node_id=merged.target_node_id,
                relation=merged.relation,
                payload_json=payload,
                created_at=_database_datetime(merged.timestamp),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[provenance_edges.c.edge_id],
                set_={
                    "payload_json": stmt.excluded.payload_json,
                    "created_at": stmt.excluded.created_at,
                },
            )
            session.execute(stmt)
        return merged

    def write_ct_provenance_batch(
        self,
        nodes: list[ProvenanceNode],
        edges: list[ProvenanceEdge],
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]:
        """Write a CT subgraph under flow-identity locks and one savepoint."""

        incoming_flows: dict[tuple[str, str], str] = {}
        for edge in edges:
            flow_id = _ct_flow_id(edge)
            if flow_id is None:
                raise CtProvenanceBatchConflictError(edge.edge_id)
            identity = (edge.trace_id, flow_id)
            previous = incoming_flows.get(identity)
            if previous is not None and previous != edge.edge_id:
                raise CtProvenanceBatchConflictError(f"{edge.trace_id}:{flow_id}")
            incoming_flows[identity] = edge.edge_id

        with self._write_session() as session:
            with session.begin_nested():
                for trace_id, flow_id in sorted(incoming_flows):
                    _lock_provenance_identity(
                        session, "ct-flow", f"{trace_id}:{flow_id}"
                    )
                trace_ids = sorted({trace_id for trace_id, _ in incoming_flows})
                if trace_ids:
                    rows = session.execute(
                        select(provenance_edges.c.payload_json).where(
                            provenance_edges.c.trace_id.in_(trace_ids)
                        )
                    ).scalars()
                    for row in rows:
                        existing = ProvenanceEdge.model_validate(row)
                        flow_id = _ct_flow_id(existing)
                        if flow_id is None:
                            continue
                        incoming_edge_id = incoming_flows.get(
                            (existing.trace_id, flow_id)
                        )
                        if (
                            incoming_edge_id is not None
                            and incoming_edge_id != existing.edge_id
                        ):
                            raise CtProvenanceBatchConflictError(
                                f"{existing.trace_id}:{flow_id}"
                            )
                written_nodes = [
                    self.add_provenance_node(node)
                    for node in sorted(nodes, key=lambda item: item.node_id)
                ]
                written_edges = [
                    self.add_provenance_edge(edge)
                    for edge in sorted(edges, key=lambda item: item.edge_id)
                ]
        return written_nodes, written_edges

    def list_provenance(
        self,
        trace_id: str,
        *,
        node_limit: int | None = None,
        edge_limit: int | None = None,
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]:
        node_stmt = (
            select(provenance_nodes.c.payload_json)
            .where(provenance_nodes.c.trace_id == trace_id)
            .order_by(
                provenance_nodes.c.created_at.asc(), provenance_nodes.c.node_id.asc()
            )
        )
        edge_stmt = (
            select(provenance_edges.c.payload_json)
            .where(provenance_edges.c.trace_id == trace_id)
            .order_by(
                provenance_edges.c.created_at.asc(), provenance_edges.c.edge_id.asc()
            )
        )
        if node_limit is not None:
            node_stmt = node_stmt.limit(_bounded_collection_limit(node_limit))
        with self._session_factory() as session:
            node_rows = session.execute(node_stmt).scalars().all()
        nodes = [ProvenanceNode.model_validate(row) for row in node_rows]
        if node_limit is not None:
            node_ids = [node.node_id for node in nodes]
            if not node_ids:
                return [], []
            edge_stmt = edge_stmt.where(
                provenance_edges.c.source_node_id.in_(node_ids),
                provenance_edges.c.target_node_id.in_(node_ids),
            )
        if edge_limit is not None:
            edge_stmt = edge_stmt.limit(_bounded_collection_limit(edge_limit))
        with self._session_factory() as session:
            edge_rows = session.execute(edge_stmt).scalars().all()
        return (
            nodes,
            [ProvenanceEdge.model_validate(row) for row in edge_rows],
        )

    def add_config_audit_finding(
        self,
        event: ConfigAuditEvent,
        finding: ConfigAuditFinding,
    ) -> ConfigAuditFinding:
        payload = {
            "event": event.model_dump(mode="json"),
            "finding": finding.model_dump(mode="json"),
        }
        stmt = pg_insert(config_audit_findings).values(
            finding_id=finding.finding_id,
            runtime=event.runtime,
            target_type=event.target_type,
            target_id=event.target_id,
            trace_id=str(event.metadata.get("trace_id") or event.event_id),
            severity=finding.severity,
            payload_json=payload,
            created_at=_database_datetime(event.timestamp),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[config_audit_findings.c.finding_id],
            set_={
                "runtime": stmt.excluded.runtime,
                "target_type": stmt.excluded.target_type,
                "target_id": stmt.excluded.target_id,
                "trace_id": stmt.excluded.trace_id,
                "severity": stmt.excluded.severity,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
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
        stmt = select(config_audit_findings.c.payload_json).order_by(
            desc(config_audit_findings.c.created_at),
            desc(config_audit_findings.c.finding_id),
        )
        if target_id is not None:
            stmt = stmt.where(config_audit_findings.c.target_id == target_id)
        if target_type is not None:
            stmt = stmt.where(config_audit_findings.c.target_type == target_type)
        if severity is not None:
            stmt = stmt.where(config_audit_findings.c.severity == severity)
        if trace_id is not None:
            stmt = stmt.where(config_audit_findings.c.trace_id == trace_id)
        stmt = stmt.limit(_bounded_limit(limit))
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        records = [_config_finding_record(row) for row in rows]
        return records[: _bounded_limit(limit)]

    def save_evaluation_run(
        self, run: EvaluationRun | dict[str, Any]
    ) -> dict[str, Any]:
        payload = EvaluationRun.model_validate(run).model_dump(mode="json")
        regression_gate = payload.get("regression_gate")
        regression_status = (
            regression_gate.get("status") if isinstance(regression_gate, dict) else None
        )
        stmt = pg_insert(evaluation_runs).values(
            run_id=payload["run_id"],
            run_at=_database_datetime(payload["run_at"]),
            dataset_id=payload.get("dataset_id"),
            dataset_version=payload.get("dataset_version"),
            regression_status=regression_status,
            payload_json=payload,
            created_at=func.statement_timestamp(),
        )
        stmt = stmt.on_conflict_do_nothing(
            index_elements=[evaluation_runs.c.run_id]
        ).returning(evaluation_runs.c.payload_json)
        with self._session_factory.begin() as session:
            inserted = session.execute(stmt).scalar_one_or_none()
            if inserted is not None:
                return EvaluationRun.model_validate(inserted).model_dump(mode="json")
            existing = session.execute(
                select(evaluation_runs.c.payload_json).where(
                    evaluation_runs.c.run_id == payload["run_id"]
                )
            ).scalar_one()
            stored = EvaluationRun.model_validate(existing).model_dump(mode="json")
            if stored != payload:
                raise EvaluationRunConflictError(payload["run_id"])
            return stored

    def get_latest_evaluation_run(self) -> dict[str, Any] | None:
        stmt = (
            select(evaluation_runs.c.payload_json)
            .order_by(desc(evaluation_runs.c.run_at), desc(evaluation_runs.c.run_id))
            .limit(1)
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return EvaluationRun.model_validate(row).model_dump(mode="json")

    def get_evaluation_run(self, run_id: str) -> dict[str, Any] | None:
        stmt = select(evaluation_runs.c.payload_json).where(
            evaluation_runs.c.run_id == run_id
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return EvaluationRun.model_validate(row).model_dump(mode="json")

    def list_evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        stmt = select(evaluation_runs.c.payload_json).order_by(
            desc(evaluation_runs.c.run_at),
            desc(evaluation_runs.c.run_id),
        )
        if dataset_id is not None:
            stmt = stmt.where(evaluation_runs.c.dataset_id == dataset_id)
        if dataset_version is not None:
            stmt = stmt.where(evaluation_runs.c.dataset_version == dataset_version)
        stmt = stmt.limit(_bounded_limit(limit))
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [
            EvaluationRun.model_validate(row).model_dump(mode="json") for row in rows
        ]

    def save_adapter_status(
        self, adapter_id: str, status: AdapterStatusRecord | dict[str, Any]
    ) -> dict[str, Any]:
        payload = AdapterStatusRecord.model_validate(status).model_dump(mode="json")
        heartbeat_at = payload.get("last_heartbeat_at")
        stmt = pg_insert(adapter_statuses).values(
            adapter_id=adapter_id,
            status=payload["status"],
            loaded=payload["loaded"],
            runtime_id=payload.get("runtime_id"),
            agent_id=payload.get("agent_id"),
            enforcement_mode=payload.get("enforcement_mode"),
            last_heartbeat_at=(
                _database_datetime(heartbeat_at) if heartbeat_at is not None else None
            ),
            payload_json=payload,
            updated_at=func.statement_timestamp(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[adapter_statuses.c.adapter_id],
            set_={
                "status": stmt.excluded.status,
                "loaded": stmt.excluded.loaded,
                "runtime_id": stmt.excluded.runtime_id,
                "agent_id": stmt.excluded.agent_id,
                "enforcement_mode": stmt.excluded.enforcement_mode,
                "last_heartbeat_at": stmt.excluded.last_heartbeat_at,
                "payload_json": stmt.excluded.payload_json,
                "updated_at": func.statement_timestamp(),
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return payload

    def get_adapter_status(self, adapter_id: str) -> dict[str, Any] | None:
        stmt = select(adapter_statuses.c.payload_json).where(
            adapter_statuses.c.adapter_id == adapter_id
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return AdapterStatusRecord.model_validate(row).model_dump(mode="json")

    def list_adapter_statuses(self) -> dict[str, dict[str, Any]]:
        stmt = select(adapter_statuses.c.adapter_id, adapter_statuses.c.payload_json)
        with self._session_factory() as session:
            rows = session.execute(stmt).mappings().all()
        return {
            str(row["adapter_id"]): AdapterStatusRecord.model_validate(
                row["payload_json"]
            ).model_dump(mode="json")
            for row in rows
        }

    def create_credential(
        self, credential: CredentialRecord | dict[str, Any]
    ) -> CredentialRecord:
        record = CredentialRecord.model_validate(credential)
        payload = record.model_dump(mode="json")
        stmt = pg_insert(credentials).values(
            credential_id=record.credential_id,
            token_hash=record.token_hash,
            principal_type=record.principal_type,
            principal_id=record.principal_id,
            role=record.role,
            runtime=record.runtime,
            agent_id=record.agent_id,
            payload_json=payload,
            created_at=record.created_at,
            expires_at=record.expires_at,
            revoked_at=record.revoked_at,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[credentials.c.credential_id],
            set_={
                "token_hash": stmt.excluded.token_hash,
                "principal_type": stmt.excluded.principal_type,
                "principal_id": stmt.excluded.principal_id,
                "role": stmt.excluded.role,
                "runtime": stmt.excluded.runtime,
                "agent_id": stmt.excluded.agent_id,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
                "expires_at": stmt.excluded.expires_at,
                "revoked_at": stmt.excluded.revoked_at,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return record

    def get_credential_by_token_hash(self, token_hash: str) -> CredentialRecord | None:
        stmt = select(credentials.c.payload_json).where(
            credentials.c.token_hash == token_hash,
            credentials.c.revoked_at.is_(None),
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return CredentialRecord.model_validate(row)

    def list_credentials(self) -> list[CredentialRecord]:
        stmt = select(credentials.c.payload_json).order_by(
            credentials.c.created_at.asc()
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [CredentialRecord.model_validate(row) for row in rows]

    def revoke_credential(
        self, credential_id: str, revoked_at: str
    ) -> CredentialRecord:
        current_stmt = select(credentials.c.payload_json).where(
            credentials.c.credential_id == credential_id
        )
        with self._session_factory() as session:
            current = session.execute(current_stmt).scalar_one_or_none()
            if current is None:
                raise KeyError(credential_id)
            record = CredentialRecord.model_validate(current).model_copy(
                update={"revoked_at": revoked_at}
            )
            session.execute(
                update(credentials)
                .where(credentials.c.credential_id == credential_id)
                .values(
                    payload_json=record.model_dump(mode="json"),
                    revoked_at=revoked_at,
                )
            )
            session.commit()
        return record

    def add_action_critic_review(
        self, review: ActionCriticReview
    ) -> ActionCriticReview:
        payload = review.model_dump(mode="json")
        stmt = pg_insert(action_critic_reviews).values(
            review_id=review.review_id,
            trace_id=review.trace_id,
            event_id=review.event_id,
            verdict=review.verdict,
            payload_json=payload,
            created_at=_database_datetime(review.created_at),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[action_critic_reviews.c.review_id],
            set_={
                "trace_id": stmt.excluded.trace_id,
                "event_id": stmt.excluded.event_id,
                "verdict": stmt.excluded.verdict,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
            },
        )
        with self._write_session() as session:
            session.execute(stmt)
        return review

    def list_action_critic_reviews(self, trace_id: str) -> list[ActionCriticReview]:
        stmt = (
            select(action_critic_reviews.c.payload_json)
            .where(action_critic_reviews.c.trace_id == trace_id)
            .order_by(
                action_critic_reviews.c.created_at.asc(),
                action_critic_reviews.c.review_id.asc(),
            )
        )
        with self._read_session() as session:
            rows = session.execute(stmt).scalars().all()
        return [ActionCriticReview.model_validate(row) for row in rows]

    def create_memory_change(self, change: MemoryGuardChange) -> MemoryGuardChange:
        # 存在即拒绝：on_conflict_do_nothing 绝不覆盖既有记录，
        # 以 rowcount 判定插入是否生效，冲突时回读比对。
        payload = change.model_dump(mode="json")
        stmt = (
            pg_insert(memory_guard_changes)
            .values(
                change_id=change.change_id,
                trace_id=change.trace_id,
                namespace=change.namespace,
                key=change.key,
                status=change.status,
                payload_json=payload,
                created_at=change.created_at,
                updated_at=change.updated_at,
            )
            .on_conflict_do_nothing(index_elements=[memory_guard_changes.c.change_id])
        )
        with self._write_session() as session:
            result = cast("CursorResult[Any]", session.execute(stmt))
            inserted = result.rowcount == 1
        if inserted:
            return change
        # 同 change_id 已存在：经 _read_session 回读（汇入活动事务时可见
        # 同事务内未提交写入），完全一致视为幂等重放，否则拒绝。
        read_stmt = select(memory_guard_changes.c.payload_json).where(
            memory_guard_changes.c.change_id == change.change_id
        )
        with self._read_session() as session:
            existing_payload = session.execute(read_stmt).scalar_one()
        existing = MemoryGuardChange.model_validate(existing_payload)
        if memory_change_is_replay_match(existing, change):
            return existing
        raise MemoryChangeAlreadyExistsError(change.change_id)

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None:
        stmt = select(memory_guard_changes.c.payload_json).where(
            memory_guard_changes.c.change_id == change_id
        )
        with self._read_session() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return MemoryGuardChange.model_validate(row)

    def update_memory_change_status(
        self, change_id: str, status: str
    ) -> MemoryTransitionResult:
        current = self.get_memory_change(change_id)
        if current is None:
            raise KeyError(change_id)
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
        stmt = (
            update(memory_guard_changes)
            .where(memory_guard_changes.c.change_id == change_id)
            # 前态条件 UPDATE：只有当前状态仍等于读到的前态才生效，
            # 以 rowcount 判定取代 read-modify-write，消除并发竞态。
            .where(memory_guard_changes.c.status == current.status)
            .values(
                status=updated.status,
                payload_json=updated.model_dump(mode="json"),
                updated_at=updated.updated_at,
            )
        )
        with self._write_session() as session:
            result = cast("CursorResult[Any]", session.execute(stmt))
            applied = result.rowcount == 1
        if applied:
            return MemoryTransitionResult(
                change=updated, applied=True, previous_status=current.status
            )
        # 并发转换已改变前态；重读区分幂等重放与非法转换。
        latest = self.get_memory_change(change_id)
        if latest is None:
            raise KeyError(change_id)
        if latest.status == status:
            return MemoryTransitionResult(
                change=latest, applied=False, previous_status=latest.status
            )
        raise MemoryChangeTransitionError(change_id, latest.status, status)

    def get_policy_snapshot(self) -> PolicyBundle | None:
        record = self.get_policy_snapshot_record()
        if record is None:
            return None
        return record.policy_bundle

    def get_policy_snapshot_record(self) -> PolicySnapshotRecord | None:
        stmt = select(
            policy_snapshots.c.revision,
            policy_snapshots.c.payload_json,
            policy_snapshots.c.updated_at,
            policy_snapshots.c.updated_by,
        ).where(policy_snapshots.c.policy_id == "current")
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        payload = _compat_strip_legacy_policy_bundle_fields(row["payload_json"])
        return PolicySnapshotRecord(
            revision=int(row["revision"]),
            policy_bundle=PolicyBundle.model_validate(payload),
            updated_at=str(row["updated_at"]),
            updated_by=str(row["updated_by"]),
        )

    def save_policy_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        expected_revision: int,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord:
        payload = policy_bundle.model_dump(mode="json")
        updated_at = utc_now_iso()
        with self._session_factory() as session:
            with session.begin():
                session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": _POLICY_SNAPSHOT_ADVISORY_LOCK_ID},
                )
                current_revision = session.execute(
                    select(policy_snapshots.c.revision).where(
                        policy_snapshots.c.policy_id == "current"
                    )
                ).scalar_one_or_none()
                normalized_current_revision = (
                    int(current_revision) if current_revision is not None else 0
                )
                if expected_revision != normalized_current_revision:
                    raise PolicyRevisionConflictError(
                        expected_revision=expected_revision,
                        current_revision=normalized_current_revision,
                    )
                revision = normalized_current_revision + 1
                stmt = pg_insert(policy_snapshots).values(
                    policy_id="current",
                    payload_json=payload,
                    revision=revision,
                    updated_at=updated_at,
                    updated_by=updated_by,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[policy_snapshots.c.policy_id],
                    set_={
                        "payload_json": stmt.excluded.payload_json,
                        "revision": stmt.excluded.revision,
                        "updated_at": stmt.excluded.updated_at,
                        "updated_by": stmt.excluded.updated_by,
                    },
                )
                session.execute(stmt)
                session.execute(
                    pg_insert(policy_snapshot_history).values(
                        revision=revision,
                        payload_json=payload,
                        updated_at=updated_at,
                        updated_by=updated_by,
                    )
                )
        return PolicySnapshotRecord(
            revision=revision,
            policy_bundle=policy_bundle,
            updated_at=updated_at,
            updated_by=updated_by,
        )

    def list_policy_snapshot_history(
        self, limit: int = 100
    ) -> list[PolicySnapshotRecord]:
        stmt = (
            select(
                policy_snapshot_history.c.revision,
                policy_snapshot_history.c.payload_json,
                policy_snapshot_history.c.updated_at,
                policy_snapshot_history.c.updated_by,
            )
            .order_by(desc(policy_snapshot_history.c.revision))
            .limit(_bounded_limit(limit))
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).mappings().all()
        records: list[PolicySnapshotRecord] = []
        for row in rows:
            payload = _compat_strip_legacy_policy_bundle_fields(row["payload_json"])
            records.append(
                PolicySnapshotRecord(
                    revision=int(row["revision"]),
                    policy_bundle=PolicyBundle.model_validate(payload),
                    updated_at=str(row["updated_at"]),
                    updated_by=str(row["updated_by"]),
                )
            )
        return records

    def create_task_fact(self, record: TaskFactRecord) -> TaskFactRecord:
        # 事务内 advisory lock + head revision 条件校验，与 memory 语义对齐：
        # 仅当 expected_revision 等于当前 head revision 时追加，旧 revision
        # 永不覆盖。
        task_fact = record.task_fact
        with self._session_factory() as session:
            with session.begin():
                _lock_task_identity(session, task_fact.task_id)
                head_revision = session.execute(
                    select(func.max(task_facts.c.revision)).where(
                        task_facts.c.task_id == task_fact.task_id
                    )
                ).scalar_one()
                current_revision = (
                    int(head_revision) if head_revision is not None else 0
                )
                if record.expected_revision != current_revision:
                    raise TaskRevisionConflictError(
                        expected_revision=record.expected_revision,
                        current_revision=current_revision,
                    )
                session.execute(
                    pg_insert(task_facts).values(
                        task_id=task_fact.task_id,
                        revision=task_fact.revision,
                        scope_digest=task_fact.scope_digest,
                        scope_key_id=task_fact.scope_key_id,
                        principal_id=task_fact.principal_id,
                        status=task_fact.status,
                        task_digest=task_fact.task_digest,
                        task_summary=task_fact.task_summary,
                        canonical_payload=record.canonical_payload,
                        request_digest=record.request_digest,
                        expected_revision=record.expected_revision,
                        producer=task_fact.producer,
                        authority=task_fact.authority,
                        created_at=record.created_at,
                    )
                )
        return record

    def get_task_fact(
        self, task_id: str, revision: int | None = None
    ) -> TaskFactRecord | None:
        stmt = select(
            task_facts.c.canonical_payload,
            task_facts.c.request_digest,
            task_facts.c.expected_revision,
            task_facts.c.created_at,
        ).where(task_facts.c.task_id == task_id)
        if revision is None:
            stmt = stmt.order_by(desc(task_facts.c.revision)).limit(1)
        else:
            stmt = stmt.where(task_facts.c.revision == revision)
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        return _task_fact_record_from_row(row)

    def list_task_fact_revisions(self, task_id: str) -> list[TaskFactRecord]:
        stmt = (
            select(
                task_facts.c.canonical_payload,
                task_facts.c.request_digest,
                task_facts.c.expected_revision,
                task_facts.c.created_at,
            )
            .where(task_facts.c.task_id == task_id)
            .order_by(task_facts.c.revision)
        )
        with self._read_session() as session:
            rows = session.execute(stmt).mappings().all()
        return [_task_fact_record_from_row(row) for row in rows]

    def get_security_state(self, scope_digest: str) -> SecurityStateRecord | None:
        stmt = select(
            security_states.c.scope_digest,
            security_states.c.state_version,
            security_states.c.canonical_payload,
            security_states.c.dirty,
            security_states.c.dirty_domains,
            security_states.c.projector_version,
            security_states.c.updated_at,
        ).where(security_states.c.scope_digest == scope_digest)
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        return _security_state_record_from_row(row)

    def cas_security_state(
        self,
        scope_digest: str,
        expected_state_version: int,
        record: SecurityStateRecord,
    ) -> bool:
        # 事务内 advisory lock + 单条条件 UPDATE（rowcount 判定）；无既有行
        # 时以 expected_state_version == 0 为 CAS 前提插入，与 memory 语义对齐。
        with self._session_factory() as session:
            with session.begin():
                _lock_security_state_scope(session, scope_digest)
                result = cast(
                    CursorResult[Any],
                    session.execute(
                        update(security_states)
                        .where(
                            security_states.c.scope_digest == scope_digest,
                            security_states.c.state_version == expected_state_version,
                        )
                        .values(
                            state_version=record.state_version,
                            canonical_payload=record.canonical_payload,
                            dirty=record.dirty,
                            dirty_domains=record.dirty_domains,
                            projector_version=record.projector_version,
                            updated_at=record.updated_at,
                        )
                    ),
                )
                if result.rowcount == 1:
                    return True
                if result.rowcount != 0:  # pragma: no cover - PK 单行不变量
                    raise StateVersionConflictError(
                        expected_state_version=expected_state_version,
                        current_state_version=-1,
                    )
                exists = session.execute(
                    select(security_states.c.state_version).where(
                        security_states.c.scope_digest == scope_digest
                    )
                ).scalar_one_or_none()
                if exists is not None:
                    raise StateVersionConflictError(
                        expected_state_version=expected_state_version,
                        current_state_version=int(exists),
                    )
                if expected_state_version != 0:
                    raise StateVersionConflictError(
                        expected_state_version=expected_state_version,
                        current_state_version=0,
                    )
                session.execute(
                    pg_insert(security_states).values(
                        scope_digest=scope_digest,
                        state_version=record.state_version,
                        canonical_payload=record.canonical_payload,
                        dirty=record.dirty,
                        dirty_domains=record.dirty_domains,
                        projector_version=record.projector_version,
                        updated_at=record.updated_at,
                    )
                )
                return True

    def mark_security_state_dirty(self, scope_digest: str, domains: list[str]) -> None:
        # 事务内 advisory lock：state_version 保持不变；无既有行时创建
        # version=0 的空态脏记录，与 memory 语义对齐。
        from agentguard_core.security_context import (
            PROJECTOR_VERSION,
            OnlineSecurityState,
            StateWatermarks,
        )
        from agentguard_core.signals.models import CoverageDomain

        merged_domains = cast("list[CoverageDomain]", sorted(set(domains)))
        with self._session_factory() as session:
            with session.begin():
                _lock_security_state_scope(session, scope_digest)
                row = (
                    session.execute(
                        select(
                            security_states.c.state_version,
                            security_states.c.canonical_payload,
                            security_states.c.dirty_domains,
                            security_states.c.projector_version,
                        ).where(security_states.c.scope_digest == scope_digest)
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
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
                    session.execute(
                        pg_insert(security_states).values(
                            scope_digest=scope_digest,
                            state_version=0,
                            canonical_payload=empty_state.model_dump(mode="json"),
                            dirty=True,
                            dirty_domains=merged_domains,
                            projector_version=PROJECTOR_VERSION,
                            updated_at=utc_now_iso(),
                        )
                    )
                    return
                merged = sorted(set(row["dirty_domains"]) | set(merged_domains))
                # F1 双口径同步：把 dirty 域并入 canonical_payload 的
                # dirty_domains（model_dump(mode="json") 口径，改后仍可
                # model_validate 读回），否则 projector 从 payload 重建
                # 状态后回写会静默清除失败事实。
                payload_state = OnlineSecurityState.model_validate(
                    row["canonical_payload"]
                )
                payload_state = payload_state.model_copy(
                    update={
                        "dirty_domains": sorted(
                            set(payload_state.dirty_domains) | set(merged)
                        )
                    }
                )
                session.execute(
                    update(security_states)
                    .where(security_states.c.scope_digest == scope_digest)
                    .values(
                        dirty=True,
                        dirty_domains=merged,
                        canonical_payload=payload_state.model_dump(mode="json"),
                        updated_at=utc_now_iso(),
                    )
                )

    def record_projection(
        self, record: ProjectionIdentityRecord
    ) -> tuple[ProjectionIdentityRecord, bool]:
        # 幂等三分支：PK 唯一 + 回读比对 digest；同身份异 digest 拒绝。
        with self._session_factory() as session:
            with session.begin():
                _lock_security_state_scope(session, record.scope_digest)
                existing = self._get_projection_locked(
                    session,
                    record.scope_digest,
                    record.source_record_type,
                    record.source_record_id,
                    record.source_revision,
                    record.projector_version,
                )
                if existing is not None:
                    if existing.delta_digest == record.delta_digest:
                        return existing, False
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
                session.execute(
                    pg_insert(projection_records).values(
                        scope_digest=record.scope_digest,
                        source_record_type=record.source_record_type,
                        source_record_id=record.source_record_id,
                        source_revision=record.source_revision,
                        projector_version=record.projector_version,
                        delta_digest=record.delta_digest,
                        delta_payload=record.delta_payload,
                        applied_state_version=record.applied_state_version,
                        created_at=record.created_at,
                    )
                )
        return record, True

    def _get_projection_locked(
        self,
        session: Session,
        scope_digest: str,
        source_record_type: str,
        source_record_id: str,
        source_revision: int,
        projector_version: str,
    ) -> ProjectionIdentityRecord | None:
        row = (
            session.execute(
                select(
                    projection_records.c.scope_digest,
                    projection_records.c.source_record_type,
                    projection_records.c.source_record_id,
                    projection_records.c.source_revision,
                    projection_records.c.projector_version,
                    projection_records.c.delta_digest,
                    projection_records.c.delta_payload,
                    projection_records.c.applied_state_version,
                    projection_records.c.created_at,
                ).where(
                    projection_records.c.scope_digest == scope_digest,
                    projection_records.c.source_record_type == source_record_type,
                    projection_records.c.source_record_id == source_record_id,
                    projection_records.c.source_revision == source_revision,
                    projection_records.c.projector_version == projector_version,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return _projection_identity_record_from_row(row)

    def get_projection(
        self,
        scope_digest: str,
        source_record_type: str,
        source_record_id: str,
        source_revision: int,
        projector_version: str,
    ) -> ProjectionIdentityRecord | None:
        with self._read_session() as session:
            return self._get_projection_locked(
                session,
                scope_digest,
                source_record_type,
                source_record_id,
                source_revision,
                projector_version,
            )

    def list_rebuild_inputs(
        self, scope_digest: str, *, limit: int
    ) -> list[ProjectionIdentityRecord]:
        stmt = (
            select(
                projection_records.c.scope_digest,
                projection_records.c.source_record_type,
                projection_records.c.source_record_id,
                projection_records.c.source_revision,
                projection_records.c.projector_version,
                projection_records.c.delta_digest,
                projection_records.c.delta_payload,
                projection_records.c.applied_state_version,
                projection_records.c.created_at,
            )
            .where(projection_records.c.scope_digest == scope_digest)
            .order_by(projection_records.c.applied_state_version)
            .limit(_bounded_limit(limit))
        )
        with self._read_session() as session:
            rows = session.execute(stmt).mappings().all()
        return [_projection_identity_record_from_row(row) for row in rows]

    # RTE-05 private ActionIR binding storage and approval-bound lease path.

    def save_enforcement_binding(
        self, record: EnforcementBindingRecord
    ) -> EnforcementBindingRecord:
        if not record.requires_execution_lease or record.grant_id is not None:
            raise EnforcementBindingConflictError(
                "rte-05:binding_conflict", "private binding is invalid"
            )
        with self._write_session() as session:
            _lock_binding_identities(session, record)
            rows = (
                session.execute(
                    select(enforcement_bindings)
                    .where(
                        (enforcement_bindings.c.event_id == record.event_id)
                        | (
                            enforcement_bindings.c.policy_audit_id
                            == record.policy_audit_id
                        )
                        | (enforcement_bindings.c.approval_id == record.approval_id)
                    )
                    .with_for_update()
                )
                .mappings()
                .all()
            )
            if rows:
                existing = _enforcement_binding_from_row(rows[0])
                if len(rows) != 1 or _binding_semantic_payload(
                    existing
                ) != _binding_semantic_payload(record):
                    raise EnforcementBindingConflictError(
                        "rte-05:binding_conflict",
                        "private binding identity conflicts with stored facts",
                    )
                return existing
            session.execute(
                pg_insert(enforcement_bindings).values(
                    **_enforcement_binding_values(record)
                )
            )
        return record

    def get_enforcement_binding(
        self, approval_id: str
    ) -> EnforcementBindingRecord | None:
        stmt = select(enforcement_bindings).where(
            enforcement_bindings.c.approval_id == approval_id
        )
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        return _enforcement_binding_from_row(row) if row is not None else None

    def register_approval_grant(
        self,
        binding: EnforcementBindingRecord,
        grant: CapabilityGrant,
    ) -> EnforcementBindingRecord:
        registration_digest = canonical_sha256(grant.model_dump(mode="json"))
        with self._write_session() as session:
            approval_row = (
                session.execute(
                    _approval_select()
                    .where(approval_requests.c.approval_id == binding.approval_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if approval_row is None:
                raise ApprovalLeaseNotFoundError(
                    "rte-05:approval_not_found", "approval is not available"
                )
            approval = _approval_from_row(approval_row)
            if (
                _database_datetime(approval_row["expires_at"])
                <= _database_datetime(approval_row["_database_now"])
                or approval.status != "resolved"
                or approval.decision != "allow_once"
                or approval.resolution_source != "human"
            ):
                raise ApprovalLeaseNotConsumableError(
                    "rte-05:approval_not_consumable",
                    "approval is not consumable",
                )
            stored_row = (
                session.execute(
                    select(enforcement_bindings)
                    .where(enforcement_bindings.c.approval_id == binding.approval_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if stored_row is None:
                raise ApprovalExecutionLeaseUnavailableError(
                    "rte-05:binding_unavailable",
                    "private binding is not available",
                )
            stored = _enforcement_binding_from_row(stored_row)
            if _binding_semantic_payload(stored) != _binding_semantic_payload(binding):
                raise EnforcementBindingConflictError(
                    "rte-05:binding_conflict",
                    "private binding conflicts with stored facts",
                )
            if not _grant_matches_binding(grant, stored, approval):
                raise EnforcementBindingConflictError(
                    "rte-05:grant_registration_conflict",
                    "runtime grant conflicts with private binding",
                )

            _lock_grant_identity(session, grant.grant_id)
            grant_row = (
                session.execute(
                    select(capability_grant_runtime)
                    .where(capability_grant_runtime.c.grant_id == grant.grant_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if grant_row is not None:
                existing_fingerprint = grant_row["authorization_fingerprint"]
                if (
                    grant_row["registration_digest"] != registration_digest
                    or grant_row["scope_digest"] != grant.scope_digest
                    or grant_row["expires_at"] != grant.expires_at
                    or existing_fingerprint is None
                    or not _safe_compare(
                        str(existing_fingerprint),
                        binding.authorization_fingerprint,
                    )
                ):
                    raise EnforcementBindingConflictError(
                        "rte-05:grant_registration_conflict",
                        "runtime grant registration conflicts with stored facts",
                    )
            else:
                session.execute(
                    pg_insert(capability_grant_runtime).values(
                        grant_id=grant.grant_id,
                        scope_digest=grant.scope_digest,
                        remaining_uses=grant.remaining_uses,
                        expires_at=grant.expires_at,
                        authorization_fingerprint=(
                            grant.exact_authorization_fingerprint
                        ),
                        status="active",
                        registration_digest=registration_digest,
                    )
                )

            if stored.grant_id not in (None, grant.grant_id):
                raise EnforcementBindingConflictError(
                    "rte-05:grant_registration_conflict",
                    "private binding is already registered differently",
                )
            if stored.grant_id is None:
                session.execute(
                    update(enforcement_bindings)
                    .where(
                        enforcement_bindings.c.approval_id == stored.approval_id,
                        enforcement_bindings.c.grant_id.is_(None),
                    )
                    .values(grant_id=grant.grant_id)
                )
            registered_values = dict(stored_row)
            registered_values["grant_id"] = grant.grant_id
            return _enforcement_binding_from_row(registered_values)

    def consume_approval_execution_lease(
        self, command: ApprovalLeaseConsumeCommand
    ) -> GrantConsumptionResult:
        with self._session_factory() as session:
            with session.begin():
                now = session.execute(select(func.now())).scalar_one()

                # Fixed lock/check order: credential -> approval -> binding ->
                # grant -> consumption -> lease.
                credential_row = (
                    session.execute(
                        select(credentials)
                        .where(credentials.c.credential_id == command.credential_id)
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if credential_row is None or not _credential_authorizes_binding(
                    credential_row, command, now
                ):
                    raise ApprovalLeaseAuthorizationError(
                        "rte-05:authorization_denied",
                        "credential or bound identity is not authorized",
                    )

                approval_row = (
                    session.execute(
                        select(approval_requests)
                        .where(approval_requests.c.approval_id == command.approval_id)
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if approval_row is None:
                    raise ApprovalLeaseNotFoundError(
                        "rte-05:approval_not_found", "approval is not available"
                    )
                approval_expires_at = _database_datetime(approval_row["expires_at"])
                if (
                    approval_row["resolved_at"] is None
                    or approval_row["decision"] != "allow_once"
                    or approval_row["resolution_source"] != "human"
                ):
                    raise ApprovalLeaseNotConsumableError(
                        "rte-05:approval_not_consumable",
                        "approval is not consumable",
                    )
                approval = _approval_from_locked_row(approval_row, now)

                binding_row = (
                    session.execute(
                        select(enforcement_bindings)
                        .where(
                            enforcement_bindings.c.approval_id == command.approval_id
                        )
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if binding_row is None:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:binding_unavailable",
                        "private binding is not available",
                    )
                binding = _enforcement_binding_from_row(binding_row)
                if not binding.requires_execution_lease:
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

                _lock_grant_identity(session, binding.grant_id)
                grant_row = (
                    session.execute(
                        select(capability_grant_runtime)
                        .where(capability_grant_runtime.c.grant_id == binding.grant_id)
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if grant_row is None:
                    raise ApprovalExecutionLeaseUnavailableError(
                        "rte-05:grant_unavailable",
                        "runtime grant registration is not complete",
                    )
                if not _registered_grant_matches_binding(grant_row, binding):
                    raise ApprovalExecutionLeaseStateInvalidError(
                        "rte-05:state_invalid",
                        "private approval authority state is inconsistent",
                    )
                grant_expires_at = parse_audit_timestamp(str(grant_row["expires_at"]))

                consumption_id = _derive_consumption_id(
                    binding.grant_id, binding.action_id
                )
                consumption_row = (
                    session.execute(
                        select(grant_consumptions)
                        .where(grant_consumptions.c.consumption_id == consumption_id)
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if consumption_row is not None:
                    if not _safe_compare(
                        str(consumption_row["authorization_fingerprint"]),
                        command.authorization_fingerprint,
                    ):
                        raise ApprovalLeaseConsumptionConflictError(
                            "rte-05:consumption_conflict",
                            "request conflicts with prior consumption",
                        )
                    lease_id = _derive_lease_id(consumption_id)
                    lease_row = (
                        session.execute(
                            select(execution_leases)
                            .where(execution_leases.c.lease_id == lease_id)
                            .with_for_update()
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if lease_row is None or not _lease_row_matches_binding(
                        lease_row, binding, consumption_row
                    ):
                        raise ApprovalExecutionLeaseStateInvalidError(
                            "rte-05:state_invalid",
                            "private execution lease state is inconsistent",
                        )
                    lease_status = str(lease_row["status"])
                    if (
                        approval_expires_at <= now
                        or lease_status == "expired"
                        or (parse_audit_timestamp(str(lease_row["expires_at"])) <= now)
                    ):
                        raise ApprovalExecutionLeaseExpiredError(
                            "rte-05:execution_lease_expired",
                            "execution lease has expired",
                        )
                    if grant_row["status"] != "active" or grant_expires_at <= now:
                        raise ApprovalLeaseNotConsumableError(
                            "rte-05:approval_not_consumable",
                            "approval grant is not consumable",
                        )
                    if lease_status != "consumed" or not _safe_compare(
                        str(lease_row["token_digest"]),
                        lease_token_digest(command.lease_token),
                    ):
                        raise ApprovalLeaseConsumptionConflictError(
                            "rte-05:consumption_conflict",
                            "request conflicts with prior consumption",
                        )
                    return GrantConsumptionResult(
                        consumption=_grant_consumption_from_row(consumption_row),
                        lease=_execution_lease_from_row(lease_row),
                        lease_token=command.lease_token,
                        replayed=True,
                    )

                if approval_expires_at <= now or grant_expires_at <= now:
                    raise ApprovalLeaseExpiredError(
                        "rte-05:approval_expired", "approval has expired"
                    )
                if grant_row["status"] != "active":
                    raise ApprovalLeaseNotConsumableError(
                        "rte-05:approval_not_consumable",
                        "approval grant is not consumable",
                    )
                if int(grant_row["remaining_uses"]) != 1:
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

                cas_result = cast(
                    "CursorResult[Any]",
                    session.execute(
                        update(capability_grant_runtime)
                        .where(
                            capability_grant_runtime.c.grant_id == binding.grant_id,
                            capability_grant_runtime.c.remaining_uses == 1,
                            capability_grant_runtime.c.status == "active",
                        )
                        .values(remaining_uses=0)
                    ),
                )
                if cas_result.rowcount != 1:
                    raise ApprovalLeaseConsumptionConflictError(
                        "rte-05:consumption_conflict",
                        "approval grant has already been consumed",
                    )
                issued_at = _database_datetime_iso(now)
                normalized_expires_at = _database_datetime_iso(lease_expires_at)
                consumption = GrantConsumption(
                    consumption_id=consumption_id,
                    grant_id=binding.grant_id,
                    action_id=binding.action_id,
                    authorization_fingerprint=binding.authorization_fingerprint,
                    sequence=None,
                    evidence_refs=[],
                )
                session.execute(
                    pg_insert(grant_consumptions).values(
                        consumption_id=consumption_id,
                        grant_id=binding.grant_id,
                        action_id=binding.action_id,
                        authorization_fingerprint=(binding.authorization_fingerprint),
                        consumed_at=issued_at,
                    )
                )
                lease = ExecutionLease(
                    lease_id=_derive_lease_id(consumption_id),
                    consumption_id=consumption_id,
                    approval_id=binding.approval_id,
                    grant_id=binding.grant_id,
                    action_id=binding.action_id,
                    authorization_fingerprint=binding.authorization_fingerprint,
                    runtime_binding_id=binding.runtime_binding_id,
                    issued_at=issued_at,
                    expires_at=normalized_expires_at,
                    token_digest=lease_token_digest(command.lease_token),
                    status="consumed",
                    evidence_refs=[],
                )
                session.execute(
                    pg_insert(execution_leases).values(
                        lease_id=lease.lease_id,
                        token_digest=lease.token_digest,
                        consumption_id=lease.consumption_id,
                        approval_id=lease.approval_id,
                        grant_id=lease.grant_id,
                        action_id=lease.action_id,
                        authorization_fingerprint=(lease.authorization_fingerprint),
                        runtime_binding_id=lease.runtime_binding_id,
                        issued_at=lease.issued_at,
                        expires_at=lease.expires_at,
                        status=lease.status,
                    )
                )
                return GrantConsumptionResult(
                    consumption=consumption,
                    lease=lease,
                    lease_token=command.lease_token,
                    replayed=False,
                )

    # V21-06 lease 协议方法权威实现（migration 0016 已建表）。
    # C4：原子消费的全部校验与写入在单事务内完成；行锁序固定
    # grant→consumption→lease（advisory lock 串行化同一 grant）。

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
        # 事务内 advisory lock + 存在即拒绝（与 create_task_fact 同范式）：
        # ON CONFLICT DO NOTHING 在 asyncpg 下 rowcount 恒为 -1，不能
        # 作为插入生效判据。
        with self._session_factory() as session:
            with session.begin():
                _lock_grant_identity(session, grant_id)
                existing = session.execute(
                    select(capability_grant_runtime.c.grant_id).where(
                        capability_grant_runtime.c.grant_id == grant_id
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    raise ValueError(f"grant already registered: {grant_id}")
                session.execute(
                    pg_insert(capability_grant_runtime).values(
                        grant_id=grant_id,
                        scope_digest=scope_digest,
                        remaining_uses=remaining_uses,
                        expires_at=expires_at,
                        authorization_fingerprint=authorization_fingerprint,
                        status=status,
                    )
                )
        return {
            "grant_id": grant_id,
            "scope_digest": scope_digest,
            "remaining_uses": remaining_uses,
            "expires_at": expires_at,
            "authorization_fingerprint": authorization_fingerprint,
            "status": status,
        }

    def get_capability_grant_runtime(self, grant_id: str) -> dict[str, Any] | None:
        """读 grant 运行时行（消费后 remaining_uses 校验/Phase 2 读路径）。"""
        stmt = select(capability_grant_runtime).where(
            capability_grant_runtime.c.grant_id == grant_id
        )
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        expires_at = row["expires_at"]
        fingerprint = row["authorization_fingerprint"]
        return {
            "grant_id": str(row["grant_id"]),
            "scope_digest": str(row["scope_digest"]),
            "remaining_uses": int(row["remaining_uses"]),
            "expires_at": str(expires_at) if expires_at is not None else None,
            "authorization_fingerprint": (
                str(fingerprint) if fingerprint is not None else None
            ),
            "status": str(row["status"]),
        }

    def consume_grant(
        self, scope_digest: str, intent_payload: dict[str, Any]
    ) -> GrantConsumptionResult:
        validate_intent_payload(intent_payload)
        grant_id = str(intent_payload["grant_id"])
        action_id = str(intent_payload["action_id"])
        fingerprint = str(intent_payload["authorization_fingerprint"])
        consumption_id = _derive_consumption_id(grant_id, action_id)
        lease_id = _derive_lease_id(consumption_id)
        lease_token = str(intent_payload["lease_token"])
        with self._session_factory() as session:
            with session.begin():
                # 锁序第一：grant 身份 advisory lock + 行锁。
                _lock_grant_identity(session, grant_id)
                grant_row = (
                    session.execute(
                        select(capability_grant_runtime)
                        .where(capability_grant_runtime.c.grant_id == grant_id)
                        .with_for_update()
                    )
                    .mappings()
                    .one_or_none()
                )
                if grant_row is None:
                    raise GrantNotRegisteredError(
                        "v21-06:grant_not_registered",
                        f"grant {grant_id!r} is not registered",
                    )
                if grant_row["scope_digest"] != scope_digest:
                    raise GrantScopeMismatchError(
                        "v21-06:grant_scope_mismatch",
                        "grant scope_digest does not match the request scope",
                    )
                # 锁序第二：consumption（UNIQUE(grant_id, action_id)）幂等
                # 重放分支必须先于 remaining_uses 校验（重试时用量可能已归零）。
                existing = (
                    session.execute(
                        select(grant_consumptions).where(
                            grant_consumptions.c.consumption_id == consumption_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    if not hmac_module.compare_digest(
                        str(existing["authorization_fingerprint"]).encode("utf-8"),
                        fingerprint.encode("utf-8"),
                    ):
                        raise GrantConsumptionConflictError(
                            "v21-06:consumption_conflict",
                            "double-spend attempt: same (grant_id, action_id) "
                            "with a different authorization_fingerprint",
                        )
                    lease_row = (
                        session.execute(
                            select(execution_leases).where(
                                execution_leases.c.lease_id == lease_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if lease_row is None:
                        raise LeaseStoreError(
                            "v21-06:lease_missing",
                            "consumption exists but its execution lease is " "missing",
                        )
                    # F1：终态校验先于 expires_at —— revoked/expired 状态
                    # 的 lease 不得被幂等重放绕过（撤销/过期语义
                    # fail-closed）。
                    lease_status = str(lease_row["status"])
                    if lease_status == "revoked":
                        raise LeaseRevokedError(
                            "v21-06:execution_lease_revoked",
                            "same-key retry after lease revocation must not "
                            "replay a revoked lease",
                        )
                    if lease_status == "expired":
                        raise LeaseExpiredError(
                            "v21-06:execution_lease_expired",
                            "same-key retry after lease expiry must not "
                            "issue a new lease",
                        )
                    if parse_audit_timestamp(
                        str(lease_row["expires_at"])
                    ) <= datetime.now(timezone.utc):
                        raise LeaseExpiredError(
                            "v21-06:execution_lease_expired",
                            "same-key retry after lease expiry must not "
                            "issue a new lease",
                        )
                    # F3：重放返回前恒定时间校验调用方 token 与存储
                    # token_digest 一致，伪造 token 的重放拒绝。
                    if not hmac_module.compare_digest(
                        lease_token_digest(lease_token).encode("utf-8"),
                        str(lease_row["token_digest"]).encode("utf-8"),
                    ):
                        raise LeaseTokenMismatchError(
                            "v21-06:lease_token_mismatch",
                            "replay token digest does not match the stored "
                            "lease token digest",
                        )
                    return GrantConsumptionResult(
                        consumption=_grant_consumption_from_row(existing),
                        lease=_execution_lease_from_row(lease_row),
                        lease_token=lease_token,
                        replayed=True,
                    )
                # 锁序第三前置：grant 校验 revoked/expiry/fingerprint。
                if grant_row["status"] == "revoked":
                    raise GrantRevokedError(
                        "v21-06:grant_revoked",
                        f"grant {grant_id!r} is revoked",
                    )
                grant_expires_at = grant_row["expires_at"]
                if grant_row["status"] == "expired" or (
                    grant_expires_at is not None
                    and parse_audit_timestamp(str(grant_expires_at))
                    <= datetime.now(timezone.utc)
                ):
                    raise GrantExpiredError(
                        "v21-06:grant_expired",
                        f"grant {grant_id!r} is expired",
                    )
                expected_fingerprint = grant_row["authorization_fingerprint"]
                if expected_fingerprint is not None and not (
                    hmac_module.compare_digest(
                        str(expected_fingerprint).encode("utf-8"),
                        fingerprint.encode("utf-8"),
                    )
                ):
                    raise GrantFingerprintMismatchError(
                        "v21-06:grant_fingerprint_mismatch",
                        "authorization_fingerprint does not match the grant",
                    )
                # 行级 CAS 扣减：条件 UPDATE remaining_uses-1，rowcount==1
                # 判定；不碰 security_states.canonical_payload。
                cas_result = cast(
                    "CursorResult[Any]",
                    session.execute(
                        update(capability_grant_runtime)
                        .where(capability_grant_runtime.c.grant_id == grant_id)
                        .where(capability_grant_runtime.c.remaining_uses > 0)
                        .values(
                            remaining_uses=(
                                capability_grant_runtime.c.remaining_uses - 1
                            )
                        )
                    ),
                )
                if cas_result.rowcount != 1:
                    raise GrantUsesExhaustedError(
                        "v21-06:grant_uses_exhausted",
                        f"grant {grant_id!r} has no remaining uses",
                    )
                # 写 GrantConsumption（明文 token 不落库）。
                consumption = GrantConsumption(
                    consumption_id=consumption_id,
                    grant_id=grant_id,
                    action_id=action_id,
                    authorization_fingerprint=fingerprint,
                    sequence=None,
                    evidence_refs=[],
                )
                session.execute(
                    pg_insert(grant_consumptions).values(
                        consumption_id=consumption_id,
                        grant_id=grant_id,
                        action_id=action_id,
                        authorization_fingerprint=fingerprint,
                        consumed_at=str(intent_payload["issued_at"]),
                    )
                )
                # 写 ExecutionLease（只存 token_digest）。
                lease = ExecutionLease(
                    lease_id=lease_id,
                    consumption_id=consumption_id,
                    approval_id=str(intent_payload["approval_id"]),
                    grant_id=grant_id,
                    action_id=action_id,
                    authorization_fingerprint=fingerprint,
                    runtime_binding_id=str(intent_payload["runtime_binding_id"]),
                    issued_at=str(intent_payload["issued_at"]),
                    expires_at=str(intent_payload["expires_at"]),
                    token_digest=lease_token_digest(lease_token),
                    status="consumed",
                    evidence_refs=[],
                )
                session.execute(
                    pg_insert(execution_leases).values(
                        lease_id=lease.lease_id,
                        token_digest=lease.token_digest,
                        consumption_id=lease.consumption_id,
                        approval_id=lease.approval_id,
                        grant_id=lease.grant_id,
                        action_id=lease.action_id,
                        authorization_fingerprint=(lease.authorization_fingerprint),
                        runtime_binding_id=lease.runtime_binding_id,
                        issued_at=lease.issued_at,
                        expires_at=lease.expires_at,
                        status=lease.status,
                    )
                )
                return GrantConsumptionResult(
                    consumption=consumption,
                    lease=lease,
                    lease_token=lease_token,
                    replayed=False,
                )

    def get_execution_lease(
        self, scope_digest: str, lease_ref: str
    ) -> ExecutionLease | None:
        stmt = select(execution_leases).where(
            (execution_leases.c.lease_id == lease_ref)
            | (execution_leases.c.token_digest == lease_ref)
        )
        with self._read_session() as session:
            row = session.execute(stmt).mappings().first()
            if row is None:
                return None
            grant_scope = session.execute(
                select(capability_grant_runtime.c.scope_digest).where(
                    capability_grant_runtime.c.grant_id == row["grant_id"]
                )
            ).scalar_one_or_none()
        if grant_scope != scope_digest:
            return None
        return _execution_lease_from_row(row)

    def expire_or_revoke_lease(
        self, scope_digest: str, lease_id: str, reason: str
    ) -> ExecutionLease:
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
        with self._session_factory() as session:
            with session.begin():
                row = (
                    session.execute(
                        select(execution_leases).where(
                            execution_leases.c.lease_id == lease_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise KeyError(lease_id)
                grant_scope = session.execute(
                    select(capability_grant_runtime.c.scope_digest).where(
                        capability_grant_runtime.c.grant_id == row["grant_id"]
                    )
                ).scalar_one_or_none()
                if grant_scope != scope_digest:
                    raise KeyError(lease_id)
                current_status = str(row["status"])
                if current_status in ("expired", "revoked"):
                    return _execution_lease_from_row(row)
                cas_result = cast(
                    "CursorResult[Any]",
                    session.execute(
                        update(execution_leases)
                        .where(
                            execution_leases.c.lease_id == lease_id,
                            execution_leases.c.status == current_status,
                        )
                        .values(status=target)
                    ),
                )
                if cas_result.rowcount != 1:
                    # 并发已推进终态：回读返回（幂等语义）。
                    latest = (
                        session.execute(
                            select(execution_leases).where(
                                execution_leases.c.lease_id == lease_id
                            )
                        )
                        .mappings()
                        .one()
                    )
                    return _execution_lease_from_row(latest)
                updated = dict(row)
                updated["status"] = target
                return _execution_lease_from_row(updated)

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        created_at = _database_datetime(approval.created_at)
        expires_at = _database_datetime(approval.expires_at)
        resolved_at = (
            _database_datetime(approval.resolved_at)
            if approval.status == "resolved" and approval.resolved_at is not None
            else None
        )
        stmt = pg_insert(approval_requests).values(
            approval_id=approval.approval_id,
            trace_id=approval.trace_id,
            runtime=approval.runtime,
            agent_id=approval.agent_id,
            subject_id=approval.subject_id,
            action_id=approval.action_id,
            payload_json=_approval_payload(approval),
            decision=approval.decision if resolved_at is not None else None,
            resolution_source=(
                approval.resolution_source if resolved_at is not None else None
            ),
            resolved_by=approval.resolved_by if resolved_at is not None else None,
            resolution_reason=(
                approval.resolution_reason if resolved_at is not None else None
            ),
            created_at=created_at,
            expires_at=expires_at,
            resolved_at=resolved_at,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[approval_requests.c.approval_id],
            set_={
                "trace_id": stmt.excluded.trace_id,
                "runtime": stmt.excluded.runtime,
                "agent_id": stmt.excluded.agent_id,
                "subject_id": stmt.excluded.subject_id,
                "action_id": stmt.excluded.action_id,
                "payload_json": stmt.excluded.payload_json,
            },
        )
        with self._write_session() as session:
            session.execute(stmt)
        stored = self.get_approval(approval.approval_id)
        if stored is None:  # pragma: no cover - insert/read invariant
            raise KeyError(approval.approval_id)
        return stored

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        stmt = (
            _approval_select()
            .where(
                approval_requests.c.resolved_at.is_(None),
                approval_requests.c.expires_at > func.now(),
            )
            .order_by(approval_requests.c.created_at.asc())
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).mappings().all()
        return [_approval_from_row(row) for row in rows]

    def list_approvals(
        self,
        trace_id: str | None = None,
        *,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        stmt = _approval_select().order_by(approval_requests.c.created_at.asc())
        if trace_id is not None:
            stmt = stmt.where(approval_requests.c.trace_id == trace_id)
        if limit is not None:
            stmt = stmt.limit(_bounded_collection_limit(limit))
        with self._session_factory() as session:
            rows = session.execute(stmt).mappings().all()
        return [_approval_from_row(row) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        stmt = _approval_select().where(approval_requests.c.approval_id == approval_id)
        with self._read_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        return _approval_from_row(row)

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
        stmt = (
            _approval_select()
            .where(approval_requests.c.approval_id == approval_id)
            .with_for_update()
        )
        with self._write_session() as session:
            row = session.execute(stmt).mappings().one_or_none()
            if row is None:
                raise KeyError(approval_id)
            approval = _approval_from_row(row)
            if approval.status != "pending":
                raise ApprovalStateConflictError(approval_id, approval.status)
            resolved_at = row["_database_now"]
            updates: dict[str, Any] = {
                "status": "resolved",
                "decision": decision,
                "resolved_at": _database_datetime_iso(resolved_at),
            }
            if resolution_source is not None:
                updates["resolution_source"] = resolution_source
            if resolved_by is not None:
                updates["resolved_by"] = resolved_by
            if resolution_reason is not None:
                updates["resolution_reason"] = resolution_reason
            if llm_review is not None:
                updates["llm_review"] = llm_review
            resolved = approval.model_copy(update=updates)
            session.execute(
                update(approval_requests)
                .where(approval_requests.c.approval_id == approval_id)
                .values(
                    payload_json=_approval_payload(resolved),
                    decision=decision,
                    resolution_source=resolved.resolution_source,
                    resolved_by=resolved.resolved_by,
                    resolution_reason=resolved.resolution_reason,
                    resolved_at=resolved_at,
                )
            )
        return resolved

    def create_launch_code(self, code_hash: str, expires_at: str) -> StoredLaunchCode:
        stmt = pg_insert(launch_codes).values(
            code_hash=code_hash, expires_at=expires_at, used_at=None
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[launch_codes.c.code_hash],
            set_={"expires_at": stmt.excluded.expires_at, "used_at": None},
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return StoredLaunchCode(code_hash=code_hash, expires_at=expires_at)

    def consume_launch_code(
        self, code_hash: str, used_at: str
    ) -> StoredLaunchCode | None:
        stmt = (
            update(launch_codes)
            .where(
                launch_codes.c.code_hash == code_hash, launch_codes.c.used_at.is_(None)
            )
            .values(used_at=used_at)
            .returning(
                launch_codes.c.code_hash,
                launch_codes.c.expires_at,
                launch_codes.c.used_at,
            )
        )
        with self._session_factory() as session:
            row = session.execute(stmt).mappings().one_or_none()
            session.commit()
        if row is None:
            return None
        return StoredLaunchCode(
            code_hash=row["code_hash"],
            expires_at=row["expires_at"],
            used_at=row["used_at"],
        )

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession:
        stmt = pg_insert(browser_sessions).values(
            session_hash=session_hash,
            csrf_token=csrf_token,
            expires_at=expires_at,
            revoked_at=None,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[browser_sessions.c.session_hash],
            set_={
                "csrf_token": stmt.excluded.csrf_token,
                "expires_at": stmt.excluded.expires_at,
                "revoked_at": None,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return StoredBrowserSession(
            session_hash=session_hash, csrf_token=csrf_token, expires_at=expires_at
        )

    def get_browser_session(self, session_hash: str) -> StoredBrowserSession | None:
        stmt = select(
            browser_sessions.c.session_hash,
            browser_sessions.c.csrf_token,
            browser_sessions.c.expires_at,
            browser_sessions.c.revoked_at,
        ).where(browser_sessions.c.session_hash == session_hash)
        with self._session_factory() as session:
            row = session.execute(stmt).mappings().one_or_none()
        if row is None:
            return None
        return StoredBrowserSession(
            session_hash=row["session_hash"],
            csrf_token=row["csrf_token"],
            expires_at=row["expires_at"],
            revoked_at=row["revoked_at"],
        )

    def revoke_browser_session(self, session_hash: str, revoked_at: str) -> None:
        stmt = (
            update(browser_sessions)
            .where(browser_sessions.c.session_hash == session_hash)
            .values(revoked_at=revoked_at)
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    @contextmanager
    def _read_session(self) -> Iterator[Session]:
        active = self._active_store_session.get()
        if active is not None:
            yield active
            return
        with self._session_factory() as session:
            yield session

    @contextmanager
    def _write_session(self) -> Iterator[Session]:
        active = self._active_store_session.get()
        if active is not None:
            yield active
            return
        with self._session_factory.begin() as session:
            yield session

    def _alembic_config(self) -> Config:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        config = Config()
        config.set_main_option("script_location", str(migrations_dir))
        config.set_main_option("sqlalchemy.url", self.database_url)
        return config


def _audit_filter_conditions(filters: AuditEventFilters) -> list[Any]:
    conditions: list[Any] = []
    if filters.trace_id is not None:
        conditions.append(audit_events.c.trace_id == filters.trace_id)
    if filters.case_id is not None:
        conditions.append(audit_events.c.case_id == filters.case_id)
    if filters.runtime is not None:
        conditions.append(audit_events.c.runtime == filters.runtime)
    if filters.decision is not None:
        conditions.append(audit_events.c.decision == filters.decision)
    return conditions


def _window_filter_conditions(query: AuditWindowQuery) -> list[Any]:
    conditions: list[Any] = []
    if query.evaluated_from is not None:
        conditions.append(audit_events.c.occurred_at >= query.evaluated_from)
    if query.evaluated_to is not None:
        conditions.append(audit_events.c.occurred_at < query.evaluated_to)
    if query.ingested_as_of is not None:
        conditions.append(audit_events.c.ingested_at <= query.ingested_as_of)
    if query.record_type is not None:
        conditions.append(audit_events.c.record_type == query.record_type)
    if query.trace_id is not None:
        conditions.append(audit_events.c.trace_id == query.trace_id)
    if query.case_id is not None:
        conditions.append(audit_events.c.case_id == query.case_id)
    if query.runtime is not None:
        conditions.append(audit_events.c.runtime == query.runtime)
    if query.decision is not None:
        conditions.append(audit_events.c.decision == query.decision)
    return conditions


def _bounded_limit(limit: int) -> int:
    return max(1, min(limit, MAX_REBUILD_INPUT_LIMIT))


def _safe_compare(left: str, right: str) -> bool:
    return hmac_module.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _binding_semantic_payload(record: EnforcementBindingRecord) -> tuple[Any, ...]:
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


def _enforcement_binding_values(
    record: EnforcementBindingRecord,
) -> dict[str, Any]:
    return {
        "event_id": record.event_id,
        "policy_audit_id": record.policy_audit_id,
        "approval_id": record.approval_id,
        "action_id": record.action_id,
        "action_type": record.action_type,
        "authorization_fingerprint": record.authorization_fingerprint,
        "runtime_binding_id": record.runtime_binding_id,
        "scope_digest": record.scope_digest,
        "principal_id": record.principal_id,
        "runtime": record.runtime,
        "agent_id": record.agent_id,
        "policy_revision": record.policy_revision,
        "requires_execution_lease": record.requires_execution_lease,
        "grant_id": record.grant_id,
        "created_at": record.created_at,
    }


def _enforcement_binding_from_row(row: Any) -> EnforcementBindingRecord:
    grant_id = row["grant_id"]
    return EnforcementBindingRecord(
        event_id=str(row["event_id"]),
        policy_audit_id=str(row["policy_audit_id"]),
        approval_id=str(row["approval_id"]),
        action_id=str(row["action_id"]),
        action_type=str(row["action_type"]),
        authorization_fingerprint=str(row["authorization_fingerprint"]),
        runtime_binding_id=str(row["runtime_binding_id"]),
        scope_digest=str(row["scope_digest"]),
        principal_id=str(row["principal_id"]),
        runtime=str(row["runtime"]),
        agent_id=str(row["agent_id"]),
        policy_revision=str(row["policy_revision"]),
        requires_execution_lease=bool(row["requires_execution_lease"]),
        grant_id=str(grant_id) if grant_id is not None else None,
        created_at=str(row["created_at"]),
    )


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
    grant: Any,
    binding: EnforcementBindingRecord,
) -> bool:
    fingerprint = grant["authorization_fingerprint"]
    return bool(
        str(grant["grant_id"]) == binding.grant_id
        and str(grant["scope_digest"]) == binding.scope_digest
        and fingerprint is not None
        and _safe_compare(str(fingerprint), binding.authorization_fingerprint)
        and grant["expires_at"] is not None
        and isinstance(grant["registration_digest"], str)
    )


def _credential_authorizes_binding(
    row: Any,
    command: ApprovalLeaseConsumeCommand,
    now: datetime,
) -> bool:
    try:
        credential = CredentialRecord.model_validate(row["payload_json"])
    except ValueError:
        return False
    if str(row["credential_id"]) != command.credential_id:
        return False
    if not _safe_compare(str(row["token_hash"]), command.credential_token_hash):
        return False
    if row["revoked_at"] is not None or credential.revoked_at is not None:
        return False
    expires_at = row["expires_at"]
    if expires_at is not None:
        try:
            if parse_audit_timestamp(str(expires_at)) <= now:
                return False
        except ValueError:
            return False
    return bool(
        row["principal_type"] == credential.principal_type == "component"
        and row["role"] == credential.role == "adapter"
        and "approval:wait" in credential.scopes
        and row["principal_id"] == credential.principal_id == command.principal_id
        and row["runtime"] == credential.runtime == command.runtime
        and row["agent_id"] == credential.agent_id == command.agent_id
    )


def _approval_from_locked_row(row: Any, now: datetime) -> ApprovalRequest:
    values = dict(row)
    values["_database_now"] = now
    return _approval_from_row(values)


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


def _lease_row_matches_binding(
    lease: Any,
    binding: EnforcementBindingRecord,
    consumption: Any,
) -> bool:
    return bool(
        str(lease["consumption_id"]) == str(consumption["consumption_id"])
        and str(lease["approval_id"]) == binding.approval_id
        and str(lease["grant_id"]) == binding.grant_id == str(consumption["grant_id"])
        and str(lease["action_id"])
        == binding.action_id
        == str(consumption["action_id"])
        and _safe_compare(
            str(lease["authorization_fingerprint"]),
            binding.authorization_fingerprint,
        )
        and _safe_compare(
            str(consumption["authorization_fingerprint"]),
            binding.authorization_fingerprint,
        )
        and str(lease["runtime_binding_id"]) == binding.runtime_binding_id
    )


def _task_fact_record_from_row(row: Any) -> TaskFactRecord:
    payload = row["canonical_payload"]
    return TaskFactRecord(
        task_fact=TaskFact.model_validate(payload),
        canonical_payload=dict(payload),
        request_digest=str(row["request_digest"]),
        expected_revision=int(row["expected_revision"]),
        created_at=str(row["created_at"]),
    )


def _security_state_record_from_row(row: Any) -> SecurityStateRecord:
    return SecurityStateRecord(
        scope_digest=str(row["scope_digest"]),
        state_version=int(row["state_version"]),
        canonical_payload=dict(row["canonical_payload"]),
        dirty=bool(row["dirty"]),
        dirty_domains=list(row["dirty_domains"]),
        projector_version=str(row["projector_version"]),
        updated_at=str(row["updated_at"]),
    )


def _projection_identity_record_from_row(row: Any) -> ProjectionIdentityRecord:
    return ProjectionIdentityRecord(
        scope_digest=str(row["scope_digest"]),
        source_record_type=str(row["source_record_type"]),
        source_record_id=str(row["source_record_id"]),
        source_revision=int(row["source_revision"]),
        projector_version=str(row["projector_version"]),
        delta_digest=str(row["delta_digest"]),
        delta_payload=dict(row["delta_payload"]),
        applied_state_version=int(row["applied_state_version"]),
        created_at=str(row["created_at"]),
    )


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


_APPROVAL_FORMAL_FIELDS = {
    "status",
    "decision",
    "resolution_source",
    "resolved_by",
    "resolution_reason",
    "created_at",
    "expires_at",
    "resolved_at",
}


def _approval_select() -> Any:
    return select(*approval_requests.c, func.now().label("_database_now"))


def _approval_payload(approval: ApprovalRequest) -> dict[str, Any]:
    return approval.model_dump(mode="json", exclude=_APPROVAL_FORMAL_FIELDS)


def _approval_from_row(row: Any) -> ApprovalRequest:
    created_at = _database_datetime(row["created_at"])
    expires_at = _database_datetime(row["expires_at"])
    database_now = _database_datetime(row["_database_now"])
    resolved_at = (
        _database_datetime(row["resolved_at"])
        if row["resolved_at"] is not None
        else None
    )
    if resolved_at is not None:
        status = "resolved"
        decision = row["decision"]
    elif expires_at <= database_now:
        status = "expired"
        decision = "deny"
    else:
        status = "pending"
        decision = None
    payload = dict(row["payload_json"])
    payload.update(
        {
            "status": status,
            "decision": decision,
            "resolution_source": row["resolution_source"],
            "resolved_by": row["resolved_by"],
            "resolution_reason": row["resolution_reason"],
            "created_at": _database_datetime_iso(created_at),
            "expires_at": _database_datetime_iso(expires_at),
            "resolved_at": (
                _database_datetime_iso(resolved_at) if resolved_at is not None else None
            ),
        }
    )
    return ApprovalRequest.model_validate(payload)


def _database_datetime(value: str | datetime) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _database_datetime_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url
