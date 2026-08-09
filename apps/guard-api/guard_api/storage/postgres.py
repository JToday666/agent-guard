"""PostgreSQL-backed Guard API / Control Plane store."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, desc, func, select, text, update
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
    ApprovalStateConflictError,
    AuditEventFilters,
    AuditIdConflictError,
    AuditIntegrityStatus,
    AuditWindowQuery,
    EvaluationRunConflictError,
    PolicyRevisionConflictError,
    PolicySnapshotRecord,
    ProvenanceEndpointMissingError,
    StoredBrowserSession,
    StoredLaunchCode,
    classify_audit_record_type,
    merge_provenance_edge,
    merge_provenance_node,
    parse_audit_timestamp,
)
from guard_api.storage.integrity import (
    attach_audit_integrity,
    read_audit_integrity,
    verify_audit_chain,
)
from guard_api.storage.sqlalchemy_models import (
    action_critic_reviews,
    adapter_statuses,
    approval_requests,
    audit_integrity_heads,
    audit_events,
    browser_sessions,
    config_audit_findings,
    credentials,
    evaluation_runs,
    launch_codes,
    memory_guard_changes,
    policy_snapshot_history,
    policy_snapshots,
    provenance_edges,
    provenance_nodes,
)

_POLICY_SNAPSHOT_ADVISORY_LOCK_ID = 427001030001
_AUDIT_INTEGRITY_ADVISORY_LOCK_ID = 427001030002
_AUDIT_CHAIN_ID = "default"


def _lock_provenance_identity(session: Session, kind: str, stable_id: str) -> None:
    lock_id = int.from_bytes(
        hashlib.sha256(f"provenance:{kind}:{stable_id}".encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
    )


@dataclass(slots=True)
class PostgresControlPlaneStore:
    database_url: str
    _engine: Engine = field(init=False, repr=False)
    _session_factory: sessionmaker[Session] = field(init=False, repr=False)
    _active_evaluation_session: ContextVar[Session | None] = field(
        default_factory=lambda: ContextVar(
            "agentguard_active_evaluation_session", default=None
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
                from guard_api.storage.integrity import _canonical_json_bytes

                stored_content = _canonical_json_bytes(
                    {k: v for k, v in stored_payload.items() if k != "integrity"}
                )
                incoming_content = _canonical_json_bytes(
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
        if self._active_evaluation_session.get() is not None:
            raise RuntimeError("nested evaluation transactions are not supported")
        with self._session_factory.begin() as session:
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id}
            )
            token = self._active_evaluation_session.set(session)
            try:
                yield
            finally:
                self._active_evaluation_session.reset(token)

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
        payload = change.model_dump(mode="json")
        stmt = pg_insert(memory_guard_changes).values(
            change_id=change.change_id,
            trace_id=change.trace_id,
            namespace=change.namespace,
            key=change.key,
            status=change.status,
            payload_json=payload,
            created_at=change.created_at,
            updated_at=change.updated_at,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[memory_guard_changes.c.change_id],
            set_={
                "status": stmt.excluded.status,
                "payload_json": stmt.excluded.payload_json,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        with self._write_session() as session:
            session.execute(stmt)
        return change

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
    ) -> MemoryGuardChange:
        current = self.get_memory_change(change_id)
        if current is None:
            raise KeyError(change_id)
        updated = current.model_copy(
            update={"status": status, "updated_at": utc_now_iso()}
        )
        stmt = (
            update(memory_guard_changes)
            .where(memory_guard_changes.c.change_id == change_id)
            .values(
                status=updated.status,
                payload_json=updated.model_dump(mode="json"),
                updated_at=updated.updated_at,
            )
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return updated

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
        return PolicySnapshotRecord(
            revision=int(row["revision"]),
            policy_bundle=PolicyBundle.model_validate(row["payload_json"]),
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
        return [
            PolicySnapshotRecord(
                revision=int(row["revision"]),
                policy_bundle=PolicyBundle.model_validate(row["payload_json"]),
                updated_at=str(row["updated_at"]),
                updated_by=str(row["updated_by"]),
            )
            for row in rows
        ]

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
        active = self._active_evaluation_session.get()
        if active is not None:
            yield active
            return
        with self._session_factory() as session:
            yield session

    @contextmanager
    def _write_session(self) -> Iterator[Session]:
        active = self._active_evaluation_session.get()
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
    return max(1, min(limit, 1000))


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
