"""PostgreSQL-backed Guard API / Control Plane store."""

from __future__ import annotations

import hashlib
import itertools
from contextlib import contextmanager
from dataclasses import dataclass, field
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
    AuditEventFilters,
    AuditIdConflictError,
    AuditIntegrityStatus,
    AuditWindowQuery,
    EvalMetricFilters,
    EvalMetrics,
    PolicySnapshotRecord,
    StoredApprovalNonce,
    StoredBrowserSession,
    StoredLaunchCode,
    within_evaluated_range,
)
from guard_api.storage.integrity import (
    attach_audit_integrity,
    read_audit_integrity,
    verify_audit_chain,
)
from guard_api.services.metric_rules import aggregate_policy_metrics
from guard_api.storage.sqlalchemy_models import (
    action_critic_reviews,
    adapter_statuses,
    approval_nonces,
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


@dataclass(slots=True)
class PostgresControlPlaneStore:
    database_url: str
    _engine: Engine = field(init=False, repr=False)
    _session_factory: sessionmaker[Session] = field(init=False, repr=False)

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
        with self._session_factory() as session:
            with session.begin():
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
                        created_at=event.timestamp,
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
                    updated_at=event.timestamp,
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

    def list_audit_events(
        self, filters: AuditEventFilters | None = None
    ) -> list[AuditEvent]:
        filters = filters or AuditEventFilters()
        stmt = (
            select(audit_events.c.payload_json)
            .where(*_audit_filter_conditions(filters))
            .order_by(desc(audit_events.c.created_at), desc(audit_events.c.audit_id))
            .limit(_bounded_limit(filters.limit))
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [AuditEvent.model_validate(row) for row in rows]

    def read_audit_events_bounded(self, query: AuditWindowQuery) -> list[AuditEvent]:
        # 上界读 audit_integrity_heads 链头；序列范围命中现有
        # ix_audit_events_chain_sequence；JSONB 过滤为残余谓词（契约 §7.3）。
        conditions: list[Any] = [audit_events.c.chain_id == _AUDIT_CHAIN_ID]
        if query.after_sequence is not None:
            conditions.append(audit_events.c.sequence < query.after_sequence)
        conditions.extend(_window_filter_conditions(query))
        time_range_present = (
            query.evaluated_from is not None or query.evaluated_to is not None
        )
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
                )
                # 时间 cohort 经由共享解析函数在 Python 层过滤以保证与
                # Memory 端口径一致；无时间条件时 SQL LIMIT 直接限流。
                if not time_range_present:
                    stmt = stmt.limit(query.limit)
                rows = session.execute(stmt).scalars().all()
        events = (AuditEvent.model_validate(row) for row in rows)
        if time_range_present:
            events = (
                event
                for event in events
                if within_evaluated_range(
                    event.timestamp, query.evaluated_from, query.evaluated_to
                )
            )
        return list(itertools.islice(events, query.limit))

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None:
        links = audit_events.c.payload_json.op("->")("links")
        record_type = audit_events.c.payload_json.op("->>")("record_type")
        stmt = (
            select(audit_events.c.payload_json)
            .where(
                links.op("->>")("event_id") == event_id,
                links.op("?")("decision_id"),
                func.coalesce(record_type, "policy_evaluation") == "policy_evaluation",
            )
            .order_by(audit_events.c.sequence.asc(), audit_events.c.audit_id.asc())
            .limit(1)
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalars().first()
        return AuditEvent.model_validate(row) if row is not None else None

    @contextmanager
    def policy_evaluation_guard(self, event_id: str) -> Iterator[None]:
        """Hold a crash-safe per-event PostgreSQL advisory lock.

        Approval and other evaluation side effects happen before the unique
        policy audit insert. Holding a session advisory lock across the service
        operation prevents concurrent requests for one event from creating
        orphan approvals while retaining the database unique index as the final
        integrity guard.
        """

        lock_id = int.from_bytes(
            hashlib.sha256(event_id.encode("utf-8")).digest()[:8],
            byteorder="big",
            signed=True,
        )
        with self._engine.connect() as connection:
            connection.execute(
                text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": lock_id}
            )
            try:
                yield
            finally:
                connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": lock_id},
                )

    def verify_audit_integrity(self) -> AuditIntegrityStatus:
        stmt = (
            select(audit_events.c.payload_json)
            .where(audit_events.c.chain_id == _AUDIT_CHAIN_ID)
            .order_by(audit_events.c.sequence.asc(), audit_events.c.audit_id.asc())
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return verify_audit_chain(AuditEvent.model_validate(row) for row in rows)

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        # 保留 where 下推取事件，聚合口径交由跨存储共享聚合器（§19）。
        filters = filters or EvalMetricFilters()
        where_sql, params = _metric_where_clause(filters)
        stmt = text(f"""
            SELECT payload_json
            FROM audit_events
            {where_sql}
            ORDER BY sequence ASC, audit_id ASC
            """)
        with self._session_factory() as session:
            rows = session.execute(stmt, params).scalars().all()
        events = [AuditEvent.model_validate(row) for row in rows]
        return aggregate_policy_metrics(events)

    def add_provenance_node(self, node: ProvenanceNode) -> ProvenanceNode:
        payload = node.model_dump(mode="json")
        stmt = pg_insert(provenance_nodes).values(
            node_id=node.node_id,
            trace_id=node.trace_id,
            kind=node.kind,
            ref_id=node.ref_id,
            payload_json=payload,
            created_at=node.timestamp,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[provenance_nodes.c.node_id],
            set_={
                "trace_id": stmt.excluded.trace_id,
                "kind": stmt.excluded.kind,
                "ref_id": stmt.excluded.ref_id,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return node

    def add_provenance_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        payload = edge.model_dump(mode="json")
        stmt = pg_insert(provenance_edges).values(
            edge_id=edge.edge_id,
            trace_id=edge.trace_id,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            relation=edge.relation,
            payload_json=payload,
            created_at=edge.timestamp,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[provenance_edges.c.edge_id],
            set_={
                "trace_id": stmt.excluded.trace_id,
                "source_node_id": stmt.excluded.source_node_id,
                "target_node_id": stmt.excluded.target_node_id,
                "relation": stmt.excluded.relation,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return edge

    def list_provenance(
        self, trace_id: str
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
        with self._session_factory() as session:
            node_rows = session.execute(node_stmt).scalars().all()
            edge_rows = session.execute(edge_stmt).scalars().all()
        return (
            [ProvenanceNode.model_validate(row) for row in node_rows],
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
            severity=finding.severity,
            payload_json=payload,
            created_at=event.timestamp,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[config_audit_findings.c.finding_id],
            set_={"payload_json": stmt.excluded.payload_json},
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
            stmt = stmt.where(
                text(
                    "(config_audit_findings.payload_json #>> '{event,metadata,trace_id}') = :trace_id "
                    "OR (config_audit_findings.payload_json #>> '{event,event_id}') = :trace_id"
                )
            ).params(trace_id=trace_id)
        stmt = stmt.limit(_bounded_limit(limit))
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        records = [_config_finding_record(row) for row in rows]
        return records[: _bounded_limit(limit)]

    def save_evaluation_run(
        self, run: EvaluationRun | dict[str, Any]
    ) -> dict[str, Any]:
        payload = EvaluationRun.model_validate(run).model_dump(mode="json")
        stmt = pg_insert(evaluation_runs).values(
            run_id=payload["run_id"],
            run_at=payload["run_at"],
            payload_json=payload,
            created_at=utc_now_iso(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[evaluation_runs.c.run_id],
            set_={
                "run_at": stmt.excluded.run_at,
                "payload_json": stmt.excluded.payload_json,
                "created_at": stmt.excluded.created_at,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return payload

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
            stmt = stmt.where(
                evaluation_runs.c.payload_json.op("->>")("dataset_id") == dataset_id
            )
        if dataset_version is not None:
            stmt = stmt.where(
                evaluation_runs.c.payload_json.op("->>")("dataset_version")
                == dataset_version
            )
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
        stmt = pg_insert(adapter_statuses).values(
            adapter_id=adapter_id,
            payload_json=payload,
            updated_at=payload.get("last_verified_at") or utc_now_iso(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[adapter_statuses.c.adapter_id],
            set_={
                "payload_json": stmt.excluded.payload_json,
                "updated_at": stmt.excluded.updated_at,
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
            created_at=review.created_at,
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
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
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
        with self._session_factory() as session:
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
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return change

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None:
        stmt = select(memory_guard_changes.c.payload_json).where(
            memory_guard_changes.c.change_id == change_id
        )
        with self._session_factory() as session:
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
        with self._session_factory() as session:
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
                revision = (
                    int(current_revision) + 1 if current_revision is not None else 1
                )
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
        payload = approval.model_dump(mode="json")
        stmt = pg_insert(approval_requests).values(
            approval_id=approval.approval_id,
            payload_json=payload,
            status=approval.status,
            created_at=approval.created_at,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[approval_requests.c.approval_id],
            set_={
                "payload_json": stmt.excluded.payload_json,
                "status": stmt.excluded.status,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return approval

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        stmt = (
            select(approval_requests.c.payload_json)
            .where(approval_requests.c.status == "pending")
            .order_by(approval_requests.c.created_at.asc())
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [ApprovalRequest.model_validate(row) for row in rows]

    def list_approvals(self, trace_id: str | None = None) -> list[ApprovalRequest]:
        stmt = select(approval_requests.c.payload_json).order_by(
            approval_requests.c.created_at.asc()
        )
        if trace_id is not None:
            stmt = stmt.where(
                approval_requests.c.payload_json.op("->>")("trace_id") == trace_id
            )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [ApprovalRequest.model_validate(row) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        stmt = select(approval_requests.c.payload_json).where(
            approval_requests.c.approval_id == approval_id
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return ApprovalRequest.model_validate(row)

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
        approval = self.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
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
        self._update_approval(approval)
        return approval

    def expire_approval(self, approval_id: str) -> ApprovalRequest:
        approval = self.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        approval.status = "expired"
        approval.decision = "deny"
        self._update_approval(approval)
        return approval

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
        stmt = pg_insert(approval_nonces).values(
            nonce_hash=nonce_hash,
            approval_id=approval_id,
            session_hash=session_hash,
            subject_id=approval_subject_id,
            tool_call_id=tool_call_id or approval_subject_id,
            expires_at=expires_at,
            used_at=None,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[approval_nonces.c.nonce_hash],
            set_={
                "approval_id": stmt.excluded.approval_id,
                "session_hash": stmt.excluded.session_hash,
                "subject_id": stmt.excluded.subject_id,
                "tool_call_id": stmt.excluded.tool_call_id,
                "expires_at": stmt.excluded.expires_at,
                "used_at": None,
            },
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return StoredApprovalNonce(
            nonce_hash=nonce_hash,
            approval_id=approval_id,
            session_hash=session_hash,
            subject_id=approval_subject_id,
            tool_call_id=tool_call_id or approval_subject_id,
            expires_at=expires_at,
        )

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
        stmt = (
            update(approval_nonces)
            .where(
                approval_nonces.c.nonce_hash == nonce_hash,
                approval_nonces.c.used_at.is_(None),
                approval_nonces.c.approval_id == approval_id,
                approval_nonces.c.session_hash == session_hash,
                approval_nonces.c.subject_id == approval_subject_id,
            )
            .values(used_at=used_at)
            .returning(
                approval_nonces.c.nonce_hash,
                approval_nonces.c.approval_id,
                approval_nonces.c.session_hash,
                approval_nonces.c.subject_id,
                approval_nonces.c.tool_call_id,
                approval_nonces.c.expires_at,
                approval_nonces.c.used_at,
            )
        )
        with self._session_factory() as session:
            row = session.execute(stmt).mappings().one_or_none()
            session.commit()
        if row is None:
            return None
        return StoredApprovalNonce(
            nonce_hash=row["nonce_hash"],
            approval_id=row["approval_id"],
            session_hash=row["session_hash"],
            subject_id=row["subject_id"],
            tool_call_id=row["tool_call_id"],
            expires_at=row["expires_at"],
            used_at=row["used_at"],
        )

    def _update_approval(self, approval: ApprovalRequest) -> None:
        stmt = (
            update(approval_requests)
            .where(approval_requests.c.approval_id == approval.approval_id)
            .values(
                payload_json=approval.model_dump(mode="json"), status=approval.status
            )
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    def _alembic_config(self) -> Config:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        config = Config()
        config.set_main_option("script_location", str(migrations_dir))
        config.set_main_option("sqlalchemy.url", self.database_url)
        return config


def _audit_filter_conditions(filters: AuditEventFilters) -> list[Any]:
    conditions: list[Any] = []
    if filters.trace_id is not None:
        conditions.append(_json_text("trace_id") == filters.trace_id)
    if filters.case_id is not None:
        conditions.append(_json_text("case_id") == filters.case_id)
    if filters.runtime is not None:
        conditions.append(_json_text("runtime") == filters.runtime)
    if filters.decision is not None:
        conditions.append(_json_text("decision") == filters.decision)
    return conditions


def _window_filter_conditions(query: AuditWindowQuery) -> list[Any]:
    conditions: list[Any] = []
    if query.trace_id is not None:
        conditions.append(_json_text("trace_id") == query.trace_id)
    if query.case_id is not None:
        conditions.append(_json_text("case_id") == query.case_id)
    if query.runtime is not None:
        conditions.append(_json_text("runtime") == query.runtime)
    if query.decision is not None:
        conditions.append(_json_text("decision") == query.decision)
    return conditions


def _metric_where_clause(filters: EvalMetricFilters) -> tuple[str, dict[str, str]]:
    clauses: list[str] = []
    params: dict[str, str] = {}
    for key in ("trace_id", "case_id", "runtime", "decision"):
        value = getattr(filters, key)
        if value is not None:
            clauses.append(f"payload_json ->> '{key}' = :{key}")
            params[key] = value
    if not clauses:
        return "", params
    return "WHERE " + " AND ".join(clauses), params


def _json_text(key: str) -> Any:
    return audit_events.c.payload_json.op("->>")(key)


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


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url
