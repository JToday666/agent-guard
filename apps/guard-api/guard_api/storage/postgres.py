"""PostgreSQL-backed Guard API / Control Plane store."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, desc, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

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
from guard_api.storage.sqlalchemy_models import (
    approval_nonces,
    approval_requests,
    audit_events,
    browser_sessions,
    launch_codes,
    policy_snapshot_history,
    policy_snapshots,
)


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

    def add_audit_event(self, event: AuditEvent) -> None:
        payload = event.model_dump(mode="json")
        stmt = pg_insert(audit_events).values(
            audit_id=event.audit_id,
            payload_json=payload,
            created_at=event.timestamp,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[audit_events.c.audit_id],
            set_={"payload_json": stmt.excluded.payload_json, "created_at": stmt.excluded.created_at},
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    def list_audit_events(self, filters: AuditEventFilters | None = None) -> list[AuditEvent]:
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

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        filters = filters or EvalMetricFilters()
        where_sql, params = _metric_where_clause(filters)
        stmt = text(
            f"""
            SELECT
                COUNT(*) AS event_count,
                COUNT(*) FILTER (WHERE payload_json ->> 'decision' = 'allow') AS allow_count,
                COUNT(*) FILTER (WHERE payload_json ->> 'decision' = 'deny') AS deny_count,
                COUNT(*) FILTER (WHERE payload_json ->> 'decision' = 'ask') AS ask_count,
                COUNT(*) FILTER (
                    WHERE payload_json ->> 'blocked' = 'true'
                       OR payload_json ->> 'decision' IN ('deny', 'ask')
                ) AS blocked_count,
                COUNT(*) FILTER (WHERE payload_json ->> 'is_malicious' = 'false') AS benign_count,
                COUNT(*) FILTER (WHERE payload_json ->> 'is_malicious' = 'true') AS malicious_count,
                COUNT(*) FILTER (
                    WHERE payload_json ->> 'is_malicious' = 'false'
                      AND (payload_json ->> 'blocked' = 'true' OR payload_json ->> 'decision' IN ('deny', 'ask'))
                ) AS false_positive_count,
                COUNT(*) FILTER (
                    WHERE payload_json ->> 'is_malicious' = 'true'
                      AND payload_json ->> 'decision' = 'allow'
                      AND COALESCE(payload_json ->> 'blocked', 'false') = 'false'
                ) AS false_negative_count,
                AVG(NULLIF(payload_json ->> 'latency_ms', '')::numeric) AS average_latency_ms
            FROM audit_events
            {where_sql}
            """
        )
        with self._session_factory() as session:
            row = session.execute(stmt, params).mappings().one()
        event_count = int(row["event_count"])
        blocked_count = int(row["blocked_count"])
        benign_count = int(row["benign_count"])
        malicious_count = int(row["malicious_count"])
        false_positive_count = int(row["false_positive_count"])
        false_negative_count = int(row["false_negative_count"])
        average_latency = row["average_latency_ms"]
        return {
            "event_count": event_count,
            "allow_count": int(row["allow_count"]),
            "deny_count": int(row["deny_count"]),
            "ask_count": int(row["ask_count"]),
            "blocked_count": blocked_count,
            "block_rate": (blocked_count / event_count) if event_count else None,
            "fpr": (false_positive_count / benign_count) if benign_count else None,
            "fnr": (false_negative_count / malicious_count) if malicious_count else None,
            "average_latency_ms": float(average_latency) if average_latency is not None else None,
        }

    def get_policy_snapshot(self) -> PolicyBundle | None:
        record = self.get_policy_snapshot_record()
        if record is None:
            return None
        return record.policy_bundle

    def get_policy_snapshot_record(self) -> PolicySnapshotRecord | None:
        stmt = (
            select(
                policy_snapshots.c.revision,
                policy_snapshots.c.payload_json,
                policy_snapshots.c.updated_at,
                policy_snapshots.c.updated_by,
            )
            .where(policy_snapshots.c.policy_id == "current")
        )
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
            current_revision = session.execute(
                select(policy_snapshots.c.revision).where(policy_snapshots.c.policy_id == "current")
            ).scalar_one_or_none()
            revision = int(current_revision) + 1 if current_revision is not None else 1
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
            session.commit()
        return PolicySnapshotRecord(
            revision=revision,
            policy_bundle=policy_bundle,
            updated_at=updated_at,
            updated_by=updated_by,
        )

    def list_policy_snapshot_history(self, limit: int = 100) -> list[PolicySnapshotRecord]:
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
            set_={"payload_json": stmt.excluded.payload_json, "status": stmt.excluded.status},
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
        stmt = select(approval_requests.c.payload_json).order_by(approval_requests.c.created_at.asc())
        if trace_id is not None:
            stmt = stmt.where(approval_requests.c.payload_json.op("->>")("trace_id") == trace_id)
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [ApprovalRequest.model_validate(row) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        stmt = select(approval_requests.c.payload_json).where(approval_requests.c.approval_id == approval_id)
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return ApprovalRequest.model_validate(row)

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        approval = self.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        approval.status = "resolved"
        approval.decision = decision  # type: ignore[assignment]
        approval.resolved_at = utc_now_iso()
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
        stmt = pg_insert(launch_codes).values(code_hash=code_hash, expires_at=expires_at, used_at=None)
        stmt = stmt.on_conflict_do_update(
            index_elements=[launch_codes.c.code_hash],
            set_={"expires_at": stmt.excluded.expires_at, "used_at": None},
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return StoredLaunchCode(code_hash=code_hash, expires_at=expires_at)

    def consume_launch_code(self, code_hash: str, used_at: str) -> StoredLaunchCode | None:
        stmt = (
            update(launch_codes)
            .where(launch_codes.c.code_hash == code_hash, launch_codes.c.used_at.is_(None))
            .values(used_at=used_at)
            .returning(launch_codes.c.code_hash, launch_codes.c.expires_at, launch_codes.c.used_at)
        )
        with self._session_factory() as session:
            row = session.execute(stmt).mappings().one_or_none()
            session.commit()
        if row is None:
            return None
        return StoredLaunchCode(code_hash=row["code_hash"], expires_at=row["expires_at"], used_at=row["used_at"])

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
        return StoredBrowserSession(session_hash=session_hash, csrf_token=csrf_token, expires_at=expires_at)

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
        stmt = update(browser_sessions).where(browser_sessions.c.session_hash == session_hash).values(revoked_at=revoked_at)
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    def create_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        tool_call_id: str,
        expires_at: str,
    ) -> StoredApprovalNonce:
        stmt = pg_insert(approval_nonces).values(
            nonce_hash=nonce_hash,
            approval_id=approval_id,
            session_hash=session_hash,
            tool_call_id=tool_call_id,
            expires_at=expires_at,
            used_at=None,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[approval_nonces.c.nonce_hash],
            set_={
                "approval_id": stmt.excluded.approval_id,
                "session_hash": stmt.excluded.session_hash,
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
            tool_call_id=tool_call_id,
            expires_at=expires_at,
        )

    def consume_approval_nonce(
        self,
        nonce_hash: str,
        *,
        approval_id: str,
        session_hash: str,
        tool_call_id: str,
        used_at: str,
    ) -> StoredApprovalNonce | None:
        stmt = (
            update(approval_nonces)
            .where(
                approval_nonces.c.nonce_hash == nonce_hash,
                approval_nonces.c.used_at.is_(None),
                approval_nonces.c.approval_id == approval_id,
                approval_nonces.c.session_hash == session_hash,
                approval_nonces.c.tool_call_id == tool_call_id,
            )
            .values(used_at=used_at)
            .returning(
                approval_nonces.c.nonce_hash,
                approval_nonces.c.approval_id,
                approval_nonces.c.session_hash,
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
            tool_call_id=row["tool_call_id"],
            expires_at=row["expires_at"],
            used_at=row["used_at"],
        )

    def _update_approval(self, approval: ApprovalRequest) -> None:
        stmt = (
            update(approval_requests)
            .where(approval_requests.c.approval_id == approval.approval_id)
            .values(payload_json=approval.model_dump(mode="json"), status=approval.status)
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


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url
