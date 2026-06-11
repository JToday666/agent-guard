"""PostgreSQL store for the formal Core using SQLAlchemy and Alembic."""

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

from agentguard_core.models import ApprovalRequest, AuditEvent, utc_now_iso
from agentguard_core.storage.sqlalchemy_models import approvals, audit_events


@dataclass(slots=True)
class PostgresCoreStore:
    database_url: str
    _initialized: bool = False
    _engine: Engine = field(init=False, repr=False)
    _session_factory: sessionmaker[Session] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.database_url = _normalize_database_url(self.database_url)
        self._engine = create_engine(self.database_url, pool_pre_ping=True)
        self._session_factory = sessionmaker(bind=self._engine)

    def initialize(self) -> None:
        config = Config()
        config.set_main_option("script_location", str(_migrations_path()))
        config.set_main_option("sqlalchemy.url", self.database_url)
        command.upgrade(config, "head")
        self._initialized = True

    def health_check(self) -> bool:
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def add_audit_event(self, event: AuditEvent) -> None:
        self._ensure_schema()
        payload = event.model_dump(mode="json")
        stmt = pg_insert(audit_events).values(
            audit_id=event.audit_id,
            payload_json=payload,
            created_at=event.timestamp,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[audit_events.c.audit_id],
            set_={"payload_json": stmt.excluded.payload_json},
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    def list_audit_events(self) -> list[AuditEvent]:
        self._ensure_schema()
        stmt = (
            select(audit_events.c.payload_json)
            .order_by(desc(audit_events.c.created_at), desc(audit_events.c.audit_id))
            .limit(500)
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [AuditEvent.model_validate(_json_payload(row)) for row in rows]

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        self._ensure_schema()
        payload = approval.model_dump(mode="json")
        stmt = pg_insert(approvals).values(
            approval_id=approval.approval_id,
            payload_json=payload,
            status=approval.status,
            created_at=approval.created_at,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[approvals.c.approval_id],
            set_={"payload_json": stmt.excluded.payload_json, "status": stmt.excluded.status},
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()
        return approval

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        self._ensure_schema()
        stmt = (
            select(approvals.c.payload_json)
            .where(approvals.c.status == "pending")
            .order_by(approvals.c.created_at.asc())
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).scalars().all()
        return [ApprovalRequest.model_validate(_json_payload(row)) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        self._ensure_schema()
        stmt = select(approvals.c.payload_json).where(approvals.c.approval_id == approval_id)
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return ApprovalRequest.model_validate(_json_payload(row))

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

    def _update_approval(self, approval: ApprovalRequest) -> None:
        stmt = (
            update(approvals)
            .where(approvals.c.approval_id == approval.approval_id)
            .values(payload_json=approval.model_dump(mode="json"), status=approval.status)
        )
        with self._session_factory() as session:
            session.execute(stmt)
            session.commit()

    def _ensure_schema(self) -> None:
        if not self._initialized:
            self.initialize()


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url


def _migrations_path() -> Path:
    return Path(__file__).resolve().parents[1] / "migrations"


def _json_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        import json

        return json.loads(value)
    return dict(value)
