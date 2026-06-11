"""PostgreSQL store for the formal Core.

The project default is PostgreSQL. Tests inject MemoryCoreStore explicitly, so
this backend opens connections lazily when API calls actually need storage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_core.models import ApprovalRequest, AuditEvent, utc_now_iso


@dataclass(slots=True)
class PostgresCoreStore:
    database_url: str
    _initialized: bool = False

    def add_audit_event(self, event: AuditEvent) -> None:
        self._ensure_schema()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (audit_id, payload_json, created_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (audit_id) DO UPDATE SET payload_json = EXCLUDED.payload_json
                """,
                (event.audit_id, self._jsonb(event.model_dump(mode="json")), utc_now_iso()),
            )

    def list_audit_events(self) -> list[AuditEvent]:
        self._ensure_schema()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM audit_events ORDER BY created_at DESC, audit_id DESC LIMIT 500"
            ).fetchall()
        return [AuditEvent.model_validate(_json_payload(row[0])) for row in rows]

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        self._ensure_schema()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (approval_id, payload_json, status, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (approval_id) DO UPDATE
                SET payload_json = EXCLUDED.payload_json, status = EXCLUDED.status
                """,
                (
                    approval.approval_id,
                    self._jsonb(approval.model_dump(mode="json")),
                    approval.status,
                    approval.created_at,
                ),
            )
        return approval

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        self._ensure_schema()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM approvals WHERE status = 'pending' ORDER BY created_at ASC"
            ).fetchall()
        return [ApprovalRequest.model_validate(_json_payload(row[0])) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        self._ensure_schema()
        with self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM approvals WHERE approval_id = %s", (approval_id,)).fetchone()
        if row is None:
            return None
        return ApprovalRequest.model_validate(_json_payload(row[0]))

    def resolve_approval(self, approval_id: str, decision: str) -> ApprovalRequest:
        approval = self.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        approval.status = "resolved"
        approval.decision = decision  # type: ignore[assignment]
        approval.resolved_at = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE approvals SET payload_json = %s, status = %s WHERE approval_id = %s",
                (self._jsonb(approval.model_dump(mode="json")), approval.status, approval_id),
            )
        return approval

    def _connect(self) -> Any:
        import psycopg

        return psycopg.connect(self.database_url)

    def _jsonb(self, payload: dict[str, Any]) -> Any:
        from psycopg.types.json import Jsonb

        return Jsonb(payload)

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id TEXT PRIMARY KEY,
                    payload_json JSONB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    payload_json JSONB NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
        self._initialized = True


def _json_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        import json

        return json.loads(value)
    return dict(value)
