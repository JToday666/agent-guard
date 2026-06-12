"""SQLAlchemy table definitions for formal Core storage."""

from __future__ import annotations

from sqlalchemy import Column, Index, MetaData, Table, Text
from sqlalchemy.dialects.postgresql import JSONB


metadata = MetaData()


audit_events = Table(
    "audit_events",
    metadata,
    Column("audit_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_audit_events_created_at", "created_at"),
)


approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_approvals_status_created_at", "status", "created_at"),
)


launch_codes = Table(
    "launch_codes",
    metadata,
    Column("code_hash", Text, primary_key=True),
    Column("expires_at", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("used_at", Text, nullable=True),
    Index("ix_launch_codes_expires_at", "expires_at"),
    Index("ix_launch_codes_used_at", "used_at"),
)


browser_sessions = Table(
    "browser_sessions",
    metadata,
    Column("session_hash", Text, primary_key=True),
    Column("csrf_token", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("revoked_at", Text, nullable=True),
    Index("ix_browser_sessions_expires_at", "expires_at"),
    Index("ix_browser_sessions_revoked_at", "revoked_at"),
)


approval_nonces = Table(
    "approval_nonces",
    metadata,
    Column("nonce_hash", Text, primary_key=True),
    Column("approval_id", Text, nullable=False),
    Column("session_hash", Text, nullable=False),
    Column("tool_call_id", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("used_at", Text, nullable=True),
    Index("ix_approval_nonces_approval_id", "approval_id"),
    Index("ix_approval_nonces_session_hash", "session_hash"),
    Index("ix_approval_nonces_expires_at", "expires_at"),
    Index("ix_approval_nonces_used_at", "used_at"),
)
