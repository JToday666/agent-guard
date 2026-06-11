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
