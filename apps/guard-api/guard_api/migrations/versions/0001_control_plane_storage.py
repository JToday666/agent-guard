"""create fresh control plane storage

Revision ID: 0001_control_plane
Revises:
Create Date: 2026-06-12
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("audit_id", sa.Text(), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])

    op.create_table(
        "approval_requests",
        sa.Column("approval_id", sa.Text(), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_approval_requests_status_created_at",
        "approval_requests",
        ["status", "created_at"],
    )

    op.create_table(
        "launch_codes",
        sa.Column("code_hash", sa.Text(), primary_key=True),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("used_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_launch_codes_expires_at", "launch_codes", ["expires_at"])
    op.create_index("ix_launch_codes_used_at", "launch_codes", ["used_at"])

    op.create_table(
        "browser_sessions",
        sa.Column("session_hash", sa.Text(), primary_key=True),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_browser_sessions_expires_at", "browser_sessions", ["expires_at"])
    op.create_index("ix_browser_sessions_revoked_at", "browser_sessions", ["revoked_at"])

    op.create_table(
        "approval_nonces",
        sa.Column("nonce_hash", sa.Text(), primary_key=True),
        sa.Column("approval_id", sa.Text(), nullable=False),
        sa.Column("session_hash", sa.Text(), nullable=False),
        sa.Column("tool_call_id", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("used_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_approval_nonces_approval_id", "approval_nonces", ["approval_id"])
    op.create_index("ix_approval_nonces_session_hash", "approval_nonces", ["session_hash"])
    op.create_index("ix_approval_nonces_expires_at", "approval_nonces", ["expires_at"])
    op.create_index("ix_approval_nonces_used_at", "approval_nonces", ["used_at"])


def downgrade() -> None:
    op.drop_index("ix_approval_nonces_used_at", table_name="approval_nonces")
    op.drop_index("ix_approval_nonces_expires_at", table_name="approval_nonces")
    op.drop_index("ix_approval_nonces_session_hash", table_name="approval_nonces")
    op.drop_index("ix_approval_nonces_approval_id", table_name="approval_nonces")
    op.drop_table("approval_nonces")

    op.drop_index("ix_browser_sessions_revoked_at", table_name="browser_sessions")
    op.drop_index("ix_browser_sessions_expires_at", table_name="browser_sessions")
    op.drop_table("browser_sessions")

    op.drop_index("ix_launch_codes_used_at", table_name="launch_codes")
    op.drop_index("ix_launch_codes_expires_at", table_name="launch_codes")
    op.drop_table("launch_codes")

    op.drop_index("ix_approval_requests_status_created_at", table_name="approval_requests")
    op.drop_table("approval_requests")

    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_table("audit_events")
