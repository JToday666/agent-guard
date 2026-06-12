"""add auth state tables and audit query indexes

Revision ID: 0002_auth_state
Revises: 0001_core_storage
Create Date: 2026-06-11
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002_auth_state"
down_revision = "0001_core_storage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "launch_codes",
        sa.Column("code_hash", sa.Text(), primary_key=True),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("used_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_launch_codes_expires_at", "launch_codes", ["expires_at"])
    op.create_index("ix_launch_codes_used_at", "launch_codes", ["used_at"])

    op.create_table(
        "browser_sessions",
        sa.Column("session_hash", sa.Text(), primary_key=True),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
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
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("used_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_approval_nonces_approval_id", "approval_nonces", ["approval_id"])
    op.create_index("ix_approval_nonces_session_hash", "approval_nonces", ["session_hash"])
    op.create_index("ix_approval_nonces_expires_at", "approval_nonces", ["expires_at"])
    op.create_index("ix_approval_nonces_used_at", "approval_nonces", ["used_at"])

    op.execute("CREATE INDEX ix_audit_events_trace_id ON audit_events ((payload_json ->> 'trace_id'))")
    op.execute("CREATE INDEX ix_audit_events_case_id ON audit_events ((payload_json ->> 'case_id'))")
    op.execute("CREATE INDEX ix_audit_events_runtime ON audit_events ((payload_json ->> 'runtime'))")
    op.execute("CREATE INDEX ix_audit_events_decision ON audit_events ((payload_json ->> 'decision'))")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_events_decision")
    op.execute("DROP INDEX IF EXISTS ix_audit_events_runtime")
    op.execute("DROP INDEX IF EXISTS ix_audit_events_case_id")
    op.execute("DROP INDEX IF EXISTS ix_audit_events_trace_id")

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
