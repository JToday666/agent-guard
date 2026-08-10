"""make approval state atomic and remove per-row browser nonces

Revision ID: 0008_approval_state
Revises: 0007_policy_eval_unique_event
Create Date: 2026-08-09
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0008_approval_state"
down_revision = "0007_policy_eval_unique_event"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approval_requests", sa.Column("decision", sa.Text(), nullable=True))
    op.add_column(
        "approval_requests", sa.Column("resolution_source", sa.Text(), nullable=True)
    )
    op.add_column(
        "approval_requests", sa.Column("resolved_by", sa.Text(), nullable=True)
    )
    op.add_column(
        "approval_requests", sa.Column("resolution_reason", sa.Text(), nullable=True)
    )
    op.add_column(
        "approval_requests",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.execute(
        """
        UPDATE approval_requests
        SET
            decision = CASE
                WHEN status = 'resolved' THEN NULLIF(payload_json ->> 'decision', '')
                ELSE NULL
            END,
            resolution_source = CASE
                WHEN status = 'resolved'
                THEN NULLIF(payload_json ->> 'resolution_source', '')
                ELSE NULL
            END,
            resolved_by = CASE
                WHEN status = 'resolved' THEN NULLIF(payload_json ->> 'resolved_by', '')
                ELSE NULL
            END,
            resolution_reason = CASE
                WHEN status = 'resolved'
                THEN NULLIF(payload_json ->> 'resolution_reason', '')
                ELSE NULL
            END,
            expires_at = CASE
                WHEN NULLIF(payload_json ->> 'expires_at', '') IS NOT NULL
                THEN (payload_json ->> 'expires_at')::timestamptz
                WHEN status = 'expired'
                THEN created_at::timestamptz + interval '1 microsecond'
                ELSE created_at::timestamptz + interval '15 minutes'
            END,
            resolved_at = CASE
                WHEN status = 'resolved'
                THEN COALESCE(
                    NULLIF(payload_json ->> 'resolved_at', '')::timestamptz,
                    created_at::timestamptz
                )
                ELSE NULL
            END
        """
    )

    op.drop_index(
        "ix_approval_requests_status_created_at", table_name="approval_requests"
    )
    op.alter_column(
        "approval_requests",
        "created_at",
        existing_type=sa.Text(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=False,
        postgresql_using="created_at::timestamptz",
    )
    op.alter_column("approval_requests", "expires_at", nullable=False)
    op.drop_column("approval_requests", "status")

    op.create_check_constraint(
        "ck_approval_requests_decision",
        "approval_requests",
        "decision IS NULL OR decision IN ('allow_once', 'deny')",
    )
    op.create_check_constraint(
        "ck_approval_requests_resolution_source",
        "approval_requests",
        "resolution_source IS NULL OR resolution_source IN ('human', 'llm', 'system')",
    )
    op.create_check_constraint(
        "ck_approval_requests_resolution_state",
        "approval_requests",
        "(resolved_at IS NULL AND decision IS NULL) OR "
        "(resolved_at IS NOT NULL AND decision IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_approval_requests_expiry",
        "approval_requests",
        "expires_at > created_at",
    )
    op.create_index(
        "ix_approval_requests_pending_created_at",
        "approval_requests",
        ["resolved_at", "expires_at", "created_at"],
    )

    op.drop_table("approval_nonces")


def downgrade() -> None:
    op.create_table(
        "approval_nonces",
        sa.Column("nonce_hash", sa.Text(), primary_key=True),
        sa.Column("approval_id", sa.Text(), nullable=False),
        sa.Column("session_hash", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column("tool_call_id", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("used_at", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_approval_nonces_approval_id", "approval_nonces", ["approval_id"]
    )
    op.create_index(
        "ix_approval_nonces_session_hash", "approval_nonces", ["session_hash"]
    )
    op.create_index("ix_approval_nonces_subject_id", "approval_nonces", ["subject_id"])
    op.create_index("ix_approval_nonces_expires_at", "approval_nonces", ["expires_at"])
    op.create_index("ix_approval_nonces_used_at", "approval_nonces", ["used_at"])

    op.add_column("approval_requests", sa.Column("status", sa.Text(), nullable=True))
    op.execute(
        """
        UPDATE approval_requests
        SET status = CASE
            WHEN resolved_at IS NOT NULL THEN 'resolved'
            WHEN expires_at <= CURRENT_TIMESTAMP THEN 'expired'
            ELSE 'pending'
        END
        """
    )
    op.alter_column("approval_requests", "status", nullable=False)

    op.drop_index(
        "ix_approval_requests_pending_created_at", table_name="approval_requests"
    )
    op.drop_constraint(
        "ck_approval_requests_expiry", "approval_requests", type_="check"
    )
    op.drop_constraint(
        "ck_approval_requests_resolution_state", "approval_requests", type_="check"
    )
    op.drop_constraint(
        "ck_approval_requests_resolution_source", "approval_requests", type_="check"
    )
    op.drop_constraint(
        "ck_approval_requests_decision", "approval_requests", type_="check"
    )
    op.alter_column(
        "approval_requests",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.Text(),
        existing_nullable=False,
        postgresql_using="created_at::text",
    )
    op.drop_column("approval_requests", "resolved_at")
    op.drop_column("approval_requests", "expires_at")
    op.drop_column("approval_requests", "resolution_reason")
    op.drop_column("approval_requests", "resolved_by")
    op.drop_column("approval_requests", "resolution_source")
    op.drop_column("approval_requests", "decision")
    op.create_index(
        "ix_approval_requests_status_created_at",
        "approval_requests",
        ["status", "created_at"],
    )
