"""add current policy snapshot storage and history audit

Revision ID: 0002_policy_snapshots
Revises: 0001_control_plane
Create Date: 2026-06-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_policy_snapshots"
down_revision = "0001_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_snapshots",
        sa.Column("policy_id", sa.Text(), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=False),
    )
    op.create_index("ix_policy_snapshots_updated_at", "policy_snapshots", ["updated_at"])
    op.create_table(
        "policy_snapshot_history",
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_policy_snapshot_history_updated_at",
        "policy_snapshot_history",
        ["updated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_policy_snapshot_history_updated_at", table_name="policy_snapshot_history")
    op.drop_table("policy_snapshot_history")
    op.drop_index("ix_policy_snapshots_updated_at", table_name="policy_snapshots")
    op.drop_table("policy_snapshots")
