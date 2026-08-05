"""add dashboard backend todo storage

Revision ID: 0005_dashboard_backend_todo
Revises: 0004_p2_control_plane
Create Date: 2026-06-28
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_dashboard_backend_todo"
down_revision = "0004_p2_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("run_id", sa.Text(), primary_key=True),
        sa.Column("run_at", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_evaluation_runs_run_at", "evaluation_runs", ["run_at"])

    op.create_table(
        "adapter_statuses",
        sa.Column("adapter_id", sa.Text(), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_adapter_statuses_updated_at", "adapter_statuses", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_adapter_statuses_updated_at", table_name="adapter_statuses")
    op.drop_table("adapter_statuses")
    op.drop_index("ix_evaluation_runs_run_at", table_name="evaluation_runs")
    op.drop_table("evaluation_runs")
