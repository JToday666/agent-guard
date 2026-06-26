"""add approval subject ids

Revision ID: 0003_approval_subject_ids
Revises: 0002_policy_snapshots
Create Date: 2026-06-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003_approval_subject_ids"
down_revision = "0002_policy_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approval_nonces", sa.Column("subject_id", sa.Text(), nullable=True))
    op.execute("UPDATE approval_nonces SET subject_id = tool_call_id WHERE subject_id IS NULL")
    op.alter_column("approval_nonces", "subject_id", nullable=False)
    op.create_index("ix_approval_nonces_subject_id", "approval_nonces", ["subject_id"])


def downgrade() -> None:
    op.drop_index("ix_approval_nonces_subject_id", table_name="approval_nonces")
    op.drop_column("approval_nonces", "subject_id")
