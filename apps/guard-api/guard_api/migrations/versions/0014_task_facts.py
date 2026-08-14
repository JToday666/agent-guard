"""add authoritative task facts storage (V21-03 task ingress)

Revision ID: 0014_task_facts
Revises: 0013_jcs_audit_chain
Create Date: 2026-08-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0014_task_facts"
down_revision = "0013_jcs_audit_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_facts",
        sa.Column("task_id", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("scope_digest", sa.Text(), nullable=False),
        sa.Column("scope_key_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("task_digest", sa.Text(), nullable=False),
        sa.Column("task_summary", sa.Text(), nullable=False),
        sa.Column(
            "canonical_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("expected_revision", sa.Integer(), nullable=False),
        sa.Column("producer", sa.Text(), nullable=False),
        sa.Column("authority", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("task_id", "revision"),
    )
    op.create_check_constraint(
        "ck_task_facts_revision_positive", "task_facts", "revision > 0"
    )
    op.create_check_constraint(
        "ck_task_facts_status",
        "task_facts",
        "status IN ('active', 'cancelled', 'superseded')",
    )
    op.create_check_constraint(
        "ck_task_facts_authority_root",
        "task_facts",
        "producer = 'guard_api_task_ingress' AND authority = 'authoritative'",
    )
    op.create_index("ix_task_facts_principal_id", "task_facts", ["principal_id"])
    op.create_index("ix_task_facts_scope_key_id", "task_facts", ["scope_key_id"])
    op.create_index("ix_task_facts_scope_digest", "task_facts", ["scope_digest"])


def downgrade() -> None:
    op.drop_index("ix_task_facts_scope_digest", table_name="task_facts")
    op.drop_index("ix_task_facts_scope_key_id", table_name="task_facts")
    op.drop_index("ix_task_facts_principal_id", table_name="task_facts")
    op.drop_constraint("ck_task_facts_authority_root", "task_facts", type_="check")
    op.drop_constraint("ck_task_facts_status", "task_facts", type_="check")
    op.drop_constraint(
        "ck_task_facts_revision_positive", "task_facts", type_="check"
    )
    op.drop_table("task_facts")
