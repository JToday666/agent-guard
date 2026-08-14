"""add security state and projection records storage (V21-04 state projection)

Revision ID: 0015_security_state
Revises: 0014_task_facts
Create Date: 2026-08-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015_security_state"
down_revision = "0014_task_facts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_states",
        sa.Column("scope_digest", sa.Text(), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column(
            "canonical_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("dirty", sa.Boolean(), nullable=False),
        sa.Column(
            "dirty_domains",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("projector_version", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("scope_digest"),
    )
    op.create_check_constraint(
        "ck_security_states_state_version_non_negative",
        "security_states",
        "state_version >= 0",
    )
    op.create_table(
        "projection_records",
        sa.Column("scope_digest", sa.Text(), nullable=False),
        sa.Column("source_record_type", sa.Text(), nullable=False),
        sa.Column("source_record_id", sa.Text(), nullable=False),
        sa.Column("source_revision", sa.Integer(), nullable=False),
        sa.Column("projector_version", sa.Text(), nullable=False),
        sa.Column("delta_digest", sa.Text(), nullable=False),
        sa.Column(
            "delta_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("applied_state_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "scope_digest",
            "source_record_type",
            "source_record_id",
            "source_revision",
            "projector_version",
        ),
    )
    op.create_check_constraint(
        "ck_projection_records_source_record_type",
        "projection_records",
        "source_record_type IN ("
        "'policy_evaluation', 'runtime_outcome', 'approval', "
        "'memory_transition', 'policy_revision', 'runtime_observation')",
    )
    op.create_check_constraint(
        "ck_projection_records_applied_state_version_positive",
        "projection_records",
        "applied_state_version > 0",
    )
    op.create_index(
        "ix_projection_records_scope_applied_version",
        "projection_records",
        ["scope_digest", "applied_state_version"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_projection_records_scope_applied_version",
        table_name="projection_records",
    )
    op.drop_constraint(
        "ck_projection_records_applied_state_version_positive",
        "projection_records",
        type_="check",
    )
    op.drop_constraint(
        "ck_projection_records_source_record_type",
        "projection_records",
        type_="check",
    )
    op.drop_table("projection_records")
    op.drop_constraint(
        "ck_security_states_state_version_non_negative",
        "security_states",
        type_="check",
    )
    op.drop_table("security_states")
