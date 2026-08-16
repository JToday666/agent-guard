"""add private strong-approval enforcement bindings (RTE-05)

The authorization fingerprint is intentionally confined to private authority
tables.  Public Approval/Audit/Trace/Receipt schemas do not reference this
table.  ``registration_digest`` gives runtime-grant registration an exact
semantic idempotency anchor without persisting a broad serialized payload.

Revision ID: 0017_enforcement_bindings
Revises: 0016_capability_lease
Create Date: 2026-08-16
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0017_enforcement_bindings"
down_revision = "0016_capability_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "capability_grant_runtime",
        sa.Column(
            "registration_digest",
            sa.Text(),
            nullable=True,
        ),
    )
    op.create_table(
        "enforcement_bindings",
        sa.Column("event_id", sa.Text(), nullable=False),
        sa.Column("policy_audit_id", sa.Text(), nullable=False),
        sa.Column("approval_id", sa.Text(), nullable=False),
        sa.Column("action_id", sa.Text(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("authorization_fingerprint", sa.Text(), nullable=False),
        sa.Column("runtime_binding_id", sa.Text(), nullable=False),
        sa.Column("scope_digest", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("runtime", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("policy_revision", sa.Text(), nullable=False),
        sa.Column("requires_execution_lease", sa.Boolean(), nullable=False),
        sa.Column("grant_id", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("event_id"),
        sa.ForeignKeyConstraint(
            ["approval_id"],
            ["approval_requests.approval_id"],
            name="fk_enforcement_bindings_approval_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["grant_id"],
            ["capability_grant_runtime.grant_id"],
            name="fk_enforcement_bindings_grant_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "policy_audit_id", name="uq_enforcement_bindings_policy_audit_id"
        ),
        sa.UniqueConstraint("approval_id", name="uq_enforcement_bindings_approval_id"),
    )
    op.create_check_constraint(
        "ck_enforcement_bindings_requires_execution_lease",
        "enforcement_bindings",
        "requires_execution_lease",
    )
    op.create_index(
        "ix_enforcement_bindings_runtime_agent",
        "enforcement_bindings",
        ["runtime", "agent_id"],
    )
    op.create_index(
        "ix_enforcement_bindings_grant_id",
        "enforcement_bindings",
        ["grant_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_enforcement_bindings_grant_id", table_name="enforcement_bindings")
    op.drop_index(
        "ix_enforcement_bindings_runtime_agent",
        table_name="enforcement_bindings",
    )
    op.drop_constraint(
        "ck_enforcement_bindings_requires_execution_lease",
        "enforcement_bindings",
        type_="check",
    )
    op.drop_table("enforcement_bindings")
    op.drop_column("capability_grant_runtime", "registration_digest")
