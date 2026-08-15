"""add capability grant runtime / consumption / execution lease storage (V21-06)

Phase 0 structure-only：仅建表，无服务接线（V21-06 分支实施填充）。

表结构只按冻结模型所需字段设计（01 §14 CapabilityGrant / 01 §15
GrantConsumption / ExecutionLease）：

- ``capability_grant_runtime``：grant 运行时用量与生命周期状态；
- ``grant_consumptions``：消费记录，UNIQUE(grant_id, action_id) 幂等
  约束防双花（01 §15：必须原子/CAS）；
- ``execution_leases``：执行租约，UNIQUE(token_digest)；明文 lease
  token 不落库（01 §15：只保存 token_digest）。

C5 决策：ExecutionLease 只存本权威 lease store，不进
OnlineSecurityState（不与 security_states / projection_records 交互）。

Revision ID: 0016_capability_lease
Revises: 0015_security_state
Create Date: 2026-08-15
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0016_capability_lease"
down_revision = "0015_security_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "capability_grant_runtime",
        sa.Column("grant_id", sa.Text(), nullable=False),
        sa.Column("scope_digest", sa.Text(), nullable=False),
        sa.Column("remaining_uses", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=True),
        sa.Column("authorization_fingerprint", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("grant_id"),
    )
    op.create_check_constraint(
        "ck_capability_grant_runtime_remaining_uses_non_negative",
        "capability_grant_runtime",
        "remaining_uses >= 0",
    )
    op.create_check_constraint(
        "ck_capability_grant_runtime_status",
        "capability_grant_runtime",
        "status IN ('active', 'expired', 'revoked')",
    )
    op.create_index(
        "ix_capability_grant_runtime_scope",
        "capability_grant_runtime",
        ["scope_digest"],
    )

    op.create_table(
        "grant_consumptions",
        sa.Column("consumption_id", sa.Text(), nullable=False),
        sa.Column("grant_id", sa.Text(), nullable=False),
        sa.Column("action_id", sa.Text(), nullable=False),
        sa.Column("authorization_fingerprint", sa.Text(), nullable=False),
        sa.Column("consumed_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("consumption_id"),
        sa.ForeignKeyConstraint(
            ["grant_id"],
            ["capability_grant_runtime.grant_id"],
            name="fk_grant_consumptions_grant_id",
        ),
        sa.UniqueConstraint(
            "grant_id", "action_id", name="uq_grant_consumptions_grant_action"
        ),
    )

    op.create_table(
        "execution_leases",
        sa.Column("lease_id", sa.Text(), nullable=False),
        sa.Column("token_digest", sa.Text(), nullable=False),
        sa.Column("consumption_id", sa.Text(), nullable=False),
        sa.Column("approval_id", sa.Text(), nullable=False),
        sa.Column("grant_id", sa.Text(), nullable=False),
        sa.Column("action_id", sa.Text(), nullable=False),
        sa.Column("authorization_fingerprint", sa.Text(), nullable=False),
        sa.Column("runtime_binding_id", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("lease_id"),
        sa.ForeignKeyConstraint(
            ["consumption_id"],
            ["grant_consumptions.consumption_id"],
            name="fk_execution_leases_consumption_id",
        ),
        sa.UniqueConstraint("token_digest", name="uq_execution_leases_token_digest"),
    )
    op.create_check_constraint(
        "ck_execution_leases_status",
        "execution_leases",
        "status IN ('consumed', 'expired', 'revoked')",
    )
    op.create_index(
        "ix_execution_leases_consumption_id",
        "execution_leases",
        ["consumption_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_leases_consumption_id",
        table_name="execution_leases",
    )
    op.drop_constraint(
        "ck_execution_leases_status",
        "execution_leases",
        type_="check",
    )
    op.drop_table("execution_leases")
    op.drop_table("grant_consumptions")
    op.drop_index(
        "ix_capability_grant_runtime_scope",
        table_name="capability_grant_runtime",
    )
    op.drop_constraint(
        "ck_capability_grant_runtime_status",
        "capability_grant_runtime",
        type_="check",
    )
    op.drop_constraint(
        "ck_capability_grant_runtime_remaining_uses_non_negative",
        "capability_grant_runtime",
        type_="check",
    )
    op.drop_table("capability_grant_runtime")
