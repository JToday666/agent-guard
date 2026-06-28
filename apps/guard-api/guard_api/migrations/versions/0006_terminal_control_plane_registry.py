"""add terminal control plane registries

Revision ID: 0006_terminal_registry
Revises: 0005_dashboard_backend_todo
Create Date: 2026-06-28
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006_terminal_registry"
down_revision = "0005_dashboard_backend_todo"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credentials",
        sa.Column("credential_id", sa.Text(), primary_key=True),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("principal_type", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("runtime", sa.Text(), nullable=True),
        sa.Column("agent_id", sa.Text(), nullable=True),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=True),
        sa.Column("revoked_at", sa.Text(), nullable=True),
    )
    op.create_index("ix_credentials_token_hash", "credentials", ["token_hash"])
    op.create_index("ix_credentials_principal", "credentials", ["principal_type", "principal_id"])
    op.create_index("ix_credentials_runtime_agent", "credentials", ["runtime", "agent_id"])
    op.create_index("ix_credentials_revoked_at", "credentials", ["revoked_at"])


def downgrade() -> None:
    op.drop_index("ix_credentials_revoked_at", table_name="credentials")
    op.drop_index("ix_credentials_runtime_agent", table_name="credentials")
    op.drop_index("ix_credentials_principal", table_name="credentials")
    op.drop_index("ix_credentials_token_hash", table_name="credentials")
    op.drop_table("credentials")
