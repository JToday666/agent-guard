"""add exact-identity product runtime status storage

Revision ID: 0018_product_runtime_status
Revises: 0017_enforcement_bindings
Create Date: 2026-09-01

The legacy ``adapter_statuses`` table deliberately remains unchanged.  Its
single-row-per-runtime shape is still the compatibility projection for older
readers, while this table stores only fully qualified product identities.
Legacy rows are not backfilled because they do not carry a trustworthy
runtime binding or official profile identity.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0018_product_runtime_status"
down_revision = "0017_enforcement_bindings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "product_runtime_statuses_v2",
        sa.Column("runtime", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("runtime_binding_id", sa.Text(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column(
            "write_sequence",
            sa.BigInteger(),
            sa.Identity(always=True),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("loaded", sa.Boolean(), nullable=False),
        sa.Column("runtime_id", sa.Text(), nullable=False),
        sa.Column("enforcement_mode", sa.Text(), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("statement_timestamp()"),
        ),
        sa.PrimaryKeyConstraint(
            "runtime",
            "agent_id",
            "runtime_binding_id",
            "profile_id",
            name="pk_product_runtime_statuses_v2",
        ),
        sa.UniqueConstraint(
            "write_sequence",
            name="uq_product_runtime_statuses_v2_write_sequence",
        ),
        sa.CheckConstraint(
            "agent_id COLLATE \"C\" ~ '^[!-~]+$' AND "
            "runtime_binding_id COLLATE \"C\" ~ '^[!-~]+$' AND "
            "profile_id COLLATE \"C\" ~ '^[!-~]+$' AND "
            "char_length(agent_id) BETWEEN 1 AND 128 AND "
            "char_length(runtime_binding_id) BETWEEN 1 AND 256 AND "
            "((runtime = 'langgraph' AND "
            "profile_id = 'agentguard-langgraph-v2') OR "
            "(runtime = 'openclaw' AND "
            "profile_id = 'agentguard-openclaw-v2-restricted'))",
            name="ck_product_runtime_statuses_v2_exact_identity",
        ),
        sa.CheckConstraint(
            "status IN ('loaded', 'not_loaded', 'error', 'unknown')",
            name="ck_product_runtime_statuses_v2_status",
        ),
        sa.CheckConstraint(
            "loaded = (status = 'loaded')",
            name="ck_product_runtime_statuses_v2_loaded_status",
        ),
        sa.CheckConstraint(
            "enforcement_mode IN ('enforce', 'observe', 'disabled')",
            name="ck_product_runtime_statuses_v2_enforcement_mode",
        ),
    )
    op.create_index(
        "ix_product_runtime_statuses_v2_runtime_sequence",
        "product_runtime_statuses_v2",
        ["runtime", sa.text("write_sequence DESC")],
    )
    op.create_index(
        "ix_product_runtime_statuses_v2_runtime_heartbeat",
        "product_runtime_statuses_v2",
        [
            "runtime",
            sa.text("last_heartbeat_at DESC"),
            sa.text("write_sequence DESC"),
        ],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_product_runtime_statuses_v2_runtime_heartbeat",
        table_name="product_runtime_statuses_v2",
    )
    op.drop_index(
        "ix_product_runtime_statuses_v2_runtime_sequence",
        table_name="product_runtime_statuses_v2",
    )
    op.drop_table("product_runtime_statuses_v2")
