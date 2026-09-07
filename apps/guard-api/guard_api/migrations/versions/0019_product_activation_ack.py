"""add private product activation ack state

Revision ID: 0019_product_activation_ack
Revises: 0018_product_runtime_status
Create Date: 2026-09-01

The opaque ACK is server-owned authority.  Only its SHA-256 lookup digest and
signed non-secret claims are persisted, so status/Dashboard projections cannot
leak the raw token. Multiple unexpired generations may coexist for in-flight
requests; an authority drift revokes them together.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0019_product_activation_ack"
down_revision = "0018_product_runtime_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "product_activation_acks_v1",
        sa.Column("token_digest", sa.Text(), primary_key=True),
        sa.Column("runtime", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("runtime_binding_id", sa.Text(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["runtime", "agent_id", "runtime_binding_id", "profile_id"],
            [
                "product_runtime_statuses_v2.runtime",
                "product_runtime_statuses_v2.agent_id",
                "product_runtime_statuses_v2.runtime_binding_id",
                "product_runtime_statuses_v2.profile_id",
            ],
            name="fk_product_activation_acks_v1_runtime_status",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "token_digest COLLATE \"C\" ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_product_activation_acks_v1_token_digest",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name="ck_product_activation_acks_v1_window",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= issued_at",
            name="ck_product_activation_acks_v1_revocation",
        ),
    )
    op.create_index(
        "ix_product_activation_acks_v1_identity_issued",
        "product_activation_acks_v1",
        [
            "runtime",
            "agent_id",
            "runtime_binding_id",
            "profile_id",
            sa.text("issued_at DESC"),
        ],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_product_activation_acks_v1_identity_issued",
        table_name="product_activation_acks_v1",
    )
    op.drop_table("product_activation_acks_v1")
