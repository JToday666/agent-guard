"""bind active adapter credentials to runtime identities

Revision ID: 0009_credential_identity
Revises: 0008_approval_state
Create Date: 2026-08-09
"""

from __future__ import annotations

from alembic import op

revision = "0009_credential_identity"
down_revision = "0008_approval_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE credentials
        SET
            revoked_at = COALESCE(revoked_at, created_at),
            payload_json = jsonb_set(
                payload_json,
                '{revoked_at}',
                to_jsonb(COALESCE(revoked_at, created_at)),
                true
            )
        WHERE revoked_at IS NULL
          AND (
              principal_type <> 'component'
              OR role <> 'adapter'
              OR runtime IS NULL
              OR agent_id IS NULL
          )
        """
    )
    op.create_check_constraint(
        "ck_credentials_active_adapter_identity",
        "credentials",
        "revoked_at IS NOT NULL OR "
        "(principal_type = 'component' AND role = 'adapter' "
        "AND runtime IS NOT NULL AND agent_id IS NOT NULL)",
    )
    op.drop_index("ix_credentials_token_hash", table_name="credentials")
    op.create_index(
        "ix_credentials_token_hash",
        "credentials",
        ["token_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_credentials_token_hash", table_name="credentials")
    op.create_index("ix_credentials_token_hash", "credentials", ["token_hash"])
    op.drop_constraint(
        "ck_credentials_active_adapter_identity", "credentials", type_="check"
    )
