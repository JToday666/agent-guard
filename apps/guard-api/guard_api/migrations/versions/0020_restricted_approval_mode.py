"""Discriminate private restricted approval authorization from Host strong binding.

Existing rows retain their original strong-binding interpretation. A restricted
row stores server-owned ActionIR identity without claiming Host C3 support.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0020_restricted_approval_mode"
down_revision = "0019_product_activation_ack"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "enforcement_bindings",
        sa.Column(
            "release_mode", sa.Text(), nullable=False, server_default="strong_binding"
        ),
    )
    op.create_check_constraint(
        "ck_enforcement_bindings_release_mode",
        "enforcement_bindings",
        "release_mode IN ('strong_binding', 'restricted_allow_once') "
        "AND (release_mode <> 'restricted_allow_once' OR runtime = 'openclaw')",
    )


def downgrade() -> None:
    # Dropping the discriminator would reinterpret restricted grants as strong
    # authorizations in old code. Preserve those records and refuse that loss.
    op.get_bind().execute(sa.text("LOCK TABLE enforcement_bindings IN ACCESS EXCLUSIVE MODE"))
    if op.get_bind().execute(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM enforcement_bindings "
            "WHERE release_mode = 'restricted_allow_once')"
        )
    ).scalar_one():
        raise RuntimeError("restricted approvals prevent release-mode downgrade")
    op.drop_constraint(
        "ck_enforcement_bindings_release_mode", "enforcement_bindings", type_="check"
    )
    op.drop_column("enforcement_bindings", "release_mode")
