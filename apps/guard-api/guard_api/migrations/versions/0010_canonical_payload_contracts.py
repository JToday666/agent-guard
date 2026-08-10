"""canonicalize approval and adapter status payload contracts

Revision ID: 0010_canonical_payloads
Revises: 0009_credential_identity
Create Date: 2026-08-09
"""

from __future__ import annotations

from alembic import op

revision = "0010_canonical_payloads"
down_revision = "0009_credential_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Convert persisted approvals once, then keep only the canonical subject/action
    # representation. Runtime readers intentionally have no alias fallback.
    op.execute(
        """
        UPDATE approval_requests
        SET payload_json = (
            payload_json
            || jsonb_build_object(
                'subject_id', COALESCE(
                    NULLIF(payload_json ->> 'subject_id', ''),
                    payload_json ->> 'tool_call_id'
                ),
                'subject_type', COALESCE(
                    NULLIF(payload_json ->> 'subject_type', ''),
                    'tool_call'
                ),
                'action_id', COALESCE(
                    NULLIF(payload_json ->> 'action_id', ''),
                    NULLIF(payload_json ->> 'subject_id', ''),
                    payload_json ->> 'tool_call_id'
                ),
                'action_name', COALESCE(
                    NULLIF(payload_json ->> 'action_name', ''),
                    NULLIF(payload_json ->> 'tool', ''),
                    NULLIF(payload_json ->> 'subject_type', ''),
                    'unknown'
                )
            )
        ) - 'tool_call_id' - 'tool'
        """
    )

    # The route path is the sole runtime identifier for adapter status resources;
    # runtime_id in the payload continues to identify a concrete runtime instance.
    op.execute(
        """
        UPDATE adapter_statuses
        SET payload_json = payload_json - 'runtime'
        WHERE payload_json ? 'runtime'
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE approval_requests
        SET payload_json = payload_json || jsonb_build_object(
            'tool_call_id', payload_json ->> 'subject_id',
            'tool', payload_json ->> 'action_name'
        )
        """
    )
    op.execute(
        """
        UPDATE adapter_statuses
        SET payload_json = payload_json || jsonb_build_object(
            'runtime', adapter_id
        )
        """
    )
