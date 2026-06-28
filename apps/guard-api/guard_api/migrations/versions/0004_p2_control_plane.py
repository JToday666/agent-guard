"""add p2 control plane storage

Revision ID: 0004_p2_control_plane
Revises: 0003_approval_subject_ids
Create Date: 2026-06-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from agentguard_core import AuditEvent
from guard_api.storage.integrity import attach_audit_integrity, read_audit_integrity

revision = "0004_p2_control_plane"
down_revision = "0003_approval_subject_ids"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("audit_events"):
        op.add_column("audit_events", sa.Column("chain_id", sa.Text(), nullable=True))
        op.add_column("audit_events", sa.Column("sequence", sa.Integer(), nullable=True))
        op.add_column("audit_events", sa.Column("prev_hash", sa.Text(), nullable=True))
        op.add_column("audit_events", sa.Column("event_hash", sa.Text(), nullable=True))
        _backfill_audit_integrity()
        op.alter_column("audit_events", "chain_id", nullable=False)
        op.alter_column("audit_events", "sequence", nullable=False)
        op.alter_column("audit_events", "event_hash", nullable=False)
    else:
        op.create_table(
            "audit_events",
            sa.Column("audit_id", sa.Text(), primary_key=True),
            sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("created_at", sa.Text(), nullable=False),
            sa.Column("chain_id", sa.Text(), nullable=False),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("prev_hash", sa.Text(), nullable=True),
            sa.Column("event_hash", sa.Text(), nullable=False),
        )
        op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_index("ix_audit_events_chain_sequence", "audit_events", ["chain_id", "sequence"])
    op.create_index("ix_audit_events_event_hash", "audit_events", ["event_hash"])

    op.create_table(
        "audit_integrity_heads",
        sa.Column("chain_id", sa.Text(), primary_key=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_hash", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.execute(
        """
        INSERT INTO audit_integrity_heads (chain_id, sequence, event_hash, updated_at)
        SELECT
            'default',
            COALESCE(MAX(sequence), 0),
            (
                SELECT event_hash
                FROM audit_events
                WHERE chain_id = 'default'
                ORDER BY sequence DESC
                LIMIT 1
            ),
            COALESCE(MAX(created_at), '1970-01-01T00:00:00+00:00')
        FROM audit_events
        """
    )

    op.create_table(
        "provenance_nodes",
        sa.Column("node_id", sa.Text(), primary_key=True),
        sa.Column("trace_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ref_id", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_provenance_nodes_trace_id", "provenance_nodes", ["trace_id"])
    op.create_index("ix_provenance_nodes_kind", "provenance_nodes", ["kind"])

    op.create_table(
        "provenance_edges",
        sa.Column("edge_id", sa.Text(), primary_key=True),
        sa.Column("trace_id", sa.Text(), nullable=False),
        sa.Column("source_node_id", sa.Text(), nullable=False),
        sa.Column("target_node_id", sa.Text(), nullable=False),
        sa.Column("relation", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_provenance_edges_trace_id", "provenance_edges", ["trace_id"])
    op.create_index("ix_provenance_edges_relation", "provenance_edges", ["relation"])

    op.create_table(
        "config_audit_findings",
        sa.Column("finding_id", sa.Text(), primary_key=True),
        sa.Column("runtime", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_config_audit_findings_runtime", "config_audit_findings", ["runtime"])
    op.create_index("ix_config_audit_findings_target", "config_audit_findings", ["target_type", "target_id"])
    op.create_index("ix_config_audit_findings_severity", "config_audit_findings", ["severity"])

    op.create_table(
        "memory_guard_changes",
        sa.Column("change_id", sa.Text(), primary_key=True),
        sa.Column("trace_id", sa.Text(), nullable=False),
        sa.Column("namespace", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_memory_guard_changes_trace_id", "memory_guard_changes", ["trace_id"])
    op.create_index("ix_memory_guard_changes_status", "memory_guard_changes", ["status"])
    op.create_index("ix_memory_guard_changes_namespace_key", "memory_guard_changes", ["namespace", "key"])

    op.create_table(
        "action_critic_reviews",
        sa.Column("review_id", sa.Text(), primary_key=True),
        sa.Column("trace_id", sa.Text(), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("ix_action_critic_reviews_trace_id", "action_critic_reviews", ["trace_id"])
    op.create_index("ix_action_critic_reviews_event_id", "action_critic_reviews", ["event_id"])
    op.create_index("ix_action_critic_reviews_verdict", "action_critic_reviews", ["verdict"])


def downgrade() -> None:
    op.drop_index("ix_action_critic_reviews_verdict", table_name="action_critic_reviews")
    op.drop_index("ix_action_critic_reviews_event_id", table_name="action_critic_reviews")
    op.drop_index("ix_action_critic_reviews_trace_id", table_name="action_critic_reviews")
    op.drop_table("action_critic_reviews")

    op.drop_index("ix_memory_guard_changes_namespace_key", table_name="memory_guard_changes")
    op.drop_index("ix_memory_guard_changes_status", table_name="memory_guard_changes")
    op.drop_index("ix_memory_guard_changes_trace_id", table_name="memory_guard_changes")
    op.drop_table("memory_guard_changes")

    op.drop_index("ix_config_audit_findings_severity", table_name="config_audit_findings")
    op.drop_index("ix_config_audit_findings_target", table_name="config_audit_findings")
    op.drop_index("ix_config_audit_findings_runtime", table_name="config_audit_findings")
    op.drop_table("config_audit_findings")

    op.drop_index("ix_provenance_edges_relation", table_name="provenance_edges")
    op.drop_index("ix_provenance_edges_trace_id", table_name="provenance_edges")
    op.drop_table("provenance_edges")

    op.drop_index("ix_provenance_nodes_kind", table_name="provenance_nodes")
    op.drop_index("ix_provenance_nodes_trace_id", table_name="provenance_nodes")
    op.drop_table("provenance_nodes")

    op.drop_table("audit_integrity_heads")
    op.drop_index("ix_audit_events_event_hash", table_name="audit_events")
    op.drop_index("ix_audit_events_chain_sequence", table_name="audit_events")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "prev_hash")
    op.drop_column("audit_events", "sequence")
    op.drop_column("audit_events", "chain_id")


def _backfill_audit_integrity() -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            """
            SELECT audit_id, payload_json
            FROM audit_events
            ORDER BY created_at ASC, audit_id ASC
            """
        )
    ).mappings()
    prev_hash: str | None = None
    for sequence, row in enumerate(rows, start=1):
        event = AuditEvent.model_validate(row["payload_json"])
        event_with_integrity = attach_audit_integrity(event, sequence=sequence, prev_hash=prev_hash)
        integrity = read_audit_integrity(event_with_integrity)
        if integrity is None:
            raise RuntimeError("audit integrity backfill failed")
        prev_hash = integrity.event_hash
        connection.execute(
            sa.text(
                """
                UPDATE audit_events
                SET payload_json = CAST(:payload_json AS jsonb),
                    chain_id = 'default',
                    sequence = :sequence,
                    prev_hash = :prev_hash,
                    event_hash = :event_hash
                WHERE audit_id = :audit_id
                """
            ),
            {
                "audit_id": row["audit_id"],
                "payload_json": event_with_integrity.model_dump_json(),
                "sequence": integrity.sequence,
                "prev_hash": integrity.prev_hash,
                "event_hash": integrity.event_hash,
            },
        )
