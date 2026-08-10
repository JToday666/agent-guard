"""promote audit query fields and bitemporal timestamps

Revision ID: 0011_audit_query_columns
Revises: 0010_canonical_payloads
Create Date: 2026-08-09
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0011_audit_query_columns"
down_revision = "0010_canonical_payloads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.alter_column(
        "audit_events",
        "created_at",
        type_=sa.DateTime(timezone=True),
        postgresql_using="created_at::timestamptz",
    )
    op.alter_column("audit_events", "created_at", new_column_name="occurred_at")
    op.alter_column(
        "audit_events",
        "sequence",
        type_=sa.BigInteger(),
        postgresql_using="sequence::bigint",
    )
    op.alter_column(
        "audit_integrity_heads",
        "sequence",
        type_=sa.BigInteger(),
        postgresql_using="sequence::bigint",
    )

    op.add_column(
        "audit_events",
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("audit_events", sa.Column("record_type", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("trace_id", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("case_id", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("runtime", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("decision", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("event_id", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("decision_id", sa.Text(), nullable=True))
    op.add_column(
        "audit_events", sa.Column("is_malicious", sa.Boolean(), nullable=True)
    )
    op.add_column("audit_events", sa.Column("latency_ms", sa.Integer(), nullable=True))

    # The old created_at column stored the producer timestamp. Preserve it as
    # occurred_at and use it as the best available ingestion-time approximation
    # for pre-migration rows. New writes receive database statement time.
    op.execute(
        """
        UPDATE audit_events
        SET ingested_at = occurred_at,
            record_type = COALESCE(
                NULLIF(payload_json ->> 'record_type', ''),
                CASE payload_json ->> 'event_type'
                    WHEN 'config_audit' THEN 'config_audit'
                    WHEN 'runtime_observation' THEN 'runtime_observation'
                    ELSE 'policy_evaluation'
                END
            ),
            trace_id = payload_json ->> 'trace_id',
            case_id = NULLIF(payload_json ->> 'case_id', ''),
            runtime = payload_json ->> 'runtime',
            decision = NULLIF(payload_json ->> 'decision', ''),
            event_id = NULLIF(payload_json -> 'links' ->> 'event_id', ''),
            decision_id = NULLIF(payload_json -> 'links' ->> 'decision_id', ''),
            is_malicious = NULLIF(payload_json ->> 'is_malicious', '')::boolean,
            latency_ms = NULLIF(payload_json ->> 'latency_ms', '')::integer
        """
    )

    op.alter_column(
        "audit_events",
        "ingested_at",
        nullable=False,
        server_default=sa.text("now()"),
    )
    op.alter_column("audit_events", "record_type", nullable=False)
    op.alter_column("audit_events", "trace_id", nullable=False)
    op.alter_column("audit_events", "runtime", nullable=False)

    op.create_check_constraint(
        "ck_audit_events_sequence_positive", "audit_events", "sequence > 0"
    )
    op.create_check_constraint(
        "ck_audit_events_record_type",
        "audit_events",
        "record_type IN ('policy_evaluation', 'runtime_outcome', "
        "'runtime_observation', 'config_audit')",
    )
    op.create_check_constraint(
        "ck_audit_events_decision",
        "audit_events",
        "decision IS NULL OR decision IN ('allow', 'ask', 'deny')",
    )
    op.create_check_constraint(
        "ck_audit_events_latency_nonnegative",
        "audit_events",
        "latency_ms IS NULL OR latency_ms >= 0",
    )

    op.drop_index("ix_audit_events_chain_sequence", table_name="audit_events")
    op.create_index(
        "ux_audit_events_chain_sequence",
        "audit_events",
        ["chain_id", "sequence"],
        unique=True,
    )
    op.create_index(
        "ix_audit_events_trace_sequence",
        "audit_events",
        ["trace_id", "sequence"],
    )
    op.create_index(
        "ix_audit_events_runtime_sequence",
        "audit_events",
        ["runtime", "sequence"],
    )
    op.create_index(
        "ix_audit_events_case_sequence",
        "audit_events",
        ["case_id", "sequence"],
        postgresql_where=sa.text("case_id IS NOT NULL"),
    )
    op.create_index(
        "ix_audit_events_decision_sequence",
        "audit_events",
        ["decision", "sequence"],
        postgresql_where=sa.text("decision IS NOT NULL"),
    )
    op.create_index(
        "ix_audit_events_policy_occurred_sequence",
        "audit_events",
        ["occurred_at", "sequence"],
        postgresql_where=sa.text("record_type = 'policy_evaluation'"),
    )
    op.create_index("ix_audit_events_ingested_at", "audit_events", ["ingested_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_ingested_at", table_name="audit_events")
    op.drop_index("ix_audit_events_policy_occurred_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_decision_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_case_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_runtime_sequence", table_name="audit_events")
    op.drop_index("ix_audit_events_trace_sequence", table_name="audit_events")
    op.drop_index("ux_audit_events_chain_sequence", table_name="audit_events")
    op.create_index(
        "ix_audit_events_chain_sequence",
        "audit_events",
        ["chain_id", "sequence"],
    )

    op.drop_constraint(
        "ck_audit_events_latency_nonnegative", "audit_events", type_="check"
    )
    op.drop_constraint("ck_audit_events_decision", "audit_events", type_="check")
    op.drop_constraint("ck_audit_events_record_type", "audit_events", type_="check")
    op.drop_constraint(
        "ck_audit_events_sequence_positive", "audit_events", type_="check"
    )

    for column_name in (
        "latency_ms",
        "is_malicious",
        "decision_id",
        "event_id",
        "decision",
        "runtime",
        "case_id",
        "trace_id",
        "record_type",
        "ingested_at",
    ):
        op.drop_column("audit_events", column_name)

    op.alter_column(
        "audit_integrity_heads",
        "sequence",
        type_=sa.Integer(),
        postgresql_using="sequence::integer",
    )
    op.alter_column(
        "audit_events",
        "sequence",
        type_=sa.Integer(),
        postgresql_using="sequence::integer",
    )
    op.alter_column("audit_events", "occurred_at", new_column_name="created_at")
    op.alter_column(
        "audit_events",
        "created_at",
        type_=sa.Text(),
        postgresql_using="created_at::text",
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
