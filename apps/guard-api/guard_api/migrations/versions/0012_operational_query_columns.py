"""promote operational identity, status, and timestamp projections

Revision ID: 0012_operational_columns
Revises: 0011_audit_query_columns
Create Date: 2026-08-09
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0012_operational_columns"
down_revision = "0011_audit_query_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    _promote_evidence_timestamps()
    _promote_approval_identity()
    _promote_config_finding_trace()
    _promote_evaluation_queries()
    _promote_adapter_status()


def downgrade() -> None:
    _demote_adapter_status()
    _demote_evaluation_queries()
    _demote_config_finding_trace()
    _demote_approval_identity()
    _demote_evidence_timestamps()


def _promote_evidence_timestamps() -> None:
    for table_name, column_name in (
        ("audit_integrity_heads", "updated_at"),
        ("provenance_nodes", "created_at"),
        ("provenance_edges", "created_at"),
        ("config_audit_findings", "created_at"),
        ("action_critic_reviews", "created_at"),
    ):
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.Text(),
            type_=sa.DateTime(timezone=True),
            existing_nullable=False,
            postgresql_using=f"{column_name}::timestamptz",
        )


def _demote_evidence_timestamps() -> None:
    for table_name, column_name in reversed(
        (
            ("audit_integrity_heads", "updated_at"),
            ("provenance_nodes", "created_at"),
            ("provenance_edges", "created_at"),
            ("config_audit_findings", "created_at"),
            ("action_critic_reviews", "created_at"),
        )
    ):
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.DateTime(timezone=True),
            type_=sa.Text(),
            existing_nullable=False,
            postgresql_using=f"{column_name}::text",
        )


def _promote_approval_identity() -> None:
    for column_name in ("trace_id", "runtime", "agent_id", "subject_id", "action_id"):
        op.add_column(
            "approval_requests", sa.Column(column_name, sa.Text(), nullable=True)
        )
    op.execute("""
        UPDATE approval_requests
        SET trace_id = COALESCE(NULLIF(payload_json ->> 'trace_id', ''), approval_id),
            runtime = COALESCE(NULLIF(payload_json ->> 'runtime', ''), 'langgraph'),
            agent_id = COALESCE(NULLIF(payload_json ->> 'agent_id', ''), 'main'),
            subject_id = COALESCE(
                NULLIF(payload_json ->> 'subject_id', ''), approval_id
            ),
            action_id = COALESCE(
                NULLIF(payload_json ->> 'action_id', ''),
                NULLIF(payload_json ->> 'subject_id', ''),
                approval_id
            )
        """)
    for column_name in ("trace_id", "runtime", "agent_id", "subject_id", "action_id"):
        op.alter_column("approval_requests", column_name, nullable=False)
    op.create_index(
        "ix_approval_requests_trace_created_at",
        "approval_requests",
        ["trace_id", "created_at"],
    )
    op.create_index(
        "ix_approval_requests_runtime_agent_created_at",
        "approval_requests",
        ["runtime", "agent_id", "created_at"],
    )


def _demote_approval_identity() -> None:
    op.drop_index(
        "ix_approval_requests_runtime_agent_created_at",
        table_name="approval_requests",
    )
    op.drop_index(
        "ix_approval_requests_trace_created_at", table_name="approval_requests"
    )
    for column_name in ("action_id", "subject_id", "agent_id", "runtime", "trace_id"):
        op.drop_column("approval_requests", column_name)


def _promote_config_finding_trace() -> None:
    op.add_column(
        "config_audit_findings", sa.Column("trace_id", sa.Text(), nullable=True)
    )
    op.execute("""
        UPDATE config_audit_findings
        SET trace_id = COALESCE(
            NULLIF(payload_json #>> '{event,metadata,trace_id}', ''),
            NULLIF(payload_json #>> '{event,event_id}', ''),
            finding_id
        )
        """)
    op.alter_column("config_audit_findings", "trace_id", nullable=False)
    op.create_index(
        "ix_config_audit_findings_trace_id",
        "config_audit_findings",
        ["trace_id"],
    )


def _demote_config_finding_trace() -> None:
    op.drop_index(
        "ix_config_audit_findings_trace_id", table_name="config_audit_findings"
    )
    op.drop_column("config_audit_findings", "trace_id")


def _promote_evaluation_queries() -> None:
    op.alter_column(
        "evaluation_runs",
        "run_at",
        existing_type=sa.Text(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=False,
        postgresql_using="run_at::timestamptz",
    )
    op.alter_column(
        "evaluation_runs",
        "created_at",
        existing_type=sa.Text(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=False,
        postgresql_using="created_at::timestamptz",
    )
    op.alter_column("evaluation_runs", "created_at", server_default=sa.text("now()"))
    op.add_column("evaluation_runs", sa.Column("dataset_id", sa.Text()))
    op.add_column("evaluation_runs", sa.Column("dataset_version", sa.Text()))
    op.add_column("evaluation_runs", sa.Column("regression_status", sa.Text()))
    op.execute("""
        UPDATE evaluation_runs
        SET dataset_id = NULLIF(payload_json ->> 'dataset_id', ''),
            dataset_version = NULLIF(payload_json ->> 'dataset_version', ''),
            regression_status = NULLIF(
                payload_json #>> '{regression_gate,status}', ''
            )
        """)
    op.create_check_constraint(
        "ck_evaluation_runs_regression_status",
        "evaluation_runs",
        "regression_status IS NULL OR "
        "regression_status IN ('passed', 'failed', 'skipped')",
    )
    op.create_index(
        "ix_evaluation_runs_dataset_run_at",
        "evaluation_runs",
        ["dataset_id", "dataset_version", "run_at"],
    )


def _demote_evaluation_queries() -> None:
    op.drop_index("ix_evaluation_runs_dataset_run_at", table_name="evaluation_runs")
    op.drop_constraint(
        "ck_evaluation_runs_regression_status", "evaluation_runs", type_="check"
    )
    op.drop_column("evaluation_runs", "regression_status")
    op.drop_column("evaluation_runs", "dataset_version")
    op.drop_column("evaluation_runs", "dataset_id")
    op.alter_column("evaluation_runs", "created_at", server_default=None)
    for column_name in ("created_at", "run_at"):
        op.alter_column(
            "evaluation_runs",
            column_name,
            existing_type=sa.DateTime(timezone=True),
            type_=sa.Text(),
            existing_nullable=False,
            postgresql_using=f"{column_name}::text",
        )


def _promote_adapter_status() -> None:
    op.alter_column(
        "adapter_statuses",
        "updated_at",
        existing_type=sa.Text(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=False,
        postgresql_using="updated_at::timestamptz",
    )
    op.alter_column("adapter_statuses", "updated_at", server_default=sa.text("now()"))
    op.add_column("adapter_statuses", sa.Column("status", sa.Text()))
    op.add_column("adapter_statuses", sa.Column("loaded", sa.Boolean()))
    op.add_column("adapter_statuses", sa.Column("runtime_id", sa.Text()))
    op.add_column("adapter_statuses", sa.Column("agent_id", sa.Text()))
    op.add_column("adapter_statuses", sa.Column("enforcement_mode", sa.Text()))
    op.add_column(
        "adapter_statuses",
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
    )
    op.execute("""
        UPDATE adapter_statuses
        SET status = COALESCE(NULLIF(payload_json ->> 'status', ''), 'unknown'),
            loaded = COALESCE((payload_json ->> 'loaded')::boolean, false),
            runtime_id = NULLIF(payload_json ->> 'runtime_id', ''),
            agent_id = NULLIF(payload_json ->> 'agent_id', ''),
            enforcement_mode = NULLIF(payload_json ->> 'enforcement_mode', ''),
            last_heartbeat_at = NULLIF(
                payload_json ->> 'last_heartbeat_at', ''
            )::timestamptz
        """)
    op.alter_column("adapter_statuses", "status", nullable=False)
    op.alter_column("adapter_statuses", "loaded", nullable=False)
    op.create_check_constraint(
        "ck_adapter_statuses_status",
        "adapter_statuses",
        "status IN ('loaded', 'not_loaded', 'error', 'unknown')",
    )
    op.create_check_constraint(
        "ck_adapter_statuses_enforcement_mode",
        "adapter_statuses",
        "enforcement_mode IS NULL OR "
        "enforcement_mode IN ('enforce', 'observe', 'disabled')",
    )
    op.create_index("ix_adapter_statuses_status", "adapter_statuses", ["status"])
    op.create_index(
        "ix_adapter_statuses_runtime_agent",
        "adapter_statuses",
        ["runtime_id", "agent_id"],
    )
    op.create_index(
        "ix_adapter_statuses_last_heartbeat_at",
        "adapter_statuses",
        ["last_heartbeat_at"],
        postgresql_where=sa.text("last_heartbeat_at IS NOT NULL"),
    )


def _demote_adapter_status() -> None:
    op.drop_index(
        "ix_adapter_statuses_last_heartbeat_at", table_name="adapter_statuses"
    )
    op.drop_index("ix_adapter_statuses_runtime_agent", table_name="adapter_statuses")
    op.drop_index("ix_adapter_statuses_status", table_name="adapter_statuses")
    op.drop_constraint(
        "ck_adapter_statuses_enforcement_mode", "adapter_statuses", type_="check"
    )
    op.drop_constraint("ck_adapter_statuses_status", "adapter_statuses", type_="check")
    for column_name in (
        "last_heartbeat_at",
        "enforcement_mode",
        "agent_id",
        "runtime_id",
        "loaded",
        "status",
    ):
        op.drop_column("adapter_statuses", column_name)
    op.alter_column("adapter_statuses", "updated_at", server_default=None)
    op.alter_column(
        "adapter_statuses",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.Text(),
        existing_nullable=False,
        postgresql_using="updated_at::text",
    )
