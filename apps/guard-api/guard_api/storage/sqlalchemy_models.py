"""SQLAlchemy table metadata for Guard API / Control Plane storage."""

from __future__ import annotations

from sqlalchemy import Column, Index, Integer, MetaData, Table, Text
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    Column("audit_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("chain_id", Text, nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("prev_hash", Text, nullable=True),
    Column("event_hash", Text, nullable=False),
    Index("ix_audit_events_created_at", "created_at"),
    Index("ix_audit_events_chain_sequence", "chain_id", "sequence"),
    Index("ix_audit_events_event_hash", "event_hash"),
)

audit_integrity_heads = Table(
    "audit_integrity_heads",
    metadata,
    Column("chain_id", Text, primary_key=True),
    Column("sequence", Integer, nullable=False),
    Column("event_hash", Text, nullable=True),
    Column("updated_at", Text, nullable=False),
)

provenance_nodes = Table(
    "provenance_nodes",
    metadata,
    Column("node_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("ref_id", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_provenance_nodes_trace_id", "trace_id"),
    Index("ix_provenance_nodes_kind", "kind"),
)

provenance_edges = Table(
    "provenance_edges",
    metadata,
    Column("edge_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("source_node_id", Text, nullable=False),
    Column("target_node_id", Text, nullable=False),
    Column("relation", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_provenance_edges_trace_id", "trace_id"),
    Index("ix_provenance_edges_relation", "relation"),
)

config_audit_findings = Table(
    "config_audit_findings",
    metadata,
    Column("finding_id", Text, primary_key=True),
    Column("runtime", Text, nullable=False),
    Column("target_type", Text, nullable=False),
    Column("target_id", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_config_audit_findings_runtime", "runtime"),
    Index("ix_config_audit_findings_target", "target_type", "target_id"),
    Index("ix_config_audit_findings_severity", "severity"),
)

memory_guard_changes = Table(
    "memory_guard_changes",
    metadata,
    Column("change_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("namespace", Text, nullable=False),
    Column("key", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
    Index("ix_memory_guard_changes_trace_id", "trace_id"),
    Index("ix_memory_guard_changes_status", "status"),
    Index("ix_memory_guard_changes_namespace_key", "namespace", "key"),
)

action_critic_reviews = Table(
    "action_critic_reviews",
    metadata,
    Column("review_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("event_id", Text, nullable=False),
    Column("verdict", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_action_critic_reviews_trace_id", "trace_id"),
    Index("ix_action_critic_reviews_event_id", "event_id"),
    Index("ix_action_critic_reviews_verdict", "verdict"),
)

evaluation_runs = Table(
    "evaluation_runs",
    metadata,
    Column("run_id", Text, primary_key=True),
    Column("run_at", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_evaluation_runs_run_at", "run_at"),
)

adapter_statuses = Table(
    "adapter_statuses",
    metadata,
    Column("adapter_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("updated_at", Text, nullable=False),
    Index("ix_adapter_statuses_updated_at", "updated_at"),
)

credentials = Table(
    "credentials",
    metadata,
    Column("credential_id", Text, primary_key=True),
    Column("token_hash", Text, nullable=False),
    Column("principal_type", Text, nullable=False),
    Column("principal_id", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("runtime", Text, nullable=True),
    Column("agent_id", Text, nullable=True),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text, nullable=True),
    Column("revoked_at", Text, nullable=True),
    Index("ix_credentials_token_hash", "token_hash"),
    Index("ix_credentials_principal", "principal_type", "principal_id"),
    Index("ix_credentials_runtime_agent", "runtime", "agent_id"),
    Index("ix_credentials_revoked_at", "revoked_at"),
)

approval_requests = Table(
    "approval_requests",
    metadata,
    Column("approval_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Index("ix_approval_requests_status_created_at", "status", "created_at"),
)

policy_snapshots = Table(
    "policy_snapshots",
    metadata,
    Column("policy_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("updated_at", Text, nullable=False),
    Column("updated_by", Text, nullable=False),
    Index("ix_policy_snapshots_updated_at", "updated_at"),
)

policy_snapshot_history = Table(
    "policy_snapshot_history",
    metadata,
    Column("revision", Integer, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("updated_at", Text, nullable=False),
    Column("updated_by", Text, nullable=False),
    Index("ix_policy_snapshot_history_updated_at", "updated_at"),
)

launch_codes = Table(
    "launch_codes",
    metadata,
    Column("code_hash", Text, primary_key=True),
    Column("expires_at", Text, nullable=False),
    Column("used_at", Text, nullable=True),
    Index("ix_launch_codes_expires_at", "expires_at"),
    Index("ix_launch_codes_used_at", "used_at"),
)

browser_sessions = Table(
    "browser_sessions",
    metadata,
    Column("session_hash", Text, primary_key=True),
    Column("csrf_token", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("revoked_at", Text, nullable=True),
    Index("ix_browser_sessions_expires_at", "expires_at"),
    Index("ix_browser_sessions_revoked_at", "revoked_at"),
)

approval_nonces = Table(
    "approval_nonces",
    metadata,
    Column("nonce_hash", Text, primary_key=True),
    Column("approval_id", Text, nullable=False),
    Column("session_hash", Text, nullable=False),
    Column("subject_id", Text, nullable=False),
    Column("tool_call_id", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("used_at", Text, nullable=True),
    Index("ix_approval_nonces_approval_id", "approval_id"),
    Index("ix_approval_nonces_session_hash", "session_hash"),
    Index("ix_approval_nonces_subject_id", "subject_id"),
    Index("ix_approval_nonces_expires_at", "expires_at"),
    Index("ix_approval_nonces_used_at", "used_at"),
)
