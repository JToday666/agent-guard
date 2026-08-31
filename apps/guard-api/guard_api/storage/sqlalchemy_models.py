"""SQLAlchemy table metadata for Guard API / Control Plane storage."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    Column("audit_id", Text, primary_key=True),
    Column("payload_json", JSONB, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column(
        "ingested_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    ),
    Column("record_type", Text, nullable=False),
    Column("trace_id", Text, nullable=False),
    Column("case_id", Text, nullable=True),
    Column("runtime", Text, nullable=False),
    Column("decision", Text, nullable=True),
    Column("event_id", Text, nullable=True),
    Column("decision_id", Text, nullable=True),
    Column("is_malicious", Boolean, nullable=True),
    Column("latency_ms", Integer, nullable=True),
    Column("chain_id", Text, nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("prev_hash", Text, nullable=True),
    Column("event_hash", Text, nullable=False),
    CheckConstraint("sequence > 0", name="ck_audit_events_sequence_positive"),
    CheckConstraint(
        "record_type IN ('policy_evaluation', 'runtime_outcome', "
        "'runtime_observation', 'config_audit')",
        name="ck_audit_events_record_type",
    ),
    CheckConstraint(
        "decision IS NULL OR decision IN ('allow', 'ask', 'deny')",
        name="ck_audit_events_decision",
    ),
    CheckConstraint(
        "latency_ms IS NULL OR latency_ms >= 0",
        name="ck_audit_events_latency_nonnegative",
    ),
    Index("ux_audit_events_chain_sequence", "chain_id", "sequence", unique=True),
    Index("ix_audit_events_event_hash", "event_hash"),
    Index("ix_audit_events_trace_sequence", "trace_id", "sequence"),
    Index("ix_audit_events_runtime_sequence", "runtime", "sequence"),
    Index(
        "ix_audit_events_case_sequence",
        "case_id",
        "sequence",
        postgresql_where=text("case_id IS NOT NULL"),
    ),
    Index(
        "ix_audit_events_decision_sequence",
        "decision",
        "sequence",
        postgresql_where=text("decision IS NOT NULL"),
    ),
    Index(
        "ix_audit_events_policy_occurred_sequence",
        "occurred_at",
        "sequence",
        postgresql_where=text("record_type = 'policy_evaluation'"),
    ),
    Index("ix_audit_events_ingested_at", "ingested_at"),
)

audit_integrity_heads = Table(
    "audit_integrity_heads",
    metadata,
    Column("chain_id", Text, primary_key=True),
    Column("sequence", BigInteger, nullable=False),
    Column("event_hash", Text, nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

provenance_nodes = Table(
    "provenance_nodes",
    metadata,
    Column("node_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("ref_id", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
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
    Column("created_at", DateTime(timezone=True), nullable=False),
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
    Column("trace_id", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Index("ix_config_audit_findings_runtime", "runtime"),
    Index("ix_config_audit_findings_target", "target_type", "target_id"),
    Index("ix_config_audit_findings_trace_id", "trace_id"),
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
    Column("created_at", DateTime(timezone=True), nullable=False),
    Index("ix_action_critic_reviews_trace_id", "trace_id"),
    Index("ix_action_critic_reviews_event_id", "event_id"),
    Index("ix_action_critic_reviews_verdict", "verdict"),
)

evaluation_runs = Table(
    "evaluation_runs",
    metadata,
    Column("run_id", Text, primary_key=True),
    Column("run_at", DateTime(timezone=True), nullable=False),
    Column("dataset_id", Text, nullable=True),
    Column("dataset_version", Text, nullable=True),
    Column("regression_status", Text, nullable=True),
    Column("payload_json", JSONB, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    ),
    CheckConstraint(
        "regression_status IS NULL OR regression_status IN ('passed', 'failed', 'skipped')",
        name="ck_evaluation_runs_regression_status",
    ),
    Index("ix_evaluation_runs_run_at", "run_at"),
    Index(
        "ix_evaluation_runs_dataset_run_at",
        "dataset_id",
        "dataset_version",
        "run_at",
    ),
)

adapter_statuses = Table(
    "adapter_statuses",
    metadata,
    Column("adapter_id", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("loaded", Boolean, nullable=False),
    Column("runtime_id", Text, nullable=True),
    Column("agent_id", Text, nullable=True),
    Column("enforcement_mode", Text, nullable=True),
    Column("last_heartbeat_at", DateTime(timezone=True), nullable=True),
    Column("payload_json", JSONB, nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    ),
    CheckConstraint(
        "status IN ('loaded', 'not_loaded', 'error', 'unknown')",
        name="ck_adapter_statuses_status",
    ),
    CheckConstraint(
        "enforcement_mode IS NULL OR enforcement_mode IN ('enforce', 'observe', 'disabled')",
        name="ck_adapter_statuses_enforcement_mode",
    ),
    Index("ix_adapter_statuses_updated_at", "updated_at"),
    Index("ix_adapter_statuses_status", "status"),
    Index(
        "ix_adapter_statuses_runtime_agent",
        "runtime_id",
        "agent_id",
    ),
    Index(
        "ix_adapter_statuses_last_heartbeat_at",
        "last_heartbeat_at",
        postgresql_where=text("last_heartbeat_at IS NOT NULL"),
    ),
)

product_runtime_statuses_v2 = Table(
    "product_runtime_statuses_v2",
    metadata,
    Column("runtime", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("runtime_binding_id", Text, nullable=False),
    Column("profile_id", Text, nullable=False),
    Column(
        "write_sequence",
        BigInteger,
        Identity(always=True),
        nullable=False,
    ),
    Column("status", Text, nullable=False),
    Column("loaded", Boolean, nullable=False),
    Column("runtime_id", Text, nullable=False),
    Column("enforcement_mode", Text, nullable=False),
    Column("last_heartbeat_at", DateTime(timezone=True), nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.statement_timestamp(),
    ),
    CheckConstraint(
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
    CheckConstraint(
        "status IN ('loaded', 'not_loaded', 'error', 'unknown')",
        name="ck_product_runtime_statuses_v2_status",
    ),
    CheckConstraint(
        "loaded = (status = 'loaded')",
        name="ck_product_runtime_statuses_v2_loaded_status",
    ),
    CheckConstraint(
        "enforcement_mode IN ('enforce', 'observe', 'disabled')",
        name="ck_product_runtime_statuses_v2_enforcement_mode",
    ),
    PrimaryKeyConstraint(
        "runtime",
        "agent_id",
        "runtime_binding_id",
        "profile_id",
        name="pk_product_runtime_statuses_v2",
    ),
    UniqueConstraint(
        "write_sequence",
        name="uq_product_runtime_statuses_v2_write_sequence",
    ),
    Index(
        "ix_product_runtime_statuses_v2_runtime_sequence",
        "runtime",
        text("write_sequence DESC"),
    ),
    Index(
        "ix_product_runtime_statuses_v2_runtime_heartbeat",
        "runtime",
        text("last_heartbeat_at DESC"),
        text("write_sequence DESC"),
    ),
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
    CheckConstraint(
        "revoked_at IS NOT NULL OR "
        "(principal_type = 'component' AND role = 'adapter' "
        "AND runtime IS NOT NULL AND agent_id IS NOT NULL)",
        name="ck_credentials_active_adapter_identity",
    ),
    Index("ix_credentials_token_hash", "token_hash", unique=True),
    Index("ix_credentials_principal", "principal_type", "principal_id"),
    Index("ix_credentials_runtime_agent", "runtime", "agent_id"),
    Index("ix_credentials_revoked_at", "revoked_at"),
)

approval_requests = Table(
    "approval_requests",
    metadata,
    Column("approval_id", Text, primary_key=True),
    Column("trace_id", Text, nullable=False),
    Column("runtime", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("subject_id", Text, nullable=False),
    Column("action_id", Text, nullable=False),
    Column("payload_json", JSONB, nullable=False),
    Column("decision", Text, nullable=True),
    Column("resolution_source", Text, nullable=True),
    Column("resolved_by", Text, nullable=True),
    Column("resolution_reason", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True), nullable=True),
    CheckConstraint(
        "decision IS NULL OR decision IN ('allow_once', 'deny')",
        name="ck_approval_requests_decision",
    ),
    CheckConstraint(
        "resolution_source IS NULL OR resolution_source IN ('human', 'llm', 'system')",
        name="ck_approval_requests_resolution_source",
    ),
    CheckConstraint(
        "(resolved_at IS NULL AND decision IS NULL) OR "
        "(resolved_at IS NOT NULL AND decision IS NOT NULL)",
        name="ck_approval_requests_resolution_state",
    ),
    CheckConstraint("expires_at > created_at", name="ck_approval_requests_expiry"),
    Index(
        "ix_approval_requests_pending_created_at",
        "resolved_at",
        "expires_at",
        "created_at",
    ),
    Index("ix_approval_requests_trace_created_at", "trace_id", "created_at"),
    Index(
        "ix_approval_requests_runtime_agent_created_at",
        "runtime",
        "agent_id",
        "created_at",
    ),
)

# RTE-05 private ActionIR enforcement binding.  This table is intentionally
# absent from all public query/read models; it is consumed only by the guarded
# approval lease transaction.
enforcement_bindings = Table(
    "enforcement_bindings",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("policy_audit_id", Text, nullable=False, unique=True),
    Column("approval_id", Text, nullable=False, unique=True),
    Column("action_id", Text, nullable=False),
    Column("action_type", Text, nullable=False),
    Column("authorization_fingerprint", Text, nullable=False),
    Column("runtime_binding_id", Text, nullable=False),
    Column("scope_digest", Text, nullable=False),
    Column("principal_id", Text, nullable=False),
    Column("runtime", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("policy_revision", Text, nullable=False),
    Column("requires_execution_lease", Boolean, nullable=False),
    Column("grant_id", Text, nullable=True),
    Column("created_at", Text, nullable=False),
    ForeignKeyConstraint(
        ["approval_id"],
        ["approval_requests.approval_id"],
        name="fk_enforcement_bindings_approval_id",
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["grant_id"],
        ["capability_grant_runtime.grant_id"],
        name="fk_enforcement_bindings_grant_id",
        ondelete="RESTRICT",
    ),
    CheckConstraint(
        "requires_execution_lease",
        name="ck_enforcement_bindings_requires_execution_lease",
    ),
    Index("ix_enforcement_bindings_runtime_agent", "runtime", "agent_id"),
    Index("ix_enforcement_bindings_grant_id", "grant_id"),
)

# V21-06 runtime grant authority, extended by RTE-05 with a canonical digest
# of the complete CapabilityGrant.  The digest supports exact registration
# replay/conflict checks without persisting a broad JSON serializer output.
capability_grant_runtime = Table(
    "capability_grant_runtime",
    metadata,
    Column("grant_id", Text, primary_key=True),
    Column("scope_digest", Text, nullable=False),
    Column("remaining_uses", Integer, nullable=False),
    Column("expires_at", Text, nullable=True),
    Column("authorization_fingerprint", Text, nullable=True),
    Column("status", Text, nullable=False),
    Column("registration_digest", Text, nullable=True),
    CheckConstraint(
        "remaining_uses >= 0",
        name="ck_capability_grant_runtime_remaining_uses_non_negative",
    ),
    CheckConstraint(
        "status IN ('active', 'expired', 'revoked')",
        name="ck_capability_grant_runtime_status",
    ),
    Index("ix_capability_grant_runtime_scope", "scope_digest"),
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

task_facts = Table(
    "task_facts",
    metadata,
    Column("task_id", Text, primary_key=True),
    Column("revision", Integer, primary_key=True),
    Column("scope_digest", Text, nullable=False),
    Column("scope_key_id", Text, nullable=False),
    Column("principal_id", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("task_digest", Text, nullable=False),
    Column("task_summary", Text, nullable=False),
    Column("canonical_payload", JSONB, nullable=False),
    Column("request_digest", Text, nullable=False),
    Column("expected_revision", Integer, nullable=False),
    Column("producer", Text, nullable=False),
    Column("authority", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    CheckConstraint("revision > 0", name="ck_task_facts_revision_positive"),
    CheckConstraint(
        "status IN ('active', 'cancelled', 'superseded')",
        name="ck_task_facts_status",
    ),
    CheckConstraint(
        "producer = 'guard_api_task_ingress' AND authority = 'authoritative'",
        name="ck_task_facts_authority_root",
    ),
    Index("ix_task_facts_principal_id", "principal_id"),
    Index("ix_task_facts_scope_key_id", "scope_key_id"),
    Index("ix_task_facts_scope_digest", "scope_digest"),
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
