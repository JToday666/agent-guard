import type {
  AuditRecordType,
  PolicyDecision,
  RiskSeverity,
  RuntimeName,
} from "../types/dashboard";

export interface GuardAuditEventDto {
  audit_id: string;
  schema_version: string;
  trace_id: string;
  case_id: string | null;
  runtime: Exclude<RuntimeName, "unknown">;
  timestamp: string;
  stage: string;
  event_type: string;
  attack_type: string | null;
  is_malicious: boolean | null;
  summary: string;
  decision: PolicyDecision | null;
  risk_score: number | null;
  severity: Exclude<RiskSeverity, "unknown"> | null;
  blocked: boolean | null;
  resource_targets: string[];
  rule_hits: string[];
  reason: string;
  links: Record<string, string>;
  latency_ms: number | null;
  metadata: Record<string, unknown>;
  integrity?: GuardAuditIntegrityMetadataDto;
  record_type?: AuditRecordType;
  evidence?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GuardAuditIntegrityMetadataDto {
  sequence: number;
  prev_hash: string | null;
  event_hash: string;
  canonicalization: string;
}

export interface GuardApprovalDto {
  approval_id: string;
  trace_id: string;
  subject_id: string;
  subject_type: string;
  action_id: string;
  action_name: string;
  requesting_principal_id: string;
  runtime: Exclude<RuntimeName, "unknown">;
  agent_id: string;
  status: "pending" | "resolved" | "expired";
  decision_options: Array<"allow_once" | "deny">;
  decision: "allow_once" | "deny" | null;
  resource: string;
  reason: string;
  risk_score: number;
  severity: Exclude<RiskSeverity, "unknown">;
  created_at: string;
  expires_at: string;
  resolved_at: string | null;
}

export interface GuardAuditWindowScopeDto {
  kind: "audit_window";
  snapshot_id: string;
  outcomes_as_of: string;
  order: "audit_sequence";
  limit: number;
  returned_record_count: number;
  has_more: boolean;
  next_cursor: string | null;
  sequence_from: number | null;
  sequence_to: number | null;
  occurred_from: string | null;
  occurred_to: string | null;
  filters: {
    trace_id: string | null;
    case_id: string | null;
    runtime: string | null;
    decision: string | null;
  };
}

export interface GuardPolicyMetricsDto {
  metric_version: "policy_evaluation.v2";
  evaluation_count: number;
  unknown_decision_count: number;
  allow_count: number;
  ask_count: number;
  deny_count: number;
  intervention_count: number;
  intervention_rate: number | null;
  policy_deny_rate: number | null;
  approval_trigger_rate: number | null;
  policy_intervention_fpr: number | null;
  policy_intervention_fnr: number | null;
  benign_label_count: number;
  malicious_label_count: number;
  unlabeled_count: number;
  average_decision_latency_ms: number | null;
  latency_sample_count: number;
  duplicate_policy_record_count: number;
  unkeyed_policy_record_count: number;
  deduplication: "logical_policy_evaluation";
}

export interface GuardAuditWindowDto {
  scope: GuardAuditWindowScopeDto;
  events: GuardAuditEventDto[];
  policy_metrics: GuardPolicyMetricsDto;
}

export interface GuardEvaluationAttackSummaryDto {
  asr_before: number | null;
  asr_after: number | null;
}

export interface GuardEvaluationCaseDto {
  case_id: string;
  attack_type: string;
  runtime: string;
  expected_decision: PolicyDecision;
  actual_decision: PolicyDecision;
  blocked: boolean;
  attack_success: boolean;
  trace_id: string;
}

export interface GuardEvaluationRunDto {
  run_id: string;
  run_at: string;
  dataset_id?: string | null;
  dataset_version?: string | null;
  asr_before?: number | null;
  asr_after?: number | null;
  per_attack?: Record<string, GuardEvaluationAttackSummaryDto>;
  per_family?: Record<string, unknown>;
  per_rule?: Record<string, unknown>;
  cases?: GuardEvaluationCaseDto[];
  [key: string]: unknown;
}

export interface GuardApprovalResolutionDto {
  approval_id: string;
  status: string;
  decision: "allow_once" | "deny";
}

export interface BrowserSessionDto {
  authenticated: boolean;
  expires_at: string;
  csrf_token: string;
}

export interface GuardTraceDetailDto {
  trace_id: string;
  audit_events: GuardAuditEventDto[];
  approvals: GuardApprovalDto[];
  audit_window?: {
    limit?: number;
    returned_count?: number;
    has_more?: boolean;
  };
}

export interface GuardPolicyBundleDto {
  bundle_id?: string;
  version?: string;
  disabled_rules?: string[];
  rule_overrides?: Record<string, unknown>;
  tool_profiles?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GuardPolicyHistoryDto {
  revision: number;
  updated_at: string;
  updated_by: string;
  bundle_id: string;
  version: string;
}

export interface GuardAuditIntegrityDto {
  valid: boolean;
  event_count: number;
  head_hash: string | null;
  first_broken_audit_id: string | null;
}

export interface GuardConfigAuditFindingDto {
  finding_id: string;
  severity: Exclude<RiskSeverity, "unknown">;
  category: string;
  title: string;
  subject: string;
  description: string;
  evidence: string[];
  recommendation?: string | null;
}

export interface GuardConfigAuditFindingRecordDto {
  runtime: string;
  target_type: string;
  target_id: string;
  trace_id: string;
  event_id: string;
  timestamp: string;
  finding: GuardConfigAuditFindingDto;
}

export interface GuardAdapterStatusDto {
  status: "loaded" | "not_loaded" | "error" | "unknown";
  loaded: boolean;
  hook_count: number | null;
  expected_hook_count: number | null;
  last_verified_at: string | null;
  last_heartbeat_at?: string | null;
  error: string | null;
  source: string | null;
  runtime_id?: string | null;
  agent_id?: string | null;
  plugin_version?: string | null;
  runtime_version?: string | null;
  capabilities?: Record<string, unknown>;
  hooks?: string[];
  fail_closed_stages?: string[];
  [key: string]: unknown;
}

export interface GuardProvenanceNodeDto {
  node_id: string;
  trace_id: string;
  kind: string;
  ref_id: string;
  label: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface GuardProvenanceEdgeDto {
  edge_id: string;
  trace_id: string;
  source_node_id: string;
  target_node_id: string;
  relation: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface GuardProvenanceDto {
  trace_id: string;
  nodes: GuardProvenanceNodeDto[];
  edges: GuardProvenanceEdgeDto[];
}

export interface GuardHealthDto {
  status: string;
  database?: string;
}
