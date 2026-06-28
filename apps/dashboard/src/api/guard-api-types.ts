import type {
  DecisionStatus,
  RiskSeverity,
  RuntimeName,
} from "../types/dashboard";

export interface GuardAuditEventDto {
  audit_id: string;
  schema_version: string;
  trace_id: string;
  case_id: string | null;
  runtime: RuntimeName;
  timestamp: string;
  stage: string;
  event_type: string;
  attack_type: string | null;
  is_malicious: boolean | null;
  summary: string;
  decision: DecisionStatus;
  risk_score: number;
  severity: RiskSeverity;
  blocked: boolean;
  resource_targets: string[];
  rule_hits: string[];
  reason: string;
  links: Record<string, string>;
  latency_ms: number | null;
  metadata: Record<string, unknown>;
}

export interface GuardApprovalDto {
  approval_id: string;
  trace_id: string;
  subject_id?: string;
  subject_type?: string;
  action_id?: string;
  action_name?: string;
  tool_call_id: string;
  requesting_principal_id: string;
  runtime: RuntimeName;
  agent_id: string;
  status: "pending" | "resolved" | "expired";
  decision_options: Array<"allow_once" | "deny">;
  decision: "allow_once" | "deny" | null;
  tool: string;
  resource: string;
  reason: string;
  risk_score: number;
  severity: RiskSeverity;
  created_at: string;
  expires_at: string | null;
  resolved_at: string | null;
  approval_nonce?: string;
}

export interface GuardEvalMetricsDto {
  event_count: number;
  allow_count: number;
  deny_count: number;
  ask_count: number;
  blocked_count: number;
  block_rate: number | null;
  fpr: number | null;
  fnr: number | null;
  average_latency_ms: number | null;
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
  metrics: GuardEvalMetricsDto;
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
  head_hash: string;
  first_broken_audit_id: string | null;
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
