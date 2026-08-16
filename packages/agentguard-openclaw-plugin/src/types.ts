export type JsonObject = Record<string, unknown>;

export type AgentGuardPluginConfig = {
  guardApiBaseUrl: string;
  adapterToken: string;
  enforcementMode: "enforce" | "observe" | "disabled";
  requestTimeoutMs: number;
  approvalPollIntervalMs: number;
  approvalTimeoutMs: number;
  strongApprovalBindingEnabled: boolean;
  /** Trusted local provisioning value; never learned from Guard API output. */
  runtimeBindingId: string;
  diagnosticLogging: boolean;
  agentId: string;
};

/** OpenClaw resolves adapterToken SecretRef to a string before registration. */
export type OpenClawPluginConfigInput =
  | {
      guardApiBaseUrl?: string;
      adapterToken?: string;
      enforcementMode?: AgentGuardPluginConfig["enforcementMode"];
      requestTimeoutMs?: number;
      approvalPollIntervalMs?: number;
      approvalTimeoutMs?: number;
      strongApprovalBindingEnabled?: boolean;
      runtimeBindingId?: string;
      diagnosticLogging?: boolean;
      agentId?: string;
    }
  | undefined;

export type GuardEventType =
  | "tool_call_proposed"
  | "context_assembled"
  | "model_input_prepared"
  | "model_output_produced"
  | "tool_result_produced"
  | "memory_write_proposed"
  | "message_send_proposed";

export type GuardEvent = {
  schema_version: "0.3";
  event_id: string;
  event_type: GuardEventType;
  runtime: "openclaw";
  trace_id: string;
  case_id?: string | null;
  attack_type?: string | null;
  is_malicious?: boolean | null;
  timestamp: string;
  pre_execution: boolean;
  security_context: SecurityContext;
  payload: GuardPayload;
  metadata: JsonObject;
};

export type GuardPayload =
  | ToolCallPayload
  | ContextBuildPayload
  | ModelCallPayload
  | ToolResultPayload
  | MemoryEventPayload
  | MessageSendPayload;

export type SecurityContext = {
  user_task: string;
  source_type: string;
  source_trust: string;
  channel?: string | null;
  sender_id?: string | null;
  conversation_id?: string | null;
  session_key?: string | null;
  session_id?: string | null;
  run_id?: string | null;
  agent_id: string;
  current_step: string;
  model_intent?: string | null;
  context_sources: JsonObject[];
  derived_paths: string[];
  metadata: JsonObject;
};

export type ToolCallPayload = {
  tool: {
    name: string;
    category: string;
    kind?: string | null;
    input_kind?: string | null;
    call_id: string;
  };
  arguments: JsonObject;
  derived_resources: DerivedResource[];
};

export type ContextBuildPayload = {
  sources: Array<{
    source_id: string;
    source_type: string;
    source_trust: string;
    summary: string;
    contains_instruction_like_text: boolean;
    contains_sensitive_data: boolean;
  }>;
  will_enter_context: boolean;
  sanitized: boolean;
};

export type ModelCallPayload = {
  phase: "input" | "output";
  content_preview: string;
  provider?: string | null;
  model?: string | null;
  contains_instruction_like_text: boolean;
  contains_sensitive_data: boolean;
  sanitized: boolean;
  tool_plan: JsonObject[];
};

export type MessageSendPayload = {
  channel: string;
  recipient: string;
  content_preview: string;
  contains_sensitive_data: boolean;
  sanitized: boolean;
  derived_resources: DerivedResource[];
};

export type ToolResultPayload = {
  tool: {
    name: string;
    category: string;
    kind?: string | null;
    input_kind?: string | null;
    call_id: string;
  };
  result: {
    content_preview: string;
    content_type: string;
    size_bytes: number;
  };
  will_enter_context: boolean;
  will_persist: boolean;
  sanitized: boolean;
  contains_sensitive_data: boolean;
  contains_instruction_like_text: boolean;
  derived_resources: DerivedResource[];
};

export type MemoryEventPayload = {
  memory: {
    namespace: string;
    key: string;
    value_preview: string;
    source_trust: string;
    operation: string;
  };
  will_persist: boolean;
  requires_approval: boolean;
};

export type DerivedResource = {
  resource_type: string;
  operation: string;
  target: string;
  data_classification?: string | null;
  direction: string;
};

export type GuardEvaluationResponse = {
  decision: GuardDecision;
  approval: EvaluationApproval | null;
  policy_audit_id?: string | null;
  enforcement_binding?: EnforcementBinding | InvalidEnforcementBinding;
};

/** Local fail-closed sentinel; never serialized or persisted. */
export type InvalidEnforcementBinding = { invalid: true };

/** Server-authored ActionIR binding. The fingerprint is transport-only. */
export type EnforcementBinding = {
  schema_version: "2.1";
  action_id: string;
  authorization_fingerprint: string;
  runtime_binding_id: string;
  requires_execution_lease: true;
};

/** Non-secret lease linkage returned to hooks after the token is discarded. */
export type ExecutionLeaseLinks = {
  leaseId: string;
  consumptionId: string;
};

export type ExecutionLeaseReference = ExecutionLeaseLinks & {
  expiresAt: string;
};

export type EnforcementGateState =
  | "evaluating"
  | "allowed"
  | "approval_pending"
  | "approval_released"
  | "blocked"
  | "timed_out"
  | "binding_failed";

export type BindingCheckStatus =
  | "not_applicable"
  | "not_performed"
  | "passed"
  | "failed"
  | "unknown";

export type LeaseConsumeOutcome =
  | "not_applicable"
  | "not_attempted"
  | "consumed"
  | "expired"
  | "revoked"
  | "rejected"
  | "unknown";

export type Rte05ReasonCode =
  | "rte-05:binding_exact"
  | "rte-05:binding_invalid"
  | "rte-05:binding_mismatch"
  | "rte-05:approval_not_human"
  | "rte-05:approval_not_consumable"
  | "rte-05:approval_not_found"
  | "rte-05:identity_denied"
  | "rte-05:approval_expired"
  | "rte-05:approval_timed_out"
  | "rte-05:lease_consumed"
  | "rte-05:consumption_conflict"
  | "rte-05:lease_rejected"
  | "rte-05:lease_expired"
  | "rte-05:lease_revoked"
  | "rte-05:lease_unavailable"
  | "rte-05:lease_response_invalid"
  | "rte-05:lease_consume_timed_out"
  | "rte-05:multiple_binding_conflict"
  | "rte-05:correlation_capacity_exhausted";

export type RuntimeEnforcementEvidence = {
  gate_state: EnforcementGateState;
  binding_check_status: BindingCheckStatus;
  lease_consume_outcome: LeaseConsumeOutcome;
  reason_codes: Rte05ReasonCode[];
};

export type GuardDecision = {
  decision_id?: string;
  decision: "allow" | "deny" | "ask";
  risk_score?: number;
  severity?: string;
  categories?: string[];
  rule_hits?: Array<{
    rule_id: string;
    rule_name?: string | null;
    severity?: string | null;
    evidence?: string[];
  }>;
  reason: string;
  safe_message?: string | null;
  approval_intent?: JsonObject | null;
  latency_ms?: number | null;
};

export type EvaluationApproval = {
  approval_id: string;
  status: string;
  decision_options: string[];
};

export type ApprovalWaitResponse = {
  status: string;
  decision: "allow_once" | "deny" | null;
  resolution_source?: "human" | "llm" | "system" | null;
};

export type ConfigAuditFinding = {
  finding_id?: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  title: string;
  subject: string;
  description: string;
  evidence?: string[];
  recommendation?: string | null;
};

export type ConfigAuditEvent = {
  event_id?: string;
  runtime: "openclaw";
  target_type: string;
  target_id: string;
  action: string;
  findings: ConfigAuditFinding[];
  metadata?: JsonObject;
  timestamp?: string;
};

export type ConfigAuditResult = {
  decision: "allow" | "block";
  findings: ConfigAuditFinding[];
  reason?: string;
};

export type AuditRecordType =
  | "policy_evaluation"
  | "runtime_outcome"
  | "runtime_observation"
  | "config_audit";

export type AuditEvent = {
  audit_id?: string;
  schema_version: "0.4";
  record_type: AuditRecordType;
  trace_id: string;
  case_id?: string | null;
  runtime: "openclaw";
  timestamp?: string;
  stage: string;
  event_type: string;
  attack_type?: string | null;
  is_malicious?: boolean | null;
  summary: string;
  decision: "allow" | "deny" | "ask" | null;
  risk_score: number | null;
  severity: string | null;
  blocked: boolean | null;
  resource_targets?: string[];
  rule_hits?: string[];
  reason: string;
  links?: Record<string, string>;
  latency_ms?: number | null;
  metadata?: JsonObject;
  evidence?: JsonObject;
};

export type RuntimeReceiptKind =
  | "pre_execution_deny"
  | "approval_release"
  | "tool_result_modified"
  | "tool_result_quarantined"
  | "execution_completed"
  | "execution_failed";

export type RuntimeOutcomeReceipt = Omit<
  AuditEvent,
  | "record_type"
  | "event_type"
  | "decision"
  | "risk_score"
  | "severity"
  | "blocked"
  | "links"
  | "latency_ms"
  | "metadata"
  | "evidence"
> & {
  audit_id: string;
  record_type: "runtime_outcome";
  event_type: "runtime_outcome";
  decision: "allow" | "deny" | "ask";
  risk_score: number;
  severity: "low" | "medium" | "high" | "critical";
  blocked: boolean;
  links: {
    event_id: string;
    decision_id: string;
    policy_audit_id: string;
    action_id?: string;
    approval_id?: string;
    parent_audit_id?: string;
    lease_id?: string;
    consumption_id?: string;
  };
  latency_ms: null;
  metadata: {
    agent_id: string;
    outcome_kind: RuntimeReceiptKind;
  };
  evidence: {
    intervention: JsonObject;
    execution: JsonObject;
    side_effects: JsonObject;
    result: JsonObject;
    approval: JsonObject;
    enforcement?: RuntimeEnforcementEvidence;
  };
};

export type ToolHookResult = {
  params?: JsonObject;
  block?: boolean;
  blockReason?: string;
};

export type MessageHookResult = {
  content?: string;
  cancel?: boolean;
  cancelReason?: string;
  metadata?: JsonObject;
};

export type AdapterHeartbeatInput = {
  pluginVersion: string;
  runtimeVersion?: string | null;
  hooks: string[];
  capabilities: JsonObject;
};
