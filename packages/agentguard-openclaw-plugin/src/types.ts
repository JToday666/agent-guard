export type JsonObject = Record<string, unknown>;

export type AgentGuardPluginConfig = {
  guardApiBaseUrl: string;
  adapterToken: string;
  requestTimeoutMs: number;
  approvalPollIntervalMs: number;
  approvalTimeoutMs: number;
  approvalWaitBudgetMs: number;
  diagnosticLogging: boolean;
};

export type OpenClawPluginConfigInput = Partial<AgentGuardPluginConfig> | undefined;

export type GuardEvent = {
  schema_version: "0.3";
  event_id: string;
  event_type: "tool_call_proposed" | "message_send_proposed" | "tool_result_produced";
  runtime: "openclaw";
  trace_id: string;
  case_id?: string | null;
  attack_type?: string | null;
  is_malicious?: boolean | null;
  timestamp: string;
  pre_execution: boolean;
  security_context: SecurityContext;
  payload: ToolCallPayload | MessageSendPayload | ToolResultPayload;
  metadata: JsonObject;
};

export type SecurityContext = {
  user_task: string;
  source_type: string;
  source_trust: string;
  channel?: string | null;
  sender_id?: string | null;
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
};

export type GuardDecision = {
  decision: "allow" | "deny" | "ask";
  reason: string;
  safe_message?: string | null;
};

export type EvaluationApproval = {
  approval_id: string;
  status: string;
  decision_options: string[];
};

export type ApprovalWaitResponse = {
  status: string;
  decision: "allow_once" | "deny" | null;
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

export type AuditEvent = {
  audit_id?: string;
  schema_version: "0.3";
  trace_id: string;
  case_id?: string | null;
  runtime: "openclaw";
  timestamp?: string;
  stage: string;
  event_type: string;
  attack_type?: string | null;
  is_malicious?: boolean | null;
  summary: string;
  decision: "allow" | "deny" | "ask";
  risk_score: number;
  severity: string;
  blocked: boolean;
  resource_targets?: string[];
  rule_hits?: string[];
  reason: string;
  links?: Record<string, string>;
  latency_ms?: number | null;
  metadata?: JsonObject;
};

export type ToolHookResult = {
  block?: boolean;
  blockReason?: string;
};

export type MessageHookResult = {
  content?: string;
  cancel?: boolean;
  cancelReason?: string;
  metadata?: JsonObject;
};
