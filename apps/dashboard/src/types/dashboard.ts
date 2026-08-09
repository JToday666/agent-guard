export type PolicyDecision = "allow" | "deny" | "ask";

export type DecisionStatus = PolicyDecision | "unknown";

export type RiskSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export type RuntimeName = "langgraph" | "openclaw" | "unknown";

export type DataStatus = "idle" | "loading" | "ready" | "stale" | "error";

export interface AuditEventRow {
  id: string;
  auditSequence: number | null;
  eventId: string | null;
  decisionId: string | null;
  actionId: string | null;
  recordType: AuditRecordType;
  occurredAt: string;
  time: string;
  decision: DecisionStatus;
  riskScore: number | null;
  severity: RiskSeverity;
  blocked: boolean | null;
  runtime: RuntimeName;
  stage: string;
  eventType: string;
  tool: string;
  resource: string;
  resourceTargets: string[];
  reason: string;
  traceId: string;
  caseId: string | null;
  approvalId?: string;
  ruleHits: string[];
  userTask: string | null;
  agentAction: string | null;
  attackType?: string | null;
  isMalicious?: boolean | null;
  latencyMs?: number | null;
  raw?: unknown;
}

export interface ApprovalRequest {
  id: string;
  createdAt: string;
  status: ApprovalStatus;
  resource: string;
  riskScore: number;
  severity: RiskSeverity;
  reason: string;
  eventId: string;
  traceId: string;
  subjectId: string;
  subjectType: string;
  actionId: string;
  actionName: string;
  userTask: string;
  agentAction: string;
  consequence: string;
  ruleHits: string[];
  expiresAt?: string | null;
  resolvedAt?: string | null;
}

export interface TraceSummary {
  id: string;
  lastEventAt: string;
  caseId: string;
  title: string;
  status: "denied" | "paused" | "allowed" | "unknown";
  approvalId?: string;
}

export type AuditRecordType =
  "policy_evaluation" | "runtime_outcome" | "runtime_observation" | "config_audit" | "unknown";

export type InterventionType =
  | "pre_execution_deny"
  | "tool_result_quarantine"
  | "model_output_revision"
  | "audit_observation"
  | "approval_release"
  | "none"
  | "unknown";

export type ExecutionStatus = "not_invoked" | "executed" | "failed" | "unknown";

export type ResultDisposition =
  "passed_through" | "quarantined" | "modified" | "discarded" | "not_applicable" | "unknown";

export type EvidenceAvailability = "recorded" | "not_recorded" | "not_applicable";

export type SideEffectMeasurementStatus =
  "measured" | "not_measured" | "not_applicable" | "unknown";

export interface SideEffectEvidence {
  measurementStatus: SideEffectMeasurementStatus;
  count: number | null;
  summary: string | null;
}

export interface EvidenceSource {
  type: string | null;
  label: string | null;
  trustLevel: string | null;
}

export interface NormalizedResourceEvidence {
  id: string;
  type: string | null;
  operation: string | null;
  sensitivity: string | null;
  value: string;
}

export interface RuleHitEvidence {
  ruleId: string;
  name: string | null;
  severity: RiskSeverity;
  decision: DecisionStatus;
  reason: string | null;
  evidence: string[];
}

export interface RiskFactorEvidence {
  id: string;
  category: string | null;
  label: string;
  score: number | null;
  severity: RiskSeverity;
  decision: DecisionStatus;
  reason: string | null;
}

export interface RiskBreakdownEvidence {
  aggregationMethod: string | null;
  finalScore: number | null;
  finalDecision: DecisionStatus;
  factors: RiskFactorEvidence[];
}

export interface PolicyReferenceEvidence {
  bundleId: string | null;
  version: string | null;
  revision: number | null;
  digest: string | null;
}

export interface ExecutionEvidence {
  status: ExecutionStatus;
  receiptRecorded: boolean;
  invokedAt: string | null;
  completedAt: string | null;
  error: string | null;
  toolResultEnteredContext: boolean | null;
  persisted: boolean | null;
}

export interface ApprovalEvidence {
  approvalId: string | null;
  status: ApprovalStatus | "not_required" | "unknown";
  resolvedAt: string | null;
}

export interface AuditChainEvidence {
  globalStatus: "valid" | "invalid" | "unknown";
  traceMetadataStatus: "complete" | "partial" | "unknown";
  chainIndex: number | null;
  entryHash: string | null;
  previousHash: string | null;
  returnedEventCount: number;
  mayBeTruncated: boolean;
}

export interface NormalizedAuditEvidence {
  auditId: string;
  eventId: string | null;
  decisionId: string | null;
  actionId: string | null;
  policyAuditId: string | null;
  parentAuditId: string | null;
  recordType: AuditRecordType;
  stage: string;
  eventType: string;
  occurredAt: string;
  originalTask: string | null;
  source: EvidenceSource;
  contextSources: string[];
  modelIntent: string | null;
  toolName: string | null;
  toolArguments: Record<string, unknown> | null;
  resources: NormalizedResourceEvidence[];
  ruleHits: RuleHitEvidence[];
  risk: RiskBreakdownEvidence;
  policy: PolicyReferenceEvidence;
  decision: DecisionStatus;
  severity: RiskSeverity;
  decisionReason: string | null;
  intervention: InterventionType;
  execution: ExecutionEvidence;
  sideEffects: SideEffectEvidence;
  resultDisposition: ResultDisposition;
  approval: ApprovalEvidence;
  resultSummary: string | null;
  chainIndex: number | null;
  entryHash: string | null;
  previousHash: string | null;
  raw: unknown;
}

export type ExecutionApprovalStatus =
  "not_required" | "pending" | "allowed_once" | "denied" | "expired" | "unknown";

export type ExecutionPhase =
  | "proposed"
  | "evaluated"
  | "checked"
  | "waiting_approval"
  | "approval_released"
  | "waiting_receipt"
  | "terminal";

export type ExecutionStepKind = "action" | "checkpoint";

export type ExecutionStepCategory =
  | "context"
  | "model_input"
  | "model_output"
  | "tool"
  | "tool_result"
  | "memory"
  | "message"
  | "unknown";

export type ExecutionReceiptExpectation = "required" | "not_required" | "unknown";

export interface ExecutionPolicyCheck {
  auditId: string;
  decisionId: string | null;
  decision: DecisionStatus;
  riskScore: number | null;
  severity: RiskSeverity;
  reason: string | null;
  ruleHits: RuleHitEvidence[];
  occurredAt: string;
}

export interface ExecutionStepEvent {
  auditId: string;
  eventId: string | null;
  eventType: string;
  label: string;
  recordType: AuditRecordType;
  occurredAt: string;
  decision: DecisionStatus;
  execution: ExecutionStatus;
  intervention: InterventionType;
}

export interface ExecutionStepViewModel {
  stepId: string;
  kind: ExecutionStepKind;
  category: ExecutionStepCategory;
  receiptExpectation: ExecutionReceiptExpectation;
  settled: boolean;
  actionId: string | null;
  eventId: string | null;
  eventIds: string[];
  decisionId: string | null;
  actionName: string | null;
  displayName: string;
  resourceSummary: string | null;
  decision: DecisionStatus;
  approval: ExecutionApprovalStatus;
  approvalId: string | null;
  execution: ExecutionStatus;
  intervention: InterventionType;
  phase: ExecutionPhase;
  statusLabel: string;
  decisionReason: string | null;
  riskScore: number | null;
  severity: RiskSeverity;
  firstSeenAt: string;
  lastUpdatedAt: string;
  primaryAuditId: string | null;
  policyChecks: ExecutionPolicyCheck[];
  auditIds: string[];
  observationAuditIds: string[];
  outcomeAuditIds: string[];
  events: ExecutionStepEvent[];
}

export type TraceLifecycleState =
  "observing" | "waiting_approval" | "completed" | "failed" | "cancelled";

export interface ExecutionTraceViewModel {
  steps: ExecutionStepViewModel[];
  lifecycleState: TraceLifecycleState;
  lifecycleLabel: string;
  lifecycleAuditId: string | null;
}

export interface EvidenceFact {
  id:
    | "decision"
    | "intervention"
    | "execution"
    | "side_effects"
    | "result_disposition"
    | "audit_integrity";
  label: string;
  value: string;
  detail: string;
  availability: EvidenceAvailability;
  tone: "neutral" | "protective" | "success" | "warning" | "danger";
}

export type EvidenceStageId = "input_trust" | "context_intent" | "tool_policy" | "outcome_audit";

export interface EvidenceStageItem {
  id: string;
  eventId: string | null;
  label: string;
  value: string;
  detail: string | null;
  availability: EvidenceAvailability;
}

export interface EvidenceStage {
  id: EvidenceStageId;
  index: number;
  eyebrow: string;
  title: string;
  items: EvidenceStageItem[];
}

export interface TraceEvidenceConclusion {
  title: string;
  reason: string;
  outcome: string;
  confidence: "confirmed" | "partial" | "unknown";
}

export interface TraceEvidenceViewModel {
  traceId: string;
  caseId: string | null;
  startedAt: string | null;
  endedAt: string | null;
  originalAuditCount: number;
  logicalAuditCount: number;
  duplicatePolicyAuditCount: number;
  primaryEventId: string | null;
  conclusion: TraceEvidenceConclusion;
  facts: EvidenceFact[];
  stages: EvidenceStage[];
  events: NormalizedAuditEvidence[];
  primary: NormalizedAuditEvidence | null;
  integrity: AuditChainEvidence;
}

export interface AuditWindowScope {
  kind: "audit_window";
  snapshotId: string;
  outcomesAsOf: string;
  order: "audit_sequence";
  limit: number;
  returnedRecordCount: number;
  hasMore: boolean;
  nextCursor: string | null;
  sequenceFrom: number | null;
  sequenceTo: number | null;
  occurredFrom: string | null;
  occurredTo: string | null;
  filters: {
    traceId: string | null;
    caseId: string | null;
    runtime: string | null;
    decision: string | null;
  };
}

export interface WindowMetrics {
  metricVersion: "policy_evaluation.v2";
  deduplication: "logical_policy_evaluation";
  evaluationCount: number;
  unknownDecisionCount: number;
  allowCount: number;
  denyCount: number;
  askCount: number;
  interventionCount: number;
  interventionRate: number | null;
  policyDenyRate: number | null;
  approvalTriggerRate: number | null;
  policyFpr: number | null;
  policyFnr: number | null;
  benignLabelCount: number;
  maliciousLabelCount: number;
  unlabeledCount: number;
  averageDecisionLatencyMs: number | null;
  latencySampleCount: number;
  duplicatePolicyRecordCount: number;
  unkeyedPolicyRecordCount: number;
}

export interface AuditWindow {
  scope: AuditWindowScope;
  events: AuditEventRow[];
  metrics: WindowMetrics;
}

export interface DecisionTrendPoint {
  label: string;
  allow: number;
  ask: number;
  deny: number;
}

export interface HealthStatus {
  api: "online" | "offline" | "unknown";
  database: "online" | "offline" | "unknown";
  checkedAt: string | null;
}

export interface ApprovalResolution {
  approvalId: string;
  status: string;
  decision: "allow_once" | "deny";
}

export interface EvaluationRun {
  runId: string | null;
  runAt: string | null;
  datasetId: string | null;
  datasetVersion: string | null;
  datasetLabel: string;
  asrBefore: number | null;
  asrAfter: number | null;
  perAttack: EvaluationAttackMetric[];
  cases: EvaluationCase[];
}

export interface EvaluationAttackMetric {
  attackType: string;
  asrBefore: number | null;
  asrAfter: number | null;
}

export interface EvaluationCase {
  caseId: string;
  attackType: string;
  runtime: string;
  expectedDecision: DecisionStatus;
  actualDecision: DecisionStatus;
  blocked: boolean;
  attackSuccess: boolean;
  traceId: string;
}

export interface TraceDetail {
  id: string;
  events: AuditEventRow[];
  approvals: ApprovalRequest[];
  auditWindow: TraceAuditWindow;
  loadedAt: string;
}

export interface TraceAuditWindow {
  limit: number;
  returnedCount: number;
  hasMore: boolean | null;
}

export interface TracePollingState {
  status: "idle" | "checking" | "live" | "paused" | "backoff" | "stopped";
  lastCheckedAt: string | null;
  retryInMs: number | null;
}

export interface PolicyHistoryEntry {
  revision: number;
  updatedAt: string;
  updatedBy: string;
  bundleId: string;
  version: string;
}

export interface PolicySummary {
  bundleId: string;
  version: string;
  revision: number | null;
  updatedAt: string | null;
  updatedBy: string | null;
  disabledRuleCount: number;
  ruleOverrideCount: number;
  toolProfileCount: number;
}

export interface AuditIntegrity {
  valid: boolean;
  eventCount: number;
  headHash: string | null;
  firstBrokenAuditId: string | null;
}

export interface ConfigAuditFinding {
  findingId: string;
  severity: RiskSeverity;
  category: string;
  title: string;
  subject: string;
  description: string;
  evidence: string[];
  recommendation: string | null;
}

export interface ConfigAuditFindingRecord {
  runtime: string;
  targetType: string;
  targetId: string;
  traceId: string;
  eventId: string;
  timestamp: string;
  finding: ConfigAuditFinding;
}

export interface AdapterStatus {
  status: "loaded" | "not_loaded" | "error" | "unknown";
  loaded: boolean;
  hookCount: number | null;
  expectedHookCount: number;
  hookCoverage: number | null;
  lastVerifiedAt: string | null;
  lastHeartbeatAt: string | null;
  error: string | null;
  source: string | null;
  runtimeId: string | null;
  agentId: string | null;
  pluginVersion: string | null;
  runtimeVersion: string | null;
  capabilities: Record<string, unknown>;
  hooks: string[];
  failClosedStages: string[];
}

export interface ProvenanceNode {
  nodeId: string;
  traceId: string;
  kind: string;
  refId: string;
  label: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface ProvenanceEdge {
  edgeId: string;
  traceId: string;
  sourceNodeId: string;
  targetNodeId: string;
  relation: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface ProvenanceGraph {
  traceId: string;
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
}
