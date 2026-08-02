export type PolicyDecision = "allow" | "deny" | "ask";

export type DecisionStatus = PolicyDecision | "unknown";

export type RiskSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export type RuntimeName = "langgraph" | "openclaw" | "unknown";

export type DataStatus = "idle" | "loading" | "ready" | "stale" | "error";

export interface AuditEventRow {
  id: string;
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
  tool: string;
  resource: string;
  riskScore: number;
  severity: RiskSeverity;
  reason: string;
  eventId: string;
  traceId: string;
  subjectId?: string;
  subjectType?: string;
  actionId?: string;
  actionName?: string;
  userTask: string;
  agentAction: string;
  consequence: string;
  ruleHits: string[];
  approvalNonce?: string;
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
  recordType: AuditRecordType;
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

export interface EvalMetrics {
  eventCount: number;
  allowCount: number;
  denyCount: number;
  askCount: number;
  blockedCount: number;
  blockRate: number | null;
  fpr: number | null;
  fnr: number | null;
  averageLatencyMs: number | null;
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

export interface EvaluationSummary {
  runId: string | null;
  runAt: string | null;
  datasetId: string | null;
  datasetVersion: string | null;
  datasetLabel: string;
  asrBefore: number | null;
  asrAfter: number | null;
  perAttack: EvaluationAttackMetric[];
  cases: EvaluationCase[];
  blockRate: number | null;
  fpr: number | null;
  fnr: number | null;
  averageLatencyMs: number | null;
}

export interface EvaluationAttackMetric {
  attackType: string;
  asrBefore: number | null;
  asrAfter: number | null;
  reduction: number | null;
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
  metrics: EvalMetrics;
  loadedAt: string;
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
  runtime: string | null;
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
