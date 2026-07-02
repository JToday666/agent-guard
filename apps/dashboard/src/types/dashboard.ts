export type DecisionStatus = "allow" | "deny" | "ask";

export type RiskSeverity = "critical" | "high" | "medium" | "low";

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export type RuntimeName = "langgraph" | "openclaw";

export type DataStatus = "idle" | "loading" | "ready" | "stale" | "error";

export interface AuditEventRow {
  id: string;
  occurredAt: string;
  time: string;
  decision: DecisionStatus;
  riskScore: number;
  severity: RiskSeverity;
  blocked: boolean;
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
  status: "blocked" | "paused" | "allowed";
  approvalId?: string;
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
