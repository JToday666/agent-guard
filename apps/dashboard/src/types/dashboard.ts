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
  asrBefore: number | null;
  asrAfter: number | null;
  blockRate: number | null;
  fpr: number | null;
  fnr: number | null;
  averageLatencyMs: number | null;
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
  headHash: string;
  firstBrokenAuditId: string | null;
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
