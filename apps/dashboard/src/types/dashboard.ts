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
  tool: string;
  resource: string;
  reason: string;
  traceId: string;
  caseId: string | null;
  approvalId?: string;
  ruleHits: string[];
  userTask: string | null;
  agentAction: string | null;
  attackType?: string | null;
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
  averageLatencyMs: number | null;
}
