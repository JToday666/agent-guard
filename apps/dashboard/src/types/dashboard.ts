export type DecisionStatus = "allow" | "deny" | "ask";

export type RiskSeverity = "critical" | "high" | "medium" | "low";

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export type RuntimeName = "langgraph" | "openclaw";

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
  caseId: string;
  approvalId?: string;
  ruleHits: string[];
  userTask: string;
  agentAction: string;
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
}

export interface TraceSummary {
  id: string;
  lastEventAt: string;
  caseId: string;
  title: string;
  status: "blocked" | "paused" | "allowed";
  nodes: string[];
  eventId: string;
  approvalId?: string;
}

export interface MetricCard {
  label: string;
  value: string;
  route: string;
  tone: "neutral" | "warning" | "danger" | "success";
}

export interface SystemStatusItem {
  label: string;
  value: string;
  status: "online" | "stale" | "partial" | "offline";
}
