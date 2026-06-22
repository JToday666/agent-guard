import type {
  GuardApprovalDto,
  GuardAuditEventDto,
  GuardEvalMetricsDto,
} from "./guard-api-types.ts";
import type {
  ApprovalRequest,
  AuditEventRow,
  EvalMetrics,
} from "../types/dashboard.ts";
import { maskSensitiveText } from "../utils/data-redaction.ts";

function formatEventTime(timestamp: string): string {
  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) return timestamp;
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(value);
}

export function mapAuditEvent(dto: GuardAuditEventDto): AuditEventRow {
  return {
    id: dto.audit_id,
    occurredAt: dto.timestamp,
    time: formatEventTime(dto.timestamp),
    decision: dto.decision,
    riskScore: dto.risk_score,
    severity: dto.severity,
    blocked: dto.blocked,
    runtime: dto.runtime,
    stage: dto.stage,
    tool: typeof dto.metadata.tool === "string" ? dto.metadata.tool : "未提供",
    resource: dto.resource_targets[0]
      ? maskSensitiveText(dto.resource_targets[0])
      : "未提供",
    reason: dto.reason,
    traceId: dto.trace_id,
    caseId: dto.case_id,
    approvalId: dto.links.approval_id,
    ruleHits: dto.rule_hits,
    userTask:
      typeof dto.metadata.user_task === "string"
        ? dto.metadata.user_task
        : null,
    agentAction: dto.summary || null,
    attackType: dto.attack_type,
    latencyMs: dto.latency_ms,
    raw: dto,
  };
}

export function mapApproval(dto: GuardApprovalDto): ApprovalRequest {
  const status: ApprovalRequest["status"] =
    dto.status === "expired"
      ? "expired"
      : dto.status === "pending"
        ? "pending"
        : dto.decision === "allow_once"
          ? "allowed"
          : "denied";

  return {
    id: dto.approval_id,
    createdAt: dto.created_at,
    status,
    tool: dto.tool,
    resource: maskSensitiveText(dto.resource),
    riskScore: dto.risk_score,
    severity: dto.severity,
    reason: dto.reason,
    eventId: "",
    traceId: dto.trace_id,
    userTask: "未提供",
    agentAction: `${dto.tool}(${maskSensitiveText(dto.resource)})`,
    consequence:
      dto.decision === "allow_once"
        ? "该动作已获得一次性放行。"
        : "允许一次后，当前暂停的工具动作将继续执行。",
    ruleHits: [],
    approvalNonce: dto.approval_nonce,
    expiresAt: dto.expires_at,
    resolvedAt: dto.resolved_at,
  };
}

export function mapMetrics(dto: GuardEvalMetricsDto): EvalMetrics {
  return {
    eventCount: dto.event_count,
    allowCount: dto.allow_count,
    denyCount: dto.deny_count,
    askCount: dto.ask_count,
    blockedCount: dto.blocked_count,
    blockRate: dto.block_rate,
    fpr: dto.fpr,
    fnr: dto.fnr,
    averageLatencyMs: dto.average_latency_ms,
  };
}
