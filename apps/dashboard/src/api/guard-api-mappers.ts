import type {
  GuardApprovalDto,
  GuardAuditEventDto,
  GuardEvalMetricsDto,
  GuardPolicyBundleDto,
  GuardPolicyHistoryDto,
  GuardTraceDetailDto,
} from "./guard-api-types.ts";
import type {
  ApprovalRequest,
  AuditEventRow,
  EvalMetrics,
  PolicyHistoryEntry,
  PolicySummary,
  TraceDetail,
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

function readString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function fallbackResourceTargets(dto: GuardAuditEventDto): string[] {
  const metadata = dto.metadata;
  const recipient = readString(metadata.recipient);
  if (recipient) {
    const channel = readString(metadata.channel);
    return [channel ? `${channel}/${recipient}` : recipient];
  }

  const namespace = readString(metadata.memory_namespace);
  const key = readString(metadata.memory_key);
  if (namespace || key) return [[namespace, key].filter(Boolean).join("/")];

  const model = readString(metadata.model);
  if (model) return [model];

  const sourceToolCallId = readString(metadata.source_tool_call_id);
  if (sourceToolCallId) return [sourceToolCallId];

  return [];
}

function mapResourceTargets(dto: GuardAuditEventDto): string[] {
  const targets = dto.resource_targets.length
    ? dto.resource_targets
    : fallbackResourceTargets(dto);
  return targets.map((target) => maskSensitiveText(target));
}

function summarizeTargets(targets: string[]): string {
  if (!targets.length) return "未提供";
  if (targets.length === 1) return targets[0]!;
  return `${targets[0]} 等 ${targets.length} 项`;
}

function actionName(dto: GuardAuditEventDto): string {
  return (
    readString(dto.metadata.action_name) ??
    readString(dto.metadata.tool) ??
    readString(dto.metadata.source_tool) ??
    dto.event_type
  );
}

function stageName(dto: GuardAuditEventDto): string {
  if (
    dto.stage === "before_tool_call" &&
    dto.event_type !== "tool_call_proposed"
  ) {
    return dto.event_type;
  }
  return dto.stage;
}

export function mapAuditEvent(dto: GuardAuditEventDto): AuditEventRow {
  const resourceTargets = mapResourceTargets(dto);
  const action = actionName(dto);
  return {
    id: dto.audit_id,
    occurredAt: dto.timestamp,
    time: formatEventTime(dto.timestamp),
    decision: dto.decision,
    riskScore: dto.risk_score,
    severity: dto.severity,
    blocked: dto.blocked,
    runtime: dto.runtime,
    stage: stageName(dto),
    tool: action,
    resource: summarizeTargets(resourceTargets),
    resourceTargets,
    reason: dto.reason,
    traceId: dto.trace_id,
    caseId: dto.case_id,
    approvalId: dto.links.approval_id,
    ruleHits: dto.rule_hits,
    userTask:
      typeof dto.metadata.user_task === "string"
        ? dto.metadata.user_task
        : null,
    agentAction: dto.summary ? maskSensitiveText(dto.summary) : action,
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
    subjectId: dto.subject_id ?? dto.tool_call_id,
    subjectType: dto.subject_type ?? "tool_call",
    actionId: dto.action_id ?? dto.tool_call_id,
    actionName: dto.action_name ?? dto.tool,
    userTask: "未提供",
    agentAction: `${dto.tool}(${maskSensitiveText(dto.resource)})`,
    consequence: approvalConsequence(status),
    ruleHits: [],
    approvalNonce: dto.approval_nonce,
    expiresAt: dto.expires_at,
    resolvedAt: dto.resolved_at,
  };
}

function approvalConsequence(status: ApprovalRequest["status"]): string {
  if (status === "allowed") return "该动作已获得一次性放行。";
  if (status === "denied") return "该动作已被拒绝，不会继续执行。";
  if (status === "expired") return "该审批已过期，当前动作不会继续执行。";
  return "允许一次后，当前暂停的工具动作将继续执行。";
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

export function mapTraceDetail(dto: GuardTraceDetailDto): TraceDetail {
  const events = dto.audit_events
    .map(mapAuditEvent)
    .sort(
      (left, right) =>
        Date.parse(left.occurredAt) - Date.parse(right.occurredAt),
    );
  return {
    id: dto.trace_id,
    events,
    approvals: dto.approvals.map(mapApproval),
    metrics: mapMetrics(dto.metrics),
    loadedAt: new Date().toISOString(),
  };
}

export function mapPolicyHistory(
  rows: GuardPolicyHistoryDto[],
): PolicyHistoryEntry[] {
  return rows.map((row) => ({
    revision: row.revision,
    updatedAt: row.updated_at,
    updatedBy: row.updated_by,
    bundleId: row.bundle_id,
    version: row.version,
  }));
}

export function mapPolicySummary(
  dto: GuardPolicyBundleDto,
  history: PolicyHistoryEntry[] = [],
): PolicySummary {
  const latest = history[0] ?? null;
  return {
    bundleId: dto.bundle_id ?? latest?.bundleId ?? "未提供",
    version: dto.version ?? latest?.version ?? "未提供",
    revision: latest?.revision ?? null,
    updatedAt: latest?.updatedAt ?? null,
    updatedBy: latest?.updatedBy ?? null,
    disabledRuleCount: Array.isArray(dto.disabled_rules)
      ? dto.disabled_rules.length
      : 0,
    ruleOverrideCount:
      dto.rule_overrides && typeof dto.rule_overrides === "object"
        ? Object.keys(dto.rule_overrides).length
        : 0,
    toolProfileCount:
      dto.tool_profiles && typeof dto.tool_profiles === "object"
        ? Object.keys(dto.tool_profiles).length
        : 0,
  };
}
