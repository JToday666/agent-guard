import type {
  GuardAdapterStatusDto,
  GuardApprovalDto,
  GuardAuditEventDto,
  GuardAuditIntegrityDto,
  GuardConfigAuditFindingRecordDto,
  GuardEvalMetricsDto,
  GuardEvaluationRunDto,
  GuardPolicyBundleDto,
  GuardPolicyHistoryDto,
  GuardProvenanceDto,
  GuardTraceDetailDto,
} from "./guard-api-types";
import type {
  AdapterStatus,
  ApprovalRequest,
  AuditEventRow,
  AuditIntegrity,
  ConfigAuditFindingRecord,
  EvalMetrics,
  EvaluationAttackMetric,
  EvaluationCase,
  EvaluationSummary,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode,
  TraceDetail,
} from "../types/dashboard";
import { maskSensitiveText } from "../utils/data-redaction";

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
    eventType: dto.event_type,
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
    isMalicious: dto.is_malicious,
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

function evaluationDatasetLabel(
  datasetId: string | null,
  datasetVersion: string | null,
): string {
  if (datasetId && datasetVersion) return `${datasetId} / ${datasetVersion}`;
  return datasetId ?? datasetVersion ?? "未提供";
}

function metricReduction(
  before: number | null | undefined,
  after: number | null | undefined,
): number | null {
  return before === null ||
    before === undefined ||
    after === null ||
    after === undefined
    ? null
    : before - after;
}

export function emptyEvaluationSummary(
  metrics: EvalMetrics,
): EvaluationSummary {
  return {
    runId: null,
    runAt: null,
    datasetId: null,
    datasetVersion: null,
    datasetLabel: "未提供",
    asrBefore: null,
    asrAfter: null,
    perAttack: [],
    cases: [],
    blockRate: metrics.blockRate,
    fpr: metrics.fpr,
    fnr: metrics.fnr,
    averageLatencyMs: metrics.averageLatencyMs,
  };
}

export function mapEvaluationRun(
  dto: GuardEvaluationRunDto,
  metrics: EvalMetrics,
): EvaluationSummary {
  const datasetId = dto.dataset_id ?? null;
  const datasetVersion = dto.dataset_version ?? null;
  const perAttack: EvaluationAttackMetric[] = Object.entries(
    dto.per_attack ?? {},
  )
    .map(([attackType, summary]) => ({
      attackType,
      asrBefore: summary.asr_before ?? null,
      asrAfter: summary.asr_after ?? null,
      reduction: metricReduction(summary.asr_before, summary.asr_after),
    }))
    .sort((left, right) => {
      const leftValue = left.asrBefore ?? -1;
      const rightValue = right.asrBefore ?? -1;
      return (
        rightValue - leftValue ||
        left.attackType.localeCompare(right.attackType)
      );
    });
  const cases: EvaluationCase[] = (dto.cases ?? []).map((row) => ({
    caseId: row.case_id,
    attackType: row.attack_type,
    runtime: row.runtime,
    expectedDecision: row.expected_decision,
    actualDecision: row.actual_decision,
    blocked: row.blocked,
    attackSuccess: row.attack_success,
    traceId: row.trace_id,
  }));
  return {
    runId: dto.run_id,
    runAt: dto.run_at,
    datasetId,
    datasetVersion,
    datasetLabel: evaluationDatasetLabel(datasetId, datasetVersion),
    asrBefore: dto.asr_before ?? null,
    asrAfter: dto.asr_after ?? null,
    perAttack,
    cases,
    blockRate: metrics.blockRate,
    fpr: metrics.fpr,
    fnr: metrics.fnr,
    averageLatencyMs: metrics.averageLatencyMs,
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

export function mapAuditIntegrity(dto: GuardAuditIntegrityDto): AuditIntegrity {
  return {
    valid: dto.valid,
    eventCount: dto.event_count,
    headHash: dto.head_hash,
    firstBrokenAuditId: dto.first_broken_audit_id,
  };
}

export function mapConfigAuditFindingRecord(
  dto: GuardConfigAuditFindingRecordDto,
): ConfigAuditFindingRecord {
  return {
    runtime: dto.runtime,
    targetType: dto.target_type,
    targetId: dto.target_id,
    traceId: dto.trace_id,
    eventId: dto.event_id,
    timestamp: dto.timestamp,
    finding: {
      findingId: dto.finding.finding_id,
      severity: dto.finding.severity,
      category: dto.finding.category,
      title: dto.finding.title,
      subject: dto.finding.subject,
      description: dto.finding.description,
      evidence: dto.finding.evidence,
      recommendation: dto.finding.recommendation ?? null,
    },
  };
}

export function mapAdapterStatus(dto: GuardAdapterStatusDto): AdapterStatus {
  const expectedHookCount = dto.expected_hook_count;
  const hookCount = dto.hook_count;
  return {
    status: dto.status,
    loaded: dto.loaded,
    hookCount,
    expectedHookCount,
    hookCoverage:
      hookCount === null || expectedHookCount <= 0
        ? null
        : hookCount / expectedHookCount,
    lastVerifiedAt: dto.last_verified_at,
    lastHeartbeatAt: dto.last_heartbeat_at ?? null,
    error: dto.error,
    source: dto.source,
    runtime: dto.runtime ?? null,
    runtimeId: dto.runtime_id ?? null,
    agentId: dto.agent_id ?? null,
    pluginVersion: dto.plugin_version ?? null,
    runtimeVersion: dto.runtime_version ?? null,
    capabilities: dto.capabilities ?? {},
    hooks: dto.hooks ?? [],
    failClosedStages: dto.fail_closed_stages ?? [],
  };
}

export function mapProvenance(dto: GuardProvenanceDto): ProvenanceGraph {
  return {
    traceId: dto.trace_id,
    nodes: dto.nodes.map(
      (n): ProvenanceNode => ({
        nodeId: n.node_id,
        traceId: n.trace_id,
        kind: n.kind,
        refId: n.ref_id,
        label: n.label,
        timestamp: n.timestamp,
        metadata: n.metadata,
      }),
    ),
    edges: dto.edges.map(
      (e): ProvenanceEdge => ({
        edgeId: e.edge_id,
        traceId: e.trace_id,
        sourceNodeId: e.source_node_id,
        targetNodeId: e.target_node_id,
        relation: e.relation,
        timestamp: e.timestamp,
        metadata: e.metadata,
      }),
    ),
  };
}
