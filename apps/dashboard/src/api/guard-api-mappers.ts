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
import { OPENCLAW_REQUIRED_HOOK_COUNT } from "../../../../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import type {
  AdapterStatus,
  AggregateMetrics,
  ApprovalRequest,
  AuditEventRow,
  AuditIntegrity,
  AuditRecordType,
  ConfigAuditFindingRecord,
  EvaluationAttackMetric,
  EvaluationCase,
  EvaluationRun,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode,
  TraceDetail,
} from "../types/dashboard";
import { maskSensitiveText } from "../utils/data-redaction.ts";

const eventTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const legacyPolicyEventTypes = new Set([
  "context_assembled",
  "memory_write_proposed",
  "message_send_proposed",
  "model_input_prepared",
  "model_output_produced",
  "tool_call_proposed",
  "tool_result_produced",
]);

function formatEventTime(timestamp: string): string {
  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) return timestamp;
  return eventTimeFormatter.format(value);
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function readRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function readArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function readNullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readNullableBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function readBoolean(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readDecision(value: unknown): AuditEventRow["decision"] {
  return value === "allow" || value === "ask" || value === "deny" ? value : "unknown";
}

function readSeverity(value: unknown): AuditEventRow["severity"] {
  return value === "critical" || value === "high" || value === "medium" || value === "low"
    ? value
    : "unknown";
}

function readRuntime(value: unknown): AuditEventRow["runtime"] {
  return value === "langgraph" || value === "openclaw" ? value : "unknown";
}

function readRecordType(
  value: unknown,
  eventType: string,
  decision: AuditEventRow["decision"],
): AuditRecordType {
  if (
    value === "policy_evaluation" ||
    value === "runtime_outcome" ||
    value === "runtime_observation" ||
    value === "config_audit" ||
    value === "unknown"
  ) {
    return value;
  }
  if (eventType === "runtime_outcome") return "runtime_outcome";
  if (eventType === "runtime_observation") return "runtime_observation";
  if (eventType === "config_audit") return "config_audit";
  return decision !== "unknown" && legacyPolicyEventTypes.has(eventType)
    ? "policy_evaluation"
    : "unknown";
}

function fallbackResourceTargets(metadata: Record<string, unknown>): string[] {
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

function mapResourceTargets(dto: GuardAuditEventDto, metadata: Record<string, unknown>): string[] {
  const explicitTargets = readStringArray(dto.resource_targets);
  const targets = explicitTargets.length ? explicitTargets : fallbackResourceTargets(metadata);
  return targets.map((target) => maskSensitiveText(target));
}

function summarizeTargets(targets: string[]): string {
  if (!targets.length) return "未提供";
  if (targets.length === 1) return targets[0]!;
  return `${targets[0]} 等 ${targets.length} 项`;
}

function actionName(dto: GuardAuditEventDto, metadata: Record<string, unknown>): string {
  return (
    readString(metadata.action_name) ??
    readString(metadata.tool) ??
    readString(metadata.source_tool) ??
    readString(dto.event_type) ??
    "未提供"
  );
}

function stageName(dto: GuardAuditEventDto): string {
  const stage = readString(dto.stage) ?? "未提供";
  const eventType = readString(dto.event_type) ?? stage;
  if (stage === "before_tool_call" && eventType !== "tool_call_proposed") {
    return eventType;
  }
  return stage;
}

export function mapAuditEvent(dto: GuardAuditEventDto): AuditEventRow {
  const metadata = readRecord(dto.metadata);
  const links = readRecord(dto.links);
  const resourceTargets = mapResourceTargets(dto, metadata);
  const action = actionName(dto, metadata);
  const timestamp = readString(dto.timestamp) ?? "";
  const summary = readString(dto.summary);
  const decision = readDecision(dto.decision);
  const eventType = readString(dto.event_type) ?? "未提供";
  return {
    id: readString(dto.audit_id) ?? "未提供",
    auditSequence: readNullableNumber(readRecord(dto.integrity).sequence),
    eventId: readString(links.event_id),
    decisionId: readString(links.decision_id),
    actionId: readString(links.action_id),
    recordType: readRecordType(dto.record_type, eventType, decision),
    occurredAt: timestamp,
    time: formatEventTime(timestamp),
    decision,
    riskScore: readNullableNumber(dto.risk_score),
    severity: readSeverity(dto.severity),
    blocked: readNullableBoolean(dto.blocked),
    runtime: readRuntime(dto.runtime),
    stage: stageName(dto),
    eventType,
    tool: action,
    resource: summarizeTargets(resourceTargets),
    resourceTargets,
    reason: readString(dto.reason) ?? "未提供",
    traceId: readString(dto.trace_id) ?? "",
    caseId: readString(dto.case_id),
    approvalId: readString(links.approval_id) ?? undefined,
    ruleHits: readStringArray(dto.rule_hits),
    userTask: readString(metadata.user_task),
    agentAction: summary ? maskSensitiveText(summary) : action,
    attackType: readString(dto.attack_type),
    isMalicious: typeof dto.is_malicious === "boolean" ? dto.is_malicious : null,
    latencyMs: readNullableNumber(dto.latency_ms),
    raw: dto,
  };
}

export function mapApproval(dto: GuardApprovalDto): ApprovalRequest {
  const tool = readString(dto.tool) ?? "未提供";
  const resource = readString(dto.resource) ?? "未提供";
  const toolCallId = readString(dto.tool_call_id) ?? "未提供";
  const status: ApprovalRequest["status"] =
    dto.status === "expired"
      ? "expired"
      : dto.status === "pending"
        ? "pending"
        : dto.decision === "allow_once"
          ? "allowed"
          : "denied";

  return {
    id: readString(dto.approval_id) ?? "未提供",
    createdAt: readString(dto.created_at) ?? "",
    status,
    tool,
    resource: maskSensitiveText(resource),
    riskScore: readNumber(dto.risk_score),
    severity: readSeverity(dto.severity),
    reason: readString(dto.reason) ?? "未提供",
    eventId: "",
    traceId: readString(dto.trace_id) ?? "",
    subjectId: readString(dto.subject_id) ?? toolCallId,
    subjectType: readString(dto.subject_type) ?? "tool_call",
    actionId: readString(dto.action_id) ?? toolCallId,
    actionName: readString(dto.action_name) ?? tool,
    userTask: "未提供",
    agentAction: `${tool}(${maskSensitiveText(resource)})`,
    consequence: approvalConsequence(status),
    ruleHits: [],
    approvalNonce: readString(dto.approval_nonce) ?? undefined,
    expiresAt: readString(dto.expires_at),
    resolvedAt: readString(dto.resolved_at),
  };
}

function approvalConsequence(status: ApprovalRequest["status"]): string {
  if (status === "allowed") return "该动作已获得一次性放行。";
  if (status === "denied") return "该动作的本次授权已被拒绝；实际执行结果以运行时回执为准。";
  if (status === "expired") return "该审批已过期，当前动作不会继续执行。";
  return "允许一次后，当前暂停的工具动作将继续执行。";
}

export function mapAggregateMetrics(
  dto: GuardEvalMetricsDto,
  kind: AggregateMetrics["scope"]["kind"] = "aggregate_history",
): AggregateMetrics {
  const metrics = readRecord(dto);
  return {
    scope: {
      kind,
      source: "legacy_metrics_api",
      from: null,
      to: null,
      deduplication: "backend_unspecified",
    },
    reportedEventCount: readNumber(metrics.event_count),
    allowCount: readNumber(metrics.allow_count),
    denyCount: readNumber(metrics.deny_count),
    askCount: readNumber(metrics.ask_count),
    reportedInterventionCount: readNumber(metrics.blocked_count),
    reportedInterventionRate: readNullableNumber(metrics.block_rate),
    reportedFpr: readNullableNumber(metrics.fpr),
    reportedFnr: readNullableNumber(metrics.fnr),
    reportedAverageLatencyMs: readNullableNumber(metrics.average_latency_ms),
  };
}

function evaluationDatasetLabel(datasetId: string | null, datasetVersion: string | null): string {
  if (datasetId && datasetVersion) return `${datasetId} / ${datasetVersion}`;
  return datasetId ?? datasetVersion ?? "未提供";
}

function metricReduction(
  before: number | null | undefined,
  after: number | null | undefined,
): number | null {
  return before === null || before === undefined || after === null || after === undefined
    ? null
    : before - after;
}

export function emptyEvaluationRun(): EvaluationRun {
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
  };
}

export function mapEvaluationRun(dto: GuardEvaluationRunDto): EvaluationRun {
  const datasetId = readString(dto.dataset_id);
  const datasetVersion = readString(dto.dataset_version);
  const perAttack: EvaluationAttackMetric[] = Object.entries(readRecord(dto.per_attack))
    .map(([attackType, summary]) => {
      const values = readRecord(summary);
      const asrBefore = readNullableNumber(values.asr_before);
      const asrAfter = readNullableNumber(values.asr_after);
      return {
        attackType,
        asrBefore,
        asrAfter,
        reduction: metricReduction(asrBefore, asrAfter),
      };
    })
    .sort((left, right) => {
      const leftValue = left.asrBefore ?? -1;
      const rightValue = right.asrBefore ?? -1;
      return rightValue - leftValue || left.attackType.localeCompare(right.attackType);
    });
  const cases: EvaluationCase[] = readArray(dto.cases).map((item) => {
    const row = readRecord(item);
    return {
      caseId: readString(row.case_id) ?? "未提供",
      attackType: readString(row.attack_type) ?? "未提供",
      runtime: readString(row.runtime) ?? "未提供",
      expectedDecision: readDecision(row.expected_decision),
      actualDecision: readDecision(row.actual_decision),
      blocked: readBoolean(row.blocked),
      attackSuccess: readBoolean(row.attack_success),
      traceId: readString(row.trace_id) ?? "",
    };
  });
  return {
    runId: readString(dto.run_id) ?? "未提供",
    runAt: readString(dto.run_at) ?? null,
    datasetId,
    datasetVersion,
    datasetLabel: evaluationDatasetLabel(datasetId, datasetVersion),
    asrBefore: readNullableNumber(dto.asr_before),
    asrAfter: readNullableNumber(dto.asr_after),
    perAttack,
    cases,
  };
}

export function mapTraceDetail(dto: GuardTraceDetailDto): TraceDetail {
  const events = readArray(dto.audit_events)
    .map((row) => mapAuditEvent(row as GuardAuditEventDto))
    .sort((left, right) => Date.parse(left.occurredAt) - Date.parse(right.occurredAt));
  return {
    id: readString(dto.trace_id) ?? "",
    events,
    approvals: readArray(dto.approvals).map((row) => mapApproval(row as GuardApprovalDto)),
    aggregateMetrics: mapAggregateMetrics(dto.metrics, "trace_history"),
    loadedAt: new Date().toISOString(),
  };
}

export function mapPolicyHistory(rows: GuardPolicyHistoryDto[]): PolicyHistoryEntry[] {
  return readArray(rows).map((item) => {
    const row = readRecord(item);
    return {
      revision: readNumber(row.revision),
      updatedAt: readString(row.updated_at) ?? "",
      updatedBy: readString(row.updated_by) ?? "未提供",
      bundleId: readString(row.bundle_id) ?? "未提供",
      version: readString(row.version) ?? "未提供",
    };
  });
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
    disabledRuleCount: Array.isArray(dto.disabled_rules) ? dto.disabled_rules.length : 0,
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
  const integrity = readRecord(dto);
  return {
    valid: readBoolean(integrity.valid),
    eventCount: readNumber(integrity.event_count),
    headHash: readString(integrity.head_hash),
    firstBrokenAuditId: readString(integrity.first_broken_audit_id),
  };
}

export function mapConfigAuditFindingRecord(
  dto: GuardConfigAuditFindingRecordDto,
): ConfigAuditFindingRecord {
  const finding = readRecord(dto.finding);
  return {
    runtime: readString(dto.runtime) ?? "未提供",
    targetType: readString(dto.target_type) ?? "未提供",
    targetId: readString(dto.target_id) ?? "未提供",
    traceId: readString(dto.trace_id) ?? "",
    eventId: readString(dto.event_id) ?? "",
    timestamp: readString(dto.timestamp) ?? "",
    finding: {
      findingId: readString(finding.finding_id) ?? "未提供",
      severity: readSeverity(finding.severity),
      category: readString(finding.category) ?? "未分类",
      title: readString(finding.title) ?? "未命名发现项",
      subject: readString(finding.subject) ?? "未提供",
      description: readString(finding.description) ?? "未提供",
      evidence: readStringArray(finding.evidence),
      recommendation: readString(finding.recommendation),
    },
  };
}

export function mapAdapterStatus(dto: GuardAdapterStatusDto): AdapterStatus {
  const expectedHookCount = readNumber(dto.expected_hook_count, OPENCLAW_REQUIRED_HOOK_COUNT);
  const hookCount = readNullableNumber(dto.hook_count);
  return {
    status:
      dto.status === "loaded" ||
      dto.status === "not_loaded" ||
      dto.status === "error" ||
      dto.status === "unknown"
        ? dto.status
        : "unknown",
    loaded: readBoolean(dto.loaded),
    hookCount,
    expectedHookCount,
    hookCoverage:
      hookCount === null || expectedHookCount <= 0 ? null : hookCount / expectedHookCount,
    lastVerifiedAt: readString(dto.last_verified_at),
    lastHeartbeatAt: readString(dto.last_heartbeat_at),
    error: readString(dto.error),
    source: readString(dto.source),
    runtime: readString(dto.runtime),
    runtimeId: readString(dto.runtime_id),
    agentId: readString(dto.agent_id),
    pluginVersion: readString(dto.plugin_version),
    runtimeVersion: readString(dto.runtime_version),
    capabilities: readRecord(dto.capabilities),
    hooks: readStringArray(dto.hooks),
    failClosedStages: readStringArray(dto.fail_closed_stages),
  };
}

export function mapProvenance(dto: GuardProvenanceDto): ProvenanceGraph {
  return {
    traceId: readString(dto.trace_id) ?? "",
    nodes: readArray(dto.nodes).map((item): ProvenanceNode => {
      const n = readRecord(item);
      return {
        nodeId: readString(n.node_id) ?? "node",
        traceId: readString(n.trace_id) ?? readString(dto.trace_id) ?? "",
        kind: readString(n.kind) ?? "event",
        refId: readString(n.ref_id) ?? "",
        label: readString(n.label) ?? "未提供",
        timestamp: readString(n.timestamp) ?? "",
        metadata: readRecord(n.metadata),
      };
    }),
    edges: readArray(dto.edges).map((item): ProvenanceEdge => {
      const e = readRecord(item);
      return {
        edgeId: readString(e.edge_id) ?? "edge",
        traceId: readString(e.trace_id) ?? readString(dto.trace_id) ?? "",
        sourceNodeId: readString(e.source_node_id) ?? "",
        targetNodeId: readString(e.target_node_id) ?? "",
        relation: readString(e.relation) ?? "",
        timestamp: readString(e.timestamp) ?? "",
        metadata: readRecord(e.metadata),
      };
    }),
  };
}
