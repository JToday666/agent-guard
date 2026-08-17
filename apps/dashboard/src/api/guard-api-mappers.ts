import type {
  GuardAdapterStatusDto,
  GuardApprovalDto,
  GuardAuditEventDto,
  GuardAuditIntegrityDto,
  GuardAuditWindowDto,
  GuardConfigAuditFindingRecordDto,
  GuardEvaluationRunDto,
  GuardHealthDto,
  GuardPolicyBundleDto,
  GuardPolicyHistoryDto,
  GuardProvenanceDto,
  GuardTraceDetailDto,
} from "./guard-api-types";
import { OPENCLAW_REQUIRED_HOOK_COUNT } from "../../../../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import { mergeApprovalsWithAuditEvidence } from "../data/approvals/evidence.ts";
import { projectPreEnableReport } from "../data/evaluation/pre-enable-report.ts";
import type {
  AdapterStatus,
  ApprovalDecision,
  ApprovalRequest,
  ApprovalRequestEvidence,
  AuditEventRow,
  AuditIntegrity,
  AuditRecordType,
  AuditWindow,
  ConfigAuditFindingRecord,
  EvaluationAttackMetric,
  EvaluationCase,
  EvaluationRun,
  HealthStatus,
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

function readApprovalDecision(value: unknown): ApprovalDecision | null {
  return value === "allow_once" || value === "deny" ? value : null;
}

function readApprovalDecisionOptions(value: unknown): ApprovalDecision[] {
  return [
    ...new Set(
      readArray(value).flatMap((item) => {
        const decision = readApprovalDecision(item);
        return decision ? [decision] : [];
      }),
    ),
  ];
}

function readApprovalRuleIds(value: unknown): string[] {
  return [
    ...new Set(
      readArray(value).flatMap((item) => {
        if (typeof item === "string" && item) return [item];
        const ruleId = readString(readRecord(item).rule_id);
        return ruleId ? [ruleId] : [];
      }),
    ),
  ];
}

function mapApprovalEvidence(value: unknown): ApprovalRequestEvidence | null {
  const evidence = readRecord(value);
  const event = readRecord(evidence.event);
  const decision = readRecord(evidence.decision);
  const policy = readRecord(evidence.policy);
  const eventId = readString(event.event_id) ?? readString(evidence.event_id);
  const decisionId = readString(decision.decision_id) ?? readString(evidence.decision_id);
  const ruleHits = readApprovalRuleIds(decision.rule_hits ?? evidence.rule_hits);
  const eventType = readString(event.event_type);
  const taskPreview = readString(event.user_task);
  const sourceType = readString(event.source_type);
  const sourceTrust = readString(event.source_trust);
  const resourceTargets = readStringArray(event.resource_targets).map((target) =>
    maskSensitiveText(target),
  );
  const officialDecision = readDecision(decision.decision);
  const riskScore = readNullableNumber(decision.risk_score);
  const severity = readSeverity(decision.severity);
  const reason = readString(decision.reason);
  const bundleId = readString(policy.bundle_id);
  const version = readString(policy.version);
  const revision =
    typeof policy.revision === "number" && Number.isInteger(policy.revision)
      ? policy.revision
      : null;
  const digest = readString(policy.canonical_digest) ?? readString(policy.digest);
  const hasRecognizedEvidence =
    eventId !== null ||
    decisionId !== null ||
    eventType !== null ||
    taskPreview !== null ||
    sourceType !== null ||
    sourceTrust !== null ||
    resourceTargets.length > 0 ||
    officialDecision !== "unknown" ||
    riskScore !== null ||
    severity !== "unknown" ||
    reason !== null ||
    ruleHits.length > 0 ||
    bundleId !== null ||
    version !== null ||
    revision !== null ||
    digest !== null;
  if (!hasRecognizedEvidence) return null;
  return {
    eventId,
    eventTraceId: readString(event.trace_id),
    eventType,
    runtime: readRuntime(event.runtime),
    taskPreview: taskPreview ? maskSensitiveText(taskPreview) : null,
    sourceType,
    sourceTrust,
    resourceTargets,
    decisionId,
    decision: officialDecision,
    riskScore,
    severity,
    reason: reason ? maskSensitiveText(reason) : null,
    ruleHits,
    policy: {
      bundleId,
      version,
      revision,
      digest,
    },
  };
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

export function mapAuditWindow(dto: GuardAuditWindowDto): AuditWindow {
  const scope = readRecord(dto.scope);
  const filters = readRecord(scope.filters);
  const metrics = readRecord(dto.policy_metrics);
  return {
    scope: {
      kind: "audit_window",
      snapshotId: readString(scope.snapshot_id) ?? "",
      outcomesAsOf: readString(scope.outcomes_as_of) ?? "",
      order: "audit_sequence",
      limit: readNumber(scope.limit),
      returnedRecordCount: readNumber(scope.returned_record_count),
      hasMore: readBoolean(scope.has_more),
      nextCursor: readString(scope.next_cursor),
      sequenceFrom: readNullableNumber(scope.sequence_from),
      sequenceTo: readNullableNumber(scope.sequence_to),
      occurredFrom: readString(scope.occurred_from),
      occurredTo: readString(scope.occurred_to),
      filters: {
        traceId: readString(filters.trace_id),
        caseId: readString(filters.case_id),
        runtime: readString(filters.runtime),
        decision: readString(filters.decision),
      },
    },
    events: readArray(dto.events).map((row) => mapAuditEvent(row as GuardAuditEventDto)),
    metrics: {
      metricVersion: "policy_evaluation.v2",
      deduplication: "logical_policy_evaluation",
      evaluationCount: readNumber(metrics.evaluation_count),
      unknownDecisionCount: readNumber(metrics.unknown_decision_count),
      allowCount: readNumber(metrics.allow_count),
      denyCount: readNumber(metrics.deny_count),
      askCount: readNumber(metrics.ask_count),
      interventionCount: readNumber(metrics.intervention_count),
      interventionRate: readNullableNumber(metrics.intervention_rate),
      policyDenyRate: readNullableNumber(metrics.policy_deny_rate),
      approvalTriggerRate: readNullableNumber(metrics.approval_trigger_rate),
      policyFpr: readNullableNumber(metrics.policy_intervention_fpr),
      policyFnr: readNullableNumber(metrics.policy_intervention_fnr),
      benignLabelCount: readNumber(metrics.benign_label_count),
      maliciousLabelCount: readNumber(metrics.malicious_label_count),
      unlabeledCount: readNumber(metrics.unlabeled_count),
      averageDecisionLatencyMs: readNullableNumber(metrics.average_decision_latency_ms),
      latencySampleCount: readNumber(metrics.latency_sample_count),
      duplicatePolicyRecordCount: readNumber(metrics.duplicate_policy_record_count),
      unkeyedPolicyRecordCount: readNumber(metrics.unkeyed_policy_record_count),
    },
  };
}

export function mapApproval(dto: GuardApprovalDto): ApprovalRequest {
  const actionName = readString(dto.action_name) ?? "未提供";
  const resource = readString(dto.resource) ?? "未提供";
  const evidenceRecord = readRecord(dto.evidence);
  const eventEvidence = readRecord(evidenceRecord.event);
  const decisionEvidence = readRecord(evidenceRecord.decision);
  const evidence = mapApprovalEvidence(dto.evidence);
  const resolutionDecision = readApprovalDecision(dto.decision);
  const resolvedAt = readString(dto.resolved_at);
  const resolutionSource =
    dto.resolution_source === "human" ||
    dto.resolution_source === "llm" ||
    dto.resolution_source === "system"
      ? dto.resolution_source
      : null;
  const resolvedBy = readString(dto.resolved_by);
  const resolutionReasonValue = readString(dto.resolution_reason);
  const status: ApprovalRequest["status"] =
    dto.status === "expired"
      ? (dto.decision === null || resolutionDecision === "deny") &&
        dto.resolved_at === null &&
        resolutionSource === null &&
        resolvedBy === null &&
        resolutionReasonValue === null
        ? "expired"
        : "unknown"
      : dto.status === "pending"
        ? dto.decision === null &&
          dto.resolved_at === null &&
          resolutionSource === null &&
          resolvedBy === null &&
          resolutionReasonValue === null
          ? "pending"
          : "unknown"
        : dto.status !== "resolved"
          ? "unknown"
          : resolvedAt === null
            ? "unknown"
            : resolutionDecision === "allow_once"
              ? "allowed"
              : resolutionDecision === "deny"
                ? "denied"
                : "unknown";
  const eventId = readString(eventEvidence.event_id) ?? readString(evidenceRecord.event_id);
  const decisionId =
    readString(decisionEvidence.decision_id) ?? readString(evidenceRecord.decision_id);
  const userTask = evidence?.taskPreview ?? "未提供";
  const ruleHits = evidence?.ruleHits ?? [];

  return {
    id: readString(dto.approval_id) ?? "",
    createdAt: readString(dto.created_at) ?? "",
    status,
    resource: maskSensitiveText(resource),
    riskScore: readNumber(dto.risk_score),
    severity: readSeverity(dto.severity),
    reason: readString(dto.reason) ?? "未提供",
    eventId,
    policyAuditId: null,
    decisionId,
    traceId: readString(dto.trace_id) ?? "",
    subjectId: readString(dto.subject_id) ?? "未提供",
    subjectType: readString(dto.subject_type) ?? "未提供",
    actionId: readString(dto.action_id) ?? "",
    actionName,
    requestingPrincipalId: readString(dto.requesting_principal_id),
    runtime: readRuntime(dto.runtime),
    agentId: readString(dto.agent_id),
    decisionOptions: readApprovalDecisionOptions(dto.decision_options),
    decision: resolutionDecision,
    userTask,
    agentAction: `${actionName}(${maskSensitiveText(resource)})`,
    consequence: approvalConsequence(status),
    ruleHits,
    evidence,
    expiresAt: readString(dto.expires_at),
    resolvedAt,
    resolutionSource,
    resolvedBy,
    resolutionReason: resolutionReasonValue ? maskSensitiveText(resolutionReasonValue) : null,
  };
}

function approvalConsequence(status: ApprovalRequest["status"]): string {
  if (status === "allowed") return "该动作已获得一次性放行。";
  if (status === "denied") return "该动作的本次授权已被拒绝；实际执行结果以运行时回执为准。";
  if (status === "expired")
    return "该审批已过期，不能再通过本审批释放；实际执行结果以运行时回执为准。";
  if (status === "pending") return "允许一次只释放本次授权；动作是否执行及其结果以运行时回执为准。";
  return "审批状态证据不完整，当前不能据此确认授权或执行结果。";
}

function evaluationDatasetLabel(datasetId: string | null, datasetVersion: string | null): string {
  if (datasetId && datasetVersion) return `${datasetId} / ${datasetVersion}`;
  return datasetId ?? datasetVersion ?? "未提供";
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
    preEnableReport: projectPreEnableReport(null),
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
    preEnableReport: projectPreEnableReport(dto.pre_enable_report),
  };
}

export function mapTraceDetail(dto: GuardTraceDetailDto): TraceDetail {
  const auditWindow = readRecord(dto.audit_window);
  const approvalWindow = readRecord(dto.approval_window);
  const events = readArray(dto.audit_events).map((row) => mapAuditEvent(row as GuardAuditEventDto));
  const approvals = readArray(dto.approvals).map((row) => mapApproval(row as GuardApprovalDto));
  const useAuditSequence = events.every((event) => event.auditSequence !== null);
  events.sort((left, right) => {
    const primaryOrder = useAuditSequence
      ? left.auditSequence! - right.auditSequence!
      : Date.parse(left.occurredAt) - Date.parse(right.occurredAt);
    return primaryOrder || left.id.localeCompare(right.id);
  });
  return {
    id: readString(dto.trace_id) ?? "",
    events,
    approvals: mergeApprovalsWithAuditEvidence(approvals, events),
    auditWindow: {
      hasMore: readNullableBoolean(auditWindow.has_more),
      limit: readNumber(auditWindow.limit, events.length),
      returnedCount: readNumber(auditWindow.returned_count, events.length),
      nextCursor: readString(auditWindow.next_cursor),
      snapshotId: readString(auditWindow.snapshot_id),
    },
    approvalWindow: {
      hasMore: readNullableBoolean(approvalWindow.has_more),
      limit: readNumber(approvalWindow.limit, readArray(dto.approvals).length),
      returnedCount: readNumber(approvalWindow.returned_count, readArray(dto.approvals).length),
    },
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
  const anchor = readRecord(integrity.anchor);
  return {
    valid: readBoolean(integrity.valid),
    eventCount: readNumber(integrity.event_count),
    headHash: readString(integrity.head_hash),
    firstBrokenAuditId: readString(integrity.first_broken_audit_id),
    canonicalization: dto.canonicalization,
    anchor: {
      enabled: readBoolean(anchor.enabled),
      status: readAuditAnchorStatus(anchor.status),
      checkpointSequence: readNullableNumber(anchor.checkpoint_sequence),
      checkpointHeadHash: readString(anchor.checkpoint_head_hash),
      checkpointHash: readString(anchor.checkpoint_hash),
      checkpointedAt: readString(anchor.checkpointed_at),
      lag: readNullableNumber(anchor.lag),
      keyId: readString(anchor.key_id),
      errorCode: readString(anchor.error_code),
    },
  };
}

function readAuditAnchorStatus(value: unknown): AuditIntegrity["anchor"]["status"] {
  if (
    value === "disabled" ||
    value === "empty" ||
    value === "current" ||
    value === "stale" ||
    value === "invalid" ||
    value === "error"
  ) {
    return value;
  }
  return "error";
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
  const window = readRecord(dto.provenance_window);
  const nodes = readArray(dto.nodes).map((item): ProvenanceNode => {
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
  });
  const edges = readArray(dto.edges).map((item): ProvenanceEdge => {
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
  });
  return {
    traceId: readString(dto.trace_id) ?? "",
    nodes,
    edges,
    window: {
      nodeLimit: readNumber(window.node_limit, nodes.length),
      returnedNodeCount: readNumber(window.returned_node_count, nodes.length),
      nodesHaveMore: readNullableBoolean(window.nodes_have_more),
      edgeLimit: readNumber(window.edge_limit, edges.length),
      returnedEdgeCount: readNumber(window.returned_edge_count, edges.length),
      edgesHaveMore: readNullableBoolean(window.edges_have_more),
      hasMore: readNullableBoolean(window.has_more),
    },
  };
}

export function mapHealth(dto: GuardHealthDto, checkedAt = new Date().toISOString()): HealthStatus {
  const api =
    dto.status === "ok" || dto.status === "degraded"
      ? "online"
      : dto.status === "error" || dto.status === "offline"
        ? "offline"
        : "unknown";
  const database =
    dto.database === "ok"
      ? "online"
      : dto.database === "error" || dto.database === "offline"
        ? "offline"
        : "unknown";
  return { api, database, checkedAt };
}
