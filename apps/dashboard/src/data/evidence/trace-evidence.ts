import type {
  ApprovalEvidence,
  ApprovalRequest,
  AuditEventRow,
  AuditIntegrity,
  AuditRecordType,
  DecisionStatus,
  EvidenceAvailability,
  EvidenceFact,
  EvidenceSource,
  EvidenceStage,
  ExecutionEvidence,
  ExecutionStatus,
  InterventionType,
  NormalizedAuditEvidence,
  NormalizedResourceEvidence,
  PolicyReferenceEvidence,
  ResultDisposition,
  RiskBreakdownEvidence,
  RiskFactorEvidence,
  RiskSeverity,
  RuleHitEvidence,
  SideEffectEvidence,
  SideEffectMeasurementStatus,
  TraceEvidenceConclusion,
  TraceEvidenceViewModel,
  TraceAuditWindow,
} from "../../types/dashboard";
import { maskSensitiveText, redactSensitiveData } from "../../utils/data-redaction.ts";
import {
  getResourceOperationLabel,
  getResourceSensitivityLabel,
  getResourceTypeLabel,
  getRiskAggregationLabel,
  getTrustLevelLabel,
} from "../../utils/dashboard-formatters.ts";
import { ruleLabel } from "../../utils/rule-display.ts";
import { serializeStructuredData } from "../../utils/structured-data.ts";

type UnknownRecord = Record<string, unknown>;

const EMPTY_SOURCE: EvidenceSource = {
  label: null,
  trustLevel: null,
  type: null,
};

const EMPTY_POLICY: PolicyReferenceEvidence = {
  bundleId: null,
  digest: null,
  revision: null,
  version: null,
};

const EMPTY_EXECUTION: ExecutionEvidence = {
  completedAt: null,
  error: null,
  invokedAt: null,
  persisted: null,
  receiptRecorded: false,
  status: "unknown",
  toolResultEnteredContext: null,
};

const EMPTY_SIDE_EFFECTS: SideEffectEvidence = {
  count: null,
  measurementStatus: "unknown",
  summary: null,
};

const EMPTY_APPROVAL: ApprovalEvidence = {
  approvalId: null,
  resolvedAt: null,
  status: "unknown",
};

const EMPTY_RISK: RiskBreakdownEvidence = {
  aggregationMethod: null,
  factors: [],
  finalDecision: "unknown",
  finalScore: null,
};

function asRecord(value: unknown): UnknownRecord {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as UnknownRecord)
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function readMaskedString(value: unknown): string | null {
  const text = readString(value);
  return text ? maskSensitiveText(text) : null;
}

function readNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readInteger(value: unknown): number | null {
  const number = readNumber(value);
  return number === null ? null : Math.trunc(number);
}

function readBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function readStrings(value: unknown): string[] {
  return asArray(value)
    .flatMap((item) => {
      const text = readMaskedString(item);
      return text ? [text] : [];
    })
    .filter((value, index, values) => values.indexOf(value) === index);
}

function readDecision(value: unknown): DecisionStatus {
  return value === "allow" || value === "ask" || value === "deny" ? value : "unknown";
}

function readSeverity(value: unknown): RiskSeverity {
  return value === "critical" || value === "high" || value === "medium" || value === "low"
    ? value
    : "unknown";
}

function readRecordType(value: unknown): AuditRecordType {
  return value === "policy_evaluation" ||
    value === "runtime_outcome" ||
    value === "runtime_observation" ||
    value === "config_audit"
    ? value
    : "unknown";
}

function readIntervention(value: unknown): InterventionType {
  return value === "pre_execution_deny" ||
    value === "tool_result_quarantine" ||
    value === "model_output_revision" ||
    value === "audit_observation" ||
    value === "approval_release" ||
    value === "none"
    ? value
    : "unknown";
}

function readExecutionStatus(value: unknown): ExecutionStatus {
  return value === "not_invoked" || value === "executed" || value === "failed" ? value : "unknown";
}

function readDisposition(value: unknown): ResultDisposition {
  return value === "passed_through" ||
    value === "quarantined" ||
    value === "modified" ||
    value === "discarded" ||
    value === "not_applicable"
    ? value
    : "unknown";
}

function readMeasurementStatus(value: unknown): SideEffectMeasurementStatus {
  return value === "measured" || value === "not_measured" || value === "not_applicable"
    ? value
    : "unknown";
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    const text = readMaskedString(value);
    if (text) return text;
  }
  return null;
}

function firstNumber(...values: unknown[]): number | null {
  for (const value of values) {
    const number = readNumber(value);
    if (number !== null) return number;
  }
  return null;
}

function firstBoolean(...values: unknown[]): boolean | null {
  for (const value of values) {
    const boolean = readBoolean(value);
    if (boolean !== null) return boolean;
  }
  return null;
}

function firstDecision(...values: unknown[]): DecisionStatus {
  for (const value of values) {
    const decision = readDecision(value);
    if (decision !== "unknown") return decision;
  }
  return "unknown";
}

function firstSeverity(...values: unknown[]): RiskSeverity {
  for (const value of values) {
    const severity = readSeverity(value);
    if (severity !== "unknown") return severity;
  }
  return "unknown";
}

function hasOwn(root: UnknownRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(root, key);
}

function explicitLegacyValue(raw: UnknownRecord, fallback: unknown, ...keys: string[]): unknown {
  for (const key of keys) {
    if (hasOwn(raw, key)) return raw[key];
  }
  return Object.keys(raw).length ? undefined : fallback;
}

function normalizeSource(guardEvent: UnknownRecord, metadata: UnknownRecord): EvidenceSource {
  const source = asRecord(guardEvent.source);
  return {
    label: firstString(source.label, guardEvent.source_label, metadata.source_label),
    trustLevel: firstString(
      source.trust_level,
      source.trust,
      guardEvent.source_trust,
      metadata.source_trust,
    ),
    type: firstString(source.type, guardEvent.source_type, metadata.source_type),
  };
}

function normalizeResources(
  guardEvent: UnknownRecord,
  evidence: UnknownRecord,
  raw: UnknownRecord,
  event: AuditEventRow,
): NormalizedResourceEvidence[] {
  const candidates = [
    ...asArray(evidence.normalized_resources),
    ...asArray(guardEvent.normalized_resources),
    ...asArray(guardEvent.resources),
  ];
  const normalized = candidates.flatMap((item, index) => {
    if (typeof item === "string") {
      return [
        {
          id: `resource-${index}`,
          operation: null,
          sensitivity: null,
          type: null,
          value: maskSensitiveText(item),
        },
      ];
    }
    const record = asRecord(item);
    const value = firstString(
      record.value,
      record.normalized,
      record.uri,
      record.path,
      record.resource,
      record.target,
    );
    if (!value) return [];
    return [
      {
        id: firstString(record.id) ?? `resource-${index}`,
        operation: firstString(record.operation, record.action),
        sensitivity: firstString(record.sensitivity, record.classification),
        type: firstString(record.type, record.kind),
        value,
      },
    ];
  });

  if (normalized.length) return normalized;
  const rawTargets = hasOwn(raw, "resource_targets") ? readStrings(raw.resource_targets) : [];
  const legacyTargets =
    rawTargets.length || Object.keys(raw).length
      ? rawTargets
      : event.resourceTargets.map(maskSensitiveText);
  return legacyTargets.map((value, index) => ({
    id: `resource-${index}`,
    operation: null,
    sensitivity: null,
    type: null,
    value,
  }));
}

function normalizeRuleHits(
  guardDecision: UnknownRecord,
  raw: UnknownRecord,
  event: AuditEventRow,
): RuleHitEvidence[] {
  const detailed = asArray(guardDecision.rule_hits);
  if (detailed.length) {
    return detailed.flatMap((item) => {
      if (typeof item === "string") {
        return [
          {
            decision: "unknown" as const,
            evidence: [],
            name: ruleLabel(item),
            reason: null,
            ruleId: item,
            severity: "unknown" as const,
          },
        ];
      }
      const record = asRecord(item);
      const ruleId = firstString(record.rule_id, record.id, record.name);
      if (!ruleId) return [];
      return [
        {
          decision: firstDecision(record.decision),
          evidence: readStrings(record.evidence),
          name: firstString(record.name, record.title) ?? ruleLabel(ruleId),
          reason: firstString(record.reason),
          ruleId,
          severity: firstSeverity(record.severity),
        },
      ];
    });
  }

  const ids = hasOwn(raw, "rule_hits")
    ? readStrings(raw.rule_hits)
    : Object.keys(raw).length
      ? []
      : event.ruleHits;
  return ids.map((ruleId) => ({
    decision: "unknown",
    evidence: [],
    name: ruleLabel(ruleId),
    reason: null,
    ruleId,
    severity: "unknown",
  }));
}

function normalizeRisk(
  guardDecision: UnknownRecord,
  raw: UnknownRecord,
  event: AuditEventRow,
): RiskBreakdownEvidence {
  const risk = asRecord(guardDecision.risk_breakdown);
  const factors = asArray(risk.factors).flatMap((item, index): RiskFactorEvidence[] => {
    const record = asRecord(item);
    const label = firstString(record.label, record.rule, record.category, record.id);
    if (!label) return [];
    return [
      {
        category: firstString(record.category),
        decision: firstDecision(record.decision),
        id: firstString(record.id, record.rule) ?? `factor-${index}`,
        label,
        reason: firstString(record.reason),
        score: firstNumber(record.score),
        severity: firstSeverity(record.severity),
      },
    ];
  });
  const explicitRiskScore = explicitLegacyValue(raw, event.riskScore, "risk_score");
  const explicitDecision = explicitLegacyValue(raw, event.decision, "decision");
  return {
    aggregationMethod: firstString(risk.aggregation_method, risk.method),
    factors,
    finalDecision: firstDecision(risk.final_decision, guardDecision.decision, explicitDecision),
    finalScore: firstNumber(risk.final_score, guardDecision.risk_score, explicitRiskScore),
  };
}

function normalizePolicy(evidence: UnknownRecord, guardDecision: UnknownRecord) {
  const policy = asRecord(evidence.policy);
  const decisionPolicy = asRecord(guardDecision.policy);
  return {
    bundleId: firstString(policy.bundle_id, decisionPolicy.bundle_id),
    digest: firstString(
      policy.canonical_digest,
      policy.digest,
      decisionPolicy.canonical_digest,
      decisionPolicy.digest,
    ),
    revision: readInteger(policy.revision ?? decisionPolicy.revision),
    version: firstString(policy.version, decisionPolicy.version),
  } satisfies PolicyReferenceEvidence;
}

function normalizeExecution(evidence: UnknownRecord): ExecutionEvidence {
  const execution = asRecord(evidence.execution);
  const status = readExecutionStatus(execution.status);
  const explicitReceipt = firstBoolean(execution.receipt_recorded, execution.has_receipt);
  return {
    completedAt: firstString(execution.completed_at),
    error: firstString(execution.error),
    invokedAt: firstString(execution.invoked_at),
    persisted: firstBoolean(execution.persisted, execution.tool_result_persisted),
    receiptRecorded: explicitReceipt ?? status !== "unknown",
    status,
    toolResultEnteredContext: firstBoolean(
      execution.tool_result_entered_context,
      execution.entered_context,
    ),
  };
}

function normalizeSideEffects(evidence: UnknownRecord): SideEffectEvidence {
  const sideEffects = asRecord(evidence.side_effects);
  return {
    count: firstNumber(sideEffects.count),
    measurementStatus: readMeasurementStatus(sideEffects.measurement_status ?? sideEffects.status),
    summary: firstString(sideEffects.summary),
  };
}

function normalizeApproval(
  evidence: UnknownRecord,
  links: UnknownRecord,
  approvals: readonly ApprovalRequest[],
): ApprovalEvidence {
  const rawApproval = asRecord(evidence.approval);
  const approvalId = firstString(rawApproval.approval_id, links.approval_id);
  const matched = approvals.find((approval) => approval.id === approvalId);
  const statusValue = matched?.status ?? rawApproval.status;
  const resolution = firstString(rawApproval.decision);
  const status: ApprovalEvidence["status"] =
    statusValue === "pending" ||
    statusValue === "allowed" ||
    statusValue === "denied" ||
    statusValue === "expired" ||
    statusValue === "not_required"
      ? statusValue
      : statusValue === "allowed_once" ||
          (statusValue === "resolved" && resolution === "allow_once")
        ? "allowed"
        : statusValue === "deny" || (statusValue === "resolved" && resolution === "deny")
          ? "denied"
          : "unknown";
  return {
    approvalId: approvalId ?? matched?.id ?? null,
    resolvedAt: firstString(rawApproval.resolved_at, matched?.resolvedAt),
    status,
  };
}

function normalizeArguments(guardEvent: UnknownRecord): Record<string, unknown> | null {
  const tool = asRecord(guardEvent.tool);
  const args = asRecord(
    tool.arguments ??
      tool.args ??
      guardEvent.tool_arguments ??
      guardEvent.tool_args ??
      guardEvent.arguments,
  );
  if (!Object.keys(args).length) return null;
  return asRecord(redactSensitiveData(args));
}

function normalizeAuditEvent(
  event: AuditEventRow,
  approvals: readonly ApprovalRequest[],
): NormalizedAuditEvidence {
  const raw = asRecord(event.raw);
  const evidence = asRecord(raw.evidence);
  const guardEvent = asRecord(evidence.guard_event);
  const guardDecision = asRecord(evidence.guard_decision);
  const metadata = asRecord(raw.metadata);
  const links = asRecord(raw.links);
  const auditIntegrity = asRecord(raw.integrity);
  const execution = normalizeExecution(evidence);
  const risk = normalizeRisk(guardDecision, raw, event);
  const decision = firstDecision(
    guardDecision.decision,
    risk.finalDecision,
    explicitLegacyValue(raw, event.decision, "decision"),
  );
  let recordType = readRecordType(raw.record_type);
  if (recordType === "unknown" && decision !== "unknown") recordType = "policy_evaluation";

  const intervention = readIntervention(
    asRecord(evidence.intervention).type ?? evidence.intervention_type,
  );
  const disposition = readDisposition(
    asRecord(evidence.result).disposition ?? evidence.result_disposition,
  );
  const tool = asRecord(guardEvent.tool);
  const resources = normalizeResources(guardEvent, evidence, raw, event);
  const ruleHits = normalizeRuleHits(guardDecision, raw, event);

  return {
    actionId: firstString(links.action_id),
    approval: normalizeApproval(evidence, links, approvals),
    auditId: event.id,
    chainIndex: readInteger(auditIntegrity.sequence),
    contextSources: [
      ...readStrings(guardEvent.context_sources),
      ...readStrings(metadata.context_sources),
    ].filter((value, index, values) => values.indexOf(value) === index),
    decision,
    decisionId: firstString(links.decision_id),
    decisionReason: firstString(guardDecision.reason, raw.reason, event.reason),
    entryHash: firstString(auditIntegrity.event_hash),
    eventId: firstString(links.event_id, metadata.event_id),
    eventType: event.eventType,
    execution,
    intervention,
    modelIntent: firstString(guardEvent.model_intent, evidence.model_intent, metadata.model_intent),
    occurredAt: event.occurredAt,
    originalTask: firstString(
      guardEvent.user_task,
      guardEvent.original_task,
      metadata.user_task,
      event.userTask,
    ),
    policy: normalizePolicy(evidence, guardDecision),
    policyAuditId: firstString(links.policy_audit_id),
    parentAuditId: firstString(links.parent_audit_id),
    previousHash: firstString(auditIntegrity.prev_hash),
    raw: event.raw ?? event,
    recordType,
    resources,
    resultDisposition: disposition,
    resultSummary: firstString(asRecord(evidence.result).summary, evidence.result_summary),
    risk,
    ruleHits,
    severity: firstSeverity(guardDecision.severity, raw.severity, event.severity),
    sideEffects: normalizeSideEffects(evidence),
    source: normalizeSource(guardEvent, metadata),
    stage: event.stage,
    toolArguments: normalizeArguments(guardEvent),
    toolName: firstString(tool.name, guardEvent.tool_name, metadata.action_name, event.tool),
  };
}

function pickLatest<T>(
  events: readonly NormalizedAuditEvidence[],
  pick: (event: NormalizedAuditEvidence) => T | null,
): T | null {
  for (const event of [...events].reverse()) {
    const value = pick(event);
    if (value !== null) return value;
  }
  return null;
}

function pickArray<T>(
  events: readonly NormalizedAuditEvidence[],
  pick: (event: NormalizedAuditEvidence) => T[],
): T[] {
  return (
    pickLatest(events, (event) => {
      const value = pick(event);
      return value.length ? value : null;
    }) ?? []
  );
}

function combineTraceEvidence(
  events: readonly NormalizedAuditEvidence[],
): NormalizedAuditEvidence | null {
  const base = events.at(-1);
  if (!base) return null;
  const decisionRecord =
    [...events]
      .reverse()
      .find((event) => event.recordType === "policy_evaluation" && event.decision !== "unknown") ??
    [...events].reverse().find((event) => event.decision !== "unknown");
  const outcomeRecord =
    [...events]
      .reverse()
      .find(
        (event) =>
          event.recordType === "runtime_outcome" ||
          event.intervention !== "unknown" ||
          event.execution.receiptRecorded,
      ) ?? null;

  const latestSource =
    pickLatest(events, (event) =>
      event.source.type || event.source.label || event.source.trustLevel ? event.source : null,
    ) ?? EMPTY_SOURCE;
  const latestRisk =
    pickLatest(events, (event) =>
      event.risk.finalScore !== null ||
      event.risk.finalDecision !== "unknown" ||
      event.risk.factors.length
        ? event.risk
        : null,
    ) ?? EMPTY_RISK;
  const latestPolicy =
    pickLatest(events, (event) =>
      event.policy.bundleId ||
      event.policy.version ||
      event.policy.revision !== null ||
      event.policy.digest
        ? event.policy
        : null,
    ) ?? EMPTY_POLICY;
  const latestExecution =
    pickLatest(events, (event) => (event.execution.receiptRecorded ? event.execution : null)) ??
    EMPTY_EXECUTION;
  const latestSideEffects =
    pickLatest(events, (event) =>
      event.sideEffects.measurementStatus !== "unknown" ||
      event.sideEffects.count !== null ||
      event.sideEffects.summary
        ? event.sideEffects
        : null,
    ) ?? EMPTY_SIDE_EFFECTS;
  const latestApproval =
    pickLatest(events, (event) =>
      event.approval.approvalId || event.approval.status !== "unknown" ? event.approval : null,
    ) ?? EMPTY_APPROVAL;

  return {
    ...base,
    actionId: pickLatest(events, (event) => event.actionId),
    approval: latestApproval,
    contextSources: pickArray(events, (event) => event.contextSources),
    decision: decisionRecord?.decision ?? "unknown",
    decisionId: decisionRecord?.decisionId ?? null,
    decisionReason:
      decisionRecord?.decisionReason ?? pickLatest(events, (event) => event.decisionReason),
    eventId: decisionRecord?.eventId ?? outcomeRecord?.eventId ?? base.eventId,
    execution: latestExecution,
    intervention:
      pickLatest(events, (event) =>
        event.intervention !== "unknown" ? event.intervention : null,
      ) ?? "unknown",
    modelIntent: pickLatest(events, (event) => event.modelIntent),
    originalTask: pickLatest(events, (event) => event.originalTask),
    policy: latestPolicy,
    raw: events.map((event) => event.raw),
    resources: pickArray(events, (event) => event.resources),
    resultDisposition:
      pickLatest(events, (event) =>
        event.resultDisposition !== "unknown" ? event.resultDisposition : null,
      ) ?? "unknown",
    resultSummary: pickLatest(events, (event) => event.resultSummary),
    risk: latestRisk,
    ruleHits: pickArray(events, (event) => event.ruleHits),
    severity: decisionRecord?.severity ?? "unknown",
    sideEffects: latestSideEffects,
    source: latestSource,
    toolArguments: pickLatest(events, (event) => event.toolArguments),
    toolName: pickLatest(events, (event) => event.toolName),
  };
}

function policyLogicalKey(event: NormalizedAuditEvidence): string | null {
  if (event.recordType !== "policy_evaluation") return null;
  if (!event.eventId || !event.decisionId) return null;
  return `${event.eventId}:${event.decisionId}`;
}

function dedupeLogicalEvents(events: readonly NormalizedAuditEvidence[]) {
  const seen = new Set<string>();
  const logical: NormalizedAuditEvidence[] = [];
  let duplicates = 0;
  for (const event of events) {
    const key = policyLogicalKey(event);
    if (key && seen.has(key)) {
      duplicates += 1;
      continue;
    }
    if (key) seen.add(key);
    logical.push(event);
  }
  return { duplicates, logical };
}

export function getDecisionEvidenceLabel(decision: DecisionStatus): string {
  if (decision === "allow") return "允许";
  if (decision === "ask") return "需审批";
  if (decision === "deny") return "拒绝";
  return "未记录";
}

export function getInterventionLabel(intervention: InterventionType): string {
  const labels: Record<InterventionType, string> = {
    approval_release: "审批后放行",
    audit_observation: "仅审计观察",
    model_output_revision: "模型输出修订",
    none: "无干预",
    pre_execution_deny: "执行前拒绝",
    tool_result_quarantine: "工具结果隔离",
    unknown: "未记录",
  };
  return labels[intervention];
}

export function getExecutionStatusLabel(status: ExecutionStatus): string {
  if (status === "not_invoked") return "未调用工具";
  if (status === "executed") return "已执行";
  if (status === "failed") return "执行失败";
  return "暂无执行回执";
}

export function getResultDispositionLabel(disposition: ResultDisposition): string {
  const labels: Record<ResultDisposition, string> = {
    discarded: "已丢弃",
    modified: "已修改",
    not_applicable: "不适用",
    passed_through: "已透传",
    quarantined: "已隔离",
    unknown: "未记录",
  };
  return labels[disposition];
}

export function getSideEffectLabel(sideEffects: SideEffectEvidence): string {
  if (sideEffects.measurementStatus === "not_applicable") return "不适用";
  if (sideEffects.measurementStatus === "not_measured") return "未测量";
  if (sideEffects.measurementStatus !== "measured") return "未记录";
  return sideEffects.count === null ? "已测量，数量未记录" : `${sideEffects.count} 个`;
}

function availability(recorded: boolean, notApplicable = false): EvidenceAvailability {
  if (notApplicable) return "not_applicable";
  return recorded ? "recorded" : "not_recorded";
}

function policyDetail(policy: PolicyReferenceEvidence): string {
  const parts = [
    policy.bundleId ? `策略包 ${policy.bundleId}` : null,
    policy.version ? `版本 ${policy.version}` : null,
    policy.revision === null ? null : `修订 ${policy.revision}`,
    policy.digest ? `摘要 ${policy.digest.slice(0, 12)}…` : null,
  ].filter((part): part is string => Boolean(part));
  return parts.length ? parts.join(" · ") : "当时生效的策略未记录";
}

function executionDetail(execution: ExecutionEvidence): string {
  if (!execution.receiptRecorded) return "不能由策略决定推断工具是否调用";
  if (execution.status === "not_invoked") return "运行时回执确认未调用工具";
  if (execution.status === "executed") {
    return execution.completedAt ? `完成于 ${execution.completedAt}` : "运行时回执确认已执行";
  }
  if (execution.status === "failed") return execution.error ?? "运行时回执记录执行失败";
  return "回执存在，但执行状态未记录";
}

function sideEffectDetail(sideEffects: SideEffectEvidence): string {
  if (sideEffects.summary) return sideEffects.summary;
  if (sideEffects.measurementStatus === "measured" && sideEffects.count === 0) {
    return "运行时回执确认副作用数量为 0";
  }
  if (sideEffects.measurementStatus === "measured") return "来自运行时副作用测量回执";
  if (sideEffects.measurementStatus === "not_measured") return "未测量，不可按 0 处理";
  if (sideEffects.measurementStatus === "not_applicable") return "该阶段不产生外部副作用";
  return "缺失字段不按 0 处理";
}

function dispositionDetail(disposition: ResultDisposition, execution: ExecutionEvidence): string {
  if (disposition === "quarantined") {
    return execution.status === "executed"
      ? "隔离工具结果，不代表撤销已经发生的外部副作用"
      : "不可信工具结果未进入后续上下文";
  }
  if (disposition === "modified") return "下游仅接收修订后的模型输出";
  if (disposition === "discarded") return "结果已丢弃，未进入后续处理";
  if (disposition === "passed_through") return "结果按运行时回执进入后续流程";
  if (disposition === "not_applicable") return "当前事件没有可处置的工具或模型结果";
  return "结果处置未记录";
}

function buildIntegrity(
  events: readonly NormalizedAuditEvidence[],
  integrity: AuditIntegrity | null | undefined,
  auditWindow?: TraceAuditWindow,
) {
  const withMetadata = events.filter(
    (event) => event.chainIndex !== null && Boolean(event.entryHash),
  ).length;
  const traceMetadataStatus =
    !events.length || withMetadata === 0
      ? ("unknown" as const)
      : withMetadata === events.length
        ? ("complete" as const)
        : ("partial" as const);
  const globalStatus = integrity
    ? integrity.valid
      ? ("valid" as const)
      : ("invalid" as const)
    : ("unknown" as const);
  const lastWithMetadata = [...events]
    .reverse()
    .find((event) => event.chainIndex !== null || event.entryHash);
  return {
    chainIndex: lastWithMetadata?.chainIndex ?? null,
    entryHash: lastWithMetadata?.entryHash ?? null,
    globalStatus,
    mayBeTruncated: auditWindow?.hasMore ?? events.length >= 1000,
    previousHash: lastWithMetadata?.previousHash ?? null,
    returnedEventCount: auditWindow?.returnedCount ?? events.length,
    traceMetadataStatus,
  };
}

function integrityLabel(
  integrity: TraceEvidenceViewModel["integrity"],
): Pick<EvidenceFact, "availability" | "detail" | "tone" | "value"> {
  if (integrity.globalStatus === "invalid") {
    return {
      availability: "recorded",
      detail: "全局哈希链校验发现断点，请检查原始审计记录",
      tone: "danger",
      value: "哈希链校验失败",
    };
  }
  if (integrity.globalStatus === "valid") {
    const detail =
      integrity.traceMetadataStatus === "complete"
        ? "全局校验通过，当前返回事件均带完整性元数据"
        : integrity.traceMetadataStatus === "partial"
          ? "全局校验通过，但当前证据链仅部分事件带完整性元数据"
          : "全局校验通过，当前证据链未返回逐事件完整性元数据";
    return {
      availability: "recorded",
      detail: integrity.mayBeTruncated ? `${detail}；返回窗口可能达到上限` : detail,
      tone: integrity.traceMetadataStatus === "complete" ? "success" : "warning",
      value: "哈希链校验通过",
    };
  }
  return {
    availability: "not_recorded",
    detail: "未获得全局哈希链校验结果",
    tone: "neutral",
    value: "未校验",
  };
}

function buildFacts(
  primary: NormalizedAuditEvidence | null,
  integrity: TraceEvidenceViewModel["integrity"],
): EvidenceFact[] {
  const decision = primary?.decision ?? "unknown";
  const intervention = primary?.intervention ?? "unknown";
  const execution = primary?.execution ?? EMPTY_EXECUTION;
  const sideEffects = primary?.sideEffects ?? EMPTY_SIDE_EFFECTS;
  const disposition = primary?.resultDisposition ?? "unknown";
  const integrityFact = integrityLabel(integrity);
  return [
    {
      availability: availability(decision !== "unknown"),
      detail: primary ? policyDetail(primary.policy) : "未返回策略判定记录",
      id: "decision",
      label: "策略决定",
      tone:
        decision === "deny"
          ? "danger"
          : decision === "ask"
            ? "warning"
            : decision === "allow"
              ? "success"
              : "neutral",
      value: getDecisionEvidenceLabel(decision),
    },
    {
      availability: availability(intervention !== "unknown"),
      detail:
        intervention === "tool_result_quarantine"
          ? "隔离发生在工具结果进入上下文之前"
          : intervention === "model_output_revision"
            ? "模型输出在下游接收前完成修订"
            : intervention === "audit_observation"
              ? "只记录事实，不改变运行时行为"
              : intervention === "approval_release"
                ? "人工审批仅释放一次动作，执行状态仍以回执为准"
                : intervention === "pre_execution_deny"
                  ? "策略在副作用发生前拒绝动作"
                  : intervention === "none"
                    ? "运行时明确记录未采取干预"
                    : "不能仅根据策略决定或审批状态推断",
      id: "intervention",
      label: "干预方式",
      tone:
        intervention === "pre_execution_deny"
          ? "danger"
          : intervention === "tool_result_quarantine" || intervention === "model_output_revision"
            ? "protective"
            : intervention === "approval_release"
              ? "success"
              : "neutral",
      value: getInterventionLabel(intervention),
    },
    {
      availability: availability(execution.receiptRecorded),
      detail: executionDetail(execution),
      id: "execution",
      label: "实际执行",
      tone:
        execution.status === "failed"
          ? "danger"
          : execution.status === "not_invoked"
            ? "protective"
            : execution.status === "executed"
              ? "success"
              : "neutral",
      value: getExecutionStatusLabel(execution.status),
    },
    {
      availability: availability(
        sideEffects.measurementStatus !== "unknown",
        sideEffects.measurementStatus === "not_applicable",
      ),
      detail: sideEffectDetail(sideEffects),
      id: "side_effects",
      label: "副作用",
      tone:
        sideEffects.measurementStatus === "measured" && sideEffects.count === 0
          ? "success"
          : sideEffects.measurementStatus === "measured" &&
              sideEffects.count !== null &&
              sideEffects.count > 0
            ? "warning"
            : "neutral",
      value: getSideEffectLabel(sideEffects),
    },
    {
      availability: availability(disposition !== "unknown", disposition === "not_applicable"),
      detail: dispositionDetail(disposition, execution),
      id: "result_disposition",
      label: "结果处置",
      tone:
        disposition === "quarantined" || disposition === "modified" || disposition === "discarded"
          ? "protective"
          : disposition === "passed_through"
            ? "success"
            : "neutral",
      value: getResultDispositionLabel(disposition),
    },
    {
      ...integrityFact,
      id: "audit_integrity",
      label: "审计完整性",
    },
  ];
}

function valueOrMissing(value: string | null): string {
  return value ?? "未记录";
}

function sourceValue(source: EvidenceSource): string {
  return source.label ?? source.type ?? "未记录";
}

function resourceValue(resources: readonly NormalizedResourceEvidence[]): string {
  if (!resources.length) return "未记录";
  if (resources.length === 1) return resources[0]!.value;
  return `${resources[0]!.value} 等 ${resources.length} 项`;
}

function ruleValue(rules: readonly RuleHitEvidence[]): string {
  if (!rules.length) return "未记录";
  if (rules.length === 1) return rules[0]!.name ?? ruleLabel(rules[0]!.ruleId);
  return `${rules[0]!.name ?? ruleLabel(rules[0]!.ruleId)} 等 ${rules.length} 条`;
}

function argumentsValue(args: Record<string, unknown> | null): string {
  if (!args) return "未记录";
  const serialized = serializeStructuredData(args).replace(/\s+/g, " ").trim();
  return serialized.length > 96 ? `${serialized.slice(0, 96)}…` : serialized;
}

function buildStages(primary: NormalizedAuditEvidence | null): EvidenceStage[] {
  const source = primary?.source ?? EMPTY_SOURCE;
  const execution = primary?.execution ?? EMPTY_EXECUTION;
  const sideEffects = primary?.sideEffects ?? EMPTY_SIDE_EFFECTS;
  const disposition = primary?.resultDisposition ?? "unknown";
  const contextSources = primary?.contextSources ?? [];
  const resources = primary?.resources ?? [];
  const rules = primary?.ruleHits ?? [];
  const risk = primary?.risk ?? EMPTY_RISK;
  const approval = primary?.approval ?? EMPTY_APPROVAL;
  const policy = primary?.policy ?? EMPTY_POLICY;

  return [
    {
      eyebrow: "步骤 1",
      id: "input_trust",
      index: 1,
      items: [
        {
          availability: availability(Boolean(primary?.originalTask)),
          detail: "运行时接收的原始用户目标",
          eventId: primary?.auditId ?? null,
          id: "original-task",
          label: "原始任务",
          value: valueOrMissing(primary?.originalTask ?? null),
        },
        {
          availability: availability(Boolean(source.type || source.label)),
          detail: source.trustLevel
            ? `信任等级：${getTrustLevelLabel(source.trustLevel)}`
            : "信任等级未记录",
          eventId: primary?.auditId ?? null,
          id: "source",
          label: "来源与信任",
          value: sourceValue(source),
        },
      ],
      title: "输入与信任",
    },
    {
      eyebrow: "步骤 2",
      id: "context_intent",
      index: 2,
      items: [
        {
          availability: availability(contextSources.length > 0),
          detail: contextSources.length ? contextSources.join(" · ") : null,
          eventId: primary?.auditId ?? null,
          id: "context",
          label: "上下文组装",
          value: contextSources.length ? `${contextSources.length} 个上下文来源` : "未记录",
        },
        {
          availability: availability(Boolean(primary?.modelIntent)),
          detail: "模型产生的计划或动作意图",
          eventId: primary?.auditId ?? null,
          id: "model-intent",
          label: "模型意图",
          value: valueOrMissing(primary?.modelIntent ?? null),
        },
      ],
      title: "上下文与模型意图",
    },
    {
      eyebrow: "步骤 3",
      id: "tool_policy",
      index: 3,
      items: [
        {
          availability: availability(Boolean(primary?.toolName)),
          detail: argumentsValue(primary?.toolArguments ?? null),
          eventId: primary?.auditId ?? null,
          id: "tool",
          label: "工具与参数",
          value: valueOrMissing(primary?.toolName ?? null),
        },
        {
          availability: availability(resources.length > 0),
          detail: resources.length
            ? resources
                .map((resource) =>
                  [
                    resource.type ? getResourceTypeLabel(resource.type) : null,
                    resource.operation ? getResourceOperationLabel(resource.operation) : null,
                    resource.sensitivity ? getResourceSensitivityLabel(resource.sensitivity) : null,
                  ]
                    .filter(Boolean)
                    .join(" / "),
                )
                .filter(Boolean)
                .join(" · ") || "已记录资源类型与操作"
            : null,
          eventId: primary?.auditId ?? null,
          id: "resources",
          label: "资源目标",
          value: resourceValue(resources),
        },
        {
          availability: availability(rules.length > 0),
          detail:
            rules
              .map((rule) => rule.reason)
              .filter((value): value is string => Boolean(value))
              .join(" · ") || null,
          eventId: primary?.auditId ?? null,
          id: "rules",
          label: "命中规则",
          value: ruleValue(rules),
        },
        {
          availability: availability(risk.finalScore !== null || risk.factors.length > 0),
          detail: risk.aggregationMethod
            ? `${getRiskAggregationLabel(risk.aggregationMethod)} · ${risk.factors.length} 个风险因素`
            : risk.factors.length
              ? `${risk.factors.length} 个风险因素`
              : null,
          eventId: primary?.auditId ?? null,
          id: "risk",
          label: "风险组合",
          value: risk.finalScore === null ? "未记录" : `${risk.finalScore} / 100`,
        },
        {
          availability: availability(
            Boolean(policy.bundleId || policy.version || policy.revision !== null || policy.digest),
          ),
          detail: policy.digest ? `规范摘要 ${policy.digest}` : "规范摘要未记录",
          eventId: primary?.auditId ?? null,
          id: "policy",
          label: "当时生效的策略",
          value: policyDetail(policy),
        },
      ],
      title: "工具、资源与策略",
    },
    {
      eyebrow: "步骤 4",
      id: "outcome_audit",
      index: 4,
      items: [
        {
          availability: availability(
            approval.status !== "unknown",
            approval.status === "not_required",
          ),
          detail: approval.resolvedAt
            ? `处理时间：${approval.resolvedAt}`
            : approval.approvalId
              ? `审批 ID：${approval.approvalId}`
              : null,
          eventId: primary?.auditId ?? null,
          id: "approval",
          label: "审批结果",
          value:
            approval.status === "pending"
              ? "待审批"
              : approval.status === "allowed"
                ? "单次放行"
                : approval.status === "denied"
                  ? "已拒绝"
                  : approval.status === "expired"
                    ? "已过期"
                    : approval.status === "not_required"
                      ? "不适用"
                      : "未记录",
        },
        {
          availability: availability(execution.receiptRecorded),
          detail: executionDetail(execution),
          eventId: primary?.auditId ?? null,
          id: "execution",
          label: "实际执行",
          value: getExecutionStatusLabel(execution.status),
        },
        {
          availability: availability(
            sideEffects.measurementStatus !== "unknown",
            sideEffects.measurementStatus === "not_applicable",
          ),
          detail: sideEffectDetail(sideEffects),
          eventId: primary?.auditId ?? null,
          id: "side-effects",
          label: "副作用证据",
          value: getSideEffectLabel(sideEffects),
        },
        {
          availability: availability(disposition !== "unknown", disposition === "not_applicable"),
          detail: dispositionDetail(disposition, execution),
          eventId: primary?.auditId ?? null,
          id: "disposition",
          label: "结果处置",
          value: getResultDispositionLabel(disposition),
        },
      ],
      title: "执行结果与审计",
    },
  ];
}

function buildConclusion(primary: NormalizedAuditEvidence | null): TraceEvidenceConclusion {
  if (!primary) {
    return {
      confidence: "unknown",
      outcome: "当前证据链没有可用审计事件",
      reason: "未返回证据",
      title: "结论未形成",
    };
  }
  const reason = primary.decisionReason ?? primary.resultSummary ?? "判定原因未记录";
  if (primary.intervention === "pre_execution_deny") {
    const confirmed =
      primary.execution.receiptRecorded && primary.execution.status === "not_invoked";
    const sideEffectSuffix =
      primary.sideEffects.measurementStatus === "measured" && primary.sideEffects.count === 0
        ? "，副作用测量为 0"
        : "，副作用状态以运行时回执为准";
    return {
      confidence: confirmed ? "confirmed" : "partial",
      outcome: confirmed
        ? `运行时回执确认工具未调用${sideEffectSuffix}`
        : "安全策略已拒绝动作，但尚不能确认运行时是否实际调用工具",
      reason,
      title: confirmed ? "执行前拒绝已确认" : "策略拒绝，执行回执待补充",
    };
  }
  if (primary.intervention === "tool_result_quarantine") {
    return {
      confidence: primary.resultDisposition === "quarantined" ? "confirmed" : "partial",
      outcome: "工具结果未进入后续上下文；该处置不代表撤销工具已经产生的外部副作用",
      reason,
      title: "工具结果隔离",
    };
  }
  if (primary.intervention === "model_output_revision") {
    return {
      confidence: primary.resultDisposition === "modified" ? "confirmed" : "partial",
      outcome: "下游仅接收修订后的模型输出",
      reason,
      title: "模型输出修订",
    };
  }
  if (primary.intervention === "audit_observation") {
    return {
      confidence: "confirmed",
      outcome: "本事件只记录观察，不改变运行时执行路径",
      reason,
      title: "仅审计观察",
    };
  }
  if (primary.intervention === "approval_release") {
    return {
      confidence: primary.approval.status === "allowed" ? "confirmed" : "partial",
      outcome: primary.execution.receiptRecorded
        ? `审批释放后：${getExecutionStatusLabel(primary.execution.status)}`
        : "审批已放行一次；是否实际执行仍待运行时回执",
      reason,
      title: "审批后放行",
    };
  }
  if (primary.decision !== "unknown") {
    return {
      confidence: "partial",
      outcome: "已记录策略决定，运行时干预与执行结果未完整上报",
      reason,
      title: `策略决定：${getDecisionEvidenceLabel(primary.decision)}`,
    };
  }
  return {
    confidence: "unknown",
    outcome: "关键证据字段缺失，不能推断运行时结果",
    reason,
    title: "结论证据不足",
  };
}

export function buildTraceEvidenceViewModel(
  traceId: string,
  events: readonly AuditEventRow[],
  approvals: readonly ApprovalRequest[] = [],
  auditIntegrity?: AuditIntegrity | null,
  auditWindow?: TraceAuditWindow,
): TraceEvidenceViewModel {
  const useAuditSequence = events.every((event) => event.auditSequence !== null);
  const sortedEvents = [...events].sort((left, right) => {
    const primaryOrder = useAuditSequence
      ? left.auditSequence! - right.auditSequence!
      : Date.parse(left.occurredAt) - Date.parse(right.occurredAt);
    return primaryOrder || left.id.localeCompare(right.id);
  });
  const normalized = sortedEvents.map((event) => normalizeAuditEvent(event, approvals));
  const { duplicates, logical } = dedupeLogicalEvents(normalized);
  const primary = combineTraceEvidence(logical);
  const integrity = buildIntegrity(normalized, auditIntegrity, auditWindow);
  return {
    caseId: sortedEvents.find((event) => event.caseId)?.caseId ?? null,
    conclusion: buildConclusion(primary),
    duplicatePolicyAuditCount: duplicates,
    endedAt: normalized.at(-1)?.occurredAt ?? null,
    events: normalized,
    facts: buildFacts(primary, integrity),
    integrity,
    logicalAuditCount: logical.length,
    originalAuditCount: normalized.length,
    primary,
    primaryEventId: primary?.auditId ?? null,
    stages: buildStages(primary),
    startedAt: normalized[0]?.occurredAt ?? null,
    traceId,
  };
}
