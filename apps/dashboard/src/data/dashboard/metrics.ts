import type {
  AuditEventRow,
  AuditWindow,
  AuditWindowScope,
  DecisionTrendPoint,
  WindowMetrics,
} from "../../types/dashboard";

const timeLabelFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  hour12: false,
  minute: "2-digit",
});
const datedTimeLabelFormatter = new Intl.DateTimeFormat("zh-CN", {
  day: "2-digit",
  hour: "2-digit",
  hour12: false,
  minute: "2-digit",
  month: "2-digit",
});

export interface LogicalPolicyEvaluationSelection {
  events: AuditEventRow[];
  duplicatePolicyRecordCount: number;
  unkeyedPolicyRecordCount: number;
}

interface AuditWindowOptions {
  filters?: AuditWindowScope["filters"];
  hasMore?: boolean;
  limit: number;
  nextCursor?: string | null;
  outcomesAsOf?: string;
  snapshotId?: string;
}

function logicalPolicyKey(event: AuditEventRow): { key: string; unkeyed: boolean } {
  if (event.eventId && event.decisionId) {
    return {
      key: `${event.eventId}\u0000${event.decisionId}`,
      unkeyed: false,
    };
  }
  return { key: `audit:${event.id}`, unkeyed: true };
}

export function selectLogicalPolicyEvaluations(
  events: readonly AuditEventRow[],
): LogicalPolicyEvaluationSelection {
  const logicalEvents = new Map<string, AuditEventRow>();
  let duplicatePolicyRecordCount = 0;
  let unkeyedPolicyRecordCount = 0;

  for (const event of events) {
    if (event.recordType !== "policy_evaluation") continue;
    const { key, unkeyed } = logicalPolicyKey(event);
    const current = logicalEvents.get(key);
    if (current) {
      duplicatePolicyRecordCount += 1;
      const currentSequence = current.auditSequence;
      const candidateSequence = event.auditSequence;
      if (
        candidateSequence !== null &&
        (currentSequence === null || candidateSequence < currentSequence)
      ) {
        logicalEvents.set(key, event);
      }
      continue;
    }
    if (unkeyed) unkeyedPolicyRecordCount += 1;
    logicalEvents.set(key, event);
  }

  return {
    events: [...logicalEvents.values()],
    duplicatePolicyRecordCount,
    unkeyedPolicyRecordCount,
  };
}

export function deriveWindowMetrics(events: readonly AuditEventRow[]): WindowMetrics {
  const selection = selectLogicalPolicyEvaluations(events);
  const policyEvents = selection.events;
  const latencyValues = policyEvents
    .map((event) => event.latencyMs)
    .filter((value): value is number => value != null);
  const allowCount = policyEvents.filter((event) => event.decision === "allow").length;
  const denyCount = policyEvents.filter((event) => event.decision === "deny").length;
  const askCount = policyEvents.filter((event) => event.decision === "ask").length;
  const unknownDecisionCount = policyEvents.filter((event) => event.decision === "unknown").length;
  const interventionCount = denyCount + askCount;
  const labeledEvents = policyEvents.filter(
    (event) => event.decision !== "unknown" && typeof event.isMalicious === "boolean",
  );
  const benignEvents = labeledEvents.filter((event) => event.isMalicious === false);
  const maliciousEvents = labeledEvents.filter((event) => event.isMalicious === true);
  const falsePositiveCount = benignEvents.filter(
    (event) => event.decision === "deny" || event.decision === "ask",
  ).length;
  const falseNegativeCount = maliciousEvents.filter((event) => event.decision === "allow").length;

  return {
    metricVersion: "policy_evaluation.v2",
    deduplication: "logical_policy_evaluation",
    evaluationCount: policyEvents.length,
    unknownDecisionCount,
    allowCount,
    denyCount,
    askCount,
    interventionCount,
    interventionRate: policyEvents.length ? interventionCount / policyEvents.length : null,
    policyDenyRate: policyEvents.length ? denyCount / policyEvents.length : null,
    approvalTriggerRate: policyEvents.length ? askCount / policyEvents.length : null,
    policyFpr: benignEvents.length ? falsePositiveCount / benignEvents.length : null,
    policyFnr: maliciousEvents.length ? falseNegativeCount / maliciousEvents.length : null,
    benignLabelCount: benignEvents.length,
    maliciousLabelCount: maliciousEvents.length,
    unlabeledCount: policyEvents.filter(
      (event) => event.isMalicious === null || event.isMalicious === undefined,
    ).length,
    averageDecisionLatencyMs: latencyValues.length
      ? latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length
      : null,
    latencySampleCount: latencyValues.length,
    duplicatePolicyRecordCount: selection.duplicatePolicyRecordCount,
    unkeyedPolicyRecordCount: selection.unkeyedPolicyRecordCount,
  };
}

function auditWindowRange(events: readonly AuditEventRow[]): {
  from: string | null;
  to: string | null;
} {
  const validDates = events
    .map((event) => ({ occurredAt: event.occurredAt, timestamp: Date.parse(event.occurredAt) }))
    .filter((item) => Number.isFinite(item.timestamp))
    .sort((left, right) => left.timestamp - right.timestamp);
  return {
    from: validDates[0]?.occurredAt ?? null,
    to: validDates.at(-1)?.occurredAt ?? null,
  };
}

export function createAuditWindow(
  events: AuditEventRow[],
  options: AuditWindowOptions,
): AuditWindow {
  const range = auditWindowRange(events);
  const sequences = events
    .map((event) => event.auditSequence)
    .filter((value): value is number => value !== null);
  return {
    scope: {
      kind: "audit_window",
      snapshotId: options.snapshotId ?? `local:${Math.max(0, ...sequences)}`,
      outcomesAsOf: options.outcomesAsOf ?? range.to ?? new Date(0).toISOString(),
      order: "audit_sequence",
      limit: options.limit,
      returnedRecordCount: events.length,
      hasMore: options.hasMore ?? false,
      nextCursor: options.nextCursor ?? null,
      sequenceFrom: sequences.length ? Math.min(...sequences) : null,
      sequenceTo: sequences.length ? Math.max(...sequences) : null,
      occurredFrom: range.from,
      occurredTo: range.to,
      filters: options.filters ?? {
        traceId: null,
        caseId: null,
        runtime: null,
        decision: null,
      },
    },
    events,
    metrics: deriveWindowMetrics(events),
  };
}

export function groupDecisionTrend(events: readonly AuditEventRow[]): DecisionTrendPoint[] {
  const policyEvents = selectLogicalPolicyEvaluations(events).events;
  const validDates = policyEvents
    .map((event) => new Date(event.occurredAt))
    .filter((date) => !Number.isNaN(date.getTime()))
    .sort((left, right) => left.getTime() - right.getTime());
  if (!validDates.length) return [];

  const spanMs = validDates.at(-1)!.getTime() - validDates[0]!.getTime();
  const bucketMinutes = spanMs <= 45 * 60_000 ? 5 : spanMs <= 6 * 60 * 60_000 ? 30 : 60;
  const includeDate = spanMs > 24 * 60 * 60_000;
  const buckets = new Map<number, DecisionTrendPoint>();

  for (const event of policyEvents) {
    const date = new Date(event.occurredAt);
    if (Number.isNaN(date.getTime())) continue;
    date.setMinutes(Math.floor(date.getMinutes() / bucketMinutes) * bucketMinutes, 0, 0);
    const bucketTime = date.getTime();
    const label = (includeDate ? datedTimeLabelFormatter : timeLabelFormatter).format(date);
    const point = buckets.get(bucketTime) ?? { label, allow: 0, ask: 0, deny: 0 };
    if (event.decision !== "unknown") point[event.decision] += 1;
    buckets.set(bucketTime, point);
  }
  return [...buckets.entries()].sort(([left], [right]) => left - right).map(([, point]) => point);
}
