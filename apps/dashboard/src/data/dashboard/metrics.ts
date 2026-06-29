import type {
  DecisionStatus,
  DecisionTrendPoint,
  EvalMetrics,
} from "../../types/dashboard.ts";

interface MetricEvent {
  decision: DecisionStatus;
  blocked: boolean;
  occurredAt: string;
  latencyMs?: number | null;
}

export function deriveMetrics(events: readonly MetricEvent[]): EvalMetrics {
  const latencyValues = events
    .map((event) => event.latencyMs)
    .filter((value): value is number => value != null);
  const blockedCount = events.filter(
    (event) => event.blocked || event.decision !== "allow",
  ).length;
  return {
    eventCount: events.length,
    allowCount: events.filter((event) => event.decision === "allow").length,
    denyCount: events.filter((event) => event.decision === "deny").length,
    askCount: events.filter((event) => event.decision === "ask").length,
    blockedCount,
    blockRate: events.length ? blockedCount / events.length : null,
    fpr: null,
    fnr: null,
    averageLatencyMs: latencyValues.length
      ? latencyValues.reduce((sum, value) => sum + value, 0) /
        latencyValues.length
      : null,
  };
}

export function groupDecisionTrend(
  events: readonly MetricEvent[],
): DecisionTrendPoint[] {
  const buckets = new Map<string, DecisionTrendPoint>();
  for (const event of events) {
    const date = new Date(event.occurredAt);
    if (Number.isNaN(date.getTime())) continue;
    const label = `${String(date.getHours()).padStart(2, "0")}:00`;
    const point = buckets.get(label) ?? { label, allow: 0, ask: 0, deny: 0 };
    point[event.decision] += 1;
    buckets.set(label, point);
  }
  return [...buckets.values()].sort((left, right) =>
    left.label.localeCompare(right.label),
  );
}
