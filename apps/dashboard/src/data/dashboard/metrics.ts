import type { DecisionStatus, DecisionTrendPoint, EvalMetrics } from "../../types/dashboard";

interface MetricEvent {
  decision: DecisionStatus;
  blocked: boolean | null;
  occurredAt: string;
  latencyMs?: number | null;
}

export function deriveMetrics(events: readonly MetricEvent[]): EvalMetrics {
  const latencyValues = events
    .map((event) => event.latencyMs)
    .filter((value): value is number => value != null);
  const blockedCount = events.filter(
    (event) => event.blocked === true || event.decision === "deny" || event.decision === "ask",
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
      ? latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length
      : null,
  };
}

export function groupDecisionTrend(events: readonly MetricEvent[]): DecisionTrendPoint[] {
  const validDates = events
    .map((event) => new Date(event.occurredAt))
    .filter((date) => !Number.isNaN(date.getTime()))
    .sort((left, right) => left.getTime() - right.getTime());
  if (!validDates.length) return [];

  const spanMs = validDates.at(-1)!.getTime() - validDates[0]!.getTime();
  const bucketMinutes = spanMs <= 45 * 60_000 ? 5 : spanMs <= 6 * 60 * 60_000 ? 30 : 60;
  const includeDate = spanMs > 24 * 60 * 60_000;
  const buckets = new Map<number, DecisionTrendPoint>();

  for (const event of events) {
    const date = new Date(event.occurredAt);
    if (Number.isNaN(date.getTime())) continue;
    date.setMinutes(Math.floor(date.getMinutes() / bucketMinutes) * bucketMinutes, 0, 0);
    const bucketTime = date.getTime();
    const timeLabel = `${String(date.getHours()).padStart(2, "0")}:${String(
      date.getMinutes(),
    ).padStart(2, "0")}`;
    const label = includeDate
      ? `${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(
          2,
          "0",
        )} ${timeLabel}`
      : timeLabel;
    const point = buckets.get(bucketTime) ?? { label, allow: 0, ask: 0, deny: 0 };
    if (event.decision !== "unknown") point[event.decision] += 1;
    buckets.set(bucketTime, point);
  }
  return [...buckets.entries()].sort(([left], [right]) => left - right).map(([, point]) => point);
}
