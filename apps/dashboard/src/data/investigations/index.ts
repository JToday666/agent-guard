import type { AuditEventRow, TraceSummary } from "../../types/dashboard";
import type { InvestigationQueryState } from "../../utils/investigation-query";
import { ruleLabel } from "../../utils/rule-display.ts";

export interface InvestigationIndex {
  byId: Map<string, AuditEventRow>;
  byTrace: Map<string, AuditEventRow[]>;
  latestEvents: AuditEventRow[];
}

export interface RuleFilterOption {
  count: number;
  label: string;
  value: string;
}

export type InvestigationEventResolution =
  { status: "idle" } | { event: AuditEventRow; status: "found" } | { status: "not-found" };

type TraceSummaryEvent = Pick<
  AuditEventRow,
  "approvalId" | "caseId" | "decision" | "occurredAt" | "raw" | "reason"
>;

export function buildTraceSummary(
  id: string,
  events: TraceSummaryEvent[],
): TraceSummary | undefined {
  if (!events.length) return undefined;
  const last = events.at(-1)!;
  const isDenied = events.some((e) => e.decision === "deny");
  const hasAsk = events.some((e) => e.decision === "ask");
  const approvalStatuses = events.flatMap((event) => {
    const raw =
      event.raw && typeof event.raw === "object" ? (event.raw as Record<string, unknown>) : {};
    const evidence =
      raw.evidence && typeof raw.evidence === "object"
        ? (raw.evidence as Record<string, unknown>)
        : {};
    const approval =
      evidence.approval && typeof evidence.approval === "object"
        ? (evidence.approval as Record<string, unknown>)
        : {};
    return typeof approval.status === "string" ? [approval.status] : [];
  });
  const approvalDenied = approvalStatuses.includes("denied");
  const approvalAllowed = approvalStatuses.includes("allowed");
  const isPaused = !isDenied && !approvalDenied && hasAsk && !approvalAllowed;
  const isAllowed =
    !isDenied &&
    !approvalDenied &&
    !isPaused &&
    (approvalAllowed || events.some((e) => e.decision === "allow"));
  const approvalId = [...events].reverse().find((event) => event.approvalId)?.approvalId;
  return {
    id,
    lastEventAt: last.occurredAt,
    caseId: last.caseId ?? "未提供",
    title: last.reason,
    status:
      isDenied || approvalDenied
        ? "denied"
        : isPaused
          ? "paused"
          : isAllowed
            ? "allowed"
            : "unknown",
    approvalId,
  };
}

export function buildInvestigationIndex(events: AuditEventRow[]): InvestigationIndex {
  const latestEvents = [...events].sort(
    (left, right) => Date.parse(right.occurredAt) - Date.parse(left.occurredAt),
  );
  const byId = new Map<string, AuditEventRow>();
  const byTrace = new Map<string, AuditEventRow[]>();

  for (const event of latestEvents) {
    byId.set(event.id, event);
    const traceEvents = byTrace.get(event.traceId) ?? [];
    traceEvents.push(event);
    byTrace.set(event.traceId, traceEvents);
  }

  for (const traceEvents of byTrace.values()) {
    traceEvents.sort((left, right) => Date.parse(left.occurredAt) - Date.parse(right.occurredAt));
  }

  return { byId, byTrace, latestEvents };
}

export function filterInvestigationEvents(
  index: InvestigationIndex,
  query: InvestigationQueryState,
): AuditEventRow[] {
  const searchValue = query.search.toLocaleLowerCase("zh-CN");

  return index.latestEvents.filter((event) => {
    if (query.decision && event.decision !== query.decision) return false;
    if (query.runtime && event.runtime !== query.runtime) return false;
    if (query.severity && event.severity !== query.severity) return false;
    if (query.rule && !event.ruleHits.includes(query.rule)) return false;
    if (query.blocked && event.blocked !== (query.blocked === "true")) return false;
    if (query.eventType && event.eventType !== query.eventType) return false;
    if (query.stage && event.stage !== query.stage) return false;
    if (query.attackType && event.attackType !== query.attackType) return false;
    if (!searchValue) return true;

    return [
      event.id,
      event.resource,
      event.reason,
      event.tool,
      event.caseId,
      event.traceId,
      event.stage,
      event.eventType,
      event.attackType,
      event.userTask,
      event.agentAction,
      ...event.resourceTargets,
      ...event.ruleHits,
      ...event.ruleHits.map(ruleLabel),
    ]
      .join(" ")
      .toLocaleLowerCase("zh-CN")
      .includes(searchValue);
  });
}

export function resolveInvestigationEvent(
  index: InvestigationIndex,
  eventId: string,
  traceId?: string,
): InvestigationEventResolution {
  if (!eventId) return { status: "idle" };
  const event = index.byId.get(eventId);
  if (!event || (traceId && event.traceId !== traceId)) {
    return { status: "not-found" };
  }
  return { event, status: "found" };
}

export function getRuleFilterOptions(events: readonly AuditEventRow[]): RuleFilterOption[] {
  const counts = new Map<string, number>();
  for (const event of events) {
    for (const rule of event.ruleHits) {
      counts.set(rule, (counts.get(rule) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ count, label: ruleLabel(value), value }))
    .sort((left, right) => {
      if (right.count !== left.count) return right.count - left.count;
      return left.value.localeCompare(right.value);
    });
}
