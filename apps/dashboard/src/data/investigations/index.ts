import type { AuditEventRow, TraceSummary } from "../../types/dashboard";
import type { InvestigationQueryState } from "../../utils/investigation-query";

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
  | { status: "idle" }
  | { event: AuditEventRow; status: "found" }
  | { status: "not-found" };

export interface TraceConclusion {
  title: string;
  reason: string;
  result: string;
  ruleHits: string[];
}

type TraceSummaryEvent = Pick<
  AuditEventRow,
  "approvalId" | "caseId" | "decision" | "occurredAt" | "reason"
>;

type TraceConclusionEvent = Pick<
  AuditEventRow,
  "blocked" | "decision" | "reason" | "riskScore" | "ruleHits"
>;

export function buildTraceSummary(
  id: string,
  events: TraceSummaryEvent[],
): TraceSummary | undefined {
  if (!events.length) return undefined;
  const last = events.at(-1)!;
  const isDenied = events.some((e) => e.decision === "deny");
  const isPaused = !isDenied && events.some((e) => e.decision === "ask");
  return {
    id,
    lastEventAt: last.occurredAt,
    caseId: last.caseId ?? "未提供",
    title: last.reason,
    status: isDenied ? "blocked" : isPaused ? "paused" : "allowed",
    approvalId: last.approvalId,
  };
}

export function buildTraceConclusion(
  events: TraceConclusionEvent[],
): TraceConclusion | undefined {
  if (!events.length) return undefined;
  const highestRisk = [...events].sort(
    (left, right) => right.riskScore - left.riskScore,
  )[0]!;
  const hasDeny = events.some((event) => event.decision === "deny");
  const hasAsk = !hasDeny && events.some((event) => event.decision === "ask");

  return {
    title: hasDeny ? "已阻断高风险工具调用" : hasAsk ? "等待人工审批" : "已放行",
    reason: highestRisk.reason,
    result: hasDeny
      ? "风险动作已被阻断，目标资源未继续执行"
      : hasAsk
        ? "动作暂停，等待人工审批后继续或拒绝"
        : "动作已放行，未触发阻断或审批",
    ruleHits: highestRisk.ruleHits,
  };
}

export function buildInvestigationIndex(
  events: AuditEventRow[],
): InvestigationIndex {
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
    traceEvents.sort(
      (left, right) =>
        Date.parse(left.occurredAt) - Date.parse(right.occurredAt),
    );
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
    if (query.blocked && event.blocked !== (query.blocked === "true"))
      return false;
    if (query.eventType && event.eventType !== query.eventType) return false;
    if (query.stage && event.stage !== query.stage) return false;
    if (query.attackType && event.attackType !== query.attackType) return false;
    if (!searchValue) return true;

    return [
      event.resource,
      event.reason,
      event.tool,
      event.caseId,
      event.traceId,
      event.stage,
      ...event.resourceTargets,
      ...event.ruleHits,
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

export function getRuleFilterOptions(
  events: readonly AuditEventRow[],
): RuleFilterOption[] {
  const counts = new Map<string, number>();
  for (const event of events) {
    for (const rule of event.ruleHits) {
      counts.set(rule, (counts.get(rule) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ count, label: value, value }))
    .sort((left, right) => {
      if (right.count !== left.count) return right.count - left.count;
      return left.value.localeCompare(right.value);
    });
}
