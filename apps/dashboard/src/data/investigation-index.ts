import type { AuditEventRow } from "../types/dashboard";
import type { InvestigationQueryState } from "../utils/investigation-query";

export interface InvestigationIndex {
  byId: Map<string, AuditEventRow>;
  byTrace: Map<string, AuditEventRow[]>;
  latestEvents: AuditEventRow[];
}

export type InvestigationEventResolution =
  | { status: "idle" }
  | { event: AuditEventRow; status: "found" }
  | { status: "not-found" };

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
    if (!searchValue) return true;

    return [
      event.resource,
      event.reason,
      event.tool,
      event.caseId,
      event.traceId,
      event.stage,
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
