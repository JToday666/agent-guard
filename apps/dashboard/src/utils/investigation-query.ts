import type { LocationQuery, LocationQueryRaw } from "vue-router";

import type { DecisionStatus, RiskSeverity, RuntimeName } from "../types/dashboard";

export interface InvestigationQueryState {
  blocked: "" | "true" | "false";
  decision: "" | DecisionStatus;
  eventId: string;
  page: number;
  rule: string;
  runtime: "" | RuntimeName;
  search: string;
  severity: "" | RiskSeverity;
  eventType: string;
  stage: string;
  attackType: string;
}

type QueryInput = LocationQuery | Record<string, unknown>;

function getString(query: QueryInput, key: string): string {
  const value = query[key];
  return typeof value === "string" ? value.trim() : "";
}

function getAllowedValue<T extends string>(value: string, allowedValues: readonly T[]): "" | T {
  return allowedValues.includes(value as T) ? (value as T) : "";
}

export function normalizeInvestigationQuery(query: QueryInput): InvestigationQueryState {
  const parsedPage = Number.parseInt(getString(query, "page"), 10);

  return {
    blocked: getAllowedValue(getString(query, "blocked"), ["true", "false"]),
    decision: getAllowedValue(getString(query, "decision"), ["allow", "ask", "deny"]),
    eventId: getString(query, "event_id"),
    page: Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1,
    rule: getString(query, "rule"),
    runtime: getAllowedValue(getString(query, "runtime"), ["langgraph", "openclaw"]),
    search: getString(query, "search"),
    severity: getAllowedValue(getString(query, "severity"), ["critical", "high", "medium", "low"]),
    eventType: getString(query, "event_type"),
    stage: getString(query, "stage"),
    attackType: getString(query, "attack_type"),
  };
}

export function mergeInvestigationQuery(
  currentQuery: QueryInput,
  patch: Record<string, string | number | undefined>,
): LocationQueryRaw {
  const nextQuery: LocationQueryRaw = {};

  for (const [key, value] of Object.entries(currentQuery)) {
    if (typeof value === "string" && value.trim()) nextQuery[key] = value.trim();
  }

  for (const [key, value] of Object.entries(patch)) {
    const normalizedValue = typeof value === "string" ? value.trim() : value;
    if (normalizedValue === undefined || normalizedValue === "" || (key === "page" && normalizedValue === 1)) {
      delete nextQuery[key];
    } else {
      nextQuery[key] = String(normalizedValue);
    }
  }

  return nextQuery;
}
