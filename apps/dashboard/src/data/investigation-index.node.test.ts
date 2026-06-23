import assert from "node:assert/strict";
import test from "node:test";

import type { AuditEventRow } from "../types/dashboard.ts";
import {
  buildInvestigationIndex,
  filterInvestigationEvents,
  resolveInvestigationEvent,
} from "./investigation-index.ts";

function event(overrides: Partial<AuditEventRow>): AuditEventRow {
  return {
    agentAction: null,
    blocked: false,
    caseId: null,
    decision: "allow",
    id: "event-1",
    occurredAt: "2026-01-01T10:00:00.000Z",
    raw: {},
    reason: "正常访问",
    resource: "/workspace/readme.md",
    riskScore: 10,
    ruleHits: [],
    runtime: "langgraph",
    severity: "low",
    stage: "pre_tool",
    time: "10:00:00",
    tool: "read_file",
    traceId: "trace-1",
    userTask: null,
    ...overrides,
  };
}

test("builds reusable latest-first event and trace indexes", () => {
  const older = event({ id: "older" });
  const newer = event({
    id: "newer",
    occurredAt: "2026-01-01T11:00:00.000Z",
    traceId: "trace-1",
  });
  const other = event({ id: "other", traceId: "trace-2" });

  const index = buildInvestigationIndex([older, newer, other]);

  assert.deepEqual(index.latestEvents.map((item) => item.id), ["newer", "older", "other"]);
  assert.equal(index.byId.get("newer"), newer);
  assert.deepEqual(index.byTrace.get("trace-1")?.map((item) => item.id), ["older", "newer"]);
});

test("filters indexed events by combined URL-backed criteria", () => {
  const index = buildInvestigationIndex([
    event({ id: "allow", reason: "普通读取" }),
    event({
      blocked: true,
      decision: "deny",
      id: "deny",
      reason: "敏感文件访问",
      resource: "/home/user/.ssh/config",
      ruleHits: ["P001_sensitive_file_access"],
      severity: "high",
    }),
  ]);

  const result = filterInvestigationEvents(index, {
    blocked: "true",
    decision: "deny",
    eventId: "",
    page: 1,
    rule: "P001_sensitive_file_access",
    runtime: "",
    search: "ssh",
    severity: "high",
  });

  assert.deepEqual(result.map((item) => item.id), ["deny"]);
});

test("distinguishes an absent event request from a missing event", () => {
  const index = buildInvestigationIndex([event({ id: "event-1" })]);

  assert.deepEqual(resolveInvestigationEvent(index, ""), { status: "idle" });
  assert.deepEqual(resolveInvestigationEvent(index, "missing"), {
    status: "not-found",
  });
});

test("rejects an event that does not belong to the requested trace", () => {
  const index = buildInvestigationIndex([event({ id: "event-1", traceId: "trace-1" })]);

  assert.deepEqual(resolveInvestigationEvent(index, "event-1", "trace-2"), {
    status: "not-found",
  });
  assert.deepEqual(resolveInvestigationEvent(index, "event-1", "trace-1"), {
    event: index.byId.get("event-1"),
    status: "found",
  });
});
