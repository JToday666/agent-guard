import assert from "node:assert/strict";
import test from "node:test";

import type { AuditEventRow } from "../../types/dashboard.ts";
import {
  createAuditWindow,
  deriveWindowMetrics,
  groupDecisionTrend,
  selectLogicalPolicyEvaluations,
} from "./metrics.ts";

function event(overrides: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    id: "audit-1",
    auditSequence: 1,
    eventId: "event-1",
    decisionId: "decision-1",
    actionId: "action-1",
    recordType: "policy_evaluation",
    occurredAt: "2026-06-22T06:05:00Z",
    time: "14:05:00",
    decision: "allow",
    riskScore: 10,
    severity: "low",
    blocked: false,
    runtime: "langgraph",
    stage: "before_tool_call",
    eventType: "tool_call_proposed",
    tool: "read_file",
    resource: "/workspace/readme.md",
    resourceTargets: ["/workspace/readme.md"],
    reason: "Allowed",
    traceId: "trace-1",
    caseId: null,
    ruleHits: [],
    userTask: null,
    agentAction: "read_file",
    attackType: null,
    isMalicious: false,
    latencyMs: 10,
    raw: {},
    ...overrides,
  };
}

const events = [
  event(),
  event({
    id: "audit-2",
    eventId: "event-2",
    decisionId: "decision-2",
    actionId: "action-2",
    decision: "deny",
    blocked: true,
    isMalicious: true,
    occurredAt: "2026-06-22T06:20:00Z",
    latencyMs: 30,
  }),
  event({
    id: "audit-3",
    eventId: "event-3",
    decisionId: "decision-3",
    actionId: "action-3",
    decision: "ask",
    blocked: true,
    isMalicious: false,
    occurredAt: "2026-06-22T07:10:00Z",
    latencyMs: null,
  }),
] as const;

test("derives policy metrics from logical evaluations instead of raw audit records", () => {
  const duplicate = event({
    ...events[1],
    id: "audit-2-duplicate",
    auditSequence: 4,
    decision: "allow",
    isMalicious: false,
    latencyMs: 300,
  });
  const outcome = event({
    ...events[1],
    id: "audit-2-outcome",
    recordType: "runtime_outcome",
    occurredAt: "2026-06-22T06:21:00Z",
  });
  const metrics = deriveWindowMetrics([...events, duplicate, outcome]);

  assert.equal(metrics.evaluationCount, 3);
  assert.equal(metrics.allowCount, 1);
  assert.equal(metrics.denyCount, 1);
  assert.equal(metrics.askCount, 1);
  assert.equal(metrics.interventionCount, 2);
  assert.equal(metrics.interventionRate, 2 / 3);
  assert.equal(metrics.policyDenyRate, 1 / 3);
  assert.equal(metrics.approvalTriggerRate, 1 / 3);
  assert.equal(metrics.averageDecisionLatencyMs, 20);
  assert.equal(metrics.latencySampleCount, 2);
  assert.equal(metrics.duplicatePolicyRecordCount, 1);
});

test("uses the earliest audit sequence as the canonical duplicate", () => {
  const selection = selectLogicalPolicyEvaluations([
    event({ id: "audit-late", auditSequence: 20, decision: "allow" }),
    event({ id: "audit-early", auditSequence: 10, decision: "deny" }),
  ]);

  assert.equal(selection.events.length, 1);
  assert.equal(selection.events[0]?.id, "audit-early");
  assert.equal(selection.events[0]?.decision, "deny");
  assert.equal(selection.duplicatePolicyRecordCount, 1);
});

test("uses labeled logical evaluations for policy FPR and FNR denominators", () => {
  const metrics = deriveWindowMetrics(events);

  assert.equal(metrics.benignLabelCount, 2);
  assert.equal(metrics.maliciousLabelCount, 1);
  assert.equal(metrics.policyFpr, 0.5);
  assert.equal(metrics.policyFnr, 0);
});

test("reports legacy fallback rows without guessing a logical key", () => {
  const selection = selectLogicalPolicyEvaluations([
    event({ id: "legacy-1", eventId: null, decisionId: null }),
    event({ id: "legacy-2", eventId: null, decisionId: null }),
  ]);

  assert.equal(selection.events.length, 2);
  assert.equal(selection.legacyFallbackCount, 2);
  assert.equal(selection.duplicatePolicyRecordCount, 0);
});

test("creates an explicit client-derived audit window scope", () => {
  const window = createAuditWindow([...events], {
    limit: 500,
    hasMore: null,
    source: "legacy_audit_events",
  });

  assert.equal(window.scope.returnedRecordCount, 3);
  assert.equal(window.scope.hasMore, null);
  assert.equal(window.scope.from, "2026-06-22T06:05:00Z");
  assert.equal(window.scope.to, "2026-06-22T07:10:00Z");
  assert.equal(window.metrics.evaluationCount, 3);
});

test("groups only logical policy decisions into chronological buckets", () => {
  const formatter = new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    hour12: false,
    minute: "2-digit",
  });
  const firstHour = formatter.format(new Date("2026-06-22T06:00:00Z"));
  const secondHour = formatter.format(new Date("2026-06-22T07:00:00Z"));
  const outcome = event({
    ...events[1],
    id: "audit-outcome",
    recordType: "runtime_outcome",
  });

  assert.deepEqual(groupDecisionTrend([...events, outcome]), [
    { label: firstHour, allow: 1, ask: 0, deny: 1 },
    { label: secondHour, allow: 0, ask: 1, deny: 0 },
  ]);
});
