import assert from "node:assert/strict";
import test from "node:test";

import type { ApprovalRequest, AuditEventRow, EvaluationRun } from "../../types/dashboard.ts";
import { createAuditWindow } from "./metrics.ts";
import {
  hasSameAuditWindow,
  hasSameEventWindow,
  hasSameEvaluationRun,
  reconcileApprovals,
} from "./snapshot.ts";

function makeEvent(overrides: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    id: "audit_1",
    auditSequence: 1,
    eventId: "event_1",
    decisionId: "decision_1",
    actionId: "action_1",
    recordType: "policy_evaluation",
    occurredAt: "2026-06-22T06:30:00Z",
    time: "14:30:00",
    decision: "deny",
    riskScore: 95,
    severity: "critical",
    blocked: true,
    runtime: "langgraph",
    stage: "before_tool_call",
    eventType: "tool_call_proposed",
    tool: "read_file",
    resource: "/private/token.txt",
    resourceTargets: ["/private/token.txt"],
    reason: "Sensitive resource",
    traceId: "trace_1",
    caseId: "PI-001",
    approvalId: "app_1",
    ruleHits: ["P001_sensitive_file_access"],
    userTask: null,
    agentAction: "read_file",
    attackType: "prompt_injection",
    latencyMs: 3,
    ...overrides,
  };
}

function makeApproval(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: "approval_1",
    createdAt: "2026-06-22T06:30:00Z",
    status: "pending",
    tool: "send_email",
    resource: "external@example.com",
    riskScore: 70,
    severity: "high",
    reason: "External send",
    eventId: "audit_1",
    traceId: "trace_1",
    userTask: "Send report",
    agentAction: "Send email",
    consequence: "The action will continue once.",
    ruleHits: ["P005_external_send"],
    subjectId: "call_1",
    subjectType: "tool_call",
    actionId: "call_1",
    actionName: "send_email",
    expiresAt: "2026-06-22T06:45:00Z",
    resolvedAt: null,
    ...overrides,
  };
}

test("treats equivalent audit event windows as unchanged", () => {
  assert.equal(hasSameEventWindow([makeEvent()], [makeEvent()]), true);
});

test("detects a visible audit event change", () => {
  assert.equal(hasSameEventWindow([makeEvent()], [makeEvent({ reason: "Updated reason" })]), false);
});

test("detects event type and malicious-label changes used by filters and metrics", () => {
  assert.equal(
    hasSameEventWindow(
      [makeEvent()],
      [makeEvent({ eventType: "model_output", isMalicious: true })],
    ),
    false,
  );
});

test("compares audit windows and their scoped metrics atomically", () => {
  const window = createAuditWindow([makeEvent()], {
    limit: 500,
    hasMore: null,
    source: "legacy_audit_events",
  });
  assert.equal(hasSameAuditWindow(window, createAuditWindow([makeEvent()], window.scope)), true);
  assert.equal(
    hasSameAuditWindow(window, createAuditWindow([makeEvent({ decision: "allow" })], window.scope)),
    false,
  );
});

test("compares evaluation runs without inheriting audit metrics", () => {
  const evaluation: EvaluationRun = {
    runId: "eval_1",
    runAt: "2026-06-28T00:00:00+00:00",
    datasetId: "attackbench",
    datasetVersion: "v1",
    datasetLabel: "attackbench / v1",
    asrBefore: null,
    asrAfter: null,
    perAttack: [
      {
        attackType: "prompt_injection",
        asrBefore: 0.8,
        asrAfter: 0.1,
      },
    ],
    cases: [
      {
        caseId: "PI-001",
        attackType: "prompt_injection",
        runtime: "openclaw",
        expectedDecision: "deny",
        actualDecision: "ask",
        blocked: true,
        attackSuccess: false,
        traceId: "trace_1",
      },
    ],
  };
  assert.equal(hasSameEvaluationRun(evaluation, { ...evaluation }), true);
  assert.equal(
    hasSameEvaluationRun(evaluation, {
      ...evaluation,
      perAttack: [{ ...evaluation.perAttack[0]!, asrAfter: 0.2 }],
    }),
    false,
  );
  assert.equal(
    hasSameEvaluationRun(evaluation, {
      ...evaluation,
      cases: [{ ...evaluation.cases[0]!, actualDecision: "allow" }],
    }),
    false,
  );
});

test("reuses approvals when visible data is unchanged", () => {
  const current = [makeApproval()];
  const incoming = [makeApproval()];

  const reconciled = reconcileApprovals(current, incoming);

  assert.equal(reconciled, current);
  assert.equal(reconciled[0], current[0]);
});

test("replaces approvals when visible data changes", () => {
  const current = [makeApproval()];
  const incoming = [makeApproval({ reason: "Updated reason" })];

  assert.equal(reconcileApprovals(current, incoming), incoming);
});
