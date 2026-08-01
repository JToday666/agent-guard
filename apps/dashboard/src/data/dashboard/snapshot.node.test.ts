import assert from "node:assert/strict";
import test from "node:test";

import type { ApprovalRequest, AuditEventRow, EvalMetrics, EvaluationSummary } from "../../types/dashboard.ts";
import { hasSameEventWindow, hasSameEvaluation, hasSameMetrics, reconcileApprovals } from "./snapshot.ts";

function makeEvent(overrides: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    id: "audit_1",
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

const metrics: EvalMetrics = {
  eventCount: 1,
  allowCount: 0,
  denyCount: 1,
  askCount: 0,
  blockedCount: 1,
  blockRate: 1,
  fpr: null,
  fnr: null,
  averageLatencyMs: 3,
};

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
    approvalNonce: "nonce_1",
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

test("compares evaluation metrics by value", () => {
  assert.equal(hasSameMetrics(metrics, { ...metrics }), true);
  assert.equal(hasSameMetrics(metrics, { ...metrics, blockedCount: 0 }), false);
});

test("compares evaluation summaries by value", () => {
  const evaluation: EvaluationSummary = {
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
        reduction: 0.7000000000000001,
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
    blockRate: 1,
    fpr: null,
    fnr: 0.2,
    averageLatencyMs: 3,
  };
  assert.equal(hasSameEvaluation(evaluation, { ...evaluation }), true);
  assert.equal(hasSameEvaluation(evaluation, { ...evaluation, blockRate: 0.5 }), false);
  assert.equal(hasSameEvaluation(evaluation, { ...evaluation, fnr: null }), false);
  assert.equal(
    hasSameEvaluation(evaluation, {
      ...evaluation,
      perAttack: [{ ...evaluation.perAttack[0]!, asrAfter: 0.2 }],
    }),
    false,
  );
  assert.equal(
    hasSameEvaluation(evaluation, {
      ...evaluation,
      cases: [{ ...evaluation.cases[0]!, actualDecision: "allow" }],
    }),
    false,
  );
});

test("updates approval nonce without replacing unchanged visible data", () => {
  const current = [makeApproval()];
  const incoming = [makeApproval({ approvalNonce: "nonce_2" })];

  const reconciled = reconcileApprovals(current, incoming);

  assert.equal(reconciled, current);
  assert.equal(reconciled[0], current[0]);
  assert.equal(reconciled[0]?.approvalNonce, "nonce_2");
});

test("replaces approvals when visible data changes", () => {
  const current = [makeApproval()];
  const incoming = [makeApproval({ reason: "Updated reason" })];

  assert.equal(reconcileApprovals(current, incoming), incoming);
});
