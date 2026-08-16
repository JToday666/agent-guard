import assert from "node:assert/strict";
import test from "node:test";

import type { ApprovalRequest } from "../types/dashboard.ts";
import { getApprovalEvidenceRoutes } from "./approval-evidence-route.ts";

function approval(policyAuditId: string | null): ApprovalRequest {
  return {
    agentAction: "发送邮件",
    actionId: "call-1",
    actionName: "send_email",
    agentId: "agent-1",
    consequence: "动作将继续执行",
    createdAt: "2026-06-07T12:03:30+08:00",
    decision: null,
    decisionId: "decision-1",
    decisionOptions: ["allow_once", "deny"],
    eventId: "event-2",
    evidence: null,
    id: "ask-1",
    policyAuditId,
    reason: "需要人工确认",
    requestingPrincipalId: "principal-1",
    resolutionReason: null,
    resolutionSource: null,
    resolvedAt: null,
    resolvedBy: null,
    resource: "recipient@example.invalid",
    riskScore: 64,
    ruleHits: [],
    severity: "high",
    status: "pending",
    subjectId: "call-1",
    subjectType: "tool_call",
    traceId: "trace-2",
    runtime: "langgraph",
    userTask: "发送摘要",
  };
}

test("builds separate trace and policy-audit evidence destinations", () => {
  assert.deepEqual(getApprovalEvidenceRoutes(approval("audit-2")), {
    event: {
      path: "/evidence/trace-2",
      query: { event_id: "audit-2" },
    },
    trace: { path: "/evidence/trace-2" },
  });
});

test("omits the event destination when approval has no policy audit id", () => {
  assert.deepEqual(getApprovalEvidenceRoutes(approval(null)), {
    event: null,
    trace: { path: "/evidence/trace-2" },
  });
});
