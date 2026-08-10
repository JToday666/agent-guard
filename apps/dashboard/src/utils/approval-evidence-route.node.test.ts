import assert from "node:assert/strict";
import test from "node:test";

import type { ApprovalRequest } from "../types/dashboard.ts";
import { getApprovalEvidenceRoutes } from "./approval-evidence-route.ts";

function approval(eventId: string): ApprovalRequest {
  return {
    agentAction: "发送邮件",
    actionId: "call-1",
    actionName: "send_email",
    consequence: "动作将继续执行",
    createdAt: "2026-06-07T12:03:30+08:00",
    eventId,
    id: "ask-1",
    reason: "需要人工确认",
    resource: "recipient@example.invalid",
    riskScore: 64,
    ruleHits: [],
    severity: "high",
    status: "pending",
    subjectId: "call-1",
    subjectType: "tool_call",
    traceId: "trace-2",
    userTask: "发送摘要",
  };
}

test("builds separate trace and event evidence destinations", () => {
  assert.deepEqual(getApprovalEvidenceRoutes(approval("event-2")), {
    event: {
      path: "/evidence/trace-2",
      query: { event_id: "event-2" },
    },
    trace: { path: "/evidence/trace-2" },
  });
});

test("omits the event destination when approval has no event id", () => {
  assert.deepEqual(getApprovalEvidenceRoutes(approval("")), {
    event: null,
    trace: { path: "/evidence/trace-2" },
  });
});
