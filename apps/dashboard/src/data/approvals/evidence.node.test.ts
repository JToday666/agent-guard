import assert from "node:assert/strict";
import test from "node:test";

import type { ApprovalRequest, AuditEventRow } from "../../types/dashboard.ts";
import { formatApprovalEvidenceFields, mergeApprovalsWithAuditEvidence } from "./evidence.ts";

function event(overrides: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    actionId: "call_1",
    agentAction: "Agent attempted to call send_email",
    approvalId: "app_1",
    auditSequence: 1,
    attackType: "prompt_injection",
    blocked: true,
    caseId: "PI-001",
    decision: "ask",
    decisionId: "decision_1",
    eventId: "event_1",
    id: "audit_1",
    latencyMs: 5,
    occurredAt: "2026-06-22T06:30:00Z",
    raw: {},
    recordType: "policy_evaluation",
    reason: "External send requires approval",
    resource: "recipient@example.invalid",
    resourceTargets: ["recipient@example.invalid"],
    riskScore: 62,
    ruleHits: ["P005_external_send", "P004_task_mismatch"],
    runtime: "langgraph",
    severity: "medium",
    stage: "tool_call_proposed",
    eventType: "tool_call_proposed",
    time: "14:30:00",
    tool: "send_email",
    traceId: "trace_1",
    userTask: "整理客户反馈摘要",
    ...overrides,
  };
}

function approval(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    actionId: "call_1",
    actionName: "send_email",
    agentAction: "send_email(recipient@example.invalid)",
    consequence: "允许一次后，当前暂停的工具动作将继续执行。",
    createdAt: "2026-06-22T06:30:00Z",
    eventId: "",
    id: "app_1",
    reason: "External send requires approval",
    resource: "recipient@example.invalid",
    riskScore: 62,
    ruleHits: [],
    severity: "medium",
    status: "pending",
    subjectId: "call_1",
    subjectType: "tool_call",
    tool: "send_email",
    traceId: "trace_1",
    userTask: "未提供",
    ...overrides,
  };
}

test("fills approval evidence from matching audit event", () => {
  const [result] = mergeApprovalsWithAuditEvidence([approval()], [event()]);

  assert.equal(result?.eventId, "audit_1");
  assert.equal(result?.userTask, "整理客户反馈摘要");
  assert.equal(result?.agentAction, "Agent attempted to call send_email");
  assert.deepEqual(result?.ruleHits, ["P005_external_send", "P004_task_mismatch"]);
});

test("keeps approval fields when no matching audit event is loaded", () => {
  const original = approval({ id: "missing" });
  const [result] = mergeApprovalsWithAuditEvidence([original], [event()]);

  assert.equal(result, original);
});

test("formats explicit approval evidence fields without exposing the nonce", () => {
  assert.deepEqual(formatApprovalEvidenceFields(approval({ eventId: "audit_1" })), {
    action: "send_email / call_1",
    eventId: "audit_1",
    subject: "tool_call / call_1",
    traceId: "trace_1",
  });
});
