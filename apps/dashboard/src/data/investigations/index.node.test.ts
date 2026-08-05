import assert from "node:assert/strict";
import test from "node:test";

import type { AuditEventRow } from "../../types/dashboard.ts";
import {
  buildInvestigationIndex,
  buildTraceSummary,
  filterInvestigationEvents,
  getRuleFilterOptions,
  resolveInvestigationEvent,
} from "./index.ts";

function event(overrides: Partial<AuditEventRow>): AuditEventRow {
  return {
    actionId: "action-1",
    agentAction: null,
    auditSequence: 1,
    blocked: false,
    caseId: null,
    decision: "allow",
    decisionId: "decision-1",
    eventId: "guard-event-1",
    id: "event-1",
    occurredAt: "2026-01-01T10:00:00.000Z",
    raw: {},
    recordType: "policy_evaluation",
    reason: "正常访问",
    resource: "/workspace/readme.md",
    resourceTargets: ["/workspace/readme.md"],
    riskScore: 10,
    ruleHits: [],
    runtime: "langgraph",
    severity: "low",
    stage: "pre_tool",
    eventType: "tool_call_proposed",
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

  assert.deepEqual(
    index.latestEvents.map((item) => item.id),
    ["newer", "older", "other"],
  );
  assert.equal(index.byId.get("newer"), newer);
  assert.deepEqual(
    index.byTrace.get("trace-1")?.map((item) => item.id),
    ["older", "newer"],
  );
});

test("builds dynamic rule filter options from real audit data", () => {
  const index = buildInvestigationIndex([
    event({
      id: "prompt",
      ruleHits: ["P101_prompt_injection", "P105_environment_poisoning"],
    }),
    event({
      id: "second-prompt",
      ruleHits: ["P101_prompt_injection"],
    }),
    event({
      id: "sensitive",
      ruleHits: ["P001_sensitive_file_access"],
    }),
  ]);

  assert.deepEqual(getRuleFilterOptions(index.latestEvents), [
    {
      count: 2,
      label: "提示词注入",
      value: "P101_prompt_injection",
    },
    {
      count: 1,
      label: "敏感文件访问",
      value: "P001_sensitive_file_access",
    },
    {
      count: 1,
      label: "环境内容污染",
      value: "P105_environment_poisoning",
    },
  ]);
});

test("searches event ids, tasks, actions, event types and readable rule names", () => {
  const index = buildInvestigationIndex([
    event({
      agentAction: "向外部收件人发送摘要",
      eventType: "message_send_proposed",
      id: "audit-search-001",
      ruleHits: ["P005_external_send"],
      userTask: "整理客户反馈摘要",
    }),
  ]);
  const baseQuery = {
    attackType: "",
    blocked: "" as const,
    decision: "" as const,
    eventId: "",
    eventType: "",
    page: 1,
    rule: "",
    runtime: "" as const,
    search: "",
    severity: "" as const,
    stage: "",
  };

  for (const search of [
    "audit-search-001",
    "整理客户反馈",
    "外部收件人",
    "message_send_proposed",
    "外部发送需确认",
  ]) {
    assert.deepEqual(
      filterInvestigationEvents(index, { ...baseQuery, search }).map((item) => item.id),
      ["audit-search-001"],
      search,
    );
  }
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
    eventType: "",
    stage: "",
    attackType: "",
  });

  assert.deepEqual(
    result.map((item) => item.id),
    ["deny"],
  );
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

test("keeps approval linkage aligned with the trace outcome", () => {
  const approvalEvent = event({
    approvalId: "approval-1",
    decision: "ask",
    id: "approval",
    occurredAt: "2026-01-01T10:00:00.000Z",
  });
  const deniedEvent = event({
    blocked: true,
    decision: "deny",
    id: "denied",
    occurredAt: "2026-01-01T10:01:00.000Z",
    reason: "危险动作被策略拒绝",
    riskScore: 70,
    ruleHits: ["P103_code_execution_abuse"],
  });
  const laterAllow = event({
    decision: "allow",
    id: "later-allow",
    occurredAt: "2026-01-01T10:02:00.000Z",
    reason: "后续低风险读取被策略允许",
    riskScore: 95,
  });

  assert.equal(
    buildTraceSummary("trace-1", [approvalEvent, deniedEvent, laterAllow])?.approvalId,
    "approval-1",
  );
});

test("uses an explicitly recorded approval result for the trace list status", () => {
  const approved = event({
    approvalId: "approval-1",
    decision: "ask",
    raw: {
      evidence: {
        approval: {
          status: "allowed",
        },
      },
    },
  });
  const pending = event({
    approvalId: "approval-2",
    decision: "ask",
    raw: {
      evidence: {
        approval: {
          status: "pending",
        },
      },
    },
  });

  assert.equal(buildTraceSummary("trace-approved", [approved])?.status, "allowed");
  assert.equal(buildTraceSummary("trace-pending", [pending])?.status, "paused");
});
