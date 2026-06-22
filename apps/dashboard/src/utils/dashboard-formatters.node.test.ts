import assert from "node:assert/strict";
import test from "node:test";

import {
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
  getTraceStatusLabel,
} from "./dashboard-formatters.ts";
import { maskSensitiveText, redactSensitiveData } from "./data-redaction.ts";

test("uses one Chinese vocabulary for security states", () => {
  assert.equal(getDecisionLabel("deny"), "拒绝");
  assert.equal(getDecisionTone("ask"), "warning");
  assert.equal(getRiskSeverityLabel("critical"), "严重");
  assert.equal(getTraceStatusLabel("paused"), "等待审批");
});

test("masks contact data used as a visible resource", () => {
  assert.equal(maskSensitiveText("person@example.com"), "pe***@example.com");
  assert.equal(
    maskSensitiveText("/home/alice/.ssh/id_rsa"),
    "/home/***/.ssh/id_rsa",
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
