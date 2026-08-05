import assert from "node:assert/strict";
import test from "node:test";

import {
  formatRuleListForDisplay,
  formatRuleIdsInTextForDisplay,
  prepareEvidenceDataForDisplay,
  ruleLabel,
} from "./rule-display.ts";

test("formats known rule ids as user-facing labels without exposing ids", () => {
  assert.equal(ruleLabel("P004_task_mismatch"), "任务与行为不一致");
  assert.equal(ruleLabel("P109_mcp_tool_hijacking"), "MCP 工具劫持");
  assert.equal(
    formatRuleListForDisplay(["P001_sensitive_file_access", "P004_task_mismatch"]),
    "敏感文件访问、任务与行为不一致",
  );
});

test("falls back to a readable rule name without the numeric prefix", () => {
  assert.equal(ruleLabel("P999_custom_policy_rule"), "Custom policy rule");
  assert.doesNotMatch(ruleLabel("P999_custom_policy_rule"), /P\d{3}/);
  assert.doesNotMatch(formatRuleListForDisplay(["P999_custom_policy_rule"]), /P\d{3}/);
});

test("formats embedded rule ids in user-facing text", () => {
  const text = "Matched P005_external_send and P999_custom_policy_rule during review";

  assert.equal(
    formatRuleIdsInTextForDisplay(text),
    "Matched 外部发送需确认 and Custom policy rule during review",
  );
  assert.doesNotMatch(formatRuleIdsInTextForDisplay(text), /P\d{3}/);
});

test("prepares evidence JSON with display rule labels and no raw rule ids", () => {
  const result = prepareEvidenceDataForDisplay({
    audit_id: "audit_1",
    rule_hits: ["P005_external_send", "P004_task_mismatch"],
    nested: {
      ruleHits: ["P001_sensitive_file_access"],
      reason: "blocked by P004_task_mismatch",
    },
  });

  assert.deepEqual(result, {
    audit_id: "audit_1",
    rule_hits: ["外部发送需确认", "任务与行为不一致"],
    nested: {
      ruleHits: ["敏感文件访问"],
      reason: "blocked by 任务与行为不一致",
    },
  });
});
