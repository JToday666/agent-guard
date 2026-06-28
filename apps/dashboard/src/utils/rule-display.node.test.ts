import assert from "node:assert/strict";
import test from "node:test";

import {
  formatRuleListForDisplay,
  prepareEvidenceDataForDisplay,
  ruleLabel,
  ruleOptionLabel,
} from "./rule-display.ts";

test("formats known rule ids as user-facing labels without exposing ids", () => {
  assert.equal(ruleLabel("P004_task_mismatch"), "任务与行为不一致");
  assert.equal(ruleOptionLabel("P005_external_send", 3), "外部发送需确认 3");
  assert.equal(formatRuleListForDisplay(["P001_sensitive_file_access", "P004_task_mismatch"]), "敏感文件访问、任务与行为不一致");
});

test("falls back to a readable rule name without the numeric prefix", () => {
  assert.equal(ruleLabel("P999_custom_policy_rule"), "Custom policy rule");
});

test("prepares evidence JSON with display rule labels and no raw rule ids", () => {
  const result = prepareEvidenceDataForDisplay({
    audit_id: "audit_1",
    rule_hits: ["P005_external_send", "P004_task_mismatch"],
    nested: {
      ruleHits: ["P001_sensitive_file_access"],
    },
  });

  assert.deepEqual(result, {
    audit_id: "audit_1",
    rule_hits: ["外部发送需确认", "任务与行为不一致"],
    nested: {
      ruleHits: ["敏感文件访问"],
    },
  });
});
