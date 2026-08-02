import assert from "node:assert/strict";
import test from "node:test";

import { getAttackTypeLabel } from "./attack-type.ts";

test("formats known attack types consistently and preserves unknown API values", () => {
  assert.equal(getAttackTypeLabel("prompt_injection"), "提示注入");
  assert.equal(getAttackTypeLabel("tool_hijack"), "工具调用劫持");
  assert.equal(getAttackTypeLabel("custom_attack_family"), "custom_attack_family");
});
