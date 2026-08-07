import assert from "node:assert/strict";
import test from "node:test";

import { describeAsrChange } from "./asr-change.ts";

test("describes a decrease in attack success rate", () => {
  assert.deepEqual(describeAsrChange(0.8, 0.1), {
    direction: "decrease",
    label: "攻击成功率下降",
    text: "下降 70.0pp",
    value: "70.0pp",
  });
});

test("describes an increase in attack success rate", () => {
  assert.deepEqual(describeAsrChange(0.1, 0.25), {
    direction: "increase",
    label: "攻击成功率上升",
    text: "上升 15.0pp",
    value: "15.0pp",
  });
});

test("describes an unchanged attack success rate", () => {
  assert.deepEqual(describeAsrChange(0.2, 0.2), {
    direction: "unchanged",
    label: "攻击成功率持平",
    text: "持平 0.0pp",
    value: "0.0pp",
  });
});

test("reports insufficient data when either value is missing", () => {
  assert.deepEqual(describeAsrChange(null, 0.2), {
    direction: "unknown",
    label: "变化数据不足",
    text: "数据不足",
    value: "—",
  });
});
