import assert from "node:assert/strict";
import test from "node:test";

import {
  awaitingReceipt,
  fetchFailed,
  getMissingDataLabel,
  noDataNeeded,
  notEnabled,
  notImplemented,
} from "./missing-data-display.ts";

test("keeps normal absence, fetch failure and unavailable capability distinct", () => {
  assert.equal(noDataNeeded("工具参数", "本记录非工具调用"), "无需工具参数（本记录非工具调用）");
  assert.equal(fetchFailed("证据链"), "证据链获取失败");
  assert.equal(notImplemented("溯源投影"), "当前版本未实现溯源投影");
  assert.equal(notEnabled("输出预览"), "输出预览未启用");
  assert.equal(awaitingReceipt(), "等待运行时回执");
  assert.equal(getMissingDataLabel("not_recorded"), "未记录");
});
