import assert from "node:assert/strict";
import test from "node:test";

import { formatRelativeApprovalExpiry, isApprovalExpired } from "./approval-expiry.ts";

const NOW = Date.parse("2026-08-02T10:00:00Z");

test("updates approval expiry labels against a supplied reactive clock", () => {
  assert.equal(formatRelativeApprovalExpiry("2026-08-02T10:01:01Z", NOW), "2 分钟后过期");
  assert.equal(formatRelativeApprovalExpiry("2026-08-02T10:00:00Z", NOW), "已过期");
  assert.equal(formatRelativeApprovalExpiry(undefined, NOW), "到期时间未知");
  assert.equal(formatRelativeApprovalExpiry("invalid", NOW), "到期时间未知");
});

test("only treats valid timestamps at or before the clock as expired", () => {
  assert.equal(isApprovalExpired("2026-08-02T09:59:59Z", NOW), true);
  assert.equal(isApprovalExpired("2026-08-02T10:00:01Z", NOW), false);
  assert.equal(isApprovalExpired("invalid", NOW), false);
  assert.equal(isApprovalExpired(null, NOW), false);
});
