import assert from "node:assert/strict";
import test from "node:test";

import { getApprovalResolutionFailure } from "./approval-resolution.ts";

function apiError(
  code: string,
  status: number,
): Error & {
  code: string;
  status: number;
} {
  return Object.assign(new Error("request failed"), { code, status });
}

test("classifies consumed approval nonces as a refreshable conflict", () => {
  assert.deepEqual(getApprovalResolutionFailure(apiError("APPROVAL_NONCE_INVALID", 403)), {
    kind: "conflict",
    message: "该审批凭证已失效或已被使用，队列已更新。",
    shouldRefreshQueue: true,
  });
});

test("classifies resolved or missing approvals as conflicts", () => {
  const result = getApprovalResolutionFailure(apiError("APPROVAL_NOT_FOUND", 404));

  assert.equal(result.kind, "conflict");
  assert.equal(result.shouldRefreshQueue, true);
});

test("does not expose arbitrary transport error messages", () => {
  const result = getApprovalResolutionFailure(new Error("postgres connection string leaked"));

  assert.deepEqual(result, {
    kind: "failed",
    message: "审批提交失败，当前证据和选择已保留，请检查连接后重试。",
    shouldRefreshQueue: false,
  });
});
