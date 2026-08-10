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

test("classifies expired approvals as a refreshable conflict", () => {
  assert.deepEqual(getApprovalResolutionFailure(apiError("APPROVAL_EXPIRED", 409)), {
    kind: "conflict",
    message: "该审批已过期，队列已更新。",
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

test("refreshes the queue when an approval result is uncertain", () => {
  for (const reason of [
    apiError("NETWORK_ERROR", 0),
    apiError("REQUEST_TIMEOUT", 0),
    apiError("INTERNAL_ERROR", 503),
  ]) {
    assert.deepEqual(getApprovalResolutionFailure(reason), {
      kind: "uncertain",
      message: "审批提交结果未确认，已尝试刷新待审批队列，请以当前状态为准。",
      shouldRefreshQueue: true,
    });
  }
});
