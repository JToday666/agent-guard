import assert from "node:assert/strict";
import test from "node:test";

import {
  getAuthErrorMessage,
  isSessionAuthError,
} from "./auth-error-messages.ts";

function apiError(
  code: string,
  status = 401,
): Error & {
  code: string;
  status: number;
} {
  return Object.assign(new Error(`请求失败 (${status})`), { code, status });
}

test("maps consumed launch codes to an actionable message", () => {
  const error = apiError("LAUNCH_CODE_INVALID");

  assert.equal(
    getAuthErrorMessage(error),
    "启动链接无效或已使用，请通过本机启动器重新打开 Dashboard。",
  );
});

test("recognizes expired and invalid browser sessions", () => {
  assert.equal(isSessionAuthError(apiError("SESSION_EXPIRED")), true);
  assert.equal(isSessionAuthError(apiError("REQUEST_FAILED", 503)), false);
});
