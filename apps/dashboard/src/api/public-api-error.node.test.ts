import assert from "node:assert/strict";
import test from "node:test";

import { getPublicApiErrorMessage } from "./public-api-error.ts";

test("uses stable code messages for actionable authentication errors", () => {
  assert.equal(
    getPublicApiErrorMessage(401, "LAUNCH_CODE_EXPIRED"),
    "启动链接已过期，请通过本机启动器重新打开 Dashboard。",
  );
});

test("maps unknown server errors without exposing an upstream response body", () => {
  assert.equal(
    getPublicApiErrorMessage(502, "UPSTREAM_PRIVATE_DETAIL"),
    "核心服务暂时无法完成请求，请稍后重试。",
  );
});

test("provides a controlled network failure message", () => {
  assert.equal(
    getPublicApiErrorMessage(0, "NETWORK_ERROR"),
    "无法连接核心服务，请检查服务状态后重试。",
  );
});

test("provides a distinct request timeout message", () => {
  assert.equal(getPublicApiErrorMessage(0, "REQUEST_TIMEOUT"), "核心服务请求超时，请稍后重试。");
});

test("uses a controlled message for an invalid success response", () => {
  assert.equal(
    getPublicApiErrorMessage(200, "INVALID_RESPONSE"),
    "核心服务返回的数据暂时无法识别，请稍后重试或联系管理员。",
  );
});
