import assert from "node:assert/strict";
import test from "node:test";

import { getRefreshFailureStatus, shouldEnterInitialLoading } from "./refresh-state.ts";

test("only enters blocking loading from the idle state", () => {
  assert.equal(shouldEnterInitialLoading("idle"), true);
  assert.equal(shouldEnterInitialLoading("error"), false);
  assert.equal(shouldEnterInitialLoading("ready"), false);
  assert.equal(shouldEnterInitialLoading("stale"), false);
});

test("uses stale only after a complete successful load", () => {
  assert.equal(getRefreshFailureStatus(false), "error");
  assert.equal(getRefreshFailureStatus(true), "stale");
});
