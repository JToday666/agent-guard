import assert from "node:assert/strict";
import test from "node:test";

import { getTracePollBackoffMs, isTerminalReconciliationComplete } from "./trace-reconciliation.ts";

test("uses the frozen 2/4/8/16 second trace polling backoff", () => {
  assert.deepEqual(
    [1, 2, 3, 4, 5, 9].map((failureCount) => getTracePollBackoffMs(failureCount)),
    [2_000, 4_000, 8_000, 16_000, 16_000, 16_000],
  );
});

test("requires successful Trace and Provenance reads before terminal reconciliation stops", () => {
  assert.equal(isTerminalReconciliationComplete("modified", "not_modified"), true);
  assert.equal(isTerminalReconciliationComplete("not_modified", "modified"), true);

  for (const retryable of ["failed", "aborted", "skipped"] as const) {
    assert.equal(isTerminalReconciliationComplete(retryable, "modified"), false);
    assert.equal(isTerminalReconciliationComplete("modified", retryable), false);
  }
});
