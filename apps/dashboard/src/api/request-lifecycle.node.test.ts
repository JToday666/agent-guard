import assert from "node:assert/strict";
import test from "node:test";

import { createTimedRequestSignal } from "./request-lifecycle.ts";

test("marks deadline aborts as request timeouts", async () => {
  const request = createTimedRequestSignal(undefined, 5);

  await new Promise<void>((resolve) => {
    request.signal.addEventListener("abort", () => resolve(), { once: true });
  });

  assert.equal(request.didTimeout(), true);
  assert.equal(request.signal.aborted, true);
  assert.equal((request.signal.reason as Error).name, "TimeoutError");
  request.dispose();
});

test("preserves caller aborts without reporting a timeout", () => {
  const caller = new AbortController();
  const request = createTimedRequestSignal(caller.signal, 10_000);

  caller.abort();

  assert.equal(request.didTimeout(), false);
  assert.equal(request.signal.aborted, true);
  assert.equal((request.signal.reason as Error).name, "AbortError");
  request.dispose();
});

test("normalizes an already-aborted caller signal to AbortError", () => {
  const caller = new AbortController();
  caller.abort(new Error("internal cancellation detail"));

  const request = createTimedRequestSignal(caller.signal, 10_000);

  assert.equal(request.didTimeout(), false);
  assert.equal(request.signal.aborted, true);
  assert.equal((request.signal.reason as Error).name, "AbortError");
  request.dispose();
});
