import assert from "node:assert/strict";
import test from "node:test";

import {
  booleanFlag,
  DEFAULT_EVIDENCE_POLL_INTERVAL_MS,
  resolveEvidencePollIntervalMs,
} from "./dashboard-env.ts";

test("keeps S1 enabled by default and accepts explicit build-time values", () => {
  assert.equal(booleanFlag(undefined, true), true);
  assert.equal(booleanFlag("", true), true);
  assert.equal(booleanFlag("false", true), false);
  assert.equal(booleanFlag("0", true), false);
  assert.equal(booleanFlag("off", true), false);
  assert.equal(booleanFlag("TRUE", false), true);
  assert.equal(booleanFlag("yes", false), true);
});

test("invalid build-time flag values fail to the configured safe default", () => {
  assert.equal(booleanFlag("maybe", true), true);
  assert.equal(booleanFlag("maybe", false), false);
});

test("defaults evidence polling to ten seconds", () => {
  assert.equal(resolveEvidencePollIntervalMs(undefined), DEFAULT_EVIDENCE_POLL_INTERVAL_MS);
  assert.equal(resolveEvidencePollIntervalMs(""), DEFAULT_EVIDENCE_POLL_INTERVAL_MS);
  assert.equal(resolveEvidencePollIntervalMs("invalid"), DEFAULT_EVIDENCE_POLL_INTERVAL_MS);
  assert.equal(resolveEvidencePollIntervalMs("0"), DEFAULT_EVIDENCE_POLL_INTERVAL_MS);
});

test("clamps evidence polling to two seconds and accepts slower intervals", () => {
  assert.equal(resolveEvidencePollIntervalMs("1"), 2_000);
  assert.equal(resolveEvidencePollIntervalMs("1999.9"), 2_000);
  assert.equal(resolveEvidencePollIntervalMs("2000"), 2_000);
  assert.equal(resolveEvidencePollIntervalMs("15000.8"), 15_000);
});
