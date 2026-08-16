import assert from "node:assert/strict";
import test from "node:test";

import { booleanFlag } from "./dashboard-env.ts";

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
