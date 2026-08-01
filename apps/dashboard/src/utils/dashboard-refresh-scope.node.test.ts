import assert from "node:assert/strict";
import test from "node:test";

import {
  getDashboardRefreshResources,
  getDashboardRefreshScope,
} from "./dashboard-refresh-scope.ts";

test("refresh scope maps both evidence routes to the evidence domain", () => {
  assert.equal(getDashboardRefreshScope("evidence"), "evidence");
  assert.equal(getDashboardRefreshScope("evidence-detail"), "evidence");
  assert.equal(getDashboardRefreshScope("unknown"), "overview");
});

test("refresh resources include common shell data and only page-specific domains", () => {
  const investigationResources = getDashboardRefreshResources("investigations");
  assert.deepEqual([...investigationResources], ["health", "approvals", "events"]);

  const evaluationResources = getDashboardRefreshResources("evaluation");
  assert.equal(evaluationResources.has("events"), true);
  assert.equal(evaluationResources.has("evaluation"), true);

  const systemResources = getDashboardRefreshResources("system");
  assert.equal(systemResources.has("events"), false);
  assert.equal(systemResources.has("policy"), true);
  assert.equal(systemResources.has("adapter"), true);
});
