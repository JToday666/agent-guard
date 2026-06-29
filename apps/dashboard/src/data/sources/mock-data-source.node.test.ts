import assert from "node:assert/strict";
import test from "node:test";

import { MockDashboardDataSource } from "./mock-data-source.ts";

test("mock provenance graph contains evidence nodes and event references", async () => {
  const source = new MockDashboardDataSource(0);
  const graph = await source.getTraceProvenance("trace_002");

  assert.equal(graph.traceId, "trace_002");
  assert.ok(graph.nodes.length >= 8);
  assert.ok(graph.edges.length >= 7);
  assert.ok(
    graph.nodes.some((node) => node.refId === "event:evt_20260607_002"),
  );
  assert.ok(graph.nodes.some((node) => node.refId.startsWith("context:")));
  assert.ok(graph.nodes.some((node) => node.refId.startsWith("resource:")));
  assert.ok(graph.nodes.some((node) => node.refId === "approval:ask_001"));
  assert.ok(graph.nodes.some((node) => node.kind === "action_critic"));
  assert.ok(graph.nodes.some((node) => node.refId.startsWith("outcome:")));
});

test("mock source exposes rich evaluation data for populated pages", async () => {
  const source = new MockDashboardDataSource(0);
  const metrics = await source.getMetrics();
  const evaluation = await source.getEvaluation(metrics);

  assert.equal(evaluation.runId, "eval_mock_20260628");
  assert.equal(evaluation.asrBefore, 0.732);
  assert.equal(evaluation.asrAfter, 0.048);
  assert.ok(evaluation.perAttack.length >= 3);
  assert.ok(evaluation.cases.some((row) => row.runtime === "openclaw"));
  assert.ok(evaluation.cases.some((row) => row.attackSuccess));
  assert.ok(evaluation.cases.some((row) => !row.attackSuccess));
});

test("mock source exposes config findings and OpenClaw status", async () => {
  const source = new MockDashboardDataSource(0);

  const findings = await source.getConfigAuditFindings({ limit: 20 });
  const status = await source.getAdapterStatus("openclaw");

  assert.ok(findings.length >= 3);
  assert.ok(findings.some((row) => row.finding.severity === "critical"));
  assert.ok(findings.some((row) => row.finding.severity === "high"));
  assert.equal(status.status, "loaded");
  assert.equal(status.loaded, true);
  assert.equal(status.hookCount, 16);
  assert.equal(status.expectedHookCount, 16);
  assert.ok(status.hooks.includes("before_tool_call"));
});
