import assert from "node:assert/strict";
import test from "node:test";

import { MockDashboardDataSource } from "./mock-data-source.ts";

test("mock provenance graph contains evidence nodes and event references", async () => {
  const source = new MockDashboardDataSource(0);
  const graph = await source.getTraceProvenance("trace_002");

  assert.equal(graph.traceId, "trace_002");
  assert.ok(graph.nodes.length >= 10);
  assert.ok(graph.edges.length >= 9);
  assert.ok(graph.nodes.some((node) => node.refId === "audit:evt_20260607_002"));
  assert.ok(graph.nodes.some((node) => node.kind === "task"));
  assert.ok(graph.nodes.some((node) => node.kind === "source"));
  assert.ok(graph.nodes.some((node) => node.kind === "context"));
  assert.ok(graph.nodes.some((node) => node.kind === "model_intent"));
  assert.ok(graph.nodes.some((node) => node.kind === "resource"));
  assert.ok(graph.nodes.some((node) => node.kind === "rule"));
  assert.ok(graph.nodes.some((node) => node.kind === "policy"));
  assert.ok(graph.nodes.some((node) => node.kind === "runtime_result"));
  assert.ok(graph.nodes.some((node) => node.refId === "approval:ask_001"));
  assert.ok(
    graph.nodes.every((node) => node.metadata.source !== "mock" && node.metadata.source !== "api"),
  );
});

test("mock source exposes rich evaluation data for populated pages", async () => {
  const source = new MockDashboardDataSource(0);
  const metrics = await source.getMetrics();
  const evaluation = await source.getEvaluation(metrics);

  assert.equal(evaluation.runId, "eval_mock_20260628");
  assert.equal(evaluation.asrBefore, 0.732);
  assert.equal(evaluation.asrAfter, 0.048);
  assert.ok(evaluation.perAttack.length >= 3);
  assert.ok(evaluation.cases.some((row) => row.attackType === "benign"));
  assert.ok(evaluation.cases.some((row) => row.blocked));
  assert.ok(evaluation.cases.some((row) => !row.blocked));
});

test("mock evaluation cases stay consistent with linked audit events", async () => {
  const source = new MockDashboardDataSource(0);
  const events = await source.getEvents();
  const metrics = await source.getMetrics();
  const evaluation = await source.getEvaluation(metrics);

  for (const row of evaluation.cases) {
    const event = events.find(
      (candidate) => candidate.traceId === row.traceId && candidate.caseId === row.caseId,
    );
    assert.ok(event, `${row.caseId} should link to a matching audit event`);
    assert.equal(event.runtime, row.runtime, `${row.caseId} runtime`);
    assert.equal(event.attackType, row.attackType, `${row.caseId} attack type`);
    assert.equal(event.decision, row.actualDecision, `${row.caseId} actual decision`);
    assert.equal(event.blocked, row.blocked, `${row.caseId} blocked`);
  }
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
