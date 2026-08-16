import assert from "node:assert/strict";
import test from "node:test";

import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../../../../../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import type { GuardAuditEventDto } from "../../api/guard-api-types.ts";
import { MockDashboardDataSource } from "./mock-data-source.ts";

test("mock preview source exposes reads only", () => {
  const source = new MockDashboardDataSource(0);

  assert.equal("resolveApproval" in source, false);
  assert.equal(Object.hasOwn(source, "resolveApproval"), false);
});

test("mock runtime receipts preserve exact policy, event, decision and action links", async () => {
  const source = new MockDashboardDataSource(0);
  const response = await source.getTraceDetail("trace_002");
  assert.equal(response.status, "modified");
  if (response.status !== "modified") return;

  const policy = response.value.events.find((event) => event.recordType === "policy_evaluation");
  const outcome = response.value.events.find((event) => event.recordType === "runtime_outcome");
  assert.ok(policy);
  assert.ok(outcome);
  const policyRaw = policy.raw as GuardAuditEventDto;
  const outcomeRaw = outcome.raw as GuardAuditEventDto;
  assert.equal(outcomeRaw.links?.policy_audit_id, policyRaw.audit_id);
  assert.equal(outcomeRaw.links?.event_id, policyRaw.links?.event_id);
  assert.equal(outcomeRaw.links?.decision_id, policyRaw.links?.decision_id);
  assert.equal(outcomeRaw.links?.action_id, policyRaw.links?.action_id);
});

test("mock provenance graph contains evidence nodes and event references", async () => {
  const source = new MockDashboardDataSource(0);
  const response = await source.getTraceProvenance("trace_002");
  assert.equal(response.status, "modified");
  if (response.status !== "modified") return;
  const graph = response.value;

  assert.equal(graph.traceId, "trace_002");
  assert.ok(graph.nodes.length >= 10);
  assert.ok(graph.edges.length >= 9);
  assert.ok(
    graph.nodes.some(
      (node) => node.refId === "evt_20260607_002" && node.nodeId.endsWith("audit:evt_20260607_002"),
    ),
  );
  const auditNodes = graph.nodes.filter((node) => node.kind === "audit");
  assert.ok(auditNodes.length >= 2);
  assert.ok(
    auditNodes.every(
      (node) => !node.refId.startsWith("audit:") && node.nodeId.endsWith(`audit:${node.refId}`),
    ),
  );
  const nodeIds = new Set(graph.nodes.map((node) => node.nodeId));
  assert.ok(
    graph.edges.every((edge) => nodeIds.has(edge.sourceNodeId) && nodeIds.has(edge.targetNodeId)),
  );
  assert.ok(graph.nodes.some((node) => node.kind === "task"));
  assert.ok(graph.nodes.some((node) => node.kind === "source"));
  assert.ok(graph.nodes.some((node) => node.kind === "context"));
  assert.ok(graph.nodes.some((node) => node.kind === "model_intent"));
  assert.ok(graph.nodes.some((node) => node.kind === "resource"));
  assert.ok(graph.nodes.some((node) => node.kind === "rule"));
  assert.ok(graph.nodes.some((node) => node.kind === "policy"));
  assert.ok(graph.nodes.some((node) => node.kind === "runtime_result"));
  assert.ok(graph.nodes.some((node) => node.kind === "approval" && node.refId === "ask_001"));
  assert.ok(
    graph.nodes.some((node) => node.kind === "action" && node.refId === "action_trace_002"),
  );
  assert.ok(
    graph.nodes.every((node) => node.metadata.source !== "mock" && node.metadata.source !== "api"),
  );
  assert.ok(graph.nodes.every((node) => !("eventId" in node.metadata)));
  assert.ok(graph.nodes.every((node) => !("riskScore" in node.metadata)));
});

test("mock demo provenance adds the validated Web ingress chain without touching execution data", async () => {
  const source = new MockDashboardDataSource(0);
  const response = await source.getTraceProvenance("trace_005");
  assert.equal(response.status, "modified");
  if (response.status !== "modified") return;

  const previewNodes = response.value.nodes.filter(
    ({ metadata }) => metadata.fixture_id === "rsc_context_ingress_preview_v01",
  );
  const previewEdges = response.value.edges.filter(
    ({ metadata }) => metadata.fixture_id === "rsc_context_ingress_preview_v01",
  );
  assert.equal(previewNodes.length, 4);
  assert.equal(previewEdges.length, 3);
  assert.deepEqual(
    previewNodes.map(({ metadata }) => metadata.presentation_node_kind),
    ["source", "context", "model_input", "action"],
  );
  assert.ok(previewNodes.every(({ traceId }) => traceId === "trace_005"));
  assert.ok(
    previewNodes.every(
      ({ metadata }) =>
        metadata.source_mode === "mock" &&
        metadata.element_source_mode === "mock" &&
        typeof metadata.availability === "string" &&
        typeof metadata.certainty === "string" &&
        metadata.status === "MOCK PREVIEW",
    ),
  );
  assert.ok(
    previewEdges.every(
      ({ relation, traceId, metadata }) =>
        traceId === "trace_005" &&
        relation === "assembled_into" &&
        metadata.wire_relation === "assembled_into" &&
        metadata.ct_flow_relation === "assembled_into" &&
        metadata.source_mode === "mock" &&
        typeof metadata.availability === "string" &&
        typeof metadata.certainty === "string",
    ),
  );

  const byKind = new Map(
    previewNodes.map((node) => [String(node.metadata.presentation_node_kind), node]),
  );
  const expectedPath = ["source", "context", "model_input", "action"];
  for (let index = 0; index < expectedPath.length - 1; index += 1) {
    const sourceNode = byKind.get(expectedPath[index]!);
    const targetNode = byKind.get(expectedPath[index + 1]!);
    assert.ok(sourceNode);
    assert.ok(targetNode);
    assert.ok(
      previewEdges.some(
        (edge) =>
          edge.sourceNodeId === sourceNode.nodeId && edge.targetNodeId === targetNode.nodeId,
      ),
    );
  }

  const webSource = byKind.get("source");
  const action = byKind.get("action");
  assert.ok(webSource);
  assert.ok(action);
  assert.equal(webSource.metadata.normalized_ct_source_type, "web");
  assert.equal(webSource.metadata.trust, "untrusted");
  assert.match(action.refId, /^mock_action_/);

  const trace = await source.getTraceDetail("trace_005");
  assert.equal(trace.status, "modified");
  if (trace.status === "modified") {
    assert.doesNotMatch(JSON.stringify(trace.value), /mock_prov_|assembled_into/);
  }
});

test("mock content ingress fixture is scoped to the fixed demo trace", async () => {
  const source = new MockDashboardDataSource(0);
  const response = await source.getTraceProvenance("trace_002");
  assert.equal(response.status, "modified");
  if (response.status !== "modified") return;

  assert.ok(
    response.value.nodes.every(
      ({ metadata }) => metadata.fixture_id !== "rsc_context_ingress_preview_v01",
    ),
  );
  assert.ok(
    response.value.edges.every(
      ({ metadata }) => metadata.fixture_id !== "rsc_context_ingress_preview_v01",
    ),
  );
});

test("mock trace resources honor independent conditional validators", async () => {
  const source = new MockDashboardDataSource(0);
  const trace = await source.getTraceDetail("trace_002");
  const provenance = await source.getTraceProvenance("trace_002");
  assert.equal(trace.status, "modified");
  assert.equal(provenance.status, "modified");

  const unchangedTrace = await source.getTraceDetail("trace_002", {
    etag: trace.etag ?? undefined,
  });
  const unchangedProvenance = await source.getTraceProvenance("trace_002", {
    etag: provenance.etag ?? undefined,
  });
  assert.equal(unchangedTrace.status, "not_modified");
  assert.equal(unchangedProvenance.status, "not_modified");
  assert.notEqual(trace.etag, provenance.etag);
});

test("mock read methods reject pre-aborted and in-flight requests", async () => {
  const source = new MockDashboardDataSource(1_000);
  const preAborted = new AbortController();
  preAborted.abort();

  await assert.rejects(source.getHealth(preAborted.signal), { name: "AbortError" });

  const inFlight = new AbortController();
  const evaluation = source.getLatestEvaluationRun(inFlight.signal);
  inFlight.abort();
  await assert.rejects(evaluation, { name: "AbortError" });
});

test("mock source exposes rich evaluation data for populated pages", async () => {
  const source = new MockDashboardDataSource(0);
  const evaluation = await source.getLatestEvaluationRun();

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
  const events = (await source.getAuditWindow()).events;
  const evaluation = await source.getLatestEvaluationRun();

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

test("mock audit window maps and deduplicates policy records", async () => {
  const source = new MockDashboardDataSource(0);
  const window = await source.getAuditWindow();

  assert.ok(window.events.some((event) => event.recordType === "runtime_outcome"));
  assert.ok(window.events.every((event) => event.raw && typeof event.raw === "object"));
  assert.equal(window.metrics.evaluationCount, 8);
  assert.equal(
    window.metrics.allowCount + window.metrics.askCount + window.metrics.denyCount,
    window.metrics.evaluationCount,
  );
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
  assert.equal(status.hookCount, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.equal(status.expectedHookCount, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.deepEqual(status.hooks, [...OPENCLAW_REQUIRED_HOOKS]);
});
