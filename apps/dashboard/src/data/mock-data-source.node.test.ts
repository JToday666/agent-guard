import assert from "node:assert/strict";
import test from "node:test";

import { MockDashboardDataSource } from "./sources/mock-data-source";

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
