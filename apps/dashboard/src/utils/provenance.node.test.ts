import assert from "node:assert/strict";
import test from "node:test";

import type { ProvenanceNode } from "../types/dashboard.ts";
import {
  findProvenanceNodeForEvent,
  getProvenanceRelationLabel,
  getProvenanceRiskScore,
  resolveProvenanceEventId,
} from "./provenance.ts";

function node(overrides: Partial<ProvenanceNode> = {}): ProvenanceNode {
  return {
    kind: "audit",
    label: "tool_call_proposed",
    metadata: {},
    nodeId: "audit:audit_1",
    refId: "audit_1",
    timestamp: "2026-06-28T08:00:00Z",
    traceId: "trace_1",
    ...overrides,
  };
}

test("maps canonical Guard API provenance relations to concise Chinese labels", () => {
  assert.equal(getProvenanceRelationLabel("evaluated_to"), "判定");
  assert.equal(getProvenanceRelationLabel("recorded_as"), "记录");
  assert.equal(getProvenanceRelationLabel("reviewed_by"), "复核");
  assert.equal(getProvenanceRelationLabel("future_relation"), "");
});

test("reads canonical snake-case and mock camel-case risk metadata", () => {
  assert.equal(getProvenanceRiskScore({ risk_score: 64 }), "64");
  assert.equal(getProvenanceRiskScore({ riskScore: "72" }), "72");
  assert.equal(getProvenanceRiskScore({}), "");
});

test("links raw and prefixed provenance references to audit events", () => {
  const events = [{ id: "audit_1" }, { id: "audit_2" }];
  const rawNode = node();
  const prefixedNode = node({ nodeId: "mock:event", refId: "event:audit_2" });

  assert.equal(resolveProvenanceEventId(rawNode, events), "audit_1");
  assert.equal(resolveProvenanceEventId(prefixedNode, events), "audit_2");
  assert.equal(resolveProvenanceEventId(node({ refId: "guard_event_1" }), events), undefined);
  assert.equal(findProvenanceNodeForEvent([rawNode, prefixedNode], "audit_2"), prefixedNode);
});
