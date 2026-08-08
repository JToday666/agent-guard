import assert from "node:assert/strict";
import test from "node:test";

import type { ProvenanceNode } from "../types/dashboard.ts";
import {
  findProvenanceNodeForAction,
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
  assert.equal(getProvenanceRelationLabel("received_from"), "接收来源");
  assert.equal(getProvenanceRelationLabel("proposed_action"), "提出动作");
  assert.equal(getProvenanceRelationLabel("requested_approval"), "请求审批");
  assert.equal(getProvenanceRelationLabel("executed_as"), "形成执行结果");
  assert.equal(getProvenanceRelationLabel("evaluated_to"), "判定");
  assert.equal(getProvenanceRelationLabel("recorded_as"), "记录");
  assert.equal(getProvenanceRelationLabel("reviewed_by"), "复核");
  assert.equal(getProvenanceRelationLabel("future_relation"), "");
});

test("locates actions only by exact kind and raw action reference", () => {
  const nodes = [
    node({ kind: "audit", refId: "call_1" }),
    node({ kind: "action", nodeId: "action:call_1", refId: "call_1" }),
    node({ kind: "action", nodeId: "action:action:call_2", refId: "action:call_2" }),
  ];

  assert.equal(findProvenanceNodeForAction(nodes, "call_1")?.nodeId, "action:call_1");
  assert.equal(findProvenanceNodeForAction(nodes, "call_2"), undefined);
});

test("reads only canonical snake-case risk metadata", () => {
  assert.equal(getProvenanceRiskScore({ risk_score: 64 }), "64");
  assert.equal(getProvenanceRiskScore({ riskScore: "72" }), "");
  assert.equal(getProvenanceRiskScore({}), "");
});

test("links only raw provenance references to audit events", () => {
  const events = [{ id: "audit_1" }, { id: "audit_2" }];
  const rawNode = node();
  const prefixedNode = node({ nodeId: "mock:event", refId: "event:audit_2" });

  assert.equal(resolveProvenanceEventId(rawNode, events), "audit_1");
  assert.equal(resolveProvenanceEventId(prefixedNode, events), undefined);
  assert.equal(resolveProvenanceEventId(node({ refId: "guard_event_1" }), events), undefined);
  assert.equal(findProvenanceNodeForEvent([rawNode, prefixedNode], "audit_2"), undefined);
});
