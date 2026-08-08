import assert from "node:assert/strict";
import test from "node:test";

import type {
  ExecutionStepViewModel,
  NormalizedAuditEvidence,
  ProvenanceNode,
} from "../types/dashboard.ts";
import {
  findProvenanceNodeForAction,
  findProvenanceNodeForEvent,
  findProvenanceNodeForExecutionStep,
  getProvenanceRelationLabel,
  getProvenanceRiskScore,
  resolveProvenanceAuditId,
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

function evidence(overrides: Partial<NormalizedAuditEvidence> = {}): NormalizedAuditEvidence {
  return {
    actionId: "call_1",
    approval: { approvalId: null, resolvedAt: null, status: "not_required" },
    auditId: "audit_1",
    chainIndex: 1,
    contextSources: [],
    decision: "allow",
    decisionId: "decision_1",
    decisionReason: "允许继续",
    entryHash: null,
    eventId: "guard_event_1",
    eventType: "tool_call_proposed",
    execution: {
      completedAt: null,
      error: null,
      invokedAt: null,
      persisted: null,
      receiptRecorded: false,
      status: "unknown",
      toolResultEnteredContext: null,
    },
    intervention: "none",
    modelIntent: null,
    occurredAt: "2026-06-28T08:00:00Z",
    originalTask: null,
    parentAuditId: null,
    policy: {
      bundleId: null,
      digest: null,
      revision: null,
      version: null,
    },
    policyAuditId: null,
    previousHash: null,
    raw: {},
    recordType: "policy_evaluation",
    resources: [],
    resultDisposition: "unknown",
    resultSummary: null,
    risk: { aggregationMethod: null, factors: [], finalDecision: "allow", finalScore: 0 },
    ruleHits: [],
    severity: "low",
    sideEffects: { count: null, measurementStatus: "unknown", summary: null },
    source: { label: null, trustLevel: null, type: null },
    stage: "before_tool_call",
    toolArguments: null,
    toolName: "read_file",
    ...overrides,
  };
}

function step(overrides: Partial<ExecutionStepViewModel> = {}): ExecutionStepViewModel {
  return {
    actionId: "call_1",
    actionName: "read_file",
    approval: "not_required",
    approvalId: null,
    auditIds: ["audit_1"],
    category: "tool",
    decision: "allow",
    decisionId: "decision_1",
    decisionReason: "允许继续",
    displayName: "读取文件",
    eventId: "guard_event_1",
    eventIds: ["guard_event_1"],
    events: [],
    execution: "unknown",
    firstSeenAt: "2026-06-28T08:00:00Z",
    intervention: "none",
    kind: "action",
    lastUpdatedAt: "2026-06-28T08:00:00Z",
    observationAuditIds: [],
    outcomeAuditIds: [],
    phase: "evaluated",
    policyChecks: [],
    primaryAuditId: "audit_1",
    receiptExpectation: "required",
    resourceSummary: null,
    riskScore: 0,
    settled: false,
    severity: "low",
    statusLabel: "已完成安全判断，等待运行时回执",
    stepId: "action:call_1",
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

test("resolves audit rows through stable raw references without parsing node IDs", () => {
  const events = [
    evidence(),
    evidence({
      actionId: null,
      auditId: "audit_2",
      decisionId: "decision_2",
      eventId: "guard_event_2",
      eventType: "context_assembled",
    }),
  ];

  assert.equal(resolveProvenanceAuditId(node(), events), "audit_1");
  assert.equal(
    resolveProvenanceAuditId(node({ kind: "action", refId: "call_1" }), events),
    "audit_1",
  );
  assert.equal(
    resolveProvenanceAuditId(node({ kind: "context", refId: "guard_event_2" }), events),
    "audit_2",
  );
  assert.equal(
    resolveProvenanceAuditId(node({ kind: "decision", refId: "decision_2" }), events),
    "audit_2",
  );
  assert.equal(
    resolveProvenanceAuditId(
      node({ nodeId: "event:guard_event_2", refId: "event:guard_event_2" }),
      events,
    ),
    undefined,
  );
});

test("locates execution steps by action, typed event, decision and audit fallbacks", () => {
  const nodes = [
    node({ kind: "action", nodeId: "action:call_1", refId: "call_1" }),
    node({ kind: "context", nodeId: "context:event_context", refId: "event_context" }),
    node({ kind: "event", nodeId: "event:event_input", refId: "event_input" }),
    node({ kind: "decision", nodeId: "decision:decision_fallback", refId: "decision_fallback" }),
    node({ kind: "audit", nodeId: "audit:audit_fallback", refId: "audit_fallback" }),
  ];

  assert.equal(findProvenanceNodeForExecutionStep(nodes, step())?.nodeId, "action:call_1");
  assert.equal(
    findProvenanceNodeForExecutionStep(
      nodes,
      step({
        actionId: null,
        auditIds: ["audit_context"],
        category: "context",
        eventIds: ["event_context"],
        kind: "checkpoint",
        primaryAuditId: "audit_context",
        stepId: "event:event_context",
      }),
    )?.nodeId,
    "context:event_context",
  );
  assert.equal(
    findProvenanceNodeForExecutionStep(
      nodes,
      step({
        actionId: null,
        auditIds: ["audit_input"],
        category: "model_input",
        eventIds: ["event_input"],
        kind: "checkpoint",
        primaryAuditId: "audit_input",
        stepId: "event:event_input",
      }),
    )?.nodeId,
    "event:event_input",
  );
  assert.equal(
    findProvenanceNodeForExecutionStep(
      nodes,
      step({
        actionId: null,
        auditIds: ["audit_missing"],
        decisionId: "decision_fallback",
        eventIds: ["event_missing"],
        kind: "checkpoint",
        primaryAuditId: "audit_missing",
        stepId: "event:event_missing",
      }),
    )?.nodeId,
    "decision:decision_fallback",
  );
  assert.equal(
    findProvenanceNodeForExecutionStep(
      nodes,
      step({
        actionId: null,
        auditIds: ["audit_fallback"],
        decisionId: null,
        eventIds: ["event_missing"],
        kind: "checkpoint",
        primaryAuditId: "audit_fallback",
        stepId: "event:event_missing",
      }),
    )?.nodeId,
    "audit:audit_fallback",
  );
});

test("finds event subjects only through raw references", () => {
  const rawNode = node({ kind: "event", nodeId: "event:guard_event_1", refId: "guard_event_1" });
  const prefixedNode = node({ kind: "event", nodeId: "mock:event", refId: "event:guard_event_2" });

  assert.equal(findProvenanceNodeForEvent([rawNode], "guard_event_1"), rawNode);
  assert.equal(findProvenanceNodeForEvent([prefixedNode], "guard_event_2"), undefined);
});
