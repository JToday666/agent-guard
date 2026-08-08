import assert from "node:assert/strict";
import test from "node:test";

import type {
  ExecutionStepCategory,
  ExecutionStepKind,
  ExecutionStepViewModel,
} from "../../types/dashboard.ts";
import { buildExecutionFlowLayout, getExecutionFlowLane } from "./execution-flow-layout.ts";

function step(
  stepId: string,
  category: ExecutionStepCategory,
  kind: ExecutionStepKind = "checkpoint",
): ExecutionStepViewModel {
  return {
    actionId: kind === "action" ? stepId : null,
    actionName: null,
    approval: "unknown",
    approvalId: null,
    auditIds: [`audit-${stepId}`],
    category,
    decision: "unknown",
    decisionId: null,
    decisionReason: null,
    displayName: stepId,
    eventId: `event-${stepId}`,
    eventIds: [`event-${stepId}`],
    events: [],
    execution: "unknown",
    firstSeenAt: "2026-08-09T08:00:00Z",
    intervention: "unknown",
    kind,
    lastUpdatedAt: "2026-08-09T08:00:00Z",
    observationAuditIds: [],
    outcomeAuditIds: [],
    phase: "evaluated",
    policyChecks: [],
    primaryAuditId: `audit-${stepId}`,
    receiptExpectation: "unknown",
    resourceSummary: null,
    riskScore: null,
    settled: false,
    severity: "unknown",
    statusLabel: "已完成安全判断",
    stepId,
  };
}

test("places every execution category in a stable semantic lane", () => {
  assert.equal(getExecutionFlowLane(step("context", "context")), "agent");
  assert.equal(getExecutionFlowLane(step("input", "model_input")), "agent");
  assert.equal(getExecutionFlowLane(step("output", "model_output")), "agent");
  assert.equal(getExecutionFlowLane(step("tool", "tool", "action")), "controlled");
  assert.equal(getExecutionFlowLane(step("memory", "memory", "action")), "controlled");
  assert.equal(getExecutionFlowLane(step("message", "message", "action")), "controlled");
  assert.equal(getExecutionFlowLane(step("future-action", "unknown", "action")), "controlled");
  assert.equal(getExecutionFlowLane(step("result", "tool_result")), "outcome");
  assert.equal(getExecutionFlowLane(step("future-check", "unknown")), "outcome");
});

test("uses audit order edges without asserting an unrecorded causal relation", () => {
  const layout = buildExecutionFlowLayout(
    [step("one", "context"), step("two", "tool", "action"), step("three", "tool_result")],
    "horizontal",
  );

  assert.deepEqual(
    layout.nodes.map((node) => node.id),
    ["one", "two", "three"],
  );
  assert.deepEqual(
    layout.edges.map(({ source, target, relation, label }) => ({
      label,
      relation,
      source,
      target,
    })),
    [
      { label: "随后记录", relation: "audit_order", source: "one", target: "two" },
      { label: "随后记录", relation: "audit_order", source: "two", target: "three" },
    ],
  );
});

test("keeps existing positions stable when status changes or a later step is appended", () => {
  const initialSteps = [step("one", "context"), step("two", "tool", "action")];
  const initial = buildExecutionFlowLayout(initialSteps, "horizontal");
  const updatedStep = {
    ...initialSteps[1]!,
    execution: "executed" as const,
    lastUpdatedAt: "2026-08-09T08:00:05Z",
    phase: "terminal" as const,
    settled: true,
  };
  const updated = buildExecutionFlowLayout(
    [initialSteps[0]!, updatedStep, step("three", "tool_result")],
    "horizontal",
  );

  assert.deepEqual(updated.nodes[0]?.position, initial.nodes[0]?.position);
  assert.deepEqual(updated.nodes[1]?.position, initial.nodes[1]?.position);
  assert.notDeepEqual(updated.nodes[2]?.position, initial.nodes[1]?.position);
});

test("switches to top-to-bottom ordering without changing semantic lanes", () => {
  const layout = buildExecutionFlowLayout(
    [step("one", "context"), step("two", "tool", "action"), step("three", "tool_result")],
    "vertical",
  );

  assert.ok(layout.nodes[1]!.position.y > layout.nodes[0]!.position.y);
  assert.ok(layout.nodes[2]!.position.y > layout.nodes[1]!.position.y);
  assert.deepEqual(
    layout.nodes.map((node) => node.laneId),
    ["agent", "controlled", "outcome"],
  );
});
