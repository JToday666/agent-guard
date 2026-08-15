import assert from "node:assert/strict";
import test from "node:test";

import type {
  ExecutionStepCategory,
  ExecutionStepKind,
  ExecutionStepViewModel,
} from "../../types/dashboard.ts";
import { projectExecutionStepSupervision } from "./step-supervision.ts";
import {
  buildExecutionFlowLayout,
  EXECUTION_FLOW_LANE_HEADER_HEIGHT,
  EXECUTION_FLOW_NODE_HEIGHT,
  EXECUTION_FLOW_NODE_WIDTH,
  getExecutionFlowLane,
  type ExecutionFlowOrientation,
} from "./execution-flow-layout.ts";

function step(
  stepId: string,
  category: ExecutionStepCategory,
  kind: ExecutionStepKind = "checkpoint",
): ExecutionStepViewModel {
  const stableStepId = `${kind === "action" ? "action" : "event"}:${stepId}` as const;
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
    stepId: stableStepId,
    supervision: projectExecutionStepSupervision({
      traceId: "trace-layout-test",
      elementSourceMode: "mock",
      stepId: stableStepId,
      category,
      phase: "evaluated",
      actionId: kind === "action" ? stepId : null,
      actionName: null,
      resources: [],
      stepEvents: [],
      primary: null,
      policyConflicted: false,
      approval: { conflicted: false, id: null, request: null, status: "unknown" },
      outcome: null,
      outcomeConflicted: false,
      identityConflicted: false,
      hasExplicitStart: false,
    }),
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
    ["event:one", "action:two", "event:three"],
  );
  assert.deepEqual(
    layout.edges.map(({ source, target, relation, label }) => ({
      label,
      relation,
      source,
      target,
    })),
    [
      {
        label: "随后记录",
        relation: "audit_order",
        source: "event:one",
        target: "action:two",
      },
      {
        label: "随后记录",
        relation: "audit_order",
        source: "action:two",
        target: "event:three",
      },
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

for (const orientation of ["horizontal", "vertical"] satisfies ExecutionFlowOrientation[]) {
  test(`${orientation} layout keeps every step below its lane header and inside lane bounds`, () => {
    const layout = buildExecutionFlowLayout(
      [
        step("context", "context"),
        step("tool", "tool", "action"),
        step("result", "tool_result"),
        step("message", "message", "action"),
      ],
      orientation,
    );

    for (const node of layout.nodes) {
      const lane = layout.lanes.find((candidate) => candidate.id === node.laneId);
      assert.ok(lane, `missing lane for ${node.id}`);
      assert.equal(lane.headerHeight, EXECUTION_FLOW_LANE_HEADER_HEIGHT);
      assert.ok(node.position.x >= lane.position.x);
      assert.ok(node.position.y >= lane.position.y + lane.headerHeight);
      assert.ok(node.position.x + EXECUTION_FLOW_NODE_WIDTH <= lane.position.x + lane.width);
      assert.ok(node.position.y + EXECUTION_FLOW_NODE_HEIGHT <= lane.position.y + lane.height);
    }
  });
}

test("keeps step rectangles separated in both orientations", () => {
  const steps = [
    step("context", "context"),
    step("input", "model_input"),
    step("tool", "tool", "action"),
    step("message", "message", "action"),
    step("result", "tool_result"),
  ];

  for (const orientation of ["horizontal", "vertical"] satisfies ExecutionFlowOrientation[]) {
    const nodes = buildExecutionFlowLayout(steps, orientation).nodes;
    for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
        const left = nodes[leftIndex]!;
        const right = nodes[rightIndex]!;
        const intersects =
          left.position.x < right.position.x + EXECUTION_FLOW_NODE_WIDTH &&
          left.position.x + EXECUTION_FLOW_NODE_WIDTH > right.position.x &&
          left.position.y < right.position.y + EXECUTION_FLOW_NODE_HEIGHT &&
          left.position.y + EXECUTION_FLOW_NODE_HEIGHT > right.position.y;
        assert.equal(intersects, false, `${left.id} overlaps ${right.id} in ${orientation}`);
      }
    }
  }
});
