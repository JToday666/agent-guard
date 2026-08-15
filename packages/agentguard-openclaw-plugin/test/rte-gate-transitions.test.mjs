// PR-RTE-03 — before_tool_call synchronous linkage & gate transitions
// (contract 03 §4). Drives the real registered handler from dist/hooks/tool.js
// with a fake plugin api / Guard API client and asserts the correlation state
// machine plus the receipts fired on every decision path.
import assert from "node:assert/strict";
import test from "node:test";
import { registerBeforeToolCall } from "../dist/hooks/tool.js";
import { EvidenceDegradationTracker } from "../dist/runtime/state.js";

const BASE_CONFIG = {
  guardApiBaseUrl: "http://127.0.0.1:8088",
  adapterToken: "token",
  enforcementMode: "enforce",
  requestTimeoutMs: 5000,
  approvalPollIntervalMs: 10,
  approvalTimeoutMs: 50,
  diagnosticLogging: false,
  agentId: "agent_rte",
};

function makeEvaluation(decision, extras = {}) {
  return {
    decision: {
      decision_id: "dec_rte_001",
      decision,
      risk_score: 10,
      severity: "low",
      reason: "spike",
      safe_message: "spike",
      rule_hits: [],
    },
    approval: extras.approval ?? null,
    policy_audit_id: "audit_policy_rte_001",
  };
}

function makeHookContext(options = {}) {
  const handlers = {};
  const submitted = [];
  const toolCallState = new Map();
  const api = {
    on: (name, handler) => {
      handlers[name] = handler;
    },
  };
  const client = {
    evaluate:
      options.evaluate ?? (async () => makeEvaluation(options.decision ?? "allow", options)),
    waitForApproval: async () =>
      options.waitResponse ?? { status: "resolved", decision: "allow_once" },
  };
  const delivery = {
    submit: (receipt) => {
      submitted.push(receipt);
      return Promise.resolve();
    },
  };
  const context = {
    api,
    config: { ...BASE_CONFIG, ...(options.config ?? {}) },
    makeClient: () => client,
    outcomeDelivery: delivery,
    sessionState: new Map(),
    toolCallState,
    degradations: new EvidenceDegradationTracker(),
  };
  return { handlers, submitted, toolCallState, context };
}

function toolEvent(toolCallId = "call-rte-100") {
  return {
    toolName: "spike_probe",
    params: { mode: "allow" },
    toolCallId,
    runId: "run-rte",
  };
}

const TOOL_CTX = { toolName: "spike_probe", runId: "run-rte" };

test("gate: allow links the decision synchronously and returns undefined", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "allow",
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result, undefined);
  assert.equal(submitted.length, 0);

  const state = toolCallState.get("call-rte-100");
  assert.ok(state);
  assert.equal(state.gateState, "allowed");
  assert.equal(state.correlationSource, "native_tool_call_id");
  assert.equal(state.policyAuditId, "audit_policy_rte_001");
  assert.equal(state.decisionId, "dec_rte_001");
  assert.equal(state.decision, "allow");
  assert.ok(state.guardEvent);
  assert.ok(state.evaluation);
});

test("gate: deny blocks, records blocked gate and a not_invoked pre_execution_deny receipt", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "deny",
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result.block, true);

  const state = toolCallState.get("call-rte-100");
  assert.equal(state.gateState, "blocked");
  assert.equal(state.receiptQueued, true);
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(submitted[0].evidence.execution.status, "not_invoked");
});

test("gate: ask allow_once releases to approval_released and fires approval_release(unknown)", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: {
      approval_id: "appr_rte_001",
      status: "pending",
      decision_options: ["allow_once", "deny"],
    },
    waitResponse: { status: "resolved", decision: "allow_once" },
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result, undefined);

  const state = toolCallState.get("call-rte-100");
  assert.equal(state.gateState, "approval_released");
  assert.equal(state.approvalId, "appr_rte_001");
  assert.equal(state.approvalStatus, "allowed");
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "approval_release");
  assert.equal(submitted[0].evidence.execution.status, "unknown");
});

test("gate: ask timeout lands in timed_out with an expired approval deny receipt", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: {
      approval_id: "appr_rte_002",
      status: "pending",
      decision_options: ["allow_once", "deny"],
    },
    waitResponse: { status: "timeout", decision: "deny" },
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result.block, true);

  const state = toolCallState.get("call-rte-100");
  assert.equal(state.gateState, "timed_out");
  assert.equal(state.approvalStatus, "expired");
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(submitted[0].evidence.approval.status, "expired");
});

test("gate: observe mode never blocks and still records an allowed gate", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "deny",
    config: { enforcementMode: "observe" },
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result, undefined);
  assert.equal(submitted.length, 0);

  const state = toolCallState.get("call-rte-100");
  assert.equal(state.gateState, "allowed");
});

test("gate: evaluate failure fails closed with a blocked gate in enforce mode", async () => {
  const { handlers, toolCallState, context } = makeHookContext({
    evaluate: async () => {
      throw new Error("guard api down");
    },
  });
  registerBeforeToolCall(context);

  const result = await handlers.before_tool_call(toolEvent(), TOOL_CTX);
  assert.equal(result.block, true);

  const state = toolCallState.get("call-rte-100");
  assert.ok(state, "state was remembered before the evaluate failure");
  assert.equal(state.gateState, "blocked");
  assert.equal(state.receiptQueued, true);
});

test("gate: missing native toolCallId degrades correlation to local_fallback", async () => {
  const { handlers, toolCallState, context } = makeHookContext({
    decision: "allow",
  });
  registerBeforeToolCall(context);

  await handlers.before_tool_call(
    { toolName: "spike_probe", params: {}, runId: "run-rte" },
    TOOL_CTX,
  );

  const states = [...toolCallState.values()];
  assert.equal(states.length, 1);
  assert.equal(states[0].correlationSource, "local_fallback");
  assert.ok(states[0].toolCallId.startsWith("call_"));
});
