// PR-RTE-03 — after_tool_call terminal closure tests (contract 03 §5, §12 DoD).
// Chains the real before_tool_call and after_tool_call handlers from
// dist/hooks/tool.js over one HookContext and pins the two spike safety
// constraints: Q9 (blocked gates never derive terminal facts) and Q5
// (success/failure never classified by result/error field presence).
import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyAfterToolCall,
  registerAfterToolCall,
  registerBeforeToolCall,
  terminalInterventionType,
} from "../dist/hooks/tool.js";
import {
  EvidenceDegradationTracker,
  rememberToolCallState,
} from "../dist/runtime/state.js";

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
      decision_id: "dec_rte_after_001",
      decision,
      risk_score: 10,
      severity: "low",
      reason: "spike",
      safe_message: "spike",
      rule_hits: [],
    },
    approval: extras.approval ?? null,
    policy_audit_id: "audit_policy_rte_after_001",
  };
}

function makeHookContext(options = {}) {
  const handlers = {};
  const submitted = [];
  const toolCallState = new Map();
  const degradations = new EvidenceDegradationTracker();
  const api = {
    on: (name, handler) => {
      handlers[name] = handler;
    },
  };
  const client = {
    evaluate: async () => makeEvaluation(options.decision ?? "allow", options),
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
    degradations,
  };
  return { handlers, submitted, toolCallState, degradations, context };
}

function registerBoth(context) {
  registerBeforeToolCall(context);
  registerAfterToolCall(context);
}

const TOOL_CTX = { toolName: "spike_probe", runId: "run-rte" };
const beforeEvent = (toolCallId = "call-rte-300") => ({
  toolName: "spike_probe",
  params: { mode: "allow" },
  toolCallId,
  runId: "run-rte",
});
const afterEvent = (toolCallId, fields = {}) => ({
  toolName: "spike_probe",
  params: { mode: "allow" },
  toolCallId,
  runId: "run-rte",
  ...fields,
});

test("DoD #1: allow → after hook produces a real execution_completed terminal fact", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "allow",
  });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-rte-300", { result: { ok: true }, durationMs: 12 }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1);
  const receipt = submitted[0];
  assert.equal(receipt.metadata.outcome_kind, "execution_completed");
  assert.equal(receipt.evidence.execution.status, "executed");
  assert.equal(receipt.evidence.intervention.type, "runtime_observation");
  assert.equal(receipt.evidence.execution.tool_result_entered_context, null);
  assert.equal(receipt.evidence.execution.persisted, null);
  assert.equal(receipt.links.action_id, "call-rte-300");
  // Core 一致性校验：completed_at 必须等于顶层 timestamp（同源防毫秒滚动）。
  assert.equal(receipt.timestamp, receipt.evidence.execution.completed_at);

  const state = toolCallState.get("call-rte-300");
  assert.equal(state.terminalStatus, "executed");
  assert.equal(state.receiptQueued, true);
});

test("Q5 regression: falsy success (neither result nor error) still closes as execution_completed", async () => {
  const { handlers, submitted, context } = makeHookContext({ decision: "allow" });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  // Successful false/0/""/null results arrive with NEITHER result NOR error.
  handlers.after_tool_call(afterEvent("call-rte-300"), TOOL_CTX);

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "execution_completed");
  assert.equal(submitted[0].evidence.execution.status, "executed");
});

test("DoD #3: tool failure → execution_failed with the bounded error string", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "allow",
  });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-rte-300", { error: "spike tool failure", durationMs: 3 }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "execution_failed");
  assert.equal(submitted[0].evidence.execution.status, "failed");
  assert.equal(submitted[0].evidence.execution.error, "spike tool failure");
  assert.equal(toolCallState.get("call-rte-300").terminalStatus, "failed");
});

test("DoD #2: ask allow_once → approval_release(unknown) then terminal receipt carrying approval evidence", async () => {
  const { handlers, submitted, context } = makeHookContext({
    decision: "ask",
    approval: {
      approval_id: "appr_rte_300",
      status: "pending",
      decision_options: ["allow_once", "deny"],
    },
    waitResponse: { status: "resolved", decision: "allow_once" },
  });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-rte-300", { result: { ok: true } }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 2);
  assert.equal(submitted[0].metadata.outcome_kind, "approval_release");
  assert.equal(submitted[0].evidence.execution.status, "unknown");
  assert.equal(submitted[1].metadata.outcome_kind, "execution_completed");
  assert.equal(submitted[1].links.approval_id, "appr_rte_300");
  assert.equal(submitted[1].evidence.approval.status, "allowed");
  assert.equal(submitted[1].evidence.approval.decision, "allow_once");
});

test("Q9 regression: blocked gate + after arrival derives ZERO terminal facts (emission-on-blocked is expected on the pin)", async () => {
  const { handlers, submitted, toolCallState, degradations, context } =
    makeHookContext({ decision: "deny" });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  // The real host observer emits after_tool_call for blocked items carrying an
  // error-shaped result; the plugin must treat it as diagnostic-only.
  handlers.after_tool_call(
    afterEvent("call-rte-300", {
      result: { blocked: true },
      error: "Tool call blocked by plugin",
    }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1, "only the pre_execution_deny receipt");
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  const state = toolCallState.get("call-rte-300");
  assert.equal(state.gateState, "blocked");
  assert.equal(state.terminalStatus, undefined);
  assert.equal(degradations.snapshot().total, 0, "expected behavior, not degradation");
});

test("Q9 regression: timed_out gate also never derives terminal facts", async () => {
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: {
      approval_id: "appr_rte_301",
      status: "pending",
      decision_options: ["allow_once", "deny"],
    },
    waitResponse: { status: "timeout", decision: "deny" },
  });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-rte-300", { error: "Tool call blocked by plugin" }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(toolCallState.get("call-rte-300").gateState, "timed_out");
  assert.equal(toolCallState.get("call-rte-300").terminalStatus, undefined);
});

test("DoD #5: contradiction branch — without emission-on-blocked the same observation is an enforcement_violation", () => {
  assert.equal(
    terminalInterventionType("blocked", { emitsOnBlocked: false }),
    "enforcement_violation",
  );
  assert.equal(
    terminalInterventionType("timed_out", { emitsOnBlocked: false }),
    "enforcement_violation",
  );
  assert.equal(
    terminalInterventionType("binding_failed", { emitsOnBlocked: false }),
    "enforcement_violation",
  );
  // Current pin evidence: emission-on-blocked proven → skip (diagnostic only).
  assert.equal(terminalInterventionType("blocked"), "skip");
  assert.equal(terminalInterventionType("allowed"), "runtime_observation");
  assert.equal(terminalInterventionType("approval_released"), "runtime_observation");
  assert.equal(terminalInterventionType("evaluating"), "skip");
});

test("DoD #6: local_fallback correlation never fabricates C2 terminal facts", async () => {
  const { handlers, submitted, degradations, context } = makeHookContext({
    decision: "allow",
  });
  registerBoth(context);

  await handlers.before_tool_call(
    { toolName: "spike_probe", params: {}, runId: "run-rte" },
    TOOL_CTX,
  );
  const [state] = [...context.toolCallState.values()];
  assert.equal(state.correlationSource, "local_fallback");

  handlers.after_tool_call(
    afterEvent(state.toolCallId, { result: { ok: true } }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 0);
  assert.equal(
    degradations.snapshot().byReason.after_tool_call_local_fallback_correlation,
    1,
  );
});

test("degradation: missing action id / correlation / linkage are recorded and never throw", async () => {
  const { handlers, degradations, context } = makeHookContext({
    decision: "allow",
  });
  registerBoth(context);

  // No toolCallId anywhere.
  handlers.after_tool_call({ toolName: "spike_probe" }, {});
  // Unknown toolCallId (no correlated state).
  handlers.after_tool_call(afterEvent("call-unknown"), TOOL_CTX);
  // Correlated state without policy linkage.
  rememberToolCallState(
    context.toolCallState,
    {
      event_id: "evt_unlinked",
      event_type: "tool_call_proposed",
      trace_id: "t",
      security_context: {
        user_task: "",
        source_trust: "untrusted",
        source_type: "tool",
        run_id: null,
        agent_id: "a",
        current_step: "tool_call",
        context_sources: [],
        derived_paths: [],
        metadata: {},
      },
      payload: {
        tool: { name: "spike_probe", category: "tool", call_id: "call-unlinked" },
        arguments: {},
        derived_resources: [],
      },
    },
    { nativeToolCallId: "call-unlinked" },
  );
  handlers.after_tool_call(afterEvent("call-unlinked", { result: 1 }), TOOL_CTX);

  const snapshot = degradations.snapshot();
  assert.equal(snapshot.byReason.after_tool_call_missing_action_id, 1);
  assert.equal(snapshot.byReason.after_tool_call_correlation_missing, 1);
  assert.equal(snapshot.byReason.after_tool_call_policy_linkage_missing, 1);
});

test("Q5 unit: classification never uses field presence", () => {
  assert.equal(classifyAfterToolCall({ error: "boom" }), "failed");
  assert.equal(classifyAfterToolCall({ result: { ok: true } }), "completed");
  // falsy success: neither field present
  assert.equal(classifyAfterToolCall({}), "completed");
  // empty/whitespace-less empty string is not a failure signal
  assert.equal(classifyAfterToolCall({ error: "" }), "completed");
  // non-string error never classifies as failure
  assert.equal(classifyAfterToolCall({ error: { code: 500 } }), "completed");
});

test("disabled mode: after_tool_call is inert", async () => {
  const { handlers, submitted, context } = makeHookContext({
    decision: "allow",
    config: { enforcementMode: "disabled" },
  });
  registerBoth(context);

  await handlers.before_tool_call(beforeEvent(), TOOL_CTX);
  handlers.after_tool_call(afterEvent("call-rte-300"), TOOL_CTX);
  assert.equal(submitted.length, 0);
});
