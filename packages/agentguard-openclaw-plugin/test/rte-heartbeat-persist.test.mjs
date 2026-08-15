// PR-RTE-03 — heartbeat capability declaration & tool_result_persist linkage
// (contract 02 §11, 03 §8.3).
import assert from "node:assert/strict";
import test from "node:test";
import { buildRuntimeEnforcementCapability } from "../dist/runtime/heartbeat.js";
import { registerToolResultPersist } from "../dist/hooks/tool.js";
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

test("capability: clean tracker declares C2 execution closure with zero degradation", () => {
  const capability = buildRuntimeEnforcementCapability(
    new EvidenceDegradationTracker(),
  );
  assert.equal(capability.contract, "1.0");
  assert.deepEqual(capability.profiles, {
    C0_observe: true,
    C1_pre_execution_enforcement: true,
    C2_execution_closure: true,
    C4_result_isolation: true,
  });
  assert.deepEqual(capability.correlation, { stable_native_action_id: true });
  assert.equal(capability.evidence_degradation, 0);
});

test("capability: capacity exhaustion degrades C2 while C1 stays intact", () => {
  const tracker = new EvidenceDegradationTracker();
  tracker.record("tool_call_state_capacity_exhausted");
  const capability = buildRuntimeEnforcementCapability(tracker);
  assert.equal(capability.profiles.C2_execution_closure, false);
  assert.equal(capability.profiles.C1_pre_execution_enforcement, true);
  assert.equal(capability.evidence_degradation, 1);
});

test("capability: other degradation reasons do not demote C2", () => {
  const tracker = new EvidenceDegradationTracker();
  tracker.record("after_tool_call_correlation_missing");
  const capability = buildRuntimeEnforcementCapability(tracker);
  assert.equal(capability.profiles.C2_execution_closure, true);
  assert.equal(capability.evidence_degradation, 1);
});

test("persist linkage: correlated tool_result_persist only sets resultPersistObserved", () => {
  const handlers = {};
  const submitted = [];
  const toolCallState = new Map();
  rememberToolCallState(
    toolCallState,
    {
      event_id: "evt_persist_001",
      event_type: "tool_call_proposed",
      trace_id: "trace_persist",
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
        tool: { name: "spike_probe", category: "tool", call_id: "call-p-1" },
        arguments: {},
        derived_resources: [],
      },
    },
    { nativeToolCallId: "call-p-1" },
  );

  const context = {
    api: {
      on: (name, handler) => {
        handlers[name] = handler;
      },
    },
    config: BASE_CONFIG,
    makeClient: () => ({
      evaluate: async () => ({
        decision: { decision_id: "d", decision: "allow", reason: "ok" },
        approval: null,
        policy_audit_id: "p",
      }),
    }),
    outcomeDelivery: {
      submit: (receipt) => {
        submitted.push(receipt);
        return Promise.resolve();
      },
    },
    sessionState: new Map(),
    toolCallState,
    degradations: new EvidenceDegradationTracker(),
  };
  registerToolResultPersist(context);

  const result = handlers.tool_result_persist(
    {
      toolName: "spike_probe",
      toolCallId: "call-p-1",
      runId: "run-p",
      result: "harmless tool output",
      message: "harmless tool output",
    },
    { toolName: "spike_probe", toolCallId: "call-p-1", runId: "run-p" },
  );

  // Unmodified benign result: no quarantine rewrite, no receipt fired here.
  assert.equal(result, undefined);
  assert.equal(submitted.length, 0);
  assert.equal(toolCallState.get("call-p-1").resultPersistObserved, true);

  // Un-correlated persist events must not throw or create state.
  handlers.tool_result_persist(
    {
      toolName: "spike_probe",
      toolCallId: "call-unknown",
      result: "x",
      message: "x",
    },
    { toolCallId: "call-unknown" },
  );
  assert.equal(toolCallState.has("call-unknown"), false);
});
