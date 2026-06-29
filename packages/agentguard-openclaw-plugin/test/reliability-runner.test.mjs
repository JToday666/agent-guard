import assert from "node:assert/strict";
import test from "node:test";

test("reliability runner plans every registered hook for each iteration", async () => {
  process.env.AGENTGUARD_ADAPTER_TOKEN = process.env.AGENTGUARD_ADAPTER_TOKEN || "test-adapter-token";
  process.env.AGENTGUARD_CONTROL_TOKEN = process.env.AGENTGUARD_CONTROL_TOKEN || "test-control-token";

  const {
    RELIABILITY_HOOKS,
    buildReliabilityPlan,
    expectedReliabilityEventCounts,
  } = await import("../../../scripts/openclaw-e2e-runner.mjs");

  const plan = buildReliabilityPlan({ runId: "unit", iterations: 2 });

  assert.equal(RELIABILITY_HOOKS.length, 16);
  assert.equal(plan.cases.length, 32);
  assert.deepEqual(plan.expectedEventCounts, {
    tool_call_proposed: 2,
    message_send_proposed: 2,
    config_audit: 2,
    tool_result_produced: 2,
    runtime_observation: 24,
  });
  assert.deepEqual(expectedReliabilityEventCounts(50), {
    tool_call_proposed: 50,
    message_send_proposed: 50,
    config_audit: 50,
    tool_result_produced: 50,
    runtime_observation: 600,
  });

  for (const hookName of RELIABILITY_HOOKS) {
    const hookCases = plan.cases.filter((item) => item.hookName === hookName);
    assert.equal(hookCases.length, 2, `${hookName} case count`);
    assert.equal(hookCases[0].traceId, `openclaw_rel_unit_${hookName}_001`);
    assert.equal(hookCases[1].traceId, `openclaw_rel_unit_${hookName}_002`);
  }
});

test("reliability runner summarizes missing duplicate and wrong-runtime events", async () => {
  process.env.AGENTGUARD_ADAPTER_TOKEN = process.env.AGENTGUARD_ADAPTER_TOKEN || "test-adapter-token";
  process.env.AGENTGUARD_CONTROL_TOKEN = process.env.AGENTGUARD_CONTROL_TOKEN || "test-control-token";

  const { buildReliabilityPlan, summarizeReliabilityEvents } = await import(
    "../../../scripts/openclaw-e2e-runner.mjs"
  );

  const plan = buildReliabilityPlan({ runId: "summary", iterations: 1 });
  const events = plan.cases.slice(0, -1).map((item) => ({
    trace_id: item.traceId,
    event_type: item.expectedEventType,
    runtime: "openclaw",
    stage: item.hookName,
  }));
  events.push({ ...events[0] });
  events.push({
    trace_id: "openclaw_rel_summary_wrong_runtime_001",
    event_type: "runtime_observation",
    runtime: "langgraph",
    stage: "wrong_runtime",
  });

  const summary = summarizeReliabilityEvents(plan, events);

  assert.equal(summary.expected_total, 16);
  assert.equal(summary.observed_total, 17);
  assert.deepEqual(summary.missing_traces, [plan.cases.at(-1).traceId]);
  assert.deepEqual(summary.duplicate_trace_ids, [events[0].trace_id]);
  assert.equal(summary.non_openclaw_count, 1);
  assert.equal(summary.ok, false);
});
