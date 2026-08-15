import assert from "node:assert/strict";
import test from "node:test";
import { OPENCLAW_REQUIRED_HOOK_COUNT } from "../hook-contract.mjs";

test("reliability runner plans every registered hook for each iteration", async () => {
  process.env.AGENTGUARD_ADAPTER_TOKEN =
    process.env.AGENTGUARD_ADAPTER_TOKEN || "test-adapter-token";
  process.env.AGENTGUARD_CONTROL_TOKEN =
    process.env.AGENTGUARD_CONTROL_TOKEN || "test-control-token";

  const {
    RELIABILITY_HOOKS,
    buildReliabilityPlan,
    expectedReliabilityEventCounts,
  } = await import("../../../scripts/openclaw-e2e-runner.mjs");

  const plan = buildReliabilityPlan({ runId: "unit", iterations: 2 });

  assert.equal(RELIABILITY_HOOKS.length, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.equal(plan.cases.length, OPENCLAW_REQUIRED_HOOK_COUNT * 2);
  assert.deepEqual(plan.expectedEventCounts, {
    tool_call_proposed: 2,
    model_input_prepared: 2,
    model_output_produced: 2,
    message_send_proposed: 2,
    config_audit: 2,
    tool_result_produced: 2,
    // RTE-03：after_tool_call 进入观察组 → 18 个观察 hook × 2 轮。
    runtime_observation: 36,
  });
  assert.deepEqual(expectedReliabilityEventCounts(50), {
    tool_call_proposed: 50,
    model_input_prepared: 50,
    model_output_produced: 50,
    message_send_proposed: 50,
    config_audit: 50,
    tool_result_produced: 50,
    runtime_observation: 900,
  });

  for (const hookName of RELIABILITY_HOOKS) {
    const hookCases = plan.cases.filter((item) => item.hookName === hookName);
    assert.equal(hookCases.length, 2, `${hookName} case count`);
    assert.equal(hookCases[0].traceId, `openclaw_rel_unit_${hookName}_001`);
    assert.equal(hookCases[1].traceId, `openclaw_rel_unit_${hookName}_002`);
  }
});

test("reliability runner summarizes missing duplicate and wrong-runtime events", async () => {
  process.env.AGENTGUARD_ADAPTER_TOKEN =
    process.env.AGENTGUARD_ADAPTER_TOKEN || "test-adapter-token";
  process.env.AGENTGUARD_CONTROL_TOKEN =
    process.env.AGENTGUARD_CONTROL_TOKEN || "test-control-token";

  const { buildReliabilityPlan, summarizeReliabilityEvents } =
    await import("../../../scripts/openclaw-e2e-runner.mjs");

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

  assert.equal(summary.expected_total, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.equal(summary.observed_total, OPENCLAW_REQUIRED_HOOK_COUNT + 1);
  assert.deepEqual(summary.missing_traces, [plan.cases.at(-1).traceId]);
  assert.deepEqual(summary.duplicate_trace_ids, [events[0].trace_id]);
  assert.equal(summary.non_openclaw_count, 1);
  assert.equal(summary.ok, false);
});

test("reliability runner fetches missing traces beyond audit list cap", async () => {
  process.env.AGENTGUARD_ADAPTER_TOKEN =
    process.env.AGENTGUARD_ADAPTER_TOKEN || "test-adapter-token";
  process.env.AGENTGUARD_CONTROL_TOKEN =
    process.env.AGENTGUARD_CONTROL_TOKEN || "test-control-token";

  const {
    buildReliabilityPlan,
    collectReliabilityEventsByTrace,
    summarizeReliabilityEvents,
  } = await import("../../../scripts/openclaw-e2e-runner.mjs");

  const plan = buildReliabilityPlan({ runId: "paged", iterations: 50 });
  const toEvent = (item) => ({
    trace_id: item.traceId,
    event_type: item.expectedEventType,
    runtime: "openclaw",
    stage: item.hookName,
  });
  const latestPage = plan.cases.slice(100).map(toEvent);
  const fetchedTraceIds = [];

  const events = await collectReliabilityEventsByTrace(
    plan,
    latestPage,
    async (traceId) => {
      fetchedTraceIds.push(traceId);
      const item = plan.cases.find(
        (candidate) => candidate.traceId === traceId,
      );
      return item ? [toEvent(item)] : [];
    },
  );
  const summary = summarizeReliabilityEvents(plan, events);

  // RTE-03：24 hook × 50 轮 = 1200 case；cap 内 100 个 trace 需补拉。
  assert.equal(latestPage.length, 1100);
  assert.equal(fetchedTraceIds.length, 100);
  assert.equal(events.length, 1200);
  assert.deepEqual(summary.missing_traces, []);
  assert.equal(summary.ok, true);
});

test("reliability collection keeps primary policy events instead of runtime receipts", async () => {
  const { buildReliabilityPlan, collectReliabilityEventsByTrace } =
    await import("../../../scripts/openclaw-e2e-runner.mjs");
  const plan = buildReliabilityPlan({ runId: "receipt", iterations: 1 });
  const first = plan.cases[0];
  const events = await collectReliabilityEventsByTrace(
    plan,
    [
      {
        trace_id: first.traceId,
        event_type: first.expectedEventType,
        runtime: "openclaw",
      },
      {
        trace_id: first.traceId,
        event_type: "runtime_outcome",
        runtime: "openclaw",
      },
    ],
    async (traceId) => {
      const item = plan.cases.find(
        (candidate) => candidate.traceId === traceId,
      );
      return item
        ? [
            {
              trace_id: item.traceId,
              event_type: item.expectedEventType,
              runtime: "openclaw",
            },
          ]
        : [];
    },
  );

  assert.equal(events.length, plan.cases.length);
  assert.equal(
    events.some((event) => event.event_type === "runtime_outcome"),
    false,
  );
});

test("release gate summary is safe to persist in adapter status", async () => {
  const { buildReleaseGateSummary } =
    await import("../../../scripts/openclaw-e2e-runner.mjs");

  const summary = buildReleaseGateSummary("reliability", {
    ok: true,
    generated_at: "2026-06-30T00:00:00.000Z",
    plugin: {
      registered_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
      registered_hooks: ["before_tool_call", "llm_input"],
    },
    audit: {
      expected_total: 950,
      observed_total: 950,
      missing_traces: [],
      duplicate_trace_ids: [],
      non_openclaw_count: 0,
      event_types: ["tool_call_proposed"],
    },
    integrity: { valid: true },
    failures: [],
    timings: {
      p95_hook_return_ms: 12,
      p95_report_lag_ms: 34,
    },
  });

  assert.deepEqual(summary, {
    kind: "reliability",
    ok: true,
    generated_at: "2026-06-30T00:00:00.000Z",
    registered_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
    registered_hooks: ["before_tool_call", "llm_input"],
    audit: {
      expected_total: 950,
      observed_total: 950,
      event_types: ["tool_call_proposed"],
      missing_count: 0,
      duplicate_count: 0,
      non_openclaw_count: 0,
    },
    integrity_valid: true,
    p95_hook_return_ms: 12,
    p95_report_lag_ms: 34,
    failures: [],
  });
});
