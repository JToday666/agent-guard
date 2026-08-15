// PR-RTE-02 SDK spike — in-process harness for OpenClaw `after_tool_call`.
//
// Evidence layer: in_process_harness. Drives the REAL hook runner of the pinned
// openclaw@2026.6.6 SDK through its public `plugin-sdk/hook-runtime` subpath;
// no host simulation of dispatch semantics is involved. Runtime questions that
// the in-process layer cannot settle (blocked-call emission, real toolCallId
// stability, hook ordering against tool_result_persist, retry identity) are
// deferred to the isolated-runtime probe (scripts/openclaw-after-tool-call-spike.mjs)
// and must stay `undetermined` here — this file must never infer them.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  PLUGIN_HOOK_NAMES,
  getGlobalHookRunner,
  initializeGlobalHookRunner,
  resetGlobalHookRunner,
} from "openclaw/plugin-sdk/plugin-runtime";
import { runAfterToolCallSpikeScenarios } from "../../../scripts/openclaw-after-tool-call-spike.mjs";

const SPIKE_FIXTURE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "after-tool-call-spike-capability.json",
);

function loadCapability() {
  return JSON.parse(readFileSync(SPIKE_FIXTURE_PATH, "utf8"));
}

function makeRegistry(typedHooks) {
  return { hooks: [], typedHooks };
}

function typedHook(pluginId, hookName, handler, options = {}) {
  return { pluginId, hookName, handler, priority: options.priority ?? 0 };
}

function freshRunner(typedHooks) {
  resetGlobalHookRunner();
  initializeGlobalHookRunner(makeRegistry(typedHooks));
  return getGlobalHookRunner();
}

const TOOL_CTX = {
  agentId: "spike-agent",
  sessionKey: "spike:session",
  sessionId: "spike-session-1",
  runId: "run-spike-1",
  toolName: "spike_probe_tool",
  toolCallId: "call-spike-0001",
};

test("spike harness: PLUGIN_HOOK_NAMES advertises after_tool_call on the pinned SDK", () => {
  assert.ok([...PLUGIN_HOOK_NAMES].includes("after_tool_call"));
  assert.ok([...PLUGIN_HOOK_NAMES].includes("before_tool_call"));
});

test("spike harness: after_tool_call handler receives the declared event/ctx verbatim (Q2)", () => {
  const observed = [];
  const runner = freshRunner([
    typedHook("agentguard-spike", "after_tool_call", (event, ctx) => {
      observed.push({ event, ctx });
    }),
  ]);

  const event = {
    toolName: "spike_probe_tool",
    params: { probe: "value" },
    runId: "run-spike-1",
    toolCallId: "call-spike-0001",
    result: { ok: true },
    durationMs: 12,
  };
  runner.runAfterToolCall(event, TOOL_CTX);

  assert.equal(observed.length, 1);
  assert.deepEqual(observed[0].event, event);
  assert.deepEqual(observed[0].ctx, TOOL_CTX);
});

test("spike harness: toolCallId travels identically through before and after handlers (Q3/Q4)", async () => {
  const seen = { before: null, after: null };
  const runner = freshRunner([
    typedHook("agentguard-spike", "before_tool_call", (event, ctx) => {
      seen.before = { event: event.toolCallId, ctx: ctx.toolCallId };
    }),
    typedHook("agentguard-spike", "after_tool_call", (event, ctx) => {
      seen.after = { event: event.toolCallId, ctx: ctx.toolCallId };
    }),
  ]);

  const sharedCallId = "call-spike-0002";
  await runner.runBeforeToolCall(
    { toolName: "spike_probe_tool", params: {}, toolCallId: sharedCallId },
    { ...TOOL_CTX, toolCallId: sharedCallId },
  );
  await runner.runAfterToolCall(
    {
      toolName: "spike_probe_tool",
      params: {},
      toolCallId: sharedCallId,
      result: null,
    },
    { ...TOOL_CTX, toolCallId: sharedCallId },
  );

  assert.equal(seen.before.event, sharedCallId);
  assert.equal(seen.before.ctx, sharedCallId);
  assert.equal(seen.after.event, sharedCallId);
  assert.equal(seen.after.ctx, sharedCallId);
});

test("spike harness: a throwing after_tool_call handler is contained and never mutates tool facts (Q11)", async () => {
  const order = [];
  const runner = freshRunner([
    typedHook("agentguard-spike", "after_tool_call", () => {
      order.push("throwing-handler");
      throw new Error("spike probe failure");
    }),
    typedHook("agentguard-spike-secondary", "after_tool_call", () => {
      order.push("healthy-handler");
    }),
  ]);

  // runVoidHook catches per-handler errors for the fail-open after_tool_call
  // policy; the promise must resolve and sibling handlers must still run.
  await runner.runAfterToolCall(
    { toolName: "spike_probe_tool", params: {}, toolCallId: "call-spike-0003" },
    TOOL_CTX,
  );

  assert.deepEqual(order.sort(), ["healthy-handler", "throwing-handler"]);
});

test("spike harness: after_tool_call handler return values are ignored (void contract)", async () => {
  const runner = freshRunner([
    typedHook("agentguard-spike", "after_tool_call", () => ({
      block: true,
      params: { hijacked: true },
    })),
  ]);

  const outcome = await runner.runAfterToolCall(
    { toolName: "spike_probe_tool", params: {}, toolCallId: "call-spike-0004" },
    TOOL_CTX,
  );
  // Observation-only contract: the runner returns no merged/modifying result.
  assert.equal(outcome, undefined);
});

test("spike harness: before_tool_call block=true short-circuits the sequential chain (deny path)", async () => {
  const order = [];
  const runner = freshRunner([
    typedHook(
      "agentguard-spike",
      "before_tool_call",
      () => {
        order.push("blocker");
        return { block: true, blockReason: "spike deny" };
      },
      { priority: 10 },
    ),
    typedHook(
      "agentguard-spike-secondary",
      "before_tool_call",
      () => {
        order.push("never-runs");
        return { params: { rewritten: true } };
      },
      { priority: 1 },
    ),
  ]);

  const merged = await runner.runBeforeToolCall(
    { toolName: "spike_probe_tool", params: {}, toolCallId: "call-spike-0005" },
    TOOL_CTX,
  );

  assert.deepEqual(order, ["blocker"]);
  assert.equal(merged.block, true);
  assert.equal(merged.blockReason, "spike deny");
});

test("spike harness: before_tool_call param rewrites merge by priority but are not visible to sibling handlers (Q12/Q13 partial)", async () => {
  const secondSaw = { params: null };
  const runner = freshRunner([
    typedHook(
      "agentguard-spike-rewriter",
      "before_tool_call",
      () => ({ params: { rewritten: true, marker: "by-rewriter" } }),
      { priority: 10 },
    ),
    typedHook(
      "agentguard-spike-observer",
      "before_tool_call",
      (event) => {
        secondSaw.params = event.params;
      },
      { priority: 1 },
    ),
  ]);

  const merged = await runner.runBeforeToolCall(
    {
      toolName: "spike_probe_tool",
      params: { original: true },
      toolCallId: "call-spike-0006",
    },
    TOOL_CTX,
  );

  // Static SDK evidence (hook-helpers runAgentHarnessAfterToolCallHook):
  // adjusted params are consumed via consumeAdjustedParamsForToolCall and fed
  // into the after_tool_call event. The in-chain visibility question is
  // answered here at runner level: sibling handlers see the ORIGINAL params,
  // rewrites only surface in the merged decision and downstream consumption.
  assert.deepEqual(secondSaw.params, { original: true });
  assert.deepEqual(merged.params, { rewritten: true, marker: "by-rewriter" });
});

test("spike harness: async after_tool_call handlers are awaited before runAfterToolCall resolves", async () => {
  let completed = false;
  const runner = freshRunner([
    typedHook("agentguard-spike", "after_tool_call", async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      completed = true;
    }),
  ]);

  await runner.runAfterToolCall(
    { toolName: "spike_probe_tool", params: {}, toolCallId: "call-spike-0007" },
    TOOL_CTX,
  );
  assert.equal(completed, true);
});

test("capability fixture: structure is complete and consistent with spike evidence", () => {
  const capability = loadCapability();

  assert.equal(capability.runtime, "openclaw");
  assert.equal(capability.openclaw_version, "2026.6.6");
  assert.ok(["PASS", "FAIL"].includes(capability.c2_gate));
  assert.equal(capability.questions.length, 14);
  assert.equal(capability.c2_gate_criteria.length, 5);

  const allowedVerdicts = new Set(["yes", "no", "partial", "undetermined"]);
  const allowedLayers = new Set([
    "static_sdk_source",
    "in_process_harness",
    "in_process_host_path",
    "simulated_host_emit",
    "constructed_sequence",
    "isolated_runtime",
    "not_applicable",
  ]);
  for (const question of capability.questions) {
    assert.ok(question.id, "question must have an id");
    assert.ok(allowedVerdicts.has(question.verdict), question.id);
    assert.ok(allowedLayers.has(question.evidence_layer), question.id);
  }
  for (const criterion of capability.c2_gate_criteria) {
    assert.ok(allowedVerdicts.has(criterion.verdict), criterion.id);
  }

  // Conservative gate rule (contract 03 §2.2): PASS only when every criterion
  // is deterministically satisfied; any undetermined/partial/no fails the gate.
  const allYes = capability.c2_gate_criteria.every(
    (criterion) => criterion.verdict === "yes",
  );
  assert.equal(capability.c2_gate, allYes ? "PASS" : "FAIL");
});

// --- Host-path scenario assertions ------------------------------------------
// Real-fact assertions cover what the REAL wrapper/runBeforeToolCallHook code
// does (invocation counts, happens-before, identity, blocked short-circuit).
// Assertions on after_tool_call observations are explicitly scoped to
// simulated_host_emit: they prove payload shape IF the host emits, never that
// the real (unexported) run-attempt observer emits or its ordering.

test("host path: allow success drives before -> execute with identical toolCallId (Q4/Q8)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.allow_success;

  assert.equal(scenario.invocation_count, 1);
  assert.equal(scenario.emit_method, "simulated_host_emit");

  const kinds = scenario.evidence.map((entry) => entry.kind);
  assert.deepEqual(kinds, ["before_tool_call", "tool_executed", "after_tool_call"]);

  const ids = new Set(
    scenario.evidence.map((entry) => entry.toolCallId ?? entry.ctxToolCallId),
  );
  assert.equal(ids.size, 1, "before/execute/after must share one toolCallId");

  const after = scenario.evidence.find((entry) => entry.kind === "after_tool_call");
  assert.equal(after.resultPresent, true);
  assert.equal(after.errorPresent, false);
});

test("host path: tool failure propagates the error; after payload shape is simulated (Q6 scoped)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.tool_failure;

  // Real wrapper fact: the host propagates the tool error to the caller.
  assert.equal(scenario.invocation_count, 1);
  assert.equal(scenario.host_propagated_error, true);
  // Simulated emission: IF the host emits, the payload carries a bounded
  // string error and no result. Host emission on error items is NOT proven.
  assert.equal(scenario.emit_method, "simulated_host_emit");
  assert.equal(scenario.after_error_is_string, true);

  const after = scenario.evidence.find((entry) => entry.kind === "after_tool_call");
  assert.equal(after.resultPresent, false);
  assert.equal(after.errorPresent, true);
});

test("host path: deny blocks invocation for real; blocked-item emission stays undetermined (Q9 scoped)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.deny_block;

  // Solid C1 fact from the real wrapper: zero real invocations after block:true,
  // and the wrapped tool hands back the host blocked result.
  assert.equal(scenario.invocation_count, 0);
  assert.equal(scenario.blocked_result_returned, true);
  // The after observation below was scheduled by the probe. Whether the real
  // observer emits for blocked items is undetermined; PR-RTE-03 must never
  // derive terminal execution facts for blocked gate states either way.
  assert.equal(scenario.emit_method, "simulated_host_emit");
  assert.equal(scenario.after_tool_call_observed, true);
});

test("host path: multi-plugin rewrite keeps identity stable and adjusted params flow end to end (Q12, runId fixed)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.multi_plugin_rewrite;

  // The real execute receives the adjusted params produced by the rewriter.
  assert.deepEqual(scenario.executed_params, {
    mode: "allow",
    rewrittenBy: "spike-rewriter",
  });

  // With matching runId the real consumeAdjustedParamsForToolCall channel
  // hands the adjusted params to the after event (simulated emission, real
  // record/consume store).
  assert.deepEqual(scenario.after_params_seen, [
    { mode: "allow", rewrittenBy: "spike-rewriter" },
  ]);

  // Every before-chain handler saw the ORIGINAL params; identity unchanged.
  const beforeEntries = scenario.evidence.filter(
    (entry) => entry.kind === "before_tool_call",
  );
  assert.equal(beforeEntries.length, 2);
  for (const entry of beforeEntries) {
    assert.deepEqual(entry.paramsSeen, { mode: "allow" });
    assert.equal(entry.toolCallId, "spike-call-rewrite-1");
  }
});

test("host path: persist ordering is a constructed sequence, not observed host behavior (Q10 scoped)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.persist_ordering;

  // The probe arranged this sequence; it is evidence of what the probe built,
  // labeled accordingly so Q10 stays undetermined in the capability fixture.
  assert.equal(scenario.emit_method, "constructed_sequence");
  assert.equal(scenario.persist_before_after, true);
  assert.deepEqual(scenario.observed_sequence, [
    "before_tool_call",
    "tool_result_persist",
    "after_tool_call",
  ]);
});

test("host path: falsy successful results omit BOTH result and error fields (Q5 omission semantics)", async () => {
  const report = await runAfterToolCallSpikeScenarios();
  const scenario = report.scenarios.falsy_success_results;

  assert.equal(scenario.cases.length, 4);
  for (const item of scenario.cases) {
    assert.equal(item.invocation_count, 1, item.returned);
    // Successful execution, yet the after event carries neither result nor
    // error: field presence must never classify success vs failure.
    assert.equal(item.after_result_field_present, false, item.returned);
    assert.equal(item.after_error_field_present, false, item.returned);
  }
});
