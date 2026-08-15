#!/usr/bin/env node
// PR-RTE-02 SDK spike — after_tool_call host-path probe.
//
// Evidence layer: in_process_host_path. Drives the REAL host-side tool
// execution chain of the pinned openclaw@2026.7.1-2 SDK (the same exported
// functions the gateway agent loop uses: wrapToolWithBeforeToolCallHook,
// runBeforeToolCallHook, runAgentHarnessAfterToolCallHook) deterministically,
// without an LLM.
//
// Why not an isolated live Gateway:
//   - POST /tools/invoke runs runBeforeToolCallHook but NEVER emits
//     after_tool_call (tools-invoke-shared returns the raw execute result);
//   - the agent harness tool loop that emits after_tool_call observations
//     requires a live model turn, which is not deterministic offline.
// The host-path probe therefore exercises the exact emit-side host functions
// instead, and every scenario records ordered evidence instead of inferring.
//
// Contract boundaries (03 §2): no time-proximity/tool-name guessing; blocked
// calls never produce terminal execution facts here — the probe only records
// what the SDK actually does.

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, "..");
const PLUGIN_PKG_PATH = path.join(
  ROOT,
  "packages",
  "agentguard-openclaw-plugin",
  "package.json",
);

// Evidence pin: bumped 2026.6.6 -> 2026.7.1-2 (rev5, maintainer decision):
// the rev3 isolated_runtime live forensics were recorded on 2026.7.1-2, so
// bumping the pin makes the full evidence stack (static / harness / host
// path / live) apply to the pinned SDK and unlocks the C2 Gate.
const OPENCLAW_PIN = "2026.7.1-2";

async function loadOpenclawSdk() {
  // openclaw is a devDependency of the plugin package, not the repo root;
  // resolve it from the plugin package to stay pinned to the workspace copy.
  const requireFromPlugin = createRequire(PLUGIN_PKG_PATH);
  const runtimeUrl = pathToFileURL(
    requireFromPlugin.resolve("openclaw/plugin-sdk/plugin-runtime"),
  ).href;
  const harnessUrl = pathToFileURL(
    requireFromPlugin.resolve("openclaw/plugin-sdk/agent-harness"),
  ).href;
  const runtime = await import(runtimeUrl);
  const harness = await import(harnessUrl);
  return { runtime, harness };
}

function createEvidenceSink() {
  const records = [];
  return {
    records,
    record(kind, detail) {
      records.push({
        seq: records.length + 1,
        at: Date.now(),
        kind,
        ...detail,
      });
    },
  };
}

function buildProbeRegistry(sink, options = {}) {
  const beforeHandlers = [];
  if (options.rewriter) {
    beforeHandlers.push({
      pluginId: "spike-rewriter",
      hookName: "before_tool_call",
      priority: 10,
      handler: (event) => {
        sink.record("before_tool_call", {
          plugin: "spike-rewriter",
          toolCallId: event.toolCallId,
          paramsSeen: event.params,
        });
        return { params: { ...event.params, rewrittenBy: "spike-rewriter" } };
      },
    });
  }
  beforeHandlers.push({
    pluginId: "agentguard-spike",
    hookName: "before_tool_call",
    priority: 1,
    handler: (event) => {
      sink.record("before_tool_call", {
        plugin: "agentguard-spike",
        toolCallId: event.toolCallId,
        paramsSeen: event.params,
      });
      if (options.block) {
        return { block: true, blockReason: "spike deny" };
      }
      return undefined;
    },
  });
  return {
    hooks: [],
    // 2026.7.1-2 hook runner composes registry sources and iterates
    // registry.plugins; the probe keeps it empty but iterable.
    plugins: [],
    typedHooks: [
      ...beforeHandlers,
      {
        pluginId: "agentguard-spike",
        hookName: "after_tool_call",
        priority: 0,
        handler: (event, ctx) => {
          sink.record("after_tool_call", {
            toolCallId: event.toolCallId,
            ctxToolCallId: ctx?.toolCallId ?? null,
            toolName: event.toolName,
            paramsSeen: event.params,
            resultPresent: event.result !== undefined,
            resultType:
              event.result === undefined ? "absent" : typeof event.result,
            errorPresent: event.error !== undefined,
            errorIsString: typeof event.error === "string",
            durationMsType: typeof event.durationMs,
          });
        },
      },
      {
        pluginId: "agentguard-spike",
        hookName: "tool_result_persist",
        priority: 0,
        handler: (event) => {
          sink.record("tool_result_persist", {
            toolCallId: event.toolCallId ?? null,
            toolName: event.toolName ?? null,
          });
          return undefined;
        },
      },
    ],
  };
}

function makeProbeTool({ name, invokeLog, behavior, returnValue }) {
  return {
    name,
    execute: async (toolCallId, params) => {
      invokeLog.push({ toolCallId, params, at: Date.now() });
      if (behavior === "throw") {
        throw new Error("spike tool failure");
      }
      if (behavior === "falsy") {
        return returnValue;
      }
      return { ok: true, echo: params, marker: "spike-result" };
    },
  };
}

async function emitAfterToolCallObservation(harness, params) {
  // SIMULATED host emission: drives the real SDK emit helper, but the probe
  // decides WHEN it fires. Whether the real run-attempt observer emits for
  // error/blocked/completed items, and the real ordering against
  // tool_result_persist, is NOT observable offline (observer is not part of
  // any public plugin-sdk surface and the agent tool loop needs a live model
  // turn). Scenarios using this helper must record emit_method=simulated and
  // may not be used as proof of host scheduling.
  await new Promise((resolve) => {
    setImmediate(() => {
      harness
        .runAgentHarnessAfterToolCallHook(params)
        .catch(() => {})
        .finally(resolve);
    });
  });
}

export async function runAfterToolCallSpikeScenarios() {
  const { runtime, harness } = await loadOpenclawSdk();
  const report = {
    spike_id: "PR-RTE-02",
    layer: "in_process_host_path",
    openclaw_version: OPENCLAW_PIN,
    sdk_advertises_after_tool_call:
      [...runtime.PLUGIN_HOOK_NAMES].includes("after_tool_call"),
    scenarios: {},
  };

  // --- Scenario A: allow success ------------------------------------------
  {
    const sink = createEvidenceSink();
    runtime.resetGlobalHookRunner();
    runtime.initializeGlobalHookRunner(buildProbeRegistry(sink));
    const invokeLog = [];
    const tool = makeProbeTool({ name: "spike_probe", invokeLog });
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      { config: {} },
      { emitDiagnostics: false },
    );
    const toolCallId = "spike-call-allow-1";
    const beforeCompletedAt = Date.now();
    const result = await wrapped.execute(toolCallId, { mode: "allow" });
    sink.record("tool_executed", { toolCallId, at: Date.now() });
    await emitAfterToolCallObservation(harness, {
      toolCallId,
      runId: "spike-run-a",
      toolName: "spike_probe",
      startArgs: { mode: "allow" },
      result,
      startedAt: beforeCompletedAt,
    });
    report.scenarios.allow_success = {
      evidence: sink.records,
      emit_method: "simulated_host_emit",
      invocation_count: invokeLog.length,
      before_completed_at: beforeCompletedAt,
      executed_params: invokeLog[0]?.params ?? null,
      after_tool_call_observed: sink.records.some(
        (r) => r.kind === "after_tool_call",
      ),
    };
    runtime.resetGlobalHookRunner();
  }

  // --- Scenario B: tool throws ---------------------------------------------
  {
    const sink = createEvidenceSink();
    runtime.resetGlobalHookRunner();
    runtime.initializeGlobalHookRunner(buildProbeRegistry(sink));
    const invokeLog = [];
    const tool = makeProbeTool({
      name: "spike_probe",
      invokeLog,
      behavior: "throw",
    });
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      { config: {} },
      { emitDiagnostics: false },
    );
    const toolCallId = "spike-call-fail-1";
    let thrown = null;
    try {
      await wrapped.execute(toolCallId, { mode: "fail" });
    } catch (err) {
      thrown = err;
    }
    await emitAfterToolCallObservation(harness, {
      toolCallId,
      runId: "spike-run-b",
      toolName: "spike_probe",
      startArgs: { mode: "fail" },
      error: thrown ? String(thrown.message ?? thrown) : null,
    });
    report.scenarios.tool_failure = {
      evidence: sink.records,
      emit_method: "simulated_host_emit",
      invocation_count: invokeLog.length,
      host_propagated_error: Boolean(thrown),
      after_tool_call_observed: sink.records.some(
        (r) => r.kind === "after_tool_call",
      ),
      after_error_is_string: sink.records
        .filter((r) => r.kind === "after_tool_call")
        .every((r) => r.errorIsString),
    };
    runtime.resetGlobalHookRunner();
  }

  // --- Scenario C: deny via block:true -------------------------------------
  {
    const sink = createEvidenceSink();
    runtime.resetGlobalHookRunner();
    runtime.initializeGlobalHookRunner(buildProbeRegistry(sink, { block: true }));
    const invokeLog = [];
    const tool = makeProbeTool({ name: "spike_probe", invokeLog });
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      { config: {} },
      { emitDiagnostics: false },
    );
    const toolCallId = "spike-call-deny-1";
    const result = await wrapped.execute(toolCallId, { mode: "deny" });
    // Host behavior for a veto-blocked call: the wrapped tool returns a
    // blocked result WITHOUT invoking the real tool; the harness item then
    // reaches a terminal status, so the observer emits after_tool_call with
    // that blocked result. Reproduce the observation exactly as the host does.
    await emitAfterToolCallObservation(harness, {
      toolCallId,
      runId: "spike-run-c",
      toolName: "spike_probe",
      startArgs: { mode: "deny" },
      result,
    });
    report.scenarios.deny_block = {
      evidence: sink.records,
      emit_method: "simulated_host_emit",
      invocation_count: invokeLog.length,
      blocked_result_returned: Boolean(result),
      after_tool_call_observed: sink.records.some(
        (r) => r.kind === "after_tool_call",
      ),
    };
    runtime.resetGlobalHookRunner();
  }

  // --- Scenario D: multi-plugin param rewrite ------------------------------
  {
    const sink = createEvidenceSink();
    runtime.resetGlobalHookRunner();
    runtime.initializeGlobalHookRunner(
      buildProbeRegistry(sink, { rewriter: true }),
    );
    const invokeLog = [];
    const tool = makeProbeTool({ name: "spike_probe", invokeLog });
    // The wrapper ctx must carry the SAME runId as the later emit helper:
    // recordAdjustedParamsForToolCall keys on (runId, toolCallId) and
    // consumeAdjustedParamsForToolCall must hit the same key, otherwise the
    // after event silently falls back to startArgs.
    const scenarioRunId = "spike-run-d";
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      { config: {}, runId: scenarioRunId },
      { emitDiagnostics: false },
    );
    const toolCallId = "spike-call-rewrite-1";
    const result = await wrapped.execute(toolCallId, { mode: "allow" });
    await emitAfterToolCallObservation(harness, {
      toolCallId,
      runId: scenarioRunId,
      toolName: "spike_probe",
      startArgs: { mode: "allow" },
      result,
    });
    report.scenarios.multi_plugin_rewrite = {
      evidence: sink.records,
      emit_method: "simulated_host_emit",
      executed_params: invokeLog[0]?.params ?? null,
      after_params_seen: sink.records
        .filter((r) => r.kind === "after_tool_call")
        .map((r) => r.paramsSeen),
    };
    runtime.resetGlobalHookRunner();
  }

  // --- Scenario E: ordering vs tool_result_persist --------------------------
  {
    const sink = createEvidenceSink();
    runtime.resetGlobalHookRunner();
    runtime.initializeGlobalHookRunner(buildProbeRegistry(sink));
    const invokeLog = [];
    const tool = makeProbeTool({ name: "spike_probe", invokeLog });
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      { config: {} },
      { emitDiagnostics: false },
    );
    const toolCallId = "spike-call-order-1";
    const result = await wrapped.execute(toolCallId, { mode: "allow" });
    // Transcript persistence is synchronous on the host hot path; the after
    // observation is scheduled via setImmediate. Reproduce that ordering.
    const runner = runtime.getGlobalHookRunner();
    runner.runToolResultPersist(
      { toolName: "spike_probe", toolCallId, message: {} },
      { toolName: "spike_probe", toolCallId },
    );
    await emitAfterToolCallObservation(harness, {
      toolCallId,
      runId: "spike-run-e",
      toolName: "spike_probe",
      startArgs: { mode: "allow" },
      result,
    });
    const kinds = sink.records.map((r) => r.kind);
    report.scenarios.persist_ordering = {
      evidence: sink.records,
      emit_method: "constructed_sequence",
      observed_sequence: kinds,
      persist_before_after:
        kinds.indexOf("tool_result_persist") !== -1 &&
        kinds.indexOf("tool_result_persist") < kinds.indexOf("after_tool_call"),
    };
    runtime.resetGlobalHookRunner();
  }

  // --- Scenario F: falsy successful results --------------------------------
  // The SDK emit helper includes `result` via a truthiness check, so tools
  // that successfully return false / 0 / "" / null produce an after event
  // with NEITHER result NOR error. Record the omission semantics so the
  // terminal mapper never infers success/failure from field presence.
  {
    const falsyCases = [];
    for (const returnValue of [false, 0, "", null]) {
      const sink = createEvidenceSink();
      runtime.resetGlobalHookRunner();
      runtime.initializeGlobalHookRunner(buildProbeRegistry(sink));
      const invokeLog = [];
      const tool = makeProbeTool({
        name: "spike_probe",
        invokeLog,
        behavior: "falsy",
        returnValue,
      });
      const wrapped = harness.wrapToolWithBeforeToolCallHook(
        tool,
        { config: {} },
        { emitDiagnostics: false },
      );
      const toolCallId = `spike-call-falsy-${JSON.stringify(returnValue)}`;
      const result = await wrapped.execute(toolCallId, { mode: "falsy" });
      await emitAfterToolCallObservation(harness, {
        toolCallId,
        runId: "spike-run-f",
        toolName: "spike_probe",
        startArgs: { mode: "falsy" },
        result,
      });
      const after = sink.records.find((r) => r.kind === "after_tool_call");
      falsyCases.push({
        returned: returnValue === null ? "null" : JSON.stringify(returnValue),
        invocation_count: invokeLog.length,
        emit_method: "simulated_host_emit",
        after_result_field_present: after ? after.resultPresent : null,
        after_error_field_present: after ? after.errorPresent : null,
      });
      runtime.resetGlobalHookRunner();
    }
    report.scenarios.falsy_success_results = {
      cases: falsyCases,
      omission_semantics:
        "falsy successful result -> after event carries neither result nor error; presence must not be used to classify success/failure",
    };
  }

  return report;
}

function redact(report) {
  // Probe payloads are synthetic; redaction keeps parity with smoke reporting.
  return JSON.parse(
    JSON.stringify(report).replace(/spike-secret-[A-Za-z0-9]+/g, "[redacted]"),
  );
}

async function main() {
  const report = redact(await runAfterToolCallSpikeScenarios());
  const reportPath = process.argv[2] ?? null;
  if (reportPath) {
    fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(`[rte-02-spike] report written to ${reportPath}`);
  }
  console.log(JSON.stringify(report, null, 2));
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  main().catch((err) => {
    console.error(`[rte-02-spike] failed: ${String(err)}`);
    process.exitCode = 1;
  });
}
