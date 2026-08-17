#!/usr/bin/env node
/**
 * RTE-05 live acceptance through the pinned OpenClaw host SDK.
 *
 * This runner installs the compiled AgentGuard handlers in OpenClaw's real
 * global hook runner, executes the real agent-harness tool wrapper, and emits
 * after_tool_call through the SDK helper used by the host agent loop.  The
 * Guard API and approval resolver live in the parent pytest process.
 */

import fs from "node:fs";
import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, "..");
const PLUGIN_PACKAGE = path.join(
  ROOT,
  "packages",
  "agentguard-openclaw-plugin",
  "package.json",
);
const OPENCLAW_PIN = "2026.7.1-2";
const RESULT_MARKER = "AGENTGUARD_RTE05_OPENCLAW_RESULT=";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`missing required RTE-05 host setting: ${name}`);
  }
  return value;
}

function positiveIntegerEnvironment(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`invalid RTE-05 host setting: ${name}`);
  }
  return parsed;
}

function resolvedOpenClawVersion(requireFromHost) {
  let probeDirectory = path.dirname(
    requireFromHost.resolve("openclaw/plugin-sdk/plugin-runtime"),
  );
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = path.join(probeDirectory, "package.json");
    if (fs.existsSync(candidate)) {
      const packageJson = JSON.parse(fs.readFileSync(candidate, "utf8"));
      if (packageJson.name === "openclaw") {
        return packageJson.version;
      }
    }
    probeDirectory = path.dirname(probeDirectory);
  }
  return "unknown";
}

async function loadPinnedHostSdk() {
  const explicitRoot = process.env.AGENTGUARD_OPENCLAW_ROOT;
  const resolveBase = explicitRoot
    ? path.join(explicitRoot, "package.json")
    : PLUGIN_PACKAGE;
  const requireFromHost = createRequire(resolveBase);
  const runtime = await import(
    pathToFileURL(
      requireFromHost.resolve("openclaw/plugin-sdk/plugin-runtime"),
    ).href
  );
  const harness = await import(
    pathToFileURL(
      requireFromHost.resolve("openclaw/plugin-sdk/agent-harness"),
    ).href
  );
  const resolvedVersion = resolvedOpenClawVersion(requireFromHost);
  const expectedVersion =
    process.env.AGENTGUARD_OPENCLAW_EXPECT_VERSION ?? OPENCLAW_PIN;
  if (resolvedVersion !== expectedVersion || expectedVersion !== OPENCLAW_PIN) {
    throw new Error(
      `RTE-05 requires openclaw@${OPENCLAW_PIN}; resolved ${resolvedVersion}`,
    );
  }
  return { harness, runtime, resolvedVersion };
}

async function main() {
  const baseUrl = requiredEnvironment("AGENTGUARD_RTE05_LIVE_BASE_URL");
  const adapterToken = requiredEnvironment(
    "AGENTGUARD_RTE05_LIVE_ADAPTER_TOKEN",
  );
  const taskId = requiredEnvironment("AGENTGUARD_RTE05_LIVE_TASK_ID");
  const runtimeBindingId = requiredEnvironment(
    "AGENTGUARD_RTE05_LIVE_RUNTIME_BINDING_ID",
  );
  const traceId = requiredEnvironment("AGENTGUARD_RTE05_LIVE_TRACE_ID");
  const actionId = requiredEnvironment("AGENTGUARD_RTE05_LIVE_ACTION_ID");
  const stateDirectory = requiredEnvironment("OPENCLAW_STATE_DIR");
  const scenario = process.env.AGENTGUARD_RTE05_LIVE_SCENARIO ?? "success";
  if (scenario !== "success" && scenario !== "drift") {
    throw new Error("RTE-05 host scenario must be success or drift");
  }
  await mkdir(stateDirectory, { recursive: true, mode: 0o700 });

  // OPENCLAW_STATE_DIR must be present before either SDK or plugin import.
  const { harness, runtime, resolvedVersion } = await loadPinnedHostSdk();
  const { default: plugin } = await import(
    "../packages/agentguard-openclaw-plugin/dist/index.js"
  );
  const typedHooks = [];
  const services = [];
  const api = {
    pluginConfig: {
      guardApiBaseUrl: baseUrl,
      adapterToken,
      enforcementMode: "enforce",
      requestTimeoutMs: positiveIntegerEnvironment(
        "AGENTGUARD_RTE05_LIVE_REQUEST_TIMEOUT_MS",
        1_000,
      ),
      approvalPollIntervalMs: 25,
      approvalTimeoutMs: 10_000,
      strongApprovalBindingEnabled: true,
      runtimeBindingId,
      diagnosticLogging: false,
      agentId: "main",
    },
    runtime: { version: resolvedVersion },
    registerService(service) {
      services.push(service);
    },
    on(hookName, handler, options = {}) {
      typedHooks.push({
        pluginId: "agentguard-security",
        hookName,
        priority: options.priority ?? 0,
        handler,
      });
    },
  };
  plugin.register(api);

  const beforeHookCount = typedHooks.filter(
    (entry) => entry.hookName === "before_tool_call",
  ).length;
  const afterHookCount = typedHooks.filter(
    (entry) => entry.hookName === "after_tool_call",
  ).length;
  if (beforeHookCount !== 1 || afterHookCount < 2) {
    throw new Error("compiled plugin did not register the required tool hooks");
  }

  runtime.resetGlobalHookRunner();
  runtime.initializeGlobalHookRunner({ hooks: [], plugins: [], typedHooks });
  try {
    const hookRunner = runtime.getGlobalHookRunner();
    if (!hookRunner) {
      throw new Error("OpenClaw did not initialize its global hook runner");
    }

    const sessionKey = `agent:main:${traceId}`;
    const userTask = "Send the routine status update to the review recipient.";

    // The pinned tool wrapper intentionally projects only standard tool
    // context.  Seed the authoritative task claim at the earlier session hook
    // through the same real global runner; before_tool_call must recover it by
    // the stable session/run identity rather than from attacker-owned params.
    await hookRunner.runBeforePromptBuild(
      {
        prompt: userTask,
        runId: traceId,
        userTask,
        sourceType: "user_request",
        sourceTrust: "trusted",
      },
      {
        agentId: "main",
        sessionKey,
        runId: traceId,
        taskId,
        userTask,
        sourceType: "user_request",
        sourceTrust: "trusted",
      },
    );

    const hostParams = {
      to: "review-recipient@external.invalid",
      subject: "Routine status update",
      body: "The routine status update is ready for review.",
    };
    const invocations = [];
    const tool = {
      name: "send_email",
      execute: async (toolCallId, params) => {
        invocations.push({ toolCallId, params: structuredClone(params) });
        return { delivered: true };
      },
    };
    const wrapped = harness.wrapToolWithBeforeToolCallHook(
      tool,
      {
        config: {},
        agentId: "main",
        sessionKey,
        runId: traceId,
      },
      { emitDiagnostics: false },
    );

    let driftTimer;
    if (scenario === "drift") {
      // Mutate the host-owned object after evaluate snapshots it and before
      // human release. Exact revalidation must block the real execute method.
      driftTimer = setTimeout(() => {
        hostParams.body = "The host action changed after evaluation.";
      }, 75);
    }

    const startedAt = Date.now();
    const result = await wrapped.execute(actionId, hostParams);
    if (driftTimer !== undefined) {
      clearTimeout(driftTimer);
    }
    const blocked = result?.details?.status === "blocked";
    const executedParams = invocations[0]?.params ?? hostParams;
    await harness.runAgentHarnessAfterToolCallHook({
      toolCallId: actionId,
      runId: traceId,
      agentId: "main",
      sessionKey,
      toolName: "send_email",
      startArgs: executedParams,
      result,
      ...(blocked ? { error: "Tool call blocked by plugin" } : {}),
      startedAt,
    });

    // Runtime outcomes are deliberately asynchronous in production. Keep this
    // process alive for the immediate delivery attempts; pytest polls the
    // authoritative trace and also scans the durable state directory.
    await new Promise((resolve) => setTimeout(resolve, 750));
    process.stdout.write(
      `${RESULT_MARKER}${JSON.stringify({
        scenario,
        trace_id: traceId,
        action_id: actionId,
        blocked,
        invocation_count: invocations.length,
        before_hook_count: beforeHookCount,
        after_hook_count: afterHookCount,
        service_count: services.length,
        evidence_layer: "in_process_host_path",
        host_sdk: "openclaw/plugin-sdk/agent-harness",
        openclaw_version: resolvedVersion,
        strong_binding_enabled: true,
        runtime_binding_id_configured: runtimeBindingId.length > 0,
      })}\n`,
    );
  } finally {
    runtime.resetGlobalHookRunner();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "unknown host error";
  process.stderr.write(`RTE-05 OpenClaw host chain failed: ${message}\n`);
  process.exitCode = 1;
});
