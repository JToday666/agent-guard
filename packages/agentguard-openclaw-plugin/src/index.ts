import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import {
  GuardApiClient,
  buildPluginConfig,
  decisionToMessageResult,
  decisionToToolResult,
  failClosedMessageResult,
  failClosedToolResult,
  logDiagnostic,
} from "./guard-api-client.js";
import {
  buildBeforeInstallConfigAuditEvent,
  buildContextGuardEvent,
  buildMessageSendGuardEvent,
  buildModelGuardEvent,
  buildRuntimeObservationAuditEvent,
  buildToolCallGuardEvent,
  buildToolResultGuardEvent,
} from "./mapping.js";
import type { OpenClawPluginConfigInput } from "./types.js";

const PLUGIN_VERSION = "0.1.0";

const OBSERVATION_HOOKS = [
  "gateway_start",
  "gateway_stop",
  "session_start",
  "session_end",
  "before_compaction",
  "after_compaction",
  "subagent_spawned",
  "subagent_ended",
  "model_call_started",
  "model_call_ended",
  "cron_changed",
  "resolve_exec_env",
] as const;

const PROMPT_MODEL_HOOKS = ["before_prompt_build", "llm_input", "llm_output"] as const;
const BLOCKING_HOOKS = ["before_tool_call", "message_sending", "before_install"] as const;
const ALL_REGISTERED_HOOKS = [
  ...BLOCKING_HOOKS,
  ...PROMPT_MODEL_HOOKS,
  "tool_result_persist",
  ...OBSERVATION_HOOKS,
] as const;

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: "agentguard-security",
  name: "AgentGuard Security",
  description: "Evaluates OpenClaw tool calls and outbound messages through AgentGuard Guard API.",
  register(api) {
    const config = buildPluginConfig(api.pluginConfig as OpenClawPluginConfigInput);
    const makeClient = () => new GuardApiClient({ config });

    scheduleHeartbeat(config, makeClient);

    api.on(
      "before_tool_call",
      async (event, context) => {
        const client = makeClient();
        try {
          const guardEvent = buildToolCallGuardEvent(event, context);
          const decision = await client.evaluate(guardEvent);
          return await decisionToToolResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "before_tool_call failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return failClosedToolResult();
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "message_sending",
      async (event, context) => {
        const client = makeClient();
        try {
          const guardEvent = buildMessageSendGuardEvent(event, context);
          const decision = await client.evaluate(guardEvent);
          return await decisionToMessageResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "message_sending failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return failClosedMessageResult();
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "before_install",
      async (event) => {
        const client = makeClient();
        try {
          const result = await client.evaluateConfigAudit(buildBeforeInstallConfigAuditEvent(event));
          return result.decision === "block"
            ? { block: true, blockReason: "Blocked by AgentGuard config audit." }
            : undefined;
        } catch (error) {
          logDiagnostic(config, "before_install failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "before_prompt_build",
      async (event, context) => {
        const client = makeClient();
        try {
          await client.evaluate(buildContextGuardEvent("before_prompt_build", event, context));
        } catch (error) {
          logDiagnostic(config, "before_prompt_build observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_input",
      async (event, context) => {
        const client = makeClient();
        try {
          await client.evaluate(buildModelGuardEvent("llm_input", event, context));
        } catch (error) {
          logDiagnostic(config, "llm_input observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_output",
      async (event, context) => {
        const client = makeClient();
        try {
          await client.evaluate(buildModelGuardEvent("llm_output", event, context));
        } catch (error) {
          logDiagnostic(config, "llm_output observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "tool_result_persist",
      (event, context) => {
        const client = makeClient();
        try {
          void client.evaluate(buildToolResultGuardEvent(event, context)).catch((error) => {
            logDiagnostic(config, "tool_result_persist observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
        } catch (error) {
          logDiagnostic(config, "tool_result_persist mapping failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return undefined;
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    for (const hookName of OBSERVATION_HOOKS) {
      api.on(
        hookName,
        (event: unknown, context: Record<string, unknown>) => {
          const client = makeClient();
          try {
            void client
              .submitRuntimeObservation(buildRuntimeObservationAuditEvent(hookName, event, context))
              .catch((error) => {
                logDiagnostic(config, "runtime observation submit failed", {
                  hookName,
                  error: error instanceof Error ? error.message : String(error),
                });
              });
          } catch (error) {
            logDiagnostic(config, "runtime observation mapping failed", {
              hookName,
              error: error instanceof Error ? error.message : String(error),
            });
            return undefined;
          }
          return undefined;
        },
        { priority: 0, timeoutMs: 2000 },
      );
    }
  },
});

function scheduleHeartbeat(config: ReturnType<typeof buildPluginConfig>, makeClient: () => GuardApiClient): void {
  if (!config.adapterToken) {
    return;
  }
  const submit = () => {
    void makeClient()
      .submitHeartbeat({
        pluginVersion: PLUGIN_VERSION,
        runtimeVersion: runtimeVersion(),
        hooks: [...ALL_REGISTERED_HOOKS],
        capabilities: {
          event_types: [
            "tool_call_proposed",
            "context_assembled",
            "model_input_prepared",
            "model_output_produced",
            "tool_result_produced",
            "memory_write_proposed",
            "message_send_proposed",
          ],
          blocking_hooks: [...BLOCKING_HOOKS],
          observation_hooks: [...OBSERVATION_HOOKS],
          fail_closed_stages: config.failClosedStages,
          redaction: config.redaction,
        },
      })
      .catch((error) => {
        logDiagnostic(config, "heartbeat submit failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      });
  };
  unrefTimer(setTimeout(submit, 0));
  unrefTimer(setInterval(submit, config.heartbeatIntervalMs));
}

function runtimeVersion(): string {
  return "2026.6.6";
}

function unrefTimer(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>): void {
  if (typeof timer === "object" && timer !== null && "unref" in timer) {
    (timer as { unref: () => void }).unref();
  }
}

export default plugin;
