import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import {
  GuardApiClient,
  buildPluginConfig,
  decisionToMessageResult,
  decisionToToolResult,
  failClosedMessageResult,
  failClosedToolResult,
} from "./guard-api-client.js";
import {
  buildBeforeInstallConfigAuditEvent,
  buildMessageSendGuardEvent,
  buildRuntimeObservationAuditEvent,
  buildToolCallGuardEvent,
  buildToolResultGuardEvent,
} from "./mapping.js";
import type { OpenClawPluginConfigInput } from "./types.js";

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

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: "agentguard-security",
  name: "AgentGuard Security",
  description: "Evaluates OpenClaw tool calls and outbound messages through AgentGuard Guard API.",
  register(api) {
    const config = buildPluginConfig(api.pluginConfig as OpenClawPluginConfigInput);
    const makeClient = () => new GuardApiClient({ config });

    api.on(
      "before_tool_call",
      async (event, context) => {
        const client = makeClient();
        try {
          const guardEvent = buildToolCallGuardEvent(event, context);
          const decision = await client.evaluate(guardEvent);
          return await decisionToToolResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId),
          });
        } catch {
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
            waitForApproval: (approvalId) => client.waitForApproval(approvalId),
          });
        } catch {
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
        } catch {
          return { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "tool_result_persist",
      (event, context) => {
        const client = makeClient();
        try {
          void client.evaluate(buildToolResultGuardEvent(event, context)).catch(() => undefined);
        } catch {
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
              .catch(() => undefined);
          } catch {
            return undefined;
          }
          return undefined;
        },
        { priority: 0, timeoutMs: 2000 },
      );
    }
  },
});

export default plugin;
