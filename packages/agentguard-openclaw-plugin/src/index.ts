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
import { buildMessageSendGuardEvent, buildToolCallGuardEvent } from "./mapping.js";
import type { OpenClawPluginConfigInput } from "./types.js";

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: "agentguard-security",
  name: "AgentGuard Security",
  description: "Evaluates OpenClaw tool calls and outbound messages through AgentGuard Guard API.",
  register(api) {
    const config = buildPluginConfig(api.pluginConfig as OpenClawPluginConfigInput);

    api.on(
      "before_tool_call",
      async (event, context) => {
        const client = new GuardApiClient({ config });
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
        const client = new GuardApiClient({ config });
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
  },
});

export default plugin;
