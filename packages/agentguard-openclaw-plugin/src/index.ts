import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import { GuardApiClient, buildPluginConfig } from "./guard-api-client.js";
import { registerBeforePromptBuild } from "./hooks/context-guard.js";
import type { HookContext, PolicyOutcomeContext } from "./hooks/context.js";
import {
  registerBeforeInstall,
  registerObservationHooks,
} from "./hooks/lifecycle.js";
import {
  registerBeforeMessageWrite,
  registerMessageReceived,
  registerMessageSending,
} from "./hooks/message.js";
import {
  registerBeforeAgentFinalize,
  registerLlmInput,
  registerLlmOutput,
} from "./hooks/model.js";
import {
  registerBeforeToolCall,
  registerToolResultPersist,
} from "./hooks/tool.js";
import { scheduleHeartbeat } from "./runtime/heartbeat.js";
import type { SessionState, ToolCallState } from "./runtime/state.js";
import type { OpenClawPluginConfigInput } from "./types.js";

const PLUGIN_VERSION = "0.1.0-beta.1";

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: "agentguard-security",
  name: "AgentGuard Security",
  description:
    "Evaluates OpenClaw tool calls and outbound messages through AgentGuard Guard API.",
  register(api) {
    const config = buildPluginConfig(
      api.pluginConfig as OpenClawPluginConfigInput,
    );
    const makeClient = () => new GuardApiClient({ config });
    const hookContext: HookContext = {
      api,
      config,
      makeClient,
      sessionState: new Map<string, SessionState>(),
      toolCallState: new Map<string, ToolCallState>(),
      policyOutcomeState: new Map<string, PolicyOutcomeContext>(),
      finalizeRevisionKeys: new Set<string>(),
    };

    scheduleHeartbeat(config, makeClient, PLUGIN_VERSION);
    registerBeforeToolCall(hookContext);
    registerMessageSending(hookContext);
    registerBeforeInstall(hookContext);
    registerMessageReceived(hookContext);
    registerBeforePromptBuild(hookContext);
    registerLlmInput(hookContext);
    registerLlmOutput(hookContext);
    registerToolResultPersist(hookContext);
    registerBeforeMessageWrite(hookContext);
    registerBeforeAgentFinalize(hookContext);
    registerObservationHooks(hookContext);
  },
});

export default plugin;
