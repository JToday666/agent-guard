import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";
import { resolveStateDir } from "openclaw/plugin-sdk/state-paths";
import { join } from "node:path";

import { GuardApiClient, buildPluginConfig } from "./guard-api-client.js";
import {
  registerBeforeAgentRun,
  registerBeforePromptBuild,
} from "./hooks/context-guard.js";
import type { HookContext } from "./hooks/context.js";
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
import { RuntimeOutcomeDelivery } from "./runtime/outcome-delivery.js";
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
    const outcomeDelivery = new RuntimeOutcomeDelivery({
      spoolDirectory: join(
        resolveStateDir(),
        "plugins",
        "agentguard-security",
        "runtime-outcomes",
      ),
      config,
      makeClient,
    });
    const hookContext: HookContext = {
      api,
      config,
      makeClient,
      outcomeDelivery,
      sessionState: new Map<string, SessionState>(),
      toolCallState: new Map<string, ToolCallState>(),
    };

    let stopHeartbeat: (() => void) | null = null;
    api.registerService({
      id: "agentguard-security-runtime",
      start() {
        outcomeDelivery.start();
        stopHeartbeat?.();
        stopHeartbeat = scheduleHeartbeat(config, makeClient, PLUGIN_VERSION);
      },
      stop() {
        stopHeartbeat?.();
        stopHeartbeat = null;
        outcomeDelivery.stop();
      },
    });
    registerBeforeToolCall(hookContext);
    registerMessageSending(hookContext);
    registerBeforeInstall(hookContext);
    registerMessageReceived(hookContext);
    registerBeforePromptBuild(hookContext);
    registerBeforeAgentRun(hookContext);
    registerLlmInput(hookContext);
    registerLlmOutput(hookContext);
    registerToolResultPersist(hookContext);
    registerBeforeMessageWrite(hookContext);
    registerBeforeAgentFinalize(hookContext);
    registerObservationHooks(hookContext);
  },
});

export default plugin;
