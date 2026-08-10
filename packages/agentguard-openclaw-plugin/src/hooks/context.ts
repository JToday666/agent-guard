import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import { GuardApiClient, buildPluginConfig } from "../guard-api-client.js";
import type { RuntimeOutcomeDelivery } from "../runtime/outcome-delivery.js";
import type { SessionState, ToolCallState } from "../runtime/state.js";

type PluginApi = Parameters<
  NonNullable<OpenClawPluginDefinition["register"]>
>[0];

export type HookContext = {
  api: PluginApi;
  config: ReturnType<typeof buildPluginConfig>;
  makeClient: () => GuardApiClient;
  outcomeDelivery: RuntimeOutcomeDelivery;
  sessionState: Map<string, SessionState>;
  toolCallState: Map<string, ToolCallState>;
};
