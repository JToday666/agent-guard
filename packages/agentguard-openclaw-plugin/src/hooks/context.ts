import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import { GuardApiClient, buildPluginConfig } from "../guard-api-client.js";
import type { SessionState, ToolCallState } from "../runtime/state.js";
import type { GuardEvaluationResponse, GuardEvent } from "../types.js";

type PluginApi = Parameters<
  NonNullable<OpenClawPluginDefinition["register"]>
>[0];

/** before_tool_call 评估上下文，供 tool_result_persist 回写 runtime_outcome 使用。 */
export type PolicyOutcomeContext = {
  guardEvent: GuardEvent;
  evaluation: GuardEvaluationResponse;
};

export type HookContext = {
  api: PluginApi;
  config: ReturnType<typeof buildPluginConfig>;
  makeClient: () => GuardApiClient;
  sessionState: Map<string, SessionState>;
  toolCallState: Map<string, ToolCallState>;
  policyOutcomeState: Map<string, PolicyOutcomeContext>;
  finalizeRevisionKeys: Set<string>;
};
