import type { PluginHookName } from "openclaw/plugin-sdk/types";

import { OPENCLAW_OBSERVATION_HOOKS } from "../../hook-contract.mjs";
import {
  decisionToMessageResult,
  decisionToToolResult,
  failClosedMessageResult,
  failClosedToolResult,
  logDiagnostic,
} from "../guard-api-client.js";
import {
  buildBeforeInstallConfigAuditEvent,
  buildContextGuardEvent,
  buildMessageSendGuardEvent,
  buildModelGuardEvent,
  buildRuntimeObservationAuditEvent,
  buildToolCallGuardEvent,
} from "../mapping/index.js";
import {
  containsSensitiveCredentialText,
  redactUnknownCredentials,
  sanitizePersistentInstructionPoisoning,
  stringPreview,
} from "../security.js";
import {
  asRecord,
  firstNonEmptyString,
  rememberSessionState,
  rememberToolCallState,
  stringMaybe,
  withCachedRuntimeFields,
  withCachedToolContext,
} from "../runtime/state.js";
import {
  blockingApprovalHookTimeoutMs,
  decisionToBlockResult,
  failClosedBlockResult,
  isDisabled,
  isEnforcing,
  isObserve,
  quarantinedToolResultMessage,
  safeDecisionMessage,
  shouldFailClosedRuntimeStage,
  shouldRuntimeBlock,
} from "../runtime/enforcement.js";
import type { HookContext } from "./context.js";

export function registerBeforePromptBuild(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "before_prompt_build",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context, {
          promptFallback: true,
        });
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const decision = await client.evaluate(
          buildContextGuardEvent(
            "before_prompt_build",
            cached.event,
            cached.context,
          ),
        );
        if (shouldRuntimeBlock(config, decision)) {
          return decisionToBlockResult(decision) as never;
        }
      } catch (error) {
        logDiagnostic(config, "before_prompt_build enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (shouldFailClosedRuntimeStage(config, "before_prompt_build")) {
          return failClosedBlockResult() as never;
        }
      }
      return undefined;
    },
    { priority: 0, timeoutMs: 2000 },
  );
}
