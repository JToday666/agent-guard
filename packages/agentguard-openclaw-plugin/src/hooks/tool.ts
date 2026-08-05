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
} from "../mapping.js";
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

export function registerBeforeToolCall(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "before_tool_call",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const guardEvent = buildToolCallGuardEvent(
          cached.event,
          cached.context,
        );
        rememberToolCallState(toolCallState, guardEvent);
        const decision = await client.evaluate(guardEvent);
        if (isObserve(config)) {
          return undefined;
        }
        return await decisionToToolResult(decision, {
          waitForApproval: (approvalId) =>
            client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
        });
      } catch (error) {
        logDiagnostic(config, "before_tool_call failed closed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return isObserve(config) ? undefined : failClosedToolResult();
      }
    },
    { priority: 100, timeoutMs: blockingApprovalHookTimeoutMs(config) },
  );
}

export function registerToolResultPersist(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "tool_result_persist",
    ((event: object, context: object) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      let message: unknown;
      try {
        const cached = withCachedToolContext(
          sessionState,
          toolCallState,
          event,
          context,
        );
        message = asRecord(event).message;
        const redacted = redactUnknownCredentials(message);
        const sanitized = sanitizePersistentInstructionPoisoning(
          redacted.value,
        );
        void client
          .submitRuntimeObservation(
            buildRuntimeObservationAuditEvent(
              "tool_result_persist",
              { ...cached.event, message: sanitized.value },
              cached.context,
            ),
          )
          .catch((error) => {
            logDiagnostic(config, "tool_result_persist observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
        if (isEnforcing(config) && (redacted.changed || sanitized.changed)) {
          return { message: sanitized.value as never };
        }
      } catch (error) {
        logDiagnostic(config, "tool_result_persist enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (shouldFailClosedRuntimeStage(config, "tool_result_persist")) {
          return {
            message: quarantinedToolResultMessage(
              message,
              "AgentGuard is unavailable; quarantined by fail-closed policy.",
            ) as never,
          };
        }
        return undefined;
      }
      return undefined;
    }) as never,
    { priority: 0, timeoutMs: 2000 },
  );
}
