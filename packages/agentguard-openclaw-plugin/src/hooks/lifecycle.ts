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

export function registerBeforeInstall(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "before_install",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        const result = await client.evaluateConfigAudit(
          buildBeforeInstallConfigAuditEvent(event, context),
        );
        if (isObserve(config)) {
          return undefined;
        }
        return result.decision === "block"
          ? { block: true, blockReason: "Blocked by AgentGuard config audit." }
          : undefined;
      } catch (error) {
        logDiagnostic(config, "before_install failed closed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return isObserve(config)
          ? undefined
          : {
              block: true,
              blockReason:
                "AgentGuard is unavailable; blocked by fail-closed policy.",
            };
      }
    },
    { priority: 100, timeoutMs: 10_000 },
  );
}

export function registerObservationHooks(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  for (const hookName of OPENCLAW_OBSERVATION_HOOKS as readonly PluginHookName[]) {
    api.on(
      hookName,
      (event: unknown, context: Record<string, unknown>) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          const eventRecord = asRecord(event);
          const contextRecord = asRecord(context);
          rememberSessionState(sessionState, eventRecord, contextRecord);
          const cached = withCachedRuntimeFields(
            sessionState,
            eventRecord,
            contextRecord,
          );
          void client
            .submitRuntimeObservation(
              buildRuntimeObservationAuditEvent(
                hookName,
                cached.event,
                cached.context,
              ),
            )
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
}
