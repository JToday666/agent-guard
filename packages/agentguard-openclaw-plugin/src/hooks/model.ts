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

export function registerLlmInput(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "llm_input",
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
          buildModelGuardEvent("llm_input", cached.event, cached.context),
        );
        if (shouldRuntimeBlock(config, decision)) {
          return decisionToBlockResult(decision) as never;
        }
      } catch (error) {
        logDiagnostic(config, "llm_input enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (shouldFailClosedRuntimeStage(config, "llm_input")) {
          return failClosedBlockResult() as never;
        }
      }
      return undefined;
    },
    { priority: 0, timeoutMs: 2000 },
  );
}

export function registerLlmOutput(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "llm_output",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        await client.evaluate(
          buildModelGuardEvent("llm_output", cached.event, cached.context),
        );
      } catch (error) {
        logDiagnostic(config, "llm_output observation failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return undefined;
    },
    { priority: 0, timeoutMs: 2000 },
  );
}

export function registerBeforeAgentFinalize(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    sessionState,
    toolCallState,
    finalizeRevisionKeys,
  } = hookContext;
  api.on(
    "before_agent_finalize",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const eventRecord = asRecord(cached.event);
        const content =
          stringMaybe(eventRecord.lastAssistantMessage) ??
          stringPreview(eventRecord.messages);
        const guardEvent = buildModelGuardEvent(
          "llm_output",
          {
            ...cached.event,
            output: content,
            provider:
              stringMaybe(eventRecord.provider) ??
              stringMaybe(cached.context.provider),
            model:
              stringMaybe(eventRecord.model) ??
              stringMaybe(cached.context.model),
          },
          cached.context,
        );
        let shouldRevise = containsSensitiveCredentialText(content);
        let revisionReason = shouldRevise
          ? "AgentGuard detected credential exposure in the final assistant message."
          : "";
        try {
          const decision = await client.evaluate(guardEvent);
          if (shouldRuntimeBlock(config, decision)) {
            shouldRevise = true;
            revisionReason = safeDecisionMessage(decision);
          }
        } catch (error) {
          logDiagnostic(config, "before_agent_finalize evaluation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        if (!isEnforcing(config) || !shouldRevise) {
          return undefined;
        }
        const revisionKey = firstNonEmptyString(
          stringMaybe(eventRecord.turnId),
          stringMaybe(eventRecord.runId),
          stringMaybe(eventRecord.sessionKey),
          stringMaybe(eventRecord.sessionId),
        );
        if (finalizeRevisionKeys.has(revisionKey)) {
          return undefined;
        }
        finalizeRevisionKeys.add(revisionKey);
        return {
          action: "revise",
          reason:
            revisionReason ||
            "AgentGuard detected unsafe content in the final assistant message.",
          retry: {
            instruction:
              "Remove all credential, secret, token, and API Key values from the final answer. Replace any credential value with [redacted] and do not reveal environment variable contents.",
            idempotencyKey: `agentguard-credential-redaction:${revisionKey}`,
            maxAttempts: 1,
          },
        };
      } catch (error) {
        logDiagnostic(config, "before_agent_finalize handling failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
      }
    },
    { priority: 100, timeoutMs: 10_000 },
  );
}
