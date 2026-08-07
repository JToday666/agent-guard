import type { PluginHookName } from "openclaw/plugin-sdk/types";

import { OPENCLAW_OBSERVATION_HOOKS } from "../../hook-contract.mjs";
import {
  decisionToMessageResult,
  decisionToToolResult,
  failClosedMessageResult,
  failClosedToolResult,
  logDiagnostic,
  type GuardApiClient,
} from "../guard-api-client.js";
import type { AgentGuardPluginConfig } from "../types.js";
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
  setLimited,
  stringMaybe,
  withCachedRuntimeFields,
  withCachedToolContext,
} from "../runtime/state.js";
import { fireRuntimeOutcomeReceipt } from "../runtime/outcome-receipt.js";
import type { PolicyOutcomeContext } from "./context.js";
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
    policyOutcomeState,
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
        // 缓存本次策略评估上下文，供 tool_result_persist 回写 runtime_outcome。
        const toolPayload = guardEvent.payload as { tool?: { call_id?: string } };
        const callId = toolPayload.tool?.call_id;
        if (callId) {
          setLimited(policyOutcomeState, callId, {
            guardEvent,
            evaluation: decision,
          } satisfies PolicyOutcomeContext);
        }
        if (isObserve(config)) {
          return undefined;
        }
        return await decisionToToolResult(
          decision,
          {
            waitForApproval: (approvalId) =>
              client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          },
          (outcome) => {
            fireRuntimeOutcomeReceipt({
              client,
              config,
              guardEvent,
              evaluation: decision,
              kind: outcome.kind,
              approval: outcome.approval,
              stage: "before_tool_call",
              logLabel: "before_tool_call",
            });
          },
        );
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
    policyOutcomeState,
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
      let persistCallId: string | undefined;
      try {
        const cached = withCachedToolContext(
          sessionState,
          toolCallState,
          event,
          context,
        );
        persistCallId = stringMaybe(asRecord(cached.event).toolCallId);
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
          // 结果被改写后持久化：tool_result_quarantine 干预，disposition=modified。
          fireToolResultPersistOutcome(
            client,
            config,
            policyOutcomeState,
            persistCallId,
            "modified",
          );
          return { message: sanitized.value as never };
        }
      } catch (error) {
        logDiagnostic(config, "tool_result_persist enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (shouldFailClosedRuntimeStage(config, "tool_result_persist")) {
          // fail-closed 隔离：disposition=quarantined。
          fireToolResultPersistOutcome(
            client,
            config,
            policyOutcomeState,
            persistCallId,
            "quarantined",
          );
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

/** 用 before_tool_call 缓存的策略上下文回写 tool_result_persist 干预回执。 */
function fireToolResultPersistOutcome(
  client: GuardApiClient,
  config: AgentGuardPluginConfig,
  policyOutcomeState: Map<string, PolicyOutcomeContext>,
  callId: string | undefined,
  disposition: "modified" | "quarantined",
): void {
  const policyContext = callId ? policyOutcomeState.get(callId) : undefined;
  if (!policyContext) {
    logDiagnostic(
      config,
      "tool_result_persist outcome skipped (no cached policy context)",
      { call_id: callId ?? null },
    );
    return;
  }
  fireRuntimeOutcomeReceipt({
    client,
    config,
    guardEvent: policyContext.guardEvent,
    evaluation: policyContext.evaluation,
    kind: "tool_result_quarantine",
    resultDisposition: disposition,
    stage: "tool_result_persist",
    logLabel: "tool_result_persist",
  });
}
