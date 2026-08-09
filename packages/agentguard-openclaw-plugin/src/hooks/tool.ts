import {
  decisionToToolResult,
  failClosedToolResult,
  logDiagnostic,
} from "../guard-api-client.js";
import {
  buildToolCallGuardEvent,
  buildToolResultGuardEvent,
} from "../mapping/index.js";
import {
  redactUnknownCredentials,
  sanitizePersistentInstructionPoisoning,
} from "../security.js";
import {
  asRecord,
  rememberSessionState,
  rememberToolCallState,
  withCachedRuntimeFields,
  withCachedToolContext,
} from "../runtime/state.js";
import { fireRuntimeOutcomeReceipt } from "../runtime/outcome-receipt.js";
import {
  blockingApprovalHookTimeoutMs,
  isDisabled,
  isEnforcing,
  isObserve,
  quarantinedToolResultMessage,
} from "../runtime/enforcement.js";
import type { HookContext } from "./context.js";

export function registerBeforeToolCall(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState, toolCallState } = hookContext;
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
        return await decisionToToolResult(
          decision,
          {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId),
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
  const { api, config, makeClient, sessionState, toolCallState } = hookContext;
  api.on(
    "tool_result_persist",
    (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      let message: unknown = event.message;
      try {
        const cached = withCachedToolContext(
          sessionState,
          toolCallState,
          event,
          context,
        );
        const eventRecord = asRecord(cached.event);
        const resultValue = eventRecord.result ?? eventRecord.message;
        message = eventRecord.message;
        const redacted = redactUnknownCredentials(resultValue);
        const guardEvent = buildToolResultGuardEvent(
          withToolResultValue(eventRecord, redacted.value),
          cached.context,
        );
        const sanitized = sanitizePersistentInstructionPoisoning(
          redacted.value,
        );
        const modified = redacted.changed || sanitized.changed;
        void client
          .evaluate(guardEvent)
          .then((evaluation) => {
            if (isEnforcing(config) && modified) {
              fireRuntimeOutcomeReceipt({
                client,
                config,
                guardEvent,
                evaluation,
                kind: "tool_result_quarantine",
                resultDisposition: "modified",
                stage: "tool_result_persist",
                logLabel: "tool_result_persist",
              });
            }
          })
          .catch((error) => {
            logDiagnostic(config, "tool_result_persist evaluation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
        if (isEnforcing(config) && modified) {
          return { message: sanitized.value as never };
        }
      } catch (error) {
        logDiagnostic(config, "tool_result_persist enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (isEnforcing(config)) {
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
    },
    { priority: 0, timeoutMs: 2000 },
  );
}

function withToolResultValue(
  event: Record<string, unknown>,
  value: unknown,
): Record<string, unknown> {
  return event.result === undefined
    ? { ...event, message: value }
    : { ...event, result: value };
}
