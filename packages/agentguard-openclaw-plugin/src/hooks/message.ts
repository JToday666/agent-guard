import {
  decisionToMessageResult,
  failClosedMessageResult,
  logDiagnostic,
} from "../guard-api-client.js";
import {
  buildMessageSendGuardEvent,
  buildRuntimeObservationAuditEvent,
} from "../mapping/index.js";
import { redactUnknownCredentials } from "../security.js";
import {
  asRecord,
  rememberSessionState,
  withCachedRuntimeFields,
} from "../runtime/state.js";
import {
  blockingApprovalHookTimeoutMs,
  isDisabled,
  isEnforcing,
  isObserve,
} from "../runtime/enforcement.js";
import { fireRuntimeOutcomeReceipt } from "../runtime/outcome-receipt.js";
import type { HookContext } from "./context.js";

export function registerMessageSending(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState } = hookContext;
  api.on(
    "message_sending",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const guardEvent = buildMessageSendGuardEvent(
          cached.event,
          cached.context,
        );
        const decision = await client.evaluate(guardEvent);
        if (isObserve(config)) {
          return undefined;
        }
        return await decisionToMessageResult(
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
              stage: "message_sending",
              logLabel: "message_sending",
            });
          },
        );
      } catch (error) {
        logDiagnostic(config, "message_sending failed closed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return isObserve(config) ? undefined : failClosedMessageResult();
      }
    },
    { priority: 100, timeoutMs: blockingApprovalHookTimeoutMs(config) },
  );
}

export function registerMessageReceived(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState } = hookContext;
  api.on(
    "message_received",
    (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context, {
          contentFallback: true,
        });
        const cached = withCachedRuntimeFields(sessionState, event, context);
        void client
          .submitRuntimeObservation(
            buildRuntimeObservationAuditEvent(
              "message_received",
              cached.event,
              cached.context,
            ),
          )
          .catch((error) => {
            logDiagnostic(config, "message_received observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
      } catch (error) {
        logDiagnostic(config, "message_received handling failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return undefined;
    },
    { priority: 0, timeoutMs: 2000 },
  );
}

export function registerBeforeMessageWrite(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState } = hookContext;
  api.on(
    "before_message_write",
    (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        void client
          .submitRuntimeObservation(
            buildRuntimeObservationAuditEvent(
              "before_message_write",
              cached.event,
              cached.context,
            ),
          )
          .catch((error) => {
            logDiagnostic(config, "before_message_write observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
        const message = asRecord(event).message;
        const redacted = redactUnknownCredentials(message);
        return isEnforcing(config) && redacted.changed
          ? { message: redacted.value as never }
          : undefined;
      } catch (error) {
        logDiagnostic(config, "before_message_write redaction failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return isEnforcing(config) ? { block: true } : undefined;
      }
    },
    { priority: 100, timeoutMs: 2000 },
  );
}
