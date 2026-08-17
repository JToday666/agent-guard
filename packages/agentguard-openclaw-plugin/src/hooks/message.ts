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
import {
  consumeStrongApproval,
  isStrongBindingDegraded,
  snapshotGuardEvent,
  strongHostInputSnapshot,
  validateStrongBinding,
} from "../runtime/strong-binding.js";
import { FINAL_ENFORCEMENT_HOOK_PRIORITY } from "../runtime/host-capabilities.js";
import type { HookContext } from "./context.js";

export function registerMessageSending(hookContext: HookContext): void {
  const { api, config, makeClient, outcomeDelivery, sessionState, degradations } =
    hookContext;
  api.on(
    "message_sending",
    async (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      let strongBindingDeclared = false;
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const guardEvent = snapshotGuardEvent(
          buildMessageSendGuardEvent(cached.event, cached.context),
        );
        const actionSnapshot = strongHostInputSnapshot(
          event,
          context,
          guardEvent,
        );
        const approvedContentValue = asRecord(event).content;
        if (typeof approvedContentValue !== "string") {
          throw new Error("message_sending content must be a string");
        }
        const approvedContent = approvedContentValue;
        const decision = await client.evaluate(guardEvent);
        strongBindingDeclared = decision.enforcement_binding !== undefined;
        if (strongBindingDeclared) {
          const validation = validateStrongBinding(
            decision,
            guardEvent,
            config.runtimeBindingId,
          );
          const strongResult = validation.ok
            ? await consumeStrongApproval(
                client,
                decision,
                validation.binding,
                client.approvalDeadlineMs(),
                () => {
                  const latest = withCachedRuntimeFields(
                    sessionState,
                    event,
                    context,
                  );
                  const latestGuardEvent = snapshotGuardEvent(
                    buildMessageSendGuardEvent(
                      latest.event,
                      latest.context,
                    ),
                  );
                  return (
                    strongHostInputSnapshot(
                      event,
                      context,
                      latestGuardEvent,
                    ) === actionSnapshot
                  );
                },
              )
            : {
                outcome: "blocked" as const,
                approval: null,
                enforcement: validation.enforcement,
              };
          if (isStrongBindingDegraded(strongResult.enforcement)) {
            degradations.record("strong_binding_operational_degradation");
          }
          fireRuntimeOutcomeReceipt({
            client,
            config,
            guardEvent,
            evaluation: decision,
            kind:
              strongResult.outcome === "released"
                ? "approval_release"
                : "pre_execution_deny",
            approval: strongResult.approval,
            lease: strongResult.lease,
            enforcement: strongResult.enforcement,
            stage: "message_sending",
            logLabel: "message_sending",
            delivery: outcomeDelivery,
          });
          return strongResult.outcome === "released"
            ? { content: approvedContent }
            : failClosedMessageResult();
        }
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
              delivery: outcomeDelivery,
            });
          },
        );
      } catch (error) {
        logDiagnostic(config, "message_sending failed closed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return strongBindingDeclared || !isObserve(config)
          ? failClosedMessageResult()
          : undefined;
      }
    },
    {
      priority: FINAL_ENFORCEMENT_HOOK_PRIORITY,
      timeoutMs: blockingApprovalHookTimeoutMs(config),
    },
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
