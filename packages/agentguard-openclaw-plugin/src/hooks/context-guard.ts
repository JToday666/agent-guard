import { logDiagnostic } from "../guard-api-client.js";
import {
  buildContextGuardEvent,
  buildModelGuardEvent,
  buildRuntimeObservationAuditEvent,
} from "../mapping/index.js";
import {
  asRecord,
  rememberSessionState,
  withCachedRuntimeFields,
} from "../runtime/state.js";
import {
  decisionToInputGateResult,
  failClosedInputGateResult,
  guardRequestHookTimeoutMs,
  isDisabled,
  isObserve,
} from "../runtime/enforcement.js";
import { fireRuntimeOutcomeReceipt } from "../runtime/outcome-receipt.js";
import type { HookContext } from "./context.js";
import type {
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
} from "../types.js";

export function registerBeforePromptBuild(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState } = hookContext;
  api.on(
    "before_prompt_build",
    (event, context) => {
      if (isDisabled(config)) {
        return undefined;
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context, {
          promptFallback: true,
        });
        const cached = withCachedRuntimeFields(sessionState, event, context);
        void client
          .submitRuntimeObservation(
            buildRuntimeObservationAuditEvent(
              "before_prompt_build",
              cached.event,
              cached.context,
            ),
          )
          .catch((error) => {
            logDiagnostic(config, "before_prompt_build observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
      } catch (error) {
        logDiagnostic(
          config,
          "before_prompt_build observation mapping failed",
          {
            error: error instanceof Error ? error.message : String(error),
          },
        );
      }
      return undefined;
    },
    { priority: 0, timeoutMs: 2000 },
  );
}

export function registerBeforeAgentRun(hookContext: HookContext): void {
  const { api, config, makeClient, sessionState } = hookContext;
  api.on(
    "before_agent_run",
    async (event, context) => {
      if (isDisabled(config)) {
        return { outcome: "pass" };
      }
      const client = makeClient();
      try {
        rememberSessionState(sessionState, event, context, {
          promptFallback: true,
        });
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const evaluations: Array<{
          guardEvent: GuardEvent;
          evaluation: GuardEvaluationResponse;
        }> = [];
        const modelInputEvent = buildModelGuardEvent(
          "before_agent_run",
          currentInputOnly(cached.event),
          cached.context,
        );
        const toolMessages = untrustedToolMessages(cached.event);
        const requests = [
          client.evaluate(modelInputEvent).then((evaluation) => ({
            guardEvent: modelInputEvent,
            evaluation,
          })),
        ];
        if (toolMessages.length > 0) {
          const contextEvent = buildContextGuardEvent(
            "before_agent_run",
            {
              ...cached.event,
              prompt: undefined,
              messages: toolMessages,
              sourceTrust: "untrusted",
              sourceType: "tool_result",
            },
            cached.context,
          );
          requests.push(
            client.evaluate(contextEvent).then((evaluation) => ({
              guardEvent: contextEvent,
              evaluation,
            })),
          );
        }
        evaluations.push(...(await Promise.all(requests)));
        if (isObserve(config)) {
          return { outcome: "pass" };
        }
        const blocked = mostRestrictiveEvaluation(evaluations);
        if (!blocked) {
          return { outcome: "pass" };
        }
        const result = decisionToInputGateResult(blocked.evaluation);
        if (result.outcome === "block") {
          fireRuntimeOutcomeReceipt({
            client,
            config,
            guardEvent: blocked.guardEvent,
            evaluation: blocked.evaluation,
            kind: "pre_execution_deny",
            stage: "before_agent_run",
            logLabel: "before_agent_run",
          });
        }
        return result;
      } catch (error) {
        logDiagnostic(config, "before_agent_run enforcement failed", {
          error: error instanceof Error ? error.message : String(error),
        });
        return isObserve(config)
          ? { outcome: "pass" }
          : failClosedInputGateResult();
      }
    },
    { priority: 100, timeoutMs: guardRequestHookTimeoutMs(config) },
  );
}

function currentInputOnly(event: JsonObject): JsonObject {
  const senderIsOwner = event.senderIsOwner;
  return {
    ...event,
    systemPrompt: undefined,
    messages: undefined,
    sourceTrust:
      senderIsOwner === true
        ? "trusted"
        : senderIsOwner === false
          ? "untrusted"
          : (event.sourceTrust ?? event.source_trust ?? "trusted"),
    sourceType:
      senderIsOwner === true
        ? "user"
        : senderIsOwner === false
          ? "external_user"
          : (event.sourceType ?? event.source_type ?? "user"),
  };
}

function untrustedToolMessages(event: JsonObject): unknown[] {
  if (!Array.isArray(event.messages)) {
    return [];
  }
  return event.messages.filter((message) => {
    const record = asRecord(message);
    const role = String(record.role ?? "").toLowerCase();
    return (
      role === "tool" ||
      role === "function" ||
      "toolCallId" in record ||
      "tool_call_id" in record
    );
  });
}

function mostRestrictiveEvaluation(
  evaluations: Array<{
    guardEvent: GuardEvent;
    evaluation: GuardEvaluationResponse;
  }>,
):
  | {
      guardEvent: GuardEvent;
      evaluation: GuardEvaluationResponse;
    }
  | undefined {
  return (
    evaluations.find(
      ({ evaluation }) => evaluation.decision.decision === "deny",
    ) ??
    evaluations.find(({ evaluation }) => evaluation.decision.decision === "ask")
  );
}
