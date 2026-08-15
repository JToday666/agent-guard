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
  patchToolCallState,
  rememberSessionState,
  rememberToolCallState,
  stringMaybe,
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
import type {
  GuardEvaluationResponse,
  GuardEvent,
  ToolCallPayload,
} from "../types.js";
import type { ToolCallState } from "../runtime/state.js";
import type { HookContext } from "./context.js";

export function registerBeforeToolCall(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    outcomeDelivery,
    sessionState,
    toolCallState,
    degradations,
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
        const callId = (guardEvent.payload as ToolCallPayload).tool.call_id;
        const nativeToolCallId =
          stringMaybe(asRecord(event).toolCallId) ??
          stringMaybe(asRecord(context).toolCallId) ??
          null;
        rememberToolCallState(toolCallState, guardEvent, {
          nativeToolCallId,
          tracker: degradations,
        });
        const decision = await client.evaluate(guardEvent);
        // §4 冻结不变量：policy linkage 必须在 handler 返回前同步写入
        // correlation state，禁止 fire-and-forget。
        linkToolCallDecision(toolCallState, callId, guardEvent, decision);
        if (isObserve(config)) {
          patchToolCallState(toolCallState, callId, { gateState: "allowed" });
          return undefined;
        }
        const guardDecision = decision.decision.decision;
        if (guardDecision === "allow") {
          patchToolCallState(toolCallState, callId, { gateState: "allowed" });
        } else if (guardDecision === "ask") {
          patchToolCallState(toolCallState, callId, {
            gateState: "approval_pending",
            approvalId: decision.approval?.approval_id ?? null,
            approvalStatus: "pending",
          });
        }
        return await decisionToToolResult(
          decision,
          {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId),
          },
          (outcome) => {
            if (outcome.kind === "pre_execution_deny") {
              // ask 等待超时/expired → timed_out；其余拒绝路径 → blocked。
              patchToolCallState(toolCallState, callId, {
                gateState:
                  outcome.approval?.status === "expired"
                    ? "timed_out"
                    : "blocked",
                approvalId:
                  outcome.approval?.approvalId ??
                  decision.approval?.approval_id ??
                  null,
                approvalStatus: outcome.approval?.status ?? "unknown",
              });
            } else {
              patchToolCallState(toolCallState, callId, {
                gateState: "approval_released",
                approvalId: outcome.approval.approvalId,
                approvalStatus: outcome.approval.status,
              });
            }
            fireRuntimeOutcomeReceipt({
              client,
              config,
              guardEvent,
              evaluation: decision,
              kind: outcome.kind,
              approval: outcome.approval,
              stage: "before_tool_call",
              logLabel: "before_tool_call",
              delivery: outcomeDelivery,
            });
            // 回执已入 durable spool 或被确定性跳过（缺 policy_audit_id）；
            // 两种结果都终结了回执链路，允许后续生命周期驱逐（§8.2）。
            patchToolCallState(toolCallState, callId, { receiptQueued: true });
          },
        );
      } catch (error) {
        logDiagnostic(config, "before_tool_call failed closed", {
          error: error instanceof Error ? error.message : String(error),
        });
        if (!isObserve(config)) {
          markFailedClosedGate(toolCallState, event, context);
          return failClosedToolResult();
        }
        return undefined;
      }
    },
    { priority: 100, timeoutMs: blockingApprovalHookTimeoutMs(config) },
  );
}

/** 同步写入 decision linkage（policyAuditId/decisionId/decision + 完整关联）。 */
export function linkToolCallDecision(
  toolCallState: Map<string, ToolCallState>,
  callId: string,
  guardEvent: GuardEvent,
  evaluation: GuardEvaluationResponse,
): void {
  patchToolCallState(toolCallState, callId, {
    policyAuditId: evaluation.policy_audit_id ?? undefined,
    decisionId: evaluation.decision.decision_id,
    decision: evaluation.decision.decision,
    guardEvent,
    evaluation,
  });
}

/** fail-closed 路径：尝试把当前调用标记为 blocked（无回执待投，直接可驱逐）。 */
function markFailedClosedGate(
  toolCallState: Map<string, ToolCallState>,
  event: unknown,
  context: unknown,
): void {
  const callId =
    stringMaybe(asRecord(event).toolCallId) ??
    stringMaybe(asRecord(context).toolCallId);
  if (!callId) {
    return;
  }
  patchToolCallState(toolCallState, callId, {
    gateState: "blocked",
    receiptQueued: true,
  });
}

export function registerToolResultPersist(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    outcomeDelivery,
    sessionState,
    toolCallState,
  } = hookContext;
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
                delivery: outcomeDelivery,
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
