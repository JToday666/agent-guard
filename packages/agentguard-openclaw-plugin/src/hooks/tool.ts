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
  receiptEvaluation,
  rememberSessionState,
  rememberToolCallState,
  stringMaybe,
  withCachedRuntimeFields,
  withCachedToolContext,
} from "../runtime/state.js";
import {
  capacityFailureEvidence,
  correlationFailureEvidence,
  consumeStrongApproval,
  isStrongBindingDegraded,
  snapshotGuardEvent,
  snapshotToolParams,
  strongHostInputSnapshot,
  validateStrongBinding,
} from "../runtime/strong-binding.js";
import { FINAL_ENFORCEMENT_HOOK_PRIORITY } from "../runtime/host-capabilities.js";
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
import type {
  EnforcementGateState,
  ToolCallState,
} from "../runtime/state.js";
import type { TerminalInterventionType } from "../mapping/audit-outcomes.js";
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
      let strongBindingDeclared = false;
      try {
        rememberSessionState(sessionState, event, context);
        const cached = withCachedRuntimeFields(sessionState, event, context);
        const guardEvent = snapshotGuardEvent(
          buildToolCallGuardEvent(cached.event, cached.context),
        );
        const actionSnapshot = strongHostInputSnapshot(
          event,
          context,
          guardEvent,
        );
        const approvedParams = snapshotToolParams(event);
        const callId = (guardEvent.payload as ToolCallPayload).tool.call_id;
        const nativeToolCallId =
          stringMaybe(asRecord(event).toolCallId) ??
          stringMaybe(asRecord(context).toolCallId) ??
          null;
        let stateRejection:
          | "capacity_exhausted"
          | "duplicate_active_id"
          | undefined;
        const remembered = rememberToolCallState(toolCallState, guardEvent, {
          nativeToolCallId,
          tracker: degradations,
          onRejected: (reason) => {
            stateRejection = reason;
          },
        });
        if (stateRejection === "duplicate_active_id") {
          logDiagnostic(
            config,
            "before_tool_call blocked duplicate active native action id",
          );
          return failClosedToolResult();
        }
        const decision = await client.evaluate(guardEvent);
        strongBindingDeclared = decision.enforcement_binding !== undefined;
        // §4 冻结不变量：policy linkage 必须在 handler 返回前同步写入
        // correlation state，禁止 fire-and-forget。
        linkToolCallDecision(toolCallState, callId, guardEvent, decision);
        if (strongBindingDeclared) {
          patchToolCallState(toolCallState, callId, {
            gateState: "approval_pending",
            approvalId: decision.approval?.approval_id ?? null,
            approvalStatus: "pending",
          });
          const validation = validateStrongBinding(
            decision,
            guardEvent,
            config.runtimeBindingId,
          );
          if (
            remembered &&
            remembered.correlationSource !== "native_tool_call_id"
          ) {
            degradations.record("after_tool_call_local_fallback_correlation");
          }
          const strongResult =
            !remembered
              ? {
                  outcome: "blocked" as const,
                  approval: null,
                  enforcement: capacityFailureEvidence(),
                }
              : remembered.correlationSource !== "native_tool_call_id"
                ? {
                    outcome: "blocked" as const,
                    approval: null,
                    enforcement: correlationFailureEvidence(),
                  }
              : validation.ok
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
                        buildToolCallGuardEvent(
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

          if (strongResult.outcome === "released") {
            patchToolCallState(toolCallState, callId, {
              gateState: "approval_released",
              approvalId: strongResult.approval.approvalId,
              approvalStatus: "allowed",
              leaseId: strongResult.lease.leaseId,
              consumptionId: strongResult.lease.consumptionId,
              enforcement: strongResult.enforcement,
            });
            fireRuntimeOutcomeReceipt({
              client,
              config,
              guardEvent,
              evaluation: decision,
              kind: "approval_release",
              approval: strongResult.approval,
              lease: strongResult.lease,
              enforcement: strongResult.enforcement,
              stage: "before_tool_call",
              logLabel: "before_tool_call",
              delivery: outcomeDelivery,
            });
            patchToolCallState(toolCallState, callId, { receiptQueued: true });
            return { params: approvedParams };
          }

          if (isStrongBindingDegraded(strongResult.enforcement)) {
            degradations.record("strong_binding_operational_degradation");
          }

          patchToolCallState(toolCallState, callId, {
            gateState: strongResult.enforcement.gate_state,
            approvalId:
              strongResult.approval?.approvalId ??
              decision.approval?.approval_id ??
              null,
            approvalStatus: strongResult.approval?.status ?? "unknown",
            enforcement: strongResult.enforcement,
          });
          fireRuntimeOutcomeReceipt({
            client,
            config,
            guardEvent,
            evaluation: decision,
            kind: "pre_execution_deny",
            approval: strongResult.approval,
            lease: strongResult.lease,
            enforcement: strongResult.enforcement,
            stage: "before_tool_call",
            logLabel: "before_tool_call",
            delivery: outcomeDelivery,
          });
          patchToolCallState(toolCallState, callId, { receiptQueued: true });
          return failClosedToolResult();
        }
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
        if (strongBindingDeclared || !isObserve(config)) {
          markFailedClosedGate(
            toolCallState,
            event,
            context,
            strongBindingDeclared ? "binding_failed" : "blocked",
          );
          return failClosedToolResult();
        }
        return undefined;
      }
    },
    {
      priority: FINAL_ENFORCEMENT_HOOK_PRIORITY,
      timeoutMs: blockingApprovalHookTimeoutMs(config),
    },
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
    evaluation: receiptEvaluation(evaluation),
  });
}

/** fail-closed 路径：尝试把当前调用标记为 blocked（无回执待投，直接可驱逐）。 */
function markFailedClosedGate(
  toolCallState: Map<string, ToolCallState>,
  event: unknown,
  context: unknown,
  gateState: EnforcementGateState = "blocked",
): void {
  const callId =
    stringMaybe(asRecord(event).toolCallId) ??
    stringMaybe(asRecord(context).toolCallId);
  if (!callId) {
    return;
  }
  patchToolCallState(toolCallState, callId, {
    gateState,
    receiptQueued: true,
  });
}

/**
 * Spike 证据锚点（rev5 Q9，pin 2026.7.1-2）：真实 host observer 对 blocked
 * 调用也会发出 after_tool_call（零执行、error 形状），因此 blocked gate 下
 * 的 after 到达不代表 invocation，不得派生任何 terminal fact。
 */
export const AFTER_HOOK_FIRES_ON_BLOCKED = true;

const BLOCKED_GATE_STATES: ReadonlySet<EnforcementGateState> = new Set([
  "blocked",
  "timed_out",
  "binding_failed",
]);

/**
 * Q5 硬约束：成败只能用 error 字符串判定。falsy 成功结果（false/0/""/null）
 * 的 after 事件既无 result 也无 error，字段存在性永远不得参与分类。
 */
export function classifyAfterToolCall(event: unknown): "completed" | "failed" {
  const error = asRecord(event).error;
  return typeof error === "string" && error.length > 0 ? "failed" : "completed";
}

/**
 * 矛盾判定：gate 预期阻断但观察到真实 terminal 时的干预类型。
 * 当前 pin 已证明 blocked 也会发 after hook（emitsOnBlocked=true），故 blocked
 * gate 一律 skip（只记诊断）；注入 emitsOnBlocked=false 保留矛盾分支可测（DoD #5）。
 */
export function terminalInterventionType(
  gateState: EnforcementGateState,
  options: { emitsOnBlocked: boolean } = {
    emitsOnBlocked: AFTER_HOOK_FIRES_ON_BLOCKED,
  },
): TerminalInterventionType | "skip" {
  const gateExpectedExecution =
    gateState === "allowed" || gateState === "approval_released";
  if (gateExpectedExecution) {
    return "runtime_observation";
  }
  if (BLOCKED_GATE_STATES.has(gateState)) {
    return options.emitsOnBlocked ? "skip" : "enforcement_violation";
  }
  // evaluating/approval_pending 阶段不应有 terminal 观察；不派生事实。
  return "skip";
}

/**
 * RTE-03 §5：after_tool_call → execution_completed/failed terminal closure。
 * 观察型 hook：任何异常只记 bounded diagnostic，绝不影响工具结果（RTE-039）。
 */
export function registerAfterToolCall(hookContext: HookContext): void {
  const {
    api,
    config,
    makeClient,
    outcomeDelivery,
    toolCallState,
    degradations,
  } = hookContext;
  api.on(
    "after_tool_call",
    (event, context) => {
      if (isDisabled(config)) {
        return;
      }
      try {
        const eventRecord = asRecord(event);
        const callId =
          stringMaybe(eventRecord.toolCallId) ??
          stringMaybe(asRecord(context).toolCallId);
        if (!callId) {
          degradations.record("after_tool_call_missing_action_id");
          logDiagnostic(
            config,
            "after_tool_call skipped: missing native action id",
          );
          return;
        }
        const state = toolCallState.get(callId);
        if (!state) {
          degradations.record("after_tool_call_correlation_missing");
          return;
        }
        if (state.correlationCompromised) {
          logDiagnostic(
            config,
            "after_tool_call skipped: native action identity was duplicated",
            { toolCallId: callId },
          );
          return;
        }
        if (state.correlationSource !== "native_tool_call_id") {
          // C2 要求稳定原生身份；local fallback 不伪造 terminal fact。
          degradations.record("after_tool_call_local_fallback_correlation");
          return;
        }
        if (
          !state.policyAuditId ||
          !state.decisionId ||
          !state.decision ||
          !state.guardEvent ||
          !state.evaluation
        ) {
          degradations.record("after_tool_call_policy_linkage_missing");
          return;
        }
        const intervention = terminalInterventionType(state.gateState);
        if (intervention === "skip") {
          // Q9：blocked/timed_out/binding_failed + after 到达不是矛盾而是 pin
          // 已证明的 emission-on-blocked；只记诊断，不派生 terminal fact。
          logDiagnostic(
            config,
            "after_tool_call observed for blocked gate state; no terminal fact derived",
            { toolCallId: callId, gateState: state.gateState },
          );
          return;
        }
        const client = makeClient();
        const terminal = classifyAfterToolCall(event);
        const completedAt = new Date().toISOString();
        const approval =
          state.gateState === "approval_released" && state.approvalId
            ? {
                approvalId: state.approvalId,
                status: "allowed" as const,
                decision: "allow_once" as const,
                resolvedAt: null,
              }
            : undefined;
        const lease =
          state.leaseId && state.consumptionId
            ? {
                leaseId: state.leaseId,
                consumptionId: state.consumptionId,
              }
            : undefined;
        fireRuntimeOutcomeReceipt({
          client,
          config,
          guardEvent: state.guardEvent,
          evaluation: state.evaluation,
          kind: terminal === "failed" ? "execution_failed" : "execution_completed",
          approval,
          lease,
          enforcement: state.enforcement,
          interventionType: intervention,
          invokedAt: null,
          // Core 要求 execution.completed_at 与回执顶层 timestamp 完全一致，
          // 两者必须同源，避免毫秒滚动导致 422 拒收。
          timestamp: completedAt,
          completedAt,
          error:
            terminal === "failed"
              ? (stringMaybe(eventRecord.error) ?? null)
              : null,
          stage: "after_tool_call",
          logLabel: "after_tool_call",
          delivery: outcomeDelivery,
        });
        patchToolCallState(toolCallState, callId, {
          terminalStatus: terminal === "failed" ? "failed" : "executed",
          terminalObservedAt: completedAt,
          // 回执已入 durable spool 或被确定性跳过；failed 终态因此可驱逐（§8.2）。
          receiptQueued: true,
        });
      } catch (error) {
        logDiagnostic(config, "after_tool_call mapping failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    },
    { priority: 0, timeoutMs: 2000 },
  );
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
        // RTE-03 §8.3：grace 期内关联命中只补标记，不重发回执。
        const persistCallId =
          stringMaybe(eventRecord.toolCallId) ??
          stringMaybe(asRecord(cached.context).toolCallId);
        if (persistCallId) {
          patchToolCallState(toolCallState, persistCallId, {
            resultPersistObserved: true,
          });
        }
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
          // 契约 03 §7.2：fail-closed quarantine 能关联原 action/policy 时
          // 写 tool_result_quarantined 回执；无关联时仅诊断，不伪造 policy link。
          const failCallId =
            stringMaybe(asRecord(event).toolCallId) ??
            stringMaybe(asRecord(context).toolCallId);
          const failState = failCallId
            ? toolCallState.get(failCallId)
            : undefined;
          if (
            failCallId &&
            failState &&
            failState.guardEvent &&
            failState.evaluation &&
            failState.policyAuditId &&
            failState.decisionId &&
            failState.decision
          ) {
            fireRuntimeOutcomeReceipt({
              client,
              config,
              guardEvent: failState.guardEvent,
              evaluation: failState.evaluation,
              kind: "tool_result_quarantine",
              resultDisposition: "quarantined",
              stage: "tool_result_persist",
              logLabel: "tool_result_persist",
              delivery: outcomeDelivery,
            });
            patchToolCallState(toolCallState, failCallId, {
              receiptQueued: true,
            });
          } else {
            logDiagnostic(
              config,
              "tool_result_persist fail-closed quarantine without policy linkage; diagnostic only",
              { toolCallId: failCallId ?? null },
            );
          }
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
