import { buildPluginConfig } from "../guard-api-client.js";
import type { GuardEvaluationResponse } from "../types.js";
import { asRecord } from "./state.js";

export function isDisabled(
  config: ReturnType<typeof buildPluginConfig>,
): boolean {
  return config.enforcementMode === "disabled";
}

export function isObserve(
  config: ReturnType<typeof buildPluginConfig>,
): boolean {
  return config.enforcementMode === "observe";
}

export function isEnforcing(
  config: ReturnType<typeof buildPluginConfig>,
): boolean {
  return config.enforcementMode === "enforce";
}

export function blockingApprovalHookTimeoutMs(
  config: ReturnType<typeof buildPluginConfig>,
): number {
  return (
    config.requestTimeoutMs +
    config.approvalTimeoutMs +
    config.approvalPollIntervalMs +
    2_000
  );
}

export function guardRequestHookTimeoutMs(
  config: ReturnType<typeof buildPluginConfig>,
): number {
  return config.requestTimeoutMs + 2_000;
}

export function shouldRuntimeBlock(
  config: ReturnType<typeof buildPluginConfig>,
  response: GuardEvaluationResponse,
): boolean {
  return isEnforcing(config) && response.decision.decision !== "allow";
}

export function decisionToInputGateResult(response: GuardEvaluationResponse):
  | { outcome: "pass" }
  | {
      outcome: "block";
      reason: string;
      message: string;
      category: string;
    } {
  if (response.decision.decision === "allow") {
    return { outcome: "pass" };
  }
  return {
    outcome: "block",
    reason: safeDecisionMessage(response),
    message:
      response.decision.safe_message ||
      "AgentGuard blocked this request before model execution.",
    category: "agentguard_policy",
  };
}

export function failClosedInputGateResult(): {
  outcome: "block";
  reason: string;
  message: string;
  category: string;
} {
  return {
    outcome: "block",
    reason: "AgentGuard input evaluation was unavailable.",
    message: "AgentGuard is unavailable; the request was blocked.",
    category: "agentguard_unavailable",
  };
}

export function safeDecisionMessage(response: GuardEvaluationResponse): string {
  return (
    response.decision.safe_message ||
    response.decision.reason ||
    "Blocked by AgentGuard policy."
  );
}

export function quarantinedToolResultMessage(
  original: unknown,
  reason: string,
): unknown {
  const safeContent = `[AgentGuard quarantined this tool result before persistence. ${reason}]`;
  if (typeof original === "string") {
    return safeContent;
  }
  if (Array.isArray(original)) {
    return safeContent;
  }
  const record = asRecord(original);
  if (Object.keys(record).length === 0) {
    return safeContent;
  }
  if ("content" in record) {
    return { ...record, content: safeContent };
  }
  if ("text" in record) {
    return { ...record, text: safeContent };
  }
  if ("message" in record) {
    return { ...record, message: safeContent };
  }
  return safeContent;
}
