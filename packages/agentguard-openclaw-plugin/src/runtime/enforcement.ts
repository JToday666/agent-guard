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
  return Math.max(10_000, config.approvalWaitBudgetMs + 2_000);
}

export function shouldRuntimeBlock(
  config: ReturnType<typeof buildPluginConfig>,
  response: GuardEvaluationResponse,
): boolean {
  return isEnforcing(config) && response.decision.decision !== "allow";
}

export function shouldFailClosedRuntimeStage(
  config: ReturnType<typeof buildPluginConfig>,
  stage: string,
): boolean {
  return isEnforcing(config) && config.failClosedStages.includes(stage);
}

export function decisionToBlockResult(response: GuardEvaluationResponse): {
  block: true;
  blockReason: string;
} {
  return {
    block: true,
    blockReason: safeDecisionMessage(response),
  };
}

export function failClosedBlockResult(): { block: true; blockReason: string } {
  return {
    block: true,
    blockReason: "AgentGuard is unavailable; blocked by fail-closed policy.",
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
