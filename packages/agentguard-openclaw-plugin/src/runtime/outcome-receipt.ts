import {
  logDiagnostic,
  type GuardApiClient,
} from "../guard-api-client.js";
import {
  buildRuntimeOutcomeAuditEvent,
  type OutcomeApprovalEvidence,
  type RuntimeOutcomeKind,
} from "../mapping/audit-outcomes.js";
import type {
  AgentGuardPluginConfig,
  GuardEvaluationResponse,
  GuardEvent,
} from "../types.js";

export type FireRuntimeOutcomeParams = {
  client: GuardApiClient;
  config: AgentGuardPluginConfig;
  guardEvent: GuardEvent;
  evaluation: GuardEvaluationResponse;
  kind: RuntimeOutcomeKind;
  approval?: OutcomeApprovalEvidence | null;
  resultDisposition?: "modified" | "quarantined";
  stage?: string;
  logLabel: string;
};

/**
 * fire-and-forget 提交 runtime_outcome 回执：
 * - 缺少 policy_audit_id 时不构造（§8.3 必填，不臆造），仅记诊断；
 * - 构造/提交失败只记诊断，不影响主流程（不 fail-closed）。
 */
export function fireRuntimeOutcomeReceipt(
  params: FireRuntimeOutcomeParams,
): void {
  const {
    client,
    config,
    guardEvent,
    evaluation,
    kind,
    approval,
    resultDisposition,
    stage,
    logLabel,
  } = params;
  if (!evaluation.policy_audit_id) {
    logDiagnostic(
      config,
      `${logLabel}: runtime outcome receipt skipped (missing policy_audit_id)`,
      { event_id: guardEvent.event_id },
    );
    return;
  }
  try {
    const receipt = buildRuntimeOutcomeAuditEvent(guardEvent, evaluation, kind, {
      approval,
      resultDisposition,
      stage,
    });
    void client.submitRuntimeOutcome(receipt).catch((error) => {
      logDiagnostic(config, `${logLabel}: runtime outcome receipt failed`, {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  } catch (error) {
    logDiagnostic(config, `${logLabel}: runtime outcome mapping failed`, {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
