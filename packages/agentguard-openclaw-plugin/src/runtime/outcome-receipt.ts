import { logDiagnostic, type GuardApiClient } from "../guard-api-client.js";
import {
  buildRuntimeOutcomeAuditEvent,
  type OutcomeApprovalEvidence,
  type RuntimeOutcomeKind,
  type TerminalInterventionType,
} from "../mapping/audit-outcomes.js";
import type {
  AgentGuardPluginConfig,
  ExecutionLeaseLinks,
  GuardEvaluationResponse,
  GuardEvent,
  RuntimeEnforcementEvidence,
} from "../types.js";
import type { RuntimeOutcomeDelivery } from "./outcome-delivery.js";

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
  delivery: RuntimeOutcomeDelivery;
  // RTE-03 terminal closure（契约 03 §6）
  interventionType?: TerminalInterventionType;
  invokedAt?: string | null;
  completedAt?: string;
  error?: string | null;
  /** 显式顶层时间戳；terminal 回执须与 completedAt 同源（Core 一致性校验）。 */
  timestamp?: string;
  lease?: ExecutionLeaseLinks;
  enforcement?: RuntimeEnforcementEvidence;
};

/**
 * 持久化后异步提交 runtime_outcome 回执：
 * - 缺少 policy_audit_id 时不构造（§8.3 必填，不臆造），仅记诊断；
 * - 网络失败由本地队列补投，持久化失败时退化为直接提交；
 * - 回执链路不改变已完成的运行时阻断结果。
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
    delivery,
    interventionType,
    invokedAt,
    completedAt,
    error,
    timestamp,
    lease,
    enforcement,
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
    const receipt = buildRuntimeOutcomeAuditEvent(
      guardEvent,
      evaluation,
      kind,
      {
        approval,
        resultDisposition,
        stage,
        interventionType,
        invokedAt,
        completedAt,
        error,
        timestamp,
        lease,
        enforcement,
      },
    );
    delivery.submit(receipt, client, logLabel);
  } catch (error_) {
    logDiagnostic(config, `${logLabel}: runtime outcome mapping failed`, {
      error: error_ instanceof Error ? error_.message : String(error_),
    });
  }
}
