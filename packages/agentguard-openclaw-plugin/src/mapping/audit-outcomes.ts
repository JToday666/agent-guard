import type {
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
  RuntimeOutcomeReceipt,
  RuntimeReceiptKind,
} from "../types.js";

/**
 * runtime_outcome 干预种类（契约 §9.4 / §13）。
 * 插件只产生自己可确证的干预：执行前拒绝、审批后放行、工具结果隔离/改写，
 * 以及 RTE-03 terminal closure 的 execution_completed / execution_failed。
 */
export type RuntimeOutcomeKind =
  | "pre_execution_deny"
  | "approval_release"
  | "tool_result_quarantine"
  | "execution_completed"
  | "execution_failed";

/** RTE-03（契约 02 §10）：terminal 回执的干预类型；不新增 outcome kind。 */
export type TerminalInterventionType =
  | "runtime_observation"
  | "enforcement_violation";

export type OutcomeApprovalEvidence = {
  approvalId: string;
  status: "allowed" | "denied" | "expired";
  decision: "allow_once" | "deny" | null;
  resolvedAt?: string | null;
};

export type RuntimeOutcomeOptions = {
  // tool_result_quarantine：sanitize→modified，隔离→quarantined（§9.7）
  resultDisposition?: "modified" | "quarantined";
  approval?: OutcomeApprovalEvidence | null;
  timestamp?: string;
  reason?: string;
  stage?: string;
  // RTE-03 terminal closure（契约 03 §6）
  interventionType?: TerminalInterventionType;
  invokedAt?: string | null;
  completedAt?: string;
  error?: string | null;
};

const INTERVENTION_REASON: Record<RuntimeOutcomeKind, string> = {
  pre_execution_deny: "策略拒绝后插件在动作执行前终止",
  approval_release: "人工审批仅本次放行后继续执行",
  tool_result_quarantine: "工具结果在持久化前被隔离或改写",
  execution_completed: "Runtime 观察到已放行调用真实执行完成",
  execution_failed: "Runtime 观察到已放行调用真实执行失败",
};

const MAX_TERMINAL_ERROR_CHARS = 2_000;

/**
 * 构造 runtime_outcome AuditEvent（契约 §8.2/§8.3/§12.2/§13）。
 *
 * - `links.policy_audit_id` 必填，取自 evaluate 响应，指向本次策略评估审计；
 * - `audit_id` 由 `event_id + 干预类型` 确定性派生，重试天然幂等（§12.3）；
 * - evidence 按 §13 五类干预映射，未观察到的字段一律保持 unknown/null，不臆造。
 */
export function buildRuntimeOutcomeAuditEvent(
  guardEvent: GuardEvent,
  evaluation: GuardEvaluationResponse,
  kind: RuntimeOutcomeKind,
  options: RuntimeOutcomeOptions = {},
): RuntimeOutcomeReceipt {
  const decision = evaluation.decision;
  const timestamp = options.timestamp ?? new Date().toISOString();
  const policyAuditId = evaluation.policy_audit_id;
  const decisionId = decision.decision_id;
  const riskScore = decision.risk_score;
  if (!policyAuditId || !decisionId) {
    throw new Error(
      "runtime outcome receipt requires policy_audit_id and decision_id",
    );
  }
  if (typeof riskScore !== "number" || !Number.isInteger(riskScore)) {
    throw new Error("runtime outcome receipt requires an integer risk_score");
  }
  const severity = receiptSeverity(decision.severity);
  const actionId = toolCallId(guardEvent);
  const approval = options.approval ?? null;
  const outcomeKind = receiptKind(kind, options);

  const links: RuntimeOutcomeReceipt["links"] = {
    event_id: guardEvent.event_id,
    decision_id: decisionId,
    policy_audit_id: policyAuditId,
  };
  if (actionId) {
    links.action_id = actionId;
  }
  if (approval) {
    links.approval_id = approval.approvalId;
  } else if (evaluation.approval) {
    links.approval_id = evaluation.approval.approval_id;
  }

  return {
    // 确定性派生：同一逻辑评估 + 同一干预类型重试时保持稳定（§12.3 幂等）。
    audit_id: `audit_outcome_${guardEvent.event_id}_${outcomeKind}`,
    schema_version: "0.4",
    record_type: "runtime_outcome",
    trace_id: guardEvent.trace_id,
    case_id: guardEvent.case_id ?? null,
    runtime: "openclaw",
    timestamp,
    stage: options.stage ?? "after_guard_decision",
    event_type: "runtime_outcome",
    attack_type: guardEvent.attack_type ?? null,
    is_malicious: guardEvent.is_malicious ?? null,
    summary: outcomeSummary(kind, decision.decision),
    // 有关联策略时复制顶层策略摘要（§8.3）。
    decision: decision.decision,
    risk_score: riskScore,
    severity,
    blocked: decision.decision !== "allow",
    resource_targets: guardEvent.security_context.derived_paths,
    rule_hits: (decision.rule_hits ?? [])
      .map((hit) => hit.rule_id)
      .filter((ruleId) => typeof ruleId === "string" && ruleId.length > 0),
    reason: options.reason ?? decision.reason,
    links,
    latency_ms: null,
    metadata: {
      agent_id: guardEvent.security_context.agent_id,
      outcome_kind: outcomeKind,
    },
    evidence: {
      intervention: {
        type: interventionType(kind, options),
        reason: options.reason ?? INTERVENTION_REASON[kind],
      },
      execution: executionEvidence(kind, timestamp, options),
      side_effects: sideEffectsEvidence(kind),
      result: resultEvidence(kind, options),
      approval: approvalEvidence(kind, approval, evaluation),
    },
  };
}

/** terminal 回执用 runtime_observation/enforcement_violation；其余回执用 kind 自身。 */
function interventionType(
  kind: RuntimeOutcomeKind,
  options: RuntimeOutcomeOptions,
): string {
  if (kind === "execution_completed" || kind === "execution_failed") {
    return options.interventionType ?? "runtime_observation";
  }
  return kind;
}

function receiptKind(
  kind: RuntimeOutcomeKind,
  options: RuntimeOutcomeOptions,
): RuntimeReceiptKind {
  if (kind !== "tool_result_quarantine") {
    return kind;
  }
  return options.resultDisposition === "modified"
    ? "tool_result_modified"
    : "tool_result_quarantined";
}

function receiptSeverity(
  value: string | undefined,
): RuntimeOutcomeReceipt["severity"] {
  if (
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  ) {
    return value;
  }
  throw new Error("runtime outcome receipt requires a known severity");
}

function toolCallId(guardEvent: GuardEvent): string | undefined {
  const payload = guardEvent.payload as JsonObject;
  const tool = payload.tool as JsonObject | undefined;
  const callId = tool?.call_id;
  return typeof callId === "string" && callId.length > 0 ? callId : undefined;
}

function outcomeSummary(
  kind: RuntimeOutcomeKind,
  decision: "allow" | "deny" | "ask",
): string {
  if (kind === "pre_execution_deny") {
    return `OpenClaw 确认动作未被执行（policy=${decision}）`;
  }
  if (kind === "approval_release") {
    return "OpenClaw 在人工审批放行后继续执行";
  }
  if (kind === "execution_completed") {
    return "OpenClaw 观察到已放行调用真实执行完成";
  }
  if (kind === "execution_failed") {
    return "OpenClaw 观察到已放行调用真实执行失败";
  }
  return "OpenClaw 在持久化前隔离或改写了工具结果";
}

// §9.5 执行回执：只填插件可确证的状态，未观察字段保持 null/unknown。
function executionEvidence(
  kind: RuntimeOutcomeKind,
  timestamp: string,
  options: RuntimeOutcomeOptions,
): JsonObject {
  if (kind === "pre_execution_deny") {
    return {
      status: "not_invoked",
      receipt_recorded: true,
      invoked_at: null,
      completed_at: timestamp,
      error: null,
      tool_result_entered_context: false,
      persisted: false,
    };
  }
  if (kind === "approval_release") {
    // 放行发生在执行前，插件尚未观察到执行结果，按事实保持 unknown。
    return {
      status: "unknown",
      receipt_recorded: true,
      invoked_at: null,
      completed_at: timestamp,
      error: null,
      tool_result_entered_context: null,
      persisted: null,
    };
  }
  if (kind === "execution_completed") {
    // RTE-03 §6：after hook 不能证明 result 已进入上下文或已持久化，保持 null。
    return {
      status: "executed",
      receipt_recorded: true,
      invoked_at: options.invokedAt ?? null,
      completed_at: options.completedAt ?? timestamp,
      error: null,
      tool_result_entered_context: null,
      persisted: null,
    };
  }
  if (kind === "execution_failed") {
    return {
      status: "failed",
      receipt_recorded: true,
      invoked_at: options.invokedAt ?? null,
      completed_at: options.completedAt ?? timestamp,
      error: boundedTerminalError(options.error),
      tool_result_entered_context: null,
      persisted: null,
    };
  }
  // tool_result_quarantine：能进入 persist hook 说明工具已执行并产生结果。
  const quarantined = options.resultDisposition === "quarantined";
  return {
    status: "executed",
    receipt_recorded: true,
    invoked_at: null,
    completed_at: timestamp,
    error: null,
    tool_result_entered_context: quarantined ? false : null,
    persisted: quarantined ? false : null,
  };
}

// §9.6 副作用：插件不测量外部副作用，除执行前拒绝可确证为 0 外一律未测量。
function sideEffectsEvidence(kind: RuntimeOutcomeKind): JsonObject {
  if (kind === "pre_execution_deny") {
    return {
      measurement_status: "measured",
      count: 0,
      summary: "工具未进入运行时调用入口",
    };
  }
  return {
    measurement_status: "not_measured",
    count: null,
    summary: "未测量外部工具副作用",
  };
}

// §9.7 结果处置。
function resultEvidence(
  kind: RuntimeOutcomeKind,
  options: RuntimeOutcomeOptions,
): JsonObject {
  if (kind === "pre_execution_deny") {
    return {
      disposition: "not_applicable",
      summary: "没有工具结果产生",
      sanitized: false,
    };
  }
  if (kind === "approval_release") {
    return {
      disposition: "unknown",
      summary: null,
      sanitized: null,
    };
  }
  if (kind === "execution_completed") {
    // §6：不得因 after hook 携带 result 就断言进入上下文/已持久化。
    return {
      disposition: "unknown",
      summary: null,
      sanitized: null,
    };
  }
  if (kind === "execution_failed") {
    return {
      disposition: "not_applicable",
      summary: "执行失败，没有可用工具结果",
      sanitized: null,
    };
  }
  const disposition = options.resultDisposition ?? "quarantined";
  return {
    disposition,
    summary:
      disposition === "modified"
        ? "工具结果在持久化前被脱敏/改写"
        : "工具结果未进入模型上下文或记忆",
    sanitized: disposition === "modified",
  };
}

// §9.8 审批证据。
function approvalEvidence(
  kind: RuntimeOutcomeKind,
  approval: OutcomeApprovalEvidence | null,
  evaluation: GuardEvaluationResponse,
): JsonObject {
  if (approval) {
    return {
      approval_id: approval.approvalId,
      status: approval.status,
      decision: approval.decision,
      resolved_at: approval.resolvedAt ?? null,
    };
  }
  if (evaluation.approval) {
    return {
      approval_id: evaluation.approval.approval_id,
      status: "unknown",
      decision: null,
      resolved_at: null,
    };
  }
  return {
    approval_id: null,
    status: kind === "approval_release" ? "unknown" : "not_required",
    decision: null,
    resolved_at: null,
  };
}

/** execution_failed 的 error 必须是有界非空字符串（契约 02 §9）。
 * Core RuntimeExecutionEvidence.error 上限 2000 字符，截断时省略号计入上限，
 * 否则长堆栈会使回执被 Guard API 422 拒收并丢失失败证据。 */
function boundedTerminalError(value: string | null | undefined): string {
  const text =
    typeof value === "string" && value.length > 0
      ? value
      : "unknown tool failure";
  if (text.length <= MAX_TERMINAL_ERROR_CHARS) {
    return text;
  }
  return `${text.slice(0, MAX_TERMINAL_ERROR_CHARS - 3)}...`;
}
