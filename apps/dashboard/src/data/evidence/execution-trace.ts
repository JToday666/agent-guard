import type {
  ApprovalRequest,
  DecisionStatus,
  ExecutionActionViewModel,
  ExecutionApprovalStatus,
  ExecutionPolicyCheck,
  ExecutionTraceViewModel,
  NormalizedAuditEvidence,
  TraceLifecycleState,
} from "../../types/dashboard";

const ACTION_LABELS: Readonly<Record<string, string>> = {
  code_exec: "执行代码",
  memory_read: "读取记忆",
  memory_write: "写入记忆",
  read_file: "读取文件",
  search: "搜索信息",
  send_email: "发送邮件",
  write_file: "写入文件",
};

function compareEvents(
  left: NormalizedAuditEvidence,
  right: NormalizedAuditEvidence,
  useAuditSequence: boolean,
): number {
  const primaryOrder = useAuditSequence
    ? left.chainIndex! - right.chainIndex!
    : Date.parse(left.occurredAt) - Date.parse(right.occurredAt);
  return primaryOrder || left.auditId.localeCompare(right.auditId);
}

function uniqueAuditEvents(events: readonly NormalizedAuditEvidence[]): NormalizedAuditEvidence[] {
  const unique = new Map<string, NormalizedAuditEvidence>();
  const useAuditSequence = events.every((event) => event.chainIndex !== null);
  for (const event of [...events].sort((left, right) =>
    compareEvents(left, right, useAuditSequence),
  )) {
    if (!unique.has(event.auditId)) unique.set(event.auditId, event);
  }
  return [...unique.values()];
}

function uniquePolicyChecks(events: readonly NormalizedAuditEvidence[]): NormalizedAuditEvidence[] {
  const seen = new Set<string>();
  const checks: NormalizedAuditEvidence[] = [];
  for (const event of events) {
    if (event.recordType !== "policy_evaluation") continue;
    const logicalKey =
      event.eventId && event.decisionId
        ? `${event.eventId}\u0000${event.decisionId}`
        : `audit:${event.auditId}`;
    if (seen.has(logicalKey)) continue;
    seen.add(logicalKey);
    checks.push(event);
  }
  return checks;
}

function approvalStatus(approval: ApprovalRequest): ExecutionApprovalStatus {
  if (approval.status === "allowed") return "allowed_once";
  return approval.status;
}

function evidenceApprovalStatus(
  event: NormalizedAuditEvidence | undefined,
): ExecutionApprovalStatus {
  const status = event?.approval.status;
  if (status === "allowed") return "allowed_once";
  if (
    status === "pending" ||
    status === "denied" ||
    status === "expired" ||
    status === "not_required"
  ) {
    return status;
  }
  return "unknown";
}

interface ApprovalSelection {
  conflicted: boolean;
  id: string | null;
  status: ExecutionApprovalStatus;
}

function selectApproval(
  actionId: string,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
): ApprovalSelection {
  const linkedIds = new Set(
    events.flatMap((event) => (event.approval.approvalId ? [event.approval.approvalId] : [])),
  );
  if (linkedIds.size > 1) return { conflicted: true, id: null, status: "unknown" };

  const actionApprovals = approvals.filter((approval) => approval.actionId === actionId);
  const linkedId = [...linkedIds][0] ?? null;
  if (!linkedId && actionApprovals.length > 1) {
    return { conflicted: true, id: null, status: "unknown" };
  }
  const selected = linkedId
    ? approvals.find((approval) => approval.id === linkedId)
    : actionApprovals[0];
  const fallbackEvent = [...events]
    .reverse()
    .find((event) => !linkedId || event.approval.approvalId === linkedId);
  return {
    conflicted: false,
    id: linkedId ?? selected?.id ?? null,
    status: selected ? approvalStatus(selected) : evidenceApprovalStatus(fallbackEvent),
  };
}

interface PolicySelection {
  check: NormalizedAuditEvidence | null;
  conflicted: boolean;
}

function selectPrimaryPolicyCheck(
  checks: readonly NormalizedAuditEvidence[],
  outcomes: readonly NormalizedAuditEvidence[],
  approval: ApprovalSelection,
): PolicySelection {
  const outcomePolicyIds = new Set(
    outcomes.flatMap((event) => (event.policyAuditId ? [event.policyAuditId] : [])),
  );
  if (outcomePolicyIds.size > 1) return { check: null, conflicted: true };
  const outcomePolicyId = [...outcomePolicyIds][0];
  if (outcomePolicyId) {
    const check = checks.find((event) => event.auditId === outcomePolicyId) ?? null;
    return { check, conflicted: check === null };
  }

  if (approval.conflicted) return { check: null, conflicted: true };
  if (approval.id) {
    const matches = checks.filter((event) => event.approval.approvalId === approval.id);
    if (matches.length > 1) return { check: null, conflicted: true };
    if (matches.length === 1) return { check: matches[0]!, conflicted: false };
  }
  return { check: checks.at(-1) ?? null, conflicted: false };
}

function isExplicitStart(event: NormalizedAuditEvidence): boolean {
  return (
    event.recordType === "runtime_observation" &&
    (event.eventType === "tool_call_started" || event.stage === "tool_call_started")
  );
}

function actionStatus(
  action: Pick<ExecutionActionViewModel, "approval" | "decision" | "execution" | "phase">,
  hasOutcome: boolean,
): string {
  if (action.phase === "terminal") {
    if (action.execution === "executed") return "已执行";
    if (action.execution === "failed") return "执行失败";
    return "已确认未执行";
  }
  if (action.phase === "waiting_receipt") return "正在执行";
  if (action.phase === "waiting_approval") return "等待审批";
  if (action.phase === "approval_released") return "已放行，等待运行";
  if (action.approval === "denied") return "审批已拒绝，执行状态待确认";
  if (action.approval === "expired") return "审批已过期，执行状态待确认";
  if (hasOutcome) return "已收到运行结果，状态未记录";
  if (action.phase === "evaluated") return "已完成安全判断，等待运行时回执";
  return "已提出动作";
}

function actionPhase(
  execution: ExecutionActionViewModel["execution"],
  approval: ExecutionApprovalStatus,
  hasStart: boolean,
  hasPolicyCheck: boolean,
): ExecutionActionViewModel["phase"] {
  if (execution !== "unknown") return "terminal";
  if (hasStart) return "waiting_receipt";
  if (approval === "pending") return "waiting_approval";
  if (approval === "allowed_once") return "approval_released";
  return hasPolicyCheck ? "evaluated" : "proposed";
}

function toPolicyCheck(event: NormalizedAuditEvidence): ExecutionPolicyCheck {
  return {
    auditId: event.auditId,
    decision: event.decision,
    decisionId: event.decisionId,
    occurredAt: event.occurredAt,
    reason: event.decisionReason,
    riskScore: event.risk.finalScore,
    ruleHits: event.ruleHits,
    severity: event.severity,
  };
}

function buildAction(
  actionId: string,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
): ExecutionActionViewModel {
  const actionEvents = uniqueAuditEvents(events);
  const checks = uniquePolicyChecks(actionEvents);
  const outcomes = actionEvents.filter((event) => event.recordType === "runtime_outcome");
  const observations = actionEvents.filter((event) => event.recordType === "runtime_observation");
  const approval = selectApproval(actionId, actionEvents, approvals);
  const policy = selectPrimaryPolicyCheck(checks, outcomes, approval);
  const outcome =
    [...outcomes]
      .reverse()
      .find((event) => event.execution.receiptRecorded || event.execution.status !== "unknown") ??
    outcomes.at(-1);
  const execution = outcome?.execution.status ?? "unknown";
  const hasStart = observations.some(isExplicitStart);
  const phase = actionPhase(execution, approval.status, hasStart, checks.length > 0);
  const primary = policy.check;
  const actionName =
    [...actionEvents].reverse().find((event) => event.toolName)?.toolName ??
    approvals.find((item) => item.actionId === actionId)?.actionName ??
    null;
  const resources = primary?.resources.length
    ? primary.resources
    : ([...actionEvents].reverse().find((event) => event.resources.length)?.resources ?? []);
  const decision: DecisionStatus = policy.conflicted ? "unknown" : (primary?.decision ?? "unknown");
  const partial = {
    approval: approval.status,
    decision,
    execution,
    phase,
  };

  return {
    actionId,
    actionName,
    approval: approval.status,
    approvalId: approval.id,
    auditIds: actionEvents.map((event) => event.auditId),
    decision,
    decisionReason: primary?.decisionReason ?? null,
    displayName: actionName ? (ACTION_LABELS[actionName] ?? actionName) : "未命名动作",
    execution,
    firstSeenAt: actionEvents[0]!.occurredAt,
    lastUpdatedAt: actionEvents.at(-1)!.occurredAt,
    observationAuditIds: observations.map((event) => event.auditId),
    outcomeAuditIds: outcomes.map((event) => event.auditId),
    phase,
    policyChecks: checks.map(toPolicyCheck),
    primaryAuditId: primary?.auditId ?? null,
    resourceSummary: resources[0]?.value ?? null,
    riskScore: primary?.risk.finalScore ?? null,
    severity: primary?.severity ?? "unknown",
    statusLabel: actionStatus(partial, outcomes.length > 0),
  };
}

function lifecycleState(
  events: readonly NormalizedAuditEvidence[],
  actions: readonly ExecutionActionViewModel[],
): Pick<ExecutionTraceViewModel, "lifecycleAuditId" | "lifecycleLabel" | "lifecycleState"> {
  const lifecycle = [...events].reverse().find((event) => {
    if (event.recordType !== "runtime_observation") return false;
    return (
      ["trace_completed", "trace_failed", "trace_cancelled"].includes(event.eventType) ||
      ["trace_completed", "trace_failed", "trace_cancelled"].includes(event.stage)
    );
  });
  const value = lifecycle?.eventType || lifecycle?.stage;
  let state: TraceLifecycleState;
  if (value === "trace_completed") state = "completed";
  else if (value === "trace_failed") state = "failed";
  else if (value === "trace_cancelled") state = "cancelled";
  else if (actions.some((action) => action.approval === "pending")) {
    state = "waiting_approval";
  } else state = "observing";
  const labels: Record<TraceLifecycleState, string> = {
    cancelled: "运行已取消",
    completed: "运行已结束",
    failed: "运行失败",
    observing: "实时观察中",
    waiting_approval: "等待人工审批",
  };
  return {
    lifecycleAuditId: lifecycle?.auditId ?? null,
    lifecycleLabel: labels[state],
    lifecycleState: state,
  };
}

export function buildExecutionTrace(
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[] = [],
): ExecutionTraceViewModel {
  const sorted = uniqueAuditEvents(events);
  const grouped = new Map<string, NormalizedAuditEvidence[]>();
  for (const event of sorted) {
    if (!event.actionId) continue;
    const group = grouped.get(event.actionId) ?? [];
    group.push(event);
    grouped.set(event.actionId, group);
  }
  const actions = [...grouped.entries()]
    .map(([actionId, actionEvents]) => buildAction(actionId, actionEvents, approvals))
    .sort(
      (left, right) =>
        Date.parse(left.firstSeenAt) - Date.parse(right.firstSeenAt) ||
        left.actionId.localeCompare(right.actionId),
    );
  return { actions, ...lifecycleState(sorted, actions) };
}

export function shouldContinueTracePolling(trace: ExecutionTraceViewModel): boolean {
  const isTerminal =
    trace.lifecycleState === "completed" ||
    trace.lifecycleState === "failed" ||
    trace.lifecycleState === "cancelled";
  if (!isTerminal) return true;
  return trace.actions.some((action) => action.phase !== "terminal");
}

export function getExecutionApprovalLabel(status: ExecutionApprovalStatus): string {
  const labels: Record<ExecutionApprovalStatus, string> = {
    allowed_once: "单次放行",
    denied: "审批拒绝",
    expired: "审批过期",
    not_required: "无需审批",
    pending: "等待审批",
    unknown: "审批未记录",
  };
  return labels[status];
}
