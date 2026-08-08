import type {
  ApprovalRequest,
  DecisionStatus,
  ExecutionApprovalStatus,
  ExecutionPolicyCheck,
  ExecutionReceiptExpectation,
  ExecutionStepCategory,
  ExecutionStepEvent,
  ExecutionStepViewModel,
  ExecutionTraceViewModel,
  NormalizedAuditEvidence,
  TraceLifecycleState,
} from "../../types/dashboard";
import { getEventTypeLabel } from "../../utils/dashboard-formatters.ts";

const ACTION_LABELS: Readonly<Record<string, string>> = {
  browser_click: "点击页面元素",
  browser_extract_text: "提取页面内容",
  browser_input: "填写页面内容",
  browser_inspect: "检查页面状态",
  browser_navigate: "打开页面",
  browser_start: "启动浏览器",
  call_api: "调用外部接口",
  code_exec: "执行代码",
  mcp_call: "调用 MCP 工具",
  memory_read: "读取记忆",
  memory_search: "搜索记忆",
  memory_write: "写入记忆",
  memory_write_proposed: "写入记忆",
  rag_answer: "生成检索回答",
  rag_retrieve: "检索知识",
  read_file: "读取文件",
  search: "搜索信息",
  send_email: "发送邮件",
  send_message: "发送消息",
  message_send_proposed: "发送消息",
  write_file: "写入文件",
};

const RECEIPT_REQUIRED_CATEGORIES = new Set<ExecutionStepCategory>(["memory", "message", "tool"]);

const CHECKPOINT_CATEGORIES = new Set<ExecutionStepCategory>([
  "context",
  "model_input",
  "model_output",
  "tool_result",
]);

const CATEGORY_ORDER: Readonly<Record<ExecutionStepCategory, number>> = {
  tool: 0,
  memory: 1,
  message: 2,
  model_output: 3,
  context: 4,
  model_input: 5,
  tool_result: 6,
  unknown: 7,
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

function logicalStepEvents(events: readonly NormalizedAuditEvidence[]): NormalizedAuditEvidence[] {
  const seenPolicyChecks = new Set<string>();
  return uniqueAuditEvents(events).filter((event) => {
    if (event.recordType !== "policy_evaluation") return true;
    const key =
      event.eventId && event.decisionId
        ? `${event.eventId}\u0000${event.decisionId}`
        : `audit:${event.auditId}`;
    if (seenPolicyChecks.has(key)) return false;
    seenPolicyChecks.add(key);
    return true;
  });
}

function uniquePolicyChecks(events: readonly NormalizedAuditEvidence[]): NormalizedAuditEvidence[] {
  return logicalStepEvents(events).filter((event) => event.recordType === "policy_evaluation");
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
  subjectId: string | null,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
): ApprovalSelection {
  const linkedIds = new Set(
    events.flatMap((event) => (event.approval.approvalId ? [event.approval.approvalId] : [])),
  );
  if (linkedIds.size > 1) return { conflicted: true, id: null, status: "unknown" };

  const subjectApprovals = subjectId
    ? approvals.filter(
        (approval) => approval.actionId === subjectId || approval.subjectId === subjectId,
      )
    : [];
  const linkedId = [...linkedIds][0] ?? null;
  if (!linkedId && subjectApprovals.length > 1) {
    return { conflicted: true, id: null, status: "unknown" };
  }
  const selected = linkedId
    ? approvals.find((approval) => approval.id === linkedId)
    : subjectApprovals[0];
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

function isTraceLifecycle(event: NormalizedAuditEvidence): boolean {
  const value = event.eventType || event.stage;
  return ["trace_started", "trace_completed", "trace_failed", "trace_cancelled"].includes(value);
}

function isExecutionStepEvidence(event: NormalizedAuditEvidence): boolean {
  if (event.recordType === "config_audit" || isTraceLifecycle(event)) return false;
  if (event.recordType === "policy_evaluation") return Boolean(event.actionId || event.eventId);
  if (event.recordType === "runtime_outcome") return Boolean(event.actionId || event.eventId);
  if (event.recordType === "runtime_observation") return Boolean(event.actionId);
  return Boolean(
    event.actionId &&
    (event.decision !== "unknown" || event.approval.approvalId || event.execution.receiptRecorded),
  );
}

function eventCategory(event: NormalizedAuditEvidence): ExecutionStepCategory {
  if (event.eventType === "context_assembled") return "context";
  if (event.eventType === "model_input_prepared") return "model_input";
  if (event.eventType === "model_output_produced" || event.eventType === "model_output_proposed") {
    return "model_output";
  }
  if (event.eventType === "tool_call_proposed") return "tool";
  if (event.eventType === "tool_result_produced") return "tool_result";
  if (event.eventType === "memory_write_proposed") return "memory";
  if (event.eventType === "message_send_proposed") return "message";
  return "unknown";
}

function selectCategory(events: readonly NormalizedAuditEvidence[]): ExecutionStepCategory {
  return (
    events
      .map(eventCategory)
      .sort((left, right) => CATEGORY_ORDER[left] - CATEGORY_ORDER[right])[0] ?? "unknown"
  );
}

function receiptExpectation(
  category: ExecutionStepCategory,
  events: readonly NormalizedAuditEvidence[],
): ExecutionReceiptExpectation {
  if (RECEIPT_REQUIRED_CATEGORIES.has(category)) return "required";
  if (CHECKPOINT_CATEGORIES.has(category)) return "not_required";
  if (events.some((event) => isExplicitStart(event) || event.recordType === "runtime_outcome")) {
    return "required";
  }
  return "unknown";
}

function stepPhase(
  execution: ExecutionStepViewModel["execution"],
  approval: ExecutionApprovalStatus,
  expectation: ExecutionReceiptExpectation,
  hasStart: boolean,
  hasPolicyCheck: boolean,
): ExecutionStepViewModel["phase"] {
  if (execution !== "unknown") return "terminal";
  if (hasStart) return "waiting_receipt";
  if (approval === "pending") return "waiting_approval";
  if (expectation === "not_required" && hasPolicyCheck) return "checked";
  if (approval === "allowed_once") return "approval_released";
  return hasPolicyCheck ? "evaluated" : "proposed";
}

function stepStatus(
  step: Pick<
    ExecutionStepViewModel,
    "approval" | "decision" | "execution" | "intervention" | "phase" | "receiptExpectation"
  >,
  hasOutcome: boolean,
): string {
  if (step.phase === "terminal") {
    if (step.execution === "executed") return "已执行";
    if (step.execution === "failed") return "执行失败";
    return "已确认未执行";
  }
  if (step.phase === "waiting_receipt") return "正在执行";
  if (step.phase === "waiting_approval") return "等待审批";
  if (step.phase === "approval_released") return "已放行，等待运行";
  if (step.phase === "checked") {
    if (step.intervention === "model_output_revision") return "模型输出已修订";
    if (step.intervention === "tool_result_quarantine") return "工具结果已隔离";
    if (step.approval === "denied") return "审批已拒绝";
    if (step.approval === "expired") return "审批已过期";
    if (step.decision === "deny") return "安全检查已拒绝继续";
    return "安全检查已完成";
  }
  if (step.approval === "denied") return "审批已拒绝，运行结果未确认";
  if (step.approval === "expired") return "审批已过期，运行结果未确认";
  if (hasOutcome) return "已收到运行结果，状态未记录";
  if (step.phase === "evaluated" && step.receiptExpectation === "required") {
    return "已完成安全判断，等待运行时回执";
  }
  if (step.phase === "evaluated") return "已完成安全判断";
  return "已记录运行步骤";
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

function stepEventLabel(event: NormalizedAuditEvidence): string {
  const runtimeLabels: Readonly<Record<string, string>> = {
    tool_call_completed: "执行完成",
    tool_call_failed: "执行失败",
    tool_call_not_invoked: "确认未调用",
    tool_call_started: "开始执行",
  };
  return runtimeLabels[event.eventType] ?? getEventTypeLabel(event.eventType || event.stage);
}

function toStepEvent(event: NormalizedAuditEvidence): ExecutionStepEvent {
  return {
    auditId: event.auditId,
    decision: event.decision,
    eventId: event.eventId,
    eventType: event.eventType,
    execution: event.execution.status,
    intervention: event.intervention,
    label: stepEventLabel(event),
    occurredAt: event.occurredAt,
    recordType: event.recordType,
  };
}

function actionName(
  category: ExecutionStepCategory,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
  actionId: string | null,
): string | null {
  const preferredType =
    category === "tool"
      ? "tool_call_proposed"
      : category === "memory"
        ? "memory_write_proposed"
        : category === "message"
          ? "message_send_proposed"
          : category === "model_output"
            ? "model_output_produced"
            : category === "context"
              ? "context_assembled"
              : category === "model_input"
                ? "model_input_prepared"
                : category === "tool_result"
                  ? "tool_result_produced"
                  : null;
  const preferred = preferredType
    ? events.find((event) => event.eventType === preferredType && event.toolName)?.toolName
    : null;
  return (
    preferred ??
    [...events].reverse().find((event) => event.toolName)?.toolName ??
    (actionId ? approvals.find((item) => item.actionId === actionId)?.actionName : null) ??
    null
  );
}

function displayName(
  category: ExecutionStepCategory,
  name: string | null,
  events: readonly NormalizedAuditEvidence[],
): string {
  if (category === "context") return "检查输入上下文";
  if (category === "model_input") return "检查模型输入";
  if (category === "model_output") return "检查模型输出";
  if (category === "tool_result") {
    const toolLabel = name ? (ACTION_LABELS[name] ?? name) : "工具";
    return `检查${toolLabel}返回内容`;
  }
  if (category === "memory") return ACTION_LABELS[name ?? "memory_write"] ?? "写入记忆";
  if (category === "message") return ACTION_LABELS[name ?? "send_message"] ?? "发送消息";
  if (name) return ACTION_LABELS[name] ?? name;
  const eventType = events.find((event) => event.eventType)?.eventType;
  return eventType ? getEventTypeLabel(eventType) : "未命名运行步骤";
}

function buildStep(
  stepId: string,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
): ExecutionStepViewModel {
  const stepEvents = logicalStepEvents(events);
  const checks = uniquePolicyChecks(stepEvents);
  const outcomes = stepEvents.filter((event) => event.recordType === "runtime_outcome");
  const observations = stepEvents.filter((event) => event.recordType === "runtime_observation");
  const actionIds = [
    ...new Set(stepEvents.flatMap((event) => (event.actionId ? [event.actionId] : []))),
  ];
  const actionId = actionIds.length === 1 ? actionIds[0]! : null;
  const eventIds = [
    ...new Set(stepEvents.flatMap((event) => (event.eventId ? [event.eventId] : []))),
  ];
  const subjectId = actionId ?? eventIds[0] ?? null;
  const approval = selectApproval(subjectId, stepEvents, approvals);
  const policy = selectPrimaryPolicyCheck(checks, outcomes, approval);
  const outcome =
    [...outcomes]
      .reverse()
      .find((event) => event.execution.receiptRecorded || event.execution.status !== "unknown") ??
    outcomes.at(-1);
  const execution = outcome?.execution.status ?? "unknown";
  const hasStart = observations.some(isExplicitStart);
  const category = selectCategory(stepEvents);
  const expectation = receiptExpectation(category, stepEvents);
  const phase = stepPhase(execution, approval.status, expectation, hasStart, checks.length > 0);
  const primary = policy.check;
  const name = actionName(category, stepEvents, approvals, actionId);
  const resources = primary?.resources.length
    ? primary.resources
    : ([...stepEvents].reverse().find((event) => event.resources.length)?.resources ?? []);
  const decision: DecisionStatus = policy.conflicted ? "unknown" : (primary?.decision ?? "unknown");
  const intervention =
    [...stepEvents].reverse().find((event) => event.intervention !== "unknown")?.intervention ??
    "unknown";
  const kind =
    RECEIPT_REQUIRED_CATEGORIES.has(category) || (category === "unknown" && Boolean(actionId))
      ? "action"
      : "checkpoint";
  const partial = {
    approval: approval.status,
    decision,
    execution,
    intervention,
    phase,
    receiptExpectation: expectation,
  };

  return {
    actionId,
    actionName: name,
    approval: approval.status,
    approvalId: approval.id,
    auditIds: stepEvents.map((event) => event.auditId),
    category,
    decision,
    decisionId: primary?.decisionId ?? null,
    decisionReason: primary?.decisionReason ?? null,
    displayName: displayName(category, name, stepEvents),
    eventId: primary?.eventId ?? eventIds[0] ?? null,
    eventIds,
    events: stepEvents.map(toStepEvent),
    execution,
    firstSeenAt: stepEvents[0]!.occurredAt,
    intervention,
    kind,
    lastUpdatedAt: stepEvents.at(-1)!.occurredAt,
    observationAuditIds: observations.map((event) => event.auditId),
    outcomeAuditIds: outcomes.map((event) => event.auditId),
    phase,
    policyChecks: checks.map(toPolicyCheck),
    primaryAuditId: primary?.auditId ?? stepEvents[0]?.auditId ?? null,
    receiptExpectation: expectation,
    resourceSummary: resources[0]?.value ?? null,
    riskScore: primary?.risk.finalScore ?? null,
    settled: phase === "checked" || phase === "terminal",
    severity: primary?.severity ?? "unknown",
    statusLabel: stepStatus(partial, outcomes.length > 0),
    stepId,
  };
}

function lifecycleState(
  events: readonly NormalizedAuditEvidence[],
  steps: readonly ExecutionStepViewModel[],
): Pick<ExecutionTraceViewModel, "lifecycleAuditId" | "lifecycleLabel" | "lifecycleState"> {
  const lifecycle = [...events].reverse().find((event) => {
    if (event.recordType !== "runtime_observation") return false;
    return isTraceLifecycle(event) && event.eventType !== "trace_started";
  });
  const value = lifecycle?.eventType || lifecycle?.stage;
  let state: TraceLifecycleState;
  if (value === "trace_completed") state = "completed";
  else if (value === "trace_failed") state = "failed";
  else if (value === "trace_cancelled") state = "cancelled";
  else if (steps.some((step) => step.approval === "pending")) {
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

function groupKey(event: NormalizedAuditEvidence): string | null {
  if (event.actionId) return `action:${event.actionId}`;
  if (event.eventId) return `event:${event.eventId}`;
  return null;
}

export function buildExecutionTrace(
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[] = [],
): ExecutionTraceViewModel {
  const sorted = uniqueAuditEvents(events);
  const logical = logicalStepEvents(sorted);
  const grouped = new Map<string, NormalizedAuditEvidence[]>();
  for (const event of logical) {
    if (!isExecutionStepEvidence(event)) continue;
    const key = groupKey(event);
    if (!key) continue;
    const group = grouped.get(key) ?? [];
    group.push(event);
    grouped.set(key, group);
  }
  const steps = [...grouped.entries()].map(([stepId, stepEvents]) =>
    buildStep(stepId, stepEvents, approvals),
  );
  return { steps, ...lifecycleState(sorted, steps) };
}

export function shouldContinueTracePolling(trace: ExecutionTraceViewModel): boolean {
  return !["completed", "failed", "cancelled"].includes(trace.lifecycleState);
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

export function getExecutionCategoryLabel(category: ExecutionStepCategory): string {
  const labels: Record<ExecutionStepCategory, string> = {
    context: "上下文",
    memory: "记忆",
    message: "消息",
    model_input: "模型输入",
    model_output: "模型输出",
    tool: "工具动作",
    tool_result: "工具结果",
    unknown: "运行步骤",
  };
  return labels[category];
}
