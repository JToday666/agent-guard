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
  ProvenanceGraph,
  ProvenanceWindow,
  TraceApprovalWindow,
  TraceAuditWindow,
  TraceLifecycleState,
} from "../../types/dashboard";
import type {
  ApprovalBasisViewModel,
  Availability,
  DashboardDataSourceDescriptor,
  ElementSourceMode,
  RuntimeSupervisionViewModel,
  SupervisionWarning,
} from "../../types/runtime-supervision.ts";
import { getEventTypeLabel } from "../../utils/dashboard-formatters.ts";
import { projectApprovalBasis } from "./approval-basis-projector.ts";
import { projectContextManifests } from "./context-manifest-projector.ts";
import { applyCtContentToSteps, projectCtPresentation } from "./provenance-presentation.ts";
import {
  projectExecutionStepSupervision,
  type SelectedApprovalEvidence,
} from "./step-supervision.ts";

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
  web_fetch: "获取网页内容",
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
  return (
    primaryOrder ||
    left.auditId.localeCompare(right.auditId) ||
    JSON.stringify(stableJsonValue(left)).localeCompare(JSON.stringify(stableJsonValue(right)))
  );
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

function stableJsonValue(value: unknown, ancestors = new WeakSet<object>()): unknown {
  if (Array.isArray(value)) return value.map((item) => stableJsonValue(item, ancestors));
  if (typeof value !== "object" || value === null) return value;
  if (ancestors.has(value)) return "[Circular]";
  ancestors.add(value);
  const result = Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableJsonValue(item, ancestors)]),
  );
  ancestors.delete(value);
  return result;
}

function conflictingDuplicateAuditIds(
  events: readonly NormalizedAuditEvidence[],
): ReadonlySet<string> {
  const firstSignatureById = new Map<string, string>();
  const conflicts = new Set<string>();
  for (const event of events) {
    const signature = JSON.stringify(stableJsonValue(event));
    const firstSignature = firstSignatureById.get(event.auditId);
    if (firstSignature === undefined) {
      firstSignatureById.set(event.auditId, signature);
    } else if (firstSignature !== signature) {
      conflicts.add(event.auditId);
    }
  }
  return conflicts;
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

interface ApprovalSelection extends SelectedApprovalEvidence {
  conflicted: boolean;
  id: string | null;
  status: ExecutionApprovalStatus;
  request: ApprovalRequest | null;
}

function selectApproval(
  subjectId: string | null,
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
): ApprovalSelection {
  const linkedIds = new Set(
    events.flatMap((event) => (event.approval.approvalId ? [event.approval.approvalId] : [])),
  );
  if (linkedIds.size > 1) {
    return { conflicted: true, id: null, request: null, status: "unknown" };
  }

  const subjectApprovals = subjectId
    ? approvals.filter(
        (approval) => approval.actionId === subjectId || approval.subjectId === subjectId,
      )
    : [];
  const linkedId = [...linkedIds][0] ?? null;
  if (!linkedId && subjectApprovals.length > 1) {
    return { conflicted: true, id: null, request: null, status: "unknown" };
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
    request: selected ?? null,
    status: selected ? approvalStatus(selected) : evidenceApprovalStatus(fallbackEvent),
  };
}

interface PolicySelection {
  check: NormalizedAuditEvidence | null;
  conflicted: boolean;
}

interface OutcomeSelection {
  outcome: NormalizedAuditEvidence | null;
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

function selectRuntimeOutcome(
  outcomes: readonly NormalizedAuditEvidence[],
  policy: PolicySelection,
  actionId: string | null,
): OutcomeSelection {
  if (policy.conflicted) return { conflicted: true, outcome: null };
  const receiptCandidates = outcomes.filter(
    (event) => event.execution.receiptRecorded && event.execution.status !== "unknown",
  );
  if (!policy.check) {
    return { conflicted: receiptCandidates.length > 0, outcome: null };
  }
  const linkedCandidates = receiptCandidates.filter(
    (event) =>
      actionId !== null &&
      event.actionId === actionId &&
      event.policyAuditId === policy.check?.auditId &&
      event.eventId !== null &&
      event.eventId === policy.check?.eventId &&
      event.decisionId !== null &&
      event.decisionId === policy.check?.decisionId,
  );
  if (receiptCandidates.length !== linkedCandidates.length || linkedCandidates.length > 1) {
    return { conflicted: true, outcome: null };
  }
  return { conflicted: false, outcome: linkedCandidates[0] ?? null };
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
    if (name === "web_fetch") return "检查网页内容";
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
  context: ExecutionProjectionContext,
  duplicateConflicts: ReadonlySet<string>,
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
  const selectedApproval = selectApproval(subjectId, stepEvents, approvals);
  const approvalEvidenceConflicted = stepEvents.some(
    (event) => event.approval.approvalId && duplicateConflicts.has(event.auditId),
  );
  const approval: ApprovalSelection = approvalEvidenceConflicted
    ? { conflicted: true, id: null, request: null, status: "unknown" }
    : selectedApproval;
  const selectedPolicy = selectPrimaryPolicyCheck(checks, outcomes, approval);
  const policyConflicted =
    selectedPolicy.conflicted || checks.some((event) => duplicateConflicts.has(event.auditId));
  const policy: PolicySelection = policyConflicted
    ? { check: null, conflicted: true }
    : selectedPolicy;
  const selectedOutcome = selectRuntimeOutcome(outcomes, policy, actionId);
  const outcomeConflicted =
    selectedOutcome.conflicted || outcomes.some((event) => duplicateConflicts.has(event.auditId));
  const outcomeSelection: OutcomeSelection = outcomeConflicted
    ? { conflicted: true, outcome: null }
    : selectedOutcome;
  const outcome = outcomeSelection.outcome ?? undefined;
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
    supervision: projectExecutionStepSupervision({
      actionId,
      actionName: name,
      approval,
      category,
      elementSourceMode: context.elementSourceMode,
      hasExplicitStart: hasStart,
      identityConflicted: stepEvents.some((event) => duplicateConflicts.has(event.auditId)),
      outcome: outcomeSelection.outcome,
      outcomeConflicted: outcomeSelection.conflicted,
      phase,
      policyConflicted: policy.conflicted,
      primary,
      resources,
      stepEvents,
      stepId,
      traceId: context.traceId,
    }),
  };
}

function lifecycleState(
  events: readonly NormalizedAuditEvidence[],
  steps: readonly ExecutionStepViewModel[],
  duplicateConflicts: ReadonlySet<string>,
): Pick<
  ExecutionTraceViewModel,
  "lifecycleAuditId" | "lifecycleLabel" | "lifecycleState" | "lifecycleSupervision"
> {
  const lifecycleConflict = events.some(
    (event) => duplicateConflicts.has(event.auditId) && isTraceLifecycle(event),
  );
  const lifecycle = [...events].reverse().find((event) => {
    if (duplicateConflicts.has(event.auditId)) return false;
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
    lifecycleSupervision: {
      confirmedTerminal: Boolean(lifecycle),
      completionReason: lifecycleConflict
        ? "生命周期审计记录冲突，终态未确认"
        : (lifecycle?.resultSummary ?? lifecycle?.decisionReason ?? null),
    },
  };
}

function groupKey(event: NormalizedAuditEvidence): string | null {
  if (event.actionId) return `action:${event.actionId}`;
  if (event.eventId) return `event:${event.eventId}`;
  return null;
}

export interface ExecutionProjectionContext {
  traceId: string;
  elementSourceMode: ElementSourceMode;
}

export function buildExecutionTrace(
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[],
  context: ExecutionProjectionContext,
): ExecutionTraceViewModel {
  if (!context.traceId) throw new Error("Execution projection requires a stable traceId");
  const duplicateConflicts = conflictingDuplicateAuditIds(events);
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
    buildStep(stepId, stepEvents, approvals, context, duplicateConflicts),
  );
  return { steps, ...lifecycleState(sorted, steps, duplicateConflicts) };
}

export interface RuntimeSupervisionProjectionInput extends ExecutionProjectionContext {
  events: readonly NormalizedAuditEvidence[];
  approvals: readonly ApprovalRequest[];
  dataSource: DashboardDataSourceDescriptor;
  runtime?: string | null;
  agentId?: string | null;
  approvalBasisEnabled?: boolean;
  auditWindow?: TraceAuditWindow | null;
  approvalWindow?: TraceApprovalWindow | null;
  provenance?: ProvenanceGraph | null;
  provenanceWindow?: ProvenanceWindow | null;
}

interface ApprovalBasisProjectionResult {
  approvalBasisById: Record<string, ApprovalBasisViewModel>;
  availability: Availability;
  warnings: SupervisionWarning[];
}

function windowTruncationReasons(input: RuntimeSupervisionProjectionInput): string[] {
  const reasons: string[] = [];
  if (input.auditWindow?.hasMore === true) reasons.push("TRACE_AUDIT_WINDOW_TRUNCATED");
  if (input.approvalWindow?.hasMore === true) {
    reasons.push("TRACE_APPROVAL_WINDOW_TRUNCATED");
  }
  if (
    input.provenanceWindow?.hasMore === true ||
    input.provenanceWindow?.nodesHaveMore === true ||
    input.provenanceWindow?.edgesHaveMore === true
  ) {
    reasons.push("PROVENANCE_WINDOW_TRUNCATED");
  }
  return reasons;
}

function approvalBasisAvailability(
  values: readonly ApprovalBasisViewModel[],
  expectedCount: number,
): Availability {
  if (expectedCount === 0) return "not_applicable";
  if (values.length === 0) return "unavailable";
  if (values.length !== expectedCount) return "partial";
  const recorded = values.filter((basis) => basis.completeness === "recorded").length;
  const unavailable = values.filter((basis) => basis.completeness === "unavailable").length;
  if (recorded === values.length) return "recorded";
  if (unavailable === values.length) return "unavailable";
  return "partial";
}

function enforcementEvidenceAvailability(steps: readonly ExecutionStepViewModel[]): Availability {
  const values = steps.map((step) => step.supervision.enforcement.availability);
  if (values.some((value) => value === "partial")) return "partial";
  if (values.some((value) => value === "recorded")) return "recorded";
  return "unavailable";
}

function buildApprovalBasisById(
  input: RuntimeSupervisionProjectionInput,
  execution: ExecutionTraceViewModel,
  truncationReasons: readonly string[],
): ApprovalBasisProjectionResult {
  if (input.approvalBasisEnabled === false) {
    return { approvalBasisById: {}, availability: "unavailable", warnings: [] };
  }

  const approvalsById = new Map<string, ApprovalRequest[]>();
  for (const approval of input.approvals) {
    if (!approval.id) continue;
    const matches = approvalsById.get(approval.id) ?? [];
    matches.push(approval);
    approvalsById.set(approval.id, matches);
  }
  const stepsByApprovalId = new Map<string, ExecutionStepViewModel[]>();
  for (const step of execution.steps) {
    if (!step.approvalId) continue;
    const matches = stepsByApprovalId.get(step.approvalId) ?? [];
    matches.push(step);
    stepsByApprovalId.set(step.approvalId, matches);
  }

  const expectedIds = new Set([...approvalsById.keys(), ...stepsByApprovalId.keys()]);
  const entries: Array<[string, ApprovalBasisViewModel]> = [];
  const warnings: SupervisionWarning[] = [];
  const invalidApprovalCount = input.approvals.filter((approval) => !approval.id).length;
  if (invalidApprovalCount) {
    warnings.push({
      code: "identity_conflict",
      severity: "warning",
      message: `${invalidApprovalCount} 条审批请求缺少稳定审批 ID，无法生成结构化依据。`,
      sourceRefs: [],
    });
  }
  for (const approvalId of [...expectedIds].sort()) {
    const approvals = approvalsById.get(approvalId) ?? [];
    const steps = stepsByApprovalId.get(approvalId) ?? [];
    if (approvals.length !== 1 || steps.length !== 1) {
      warnings.push({
        code: "identity_conflict",
        severity: "warning",
        message: `审批 ${approvalId} 无法唯一关联一个请求与一个执行步骤。`,
        sourceRefs: [{ kind: "approval", id: approvalId, traceId: input.traceId }],
      });
      continue;
    }
    try {
      entries.push([
        approvalId,
        projectApprovalBasis({
          approval: approvals[0]!,
          step: steps[0]!,
          traceId: input.traceId,
          windowTruncationReasons: truncationReasons,
        }),
      ]);
    } catch {
      warnings.push({
        code: "projection_failed",
        severity: "error",
        message: `审批 ${approvalId} 的结构化依据投影失败；原始审计记录仍可查看。`,
        sourceRefs: [{ kind: "approval", id: approvalId, traceId: input.traceId }],
      });
    }
  }
  const approvalBasisById = Object.fromEntries(entries);
  const projectedAvailability = approvalBasisAvailability(
    Object.values(approvalBasisById),
    expectedIds.size + invalidApprovalCount,
  );
  return {
    approvalBasisById,
    availability:
      projectedAvailability === "not_applicable" && truncationReasons.length
        ? "partial"
        : projectedAvailability,
    warnings,
  };
}

function uniqueApprovalValue(
  approvals: readonly ApprovalRequest[],
  read: (approval: ApprovalRequest) => string | null,
): string | null {
  const values = new Set(
    approvals.flatMap((approval) => {
      const value = read(approval);
      return value ? [value] : [];
    }),
  );
  return values.size === 1 ? [...values][0]! : null;
}

export function buildRuntimeSupervisionViewModel(
  input: RuntimeSupervisionProjectionInput,
): RuntimeSupervisionViewModel {
  const baseExecution = buildExecutionTrace(input.events, input.approvals, {
    elementSourceMode: input.elementSourceMode,
    traceId: input.traceId,
  });
  const ctProjection = projectCtPresentation({
    traceId: input.traceId,
    elementSourceMode: input.elementSourceMode,
    events: input.events,
    provenance: input.provenance,
  });
  const execution = {
    ...baseExecution,
    steps: applyCtContentToSteps(baseExecution.steps, ctProjection.contentByEventId),
  };
  const truncationReasons = windowTruncationReasons(input);
  const approvalBasis = buildApprovalBasisById(input, execution, truncationReasons);
  const contextManifests = projectContextManifests({
    auditWindowTruncated: input.auditWindow?.hasMore === true,
    events: input.events,
    traceId: input.traceId,
  });
  const receiptRequiredSteps = execution.steps.filter(
    (step) => step.receiptExpectation === "required",
  );
  const recordedReceiptCount = receiptRequiredSteps.filter(
    (step) => step.supervision.execution.availability === "recorded",
  ).length;
  const receiptAvailability =
    receiptRequiredSteps.length === 0
      ? "not_applicable"
      : recordedReceiptCount === receiptRequiredSteps.length
        ? "recorded"
        : recordedReceiptCount > 0 ||
            receiptRequiredSteps.some(
              (step) => step.supervision.execution.availability === "partial",
            )
          ? "partial"
          : "unavailable";
  const correlationWarnings = execution.steps
    .filter((step) => step.supervision.controlIntegrity.status === "correlation_conflict")
    .map((step) => ({
      code: "correlation_conflict" as const,
      severity: "warning" as const,
      message: `步骤 ${step.stepId} 存在无法唯一关联的监督证据。`,
      sourceRefs: step.supervision.controlIntegrity.sourceRefs,
    }));
  const unsupportedV21Warnings = execution.steps
    .filter(
      (step) =>
        step.supervision.v21Assessment.availability === "partial" &&
        step.supervision.v21Assessment.authorityVerification === "conflicted",
    )
    .map((step) => ({
      code: "unsupported_contract" as const,
      severity: "warning" as const,
      message: `步骤 ${step.stepId} 的 V2.1 影子证据不完整或与正式判定冲突。`,
      sourceRefs: step.supervision.v21Assessment.sourceRefs,
    }));
  const windowWarnings: SupervisionWarning[] = truncationReasons.length
    ? [
        {
          code: "window_truncated",
          severity: "warning",
          message: "Trace、Approval 或 Provenance 窗口已截断；当前投影不代表完整证据链。",
          sourceRefs: [],
        },
      ]
    : [];
  const warnings = [
    ...correlationWarnings,
    ...unsupportedV21Warnings,
    ...approvalBasis.warnings,
    ...contextManifests.warnings,
    ...ctProjection.presentation.warnings,
    ...windowWarnings,
  ];
  const auditAvailability: Availability =
    input.auditWindow?.hasMore === true
      ? "partial"
      : input.events.length
        ? "recorded"
        : "unavailable";
  const approvalsAvailability: Availability =
    input.approvalWindow?.hasMore === true
      ? "partial"
      : input.approvals.length
        ? "recorded"
        : "unavailable";
  const provenanceTruncated = truncationReasons.includes("PROVENANCE_WINDOW_TRUNCATED");
  const enforcementAvailability = enforcementEvidenceAvailability(execution.steps);
  return {
    schemaVersion: "runtime-supervision/0.1",
    traceId: input.traceId,
    dataSource: input.dataSource,
    temporalState: execution.lifecycleSupervision.confirmedTerminal ? "historical" : "following",
    runtime: input.runtime ?? uniqueApprovalValue(input.approvals, (approval) => approval.runtime),
    agentId: input.agentId ?? uniqueApprovalValue(input.approvals, (approval) => approval.agentId),
    execution,
    approvalBasisById: approvalBasis.approvalBasisById,
    contextManifestByEventId: contextManifests.contextManifestByEventId,
    provenancePresentation: ctProjection.presentation,
    completeness: {
      auditEvents: auditAvailability,
      approvals: approvalsAvailability,
      provenance: provenanceTruncated ? "partial" : ctProjection.provenanceAvailability,
      contextManifest: contextManifests.availability,
      runtimeReceipts: receiptAvailability,
      truncatedReasons: truncationReasons,
    },
    capabilities: {
      facts: ctProjection.factAvailability,
      contextManifest: contextManifests.availability,
      approvalBasis: approvalBasis.availability,
      enforcementEvidence: enforcementAvailability,
      runtimeReceipts: receiptAvailability,
      traceCompare: "unavailable",
    },
    warnings,
  };
}

/**
 * UI boundary for the derived execution graph. A malformed projection must not
 * prevent EvidenceDetailPage from rendering its independent raw Audit model.
 */
export function buildRuntimeSupervisionViewModelSafely(
  input: RuntimeSupervisionProjectionInput,
): RuntimeSupervisionViewModel {
  try {
    return buildRuntimeSupervisionViewModel(input);
  } catch {
    return {
      schemaVersion: "runtime-supervision/0.1",
      traceId: input.traceId,
      dataSource: input.dataSource,
      temporalState: "following",
      runtime: input.runtime ?? null,
      agentId: input.agentId ?? null,
      execution: {
        steps: [],
        lifecycleState: "observing",
        lifecycleLabel: "实时观察中",
        lifecycleAuditId: null,
        lifecycleSupervision: { confirmedTerminal: false, completionReason: null },
      },
      approvalBasisById: {},
      contextManifestByEventId: {},
      provenancePresentation: { contractKind: "legacy", edges: [], nodes: [], warnings: [] },
      completeness: {
        auditEvents: "unavailable",
        approvals: "unavailable",
        provenance: "unavailable",
        contextManifest: "unavailable",
        runtimeReceipts: "unavailable",
        truncatedReasons: [],
      },
      capabilities: {
        facts: "unavailable",
        contextManifest: "unavailable",
        approvalBasis: "unavailable",
        enforcementEvidence: "unavailable",
        runtimeReceipts: "unavailable",
        traceCompare: "unavailable",
      },
      warnings: [
        {
          code: "projection_failed",
          severity: "error",
          message: "运行监督投影失败；原始审计记录仍可查看。",
          sourceRefs: [],
        },
      ],
    };
  }
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
