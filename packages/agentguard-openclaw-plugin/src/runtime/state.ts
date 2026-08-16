import { redactUnknownCredentials, stringPreview } from "../security.js";
import type {
  DerivedResource,
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
  RuntimeEnforcementEvidence,
} from "../types.js";

export type ReceiptEvaluation = Omit<
  GuardEvaluationResponse,
  "enforcement_binding"
>;

export type SessionState = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  provider?: string;
  model?: string;
  runId?: string;
  sessionId?: string;
  /** Trusted host/session task locator; never sourced from tool arguments. */
  taskId?: string;
  toolRuntimePolicies?: Record<string, JsonObject>;
};

export type TaskExtractionOptions = {
  promptFallback?: boolean;
  contentFallback?: boolean;
};

/** RTE-03（契约 03 §3.1）：before_tool_call 显式 gate 状态机。 */
export type EnforcementGateState =
  | "evaluating"
  | "allowed"
  | "approval_pending"
  | "approval_released"
  | "blocked"
  | "timed_out"
  | "binding_failed";

/** RTE-03（契约 03 §3.2）：correlation 身份来源；local_fallback 不具备 C2 资格。 */
export type ToolCallCorrelationSource =
  | "native_tool_call_id"
  | "local_fallback";

export type ToolCallState = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  toolName: string;
  toolKind?: string | null;
  toolInputKind?: string | null;
  toolCallId: string;
  runId?: string | null;
  derivedResources: DerivedResource[];
  derivedPaths: string[];
  toolParams: JsonObject;

  // RTE P0（契约 03 §3.1）
  correlationSource: ToolCallCorrelationSource;
  guardEventId: string;
  traceId: string;
  policyAuditId?: string;
  decisionId?: string;
  decision?: "allow" | "ask" | "deny";
  gateState: EnforcementGateState;
  approvalId?: string | null;
  approvalStatus?: "pending" | "allowed" | "denied" | "expired" | "unknown";
  leaseId?: string;
  consumptionId?: string;
  enforcement?: RuntimeEnforcementEvidence;
  terminalStatus?: "executed" | "failed";
  terminalObservedAt?: string;
  resultPersistObserved?: boolean;
  /** 回执已入 durable spool（或被确定性跳过）后置 true，驱动可驱逐判定（§8.2）。 */
  receiptQueued?: boolean;
  createdAtMs: number;
  updatedAtMs: number;
  /** terminal 回执构造所需的完整关联，避免 after hook 重查（§5.1）。 */
  guardEvent?: GuardEvent;
  evaluation?: ReceiptEvaluation;
  /** A native ID collision makes all later terminal observations ambiguous. */
  correlationCompromised?: boolean;
};

/** RTE-03 §8：active correlation state 硬容量；耗尽时不淘汰受保护状态。 */
export const TOOL_CALL_STATE_ACTIVE_LIMIT = 500;
/** §8.3：execution_completed 后保留 grace TTL，供 tool_result_persist 补充标记。 */
export const TERMINAL_COMPLETION_GRACE_MS = 30_000;

export type EvidenceDegradationReason =
  | "after_tool_call_missing_action_id"
  | "after_tool_call_correlation_missing"
  | "after_tool_call_policy_linkage_missing"
  | "after_tool_call_local_fallback_correlation"
  | "tool_call_state_capacity_exhausted"
  | "tool_call_state_duplicate_active_id"
  | "strong_binding_operational_degradation";

const DEGRADATION_COUNT_CAP = 10_000;

/** 有界 evidence degradation 计数（§8.5），由 heartbeat 能力声明暴露。 */
export class EvidenceDegradationTracker {
  private total = 0;
  private readonly byReason = new Map<EvidenceDegradationReason, number>();

  record(reason: EvidenceDegradationReason): void {
    if (this.total < DEGRADATION_COUNT_CAP) {
      this.total += 1;
    }
    const current = this.byReason.get(reason) ?? 0;
    if (current < DEGRADATION_COUNT_CAP) {
      this.byReason.set(reason, current + 1);
    }
  }

  snapshot(): { total: number; byReason: Record<string, number> } {
    return {
      total: this.total,
      byReason: Object.fromEntries(this.byReason.entries()),
    };
  }
}

/** §8.4：这些状态不得因普通容量压力被静默淘汰。 */
export function isToolCallStateProtected(state: ToolCallState): boolean {
  if (
    state.gateState === "evaluating" ||
    state.gateState === "approval_pending"
  ) {
    return true;
  }
  return (
    (state.gateState === "allowed" ||
      state.gateState === "approval_released") &&
    state.terminalStatus === undefined
  );
}

/** §8.2/§8.3：生命周期驱逐判定；受保护状态永远 false。 */
export function canEvictToolCallState(
  state: ToolCallState,
  nowMs: number,
): boolean {
  if (isToolCallStateProtected(state)) {
    return false;
  }
  if (
    state.gateState === "blocked" ||
    state.gateState === "timed_out" ||
    state.gateState === "binding_failed"
  ) {
    return state.receiptQueued === true;
  }
  if (state.terminalStatus === "failed") {
    return state.receiptQueued === true;
  }
  if (state.terminalStatus === "executed") {
    return nowMs - state.updatedAtMs >= TERMINAL_COMPLETION_GRACE_MS;
  }
  return false;
}

/** 更新已关联状态并刷新时间戳；不存在时返回 undefined。 */
export function patchToolCallState(
  cache: Map<string, ToolCallState>,
  callId: string,
  patch: Partial<ToolCallState>,
  nowMs: number = Date.now(),
): ToolCallState | undefined {
  const state = cache.get(callId);
  if (!state) {
    return undefined;
  }
  Object.assign(state, patch, { updatedAtMs: nowMs });
  cache.delete(callId);
  cache.set(callId, state);
  return state;
}

export function rememberSessionState(
  cache: Map<string, SessionState>,
  event: unknown,
  context: unknown,
  options: TaskExtractionOptions = {},
): void {
  const keys = cacheKeys(event, context);
  if (keys.length === 0) {
    return;
  }
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const existing = cacheState(cache, event, context) ?? {};
  const explicitUserTask = extractExplicitUserTask(event, context);
  const fallbackUserTask = extractUserTask(event, context, options);
  const sourceTrust =
    stringMaybe(eventRecord.sourceTrust ?? eventRecord.source_trust) ??
    stringMaybe(contextRecord.sourceTrust ?? contextRecord.source_trust) ??
    existing.sourceTrust;
  const sourceType =
    stringMaybe(eventRecord.sourceType ?? eventRecord.source_type) ??
    stringMaybe(contextRecord.sourceType ?? contextRecord.source_type) ??
    existing.sourceType;
  const trustedRuntimePolicy = sourceTrust === "trusted";
  const extractedRuntimePolicies = trustedRuntimePolicy
    ? extractToolRuntimePolicies(event, context)
    : {};
  const toolRuntimePolicies = mergeToolRuntimePolicies(
    existing.toolRuntimePolicies,
    extractedRuntimePolicies,
  );
  const next: SessionState = {
    ...existing,
    userTask: explicitUserTask ?? existing.userTask ?? fallbackUserTask,
    sourceTrust,
    sourceType,
    provider:
      stringMaybe(eventRecord.provider) ??
      stringMaybe(contextRecord.provider) ??
      existing.provider,
    model:
      stringMaybe(eventRecord.model) ??
      stringMaybe(contextRecord.model) ??
      existing.model,
    runId:
      stringMaybe(eventRecord.runId) ??
      stringMaybe(contextRecord.runId) ??
      existing.runId,
    sessionId:
      stringMaybe(eventRecord.sessionId) ??
      stringMaybe(contextRecord.sessionId) ??
      existing.sessionId,
    taskId:
      stringMaybe(contextRecord.taskId ?? contextRecord.task_id) ??
      existing.taskId,
    toolRuntimePolicies:
      Object.keys(toolRuntimePolicies).length > 0
        ? toolRuntimePolicies
        : existing.toolRuntimePolicies,
  };
  for (const key of keys) {
    setLimited(cache, key, next);
  }
}

export function extractToolRuntimePolicies(
  ...values: unknown[]
): Record<string, JsonObject> {
  const policies: Record<string, JsonObject> = {};
  for (const value of values) {
    collectToolRuntimePolicies(value, policies);
  }
  return policies;
}

export function collectToolRuntimePolicies(
  value: unknown,
  policies: Record<string, JsonObject>,
  depth = 0,
): void {
  if (depth > 6 || value === null || value === undefined) {
    return;
  }
  if (typeof value === "string") {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectToolRuntimePolicies(item, policies, depth + 1);
    }
    return;
  }

  const record = asRecord(value);
  collectToolDescriptorPolicy(record, policies);
  for (const key of [
    "tools",
    "availableTools",
    "available_tools",
    "toolManifest",
    "tool_manifest",
    "toolDefinitions",
    "tool_definitions",
    "toolDescriptors",
    "tool_descriptors",
    "toolPlan",
    "tool_plan",
  ]) {
    collectToolRuntimePolicies(record[key], policies, depth + 1);
  }
  collectToolRuntimePolicies(record.messages, policies, depth + 1);
}

export function collectToolDescriptorPolicy(
  value: unknown,
  policies: Record<string, JsonObject>,
): void {
  const record = asRecord(value);
  const toolName = stringMaybe(
    record.name ?? record.toolName ?? record.tool_name,
  );
  const runtimePolicy = normalizedRuntimePolicy(
    record.runtime_policy ?? record.runtimePolicy,
  );
  if (toolName && runtimePolicy) {
    policies[toolName] = {
      ...(policies[toolName] ?? {}),
      ...runtimePolicy,
    };
  }
}

export function normalizedRuntimePolicy(
  value: unknown,
): JsonObject | undefined {
  const record = asRecord(value);
  const policy: JsonObject = {};
  for (const key of [
    "browser_expected",
    "tool_manifest_scoped",
    "declared_tools",
    "mcp_boundary_required",
  ]) {
    const field = record[key];
    if (Array.isArray(field)) {
      const strings = uniqueStrings(field.map((item) => stringMaybe(item)));
      if (strings.length > 0) {
        policy[key] = strings;
      }
    } else if (
      typeof field === "boolean" ||
      typeof field === "string" ||
      typeof field === "number"
    ) {
      policy[key] = field;
    }
  }
  return Object.keys(policy).length > 0 ? policy : undefined;
}

export function mergeToolRuntimePolicies(
  existing: Record<string, JsonObject> | undefined,
  next: Record<string, JsonObject>,
): Record<string, JsonObject> {
  const merged: Record<string, JsonObject> = { ...(existing ?? {}) };
  for (const [toolName, runtimePolicy] of Object.entries(next)) {
    merged[toolName] = {
      ...(merged[toolName] ?? {}),
      ...runtimePolicy,
    };
  }
  return merged;
}

export function withCachedRuntimeFields<T extends object, C extends object>(
  cache: Map<string, SessionState>,
  event: T,
  context: C,
): { event: T & JsonObject; context: C & JsonObject } {
  const state = cacheState(cache, event, context);
  if (!state) {
    return {
      event: event as T & JsonObject,
      context: context as C & JsonObject,
    };
  }
  return {
    event: mergeRuntimeFields(event, state) as T & JsonObject,
    context: mergeRuntimeFields(context, state) as C & JsonObject,
  };
}

export function withCachedToolContext<T extends object, C extends object>(
  sessionCache: Map<string, SessionState>,
  toolCache: Map<string, ToolCallState>,
  event: T,
  context: C,
): { event: T & JsonObject; context: C & JsonObject } {
  const cached = withCachedRuntimeFields(sessionCache, event, context);
  const eventRecord = { ...asRecord(cached.event) };
  const contextRecord = { ...asRecord(cached.context) };
  const callId =
    stringMaybe(eventRecord.toolCallId) ??
    stringMaybe(contextRecord.toolCallId);
  const toolState = callId ? toolCache.get(callId) : undefined;
  if (!toolState) {
    return cached;
  }
  eventRecord.toolName =
    stringMaybe(eventRecord.toolName) ?? toolState.toolName;
  eventRecord.toolKind =
    stringMaybe(eventRecord.toolKind) ?? toolState.toolKind;
  eventRecord.toolInputKind =
    stringMaybe(eventRecord.toolInputKind) ?? toolState.toolInputKind;
  eventRecord.toolCallId =
    stringMaybe(eventRecord.toolCallId) ?? toolState.toolCallId;
  eventRecord.runId = stringMaybe(eventRecord.runId) ?? toolState.runId;
  eventRecord.userTask =
    stringMaybe(eventRecord.userTask) ?? toolState.userTask;
  eventRecord.sourceTrust =
    stringMaybe(eventRecord.sourceTrust) ?? toolState.sourceTrust;
  eventRecord.sourceType =
    stringMaybe(eventRecord.sourceType) ?? toolState.sourceType;
  if (!Array.isArray(eventRecord.derivedResources)) {
    eventRecord.derivedResources = toolState.derivedResources;
  }
  if (!Array.isArray(eventRecord.derivedPaths)) {
    eventRecord.derivedPaths = toolState.derivedPaths;
  }
  contextRecord.toolName =
    stringMaybe(contextRecord.toolName) ?? toolState.toolName;
  contextRecord.toolKind =
    stringMaybe(contextRecord.toolKind) ?? toolState.toolKind;
  contextRecord.toolInputKind =
    stringMaybe(contextRecord.toolInputKind) ?? toolState.toolInputKind;
  contextRecord.toolCallId =
    stringMaybe(contextRecord.toolCallId) ?? toolState.toolCallId;
  contextRecord.runId = stringMaybe(contextRecord.runId) ?? toolState.runId;
  contextRecord.userTask =
    stringMaybe(contextRecord.userTask) ?? toolState.userTask;
  contextRecord.sourceTrust =
    stringMaybe(contextRecord.sourceTrust) ?? toolState.sourceTrust;
  contextRecord.sourceType =
    stringMaybe(contextRecord.sourceType) ?? toolState.sourceType;
  contextRecord.derivedResources = Array.isArray(contextRecord.derivedResources)
    ? contextRecord.derivedResources
    : toolState.derivedResources;
  contextRecord.derivedPaths = Array.isArray(contextRecord.derivedPaths)
    ? contextRecord.derivedPaths
    : toolState.derivedPaths;
  contextRecord.toolParams = toolState.toolParams;
  return {
    event: eventRecord as T & JsonObject,
    context: contextRecord as C & JsonObject,
  };
}

export type RememberToolCallStateOptions = {
  /** before hook 观察到的原生 toolCallId；缺失时 correlation 降级为 local_fallback。 */
  nativeToolCallId?: string | null;
  tracker?: EvidenceDegradationTracker;
  nowMs?: number;
  limit?: number;
  onRejected?: (
    reason: "capacity_exhausted" | "duplicate_active_id",
  ) => void;
};

export function rememberToolCallState(
  cache: Map<string, ToolCallState>,
  event: GuardEvent,
  options: RememberToolCallStateOptions = {},
): ToolCallState | undefined {
  if (
    event.event_type !== "tool_call_proposed" ||
    !("tool" in event.payload) ||
    !("arguments" in event.payload)
  ) {
    return undefined;
  }
  const payload = event.payload;
  const callId = payload.tool.call_id;
  const nativeToolCallId =
    typeof options.nativeToolCallId === "string" &&
    options.nativeToolCallId.length > 0
      ? options.nativeToolCallId
      : undefined;
  const correlationSource: ToolCallCorrelationSource =
    nativeToolCallId && nativeToolCallId === callId
      ? "native_tool_call_id"
      : "local_fallback";
  const nowMs = options.nowMs ?? Date.now();
  const limit = options.limit ?? TOOL_CALL_STATE_ACTIVE_LIMIT;
  const existing = cache.get(callId);
  if (existing) {
    if (!canEvictToolCallState(existing, nowMs)) {
      // Preserve the original attempt and its approved parameters. Once a
      // native identity collides, later after-hook events cannot be assigned
      // safely to either attempt, so terminal derivation must stay disabled.
      existing.correlationCompromised = true;
      options.tracker?.record("tool_call_state_duplicate_active_id");
      options.onRejected?.("duplicate_active_id");
      return undefined;
    }
    cache.delete(callId);
  }
  if (!cache.has(callId) && cache.size >= limit) {
    // §8.4/§8.5：容量耗尽时先回收可驱逐状态；回收失败则不静默淘汰
    // 受保护状态——本次调用放弃 C2 correlation，C1 enforcement 照常继续。
    let reclaimed = false;
    for (const [key, state] of cache) {
      if (canEvictToolCallState(state, nowMs)) {
        cache.delete(key);
        reclaimed = true;
        break;
      }
    }
    if (!reclaimed) {
      options.tracker?.record("tool_call_state_capacity_exhausted");
      options.onRejected?.("capacity_exhausted");
      return undefined;
    }
  }
  const state: ToolCallState = {
    userTask: event.security_context.user_task,
    sourceTrust: event.security_context.source_trust,
    sourceType: event.security_context.source_type,
    toolName: payload.tool.name,
    toolKind: payload.tool.kind ?? null,
    toolInputKind: payload.tool.input_kind ?? null,
    toolCallId: callId,
    runId: event.security_context.run_id,
    derivedResources: payload.derived_resources,
    derivedPaths: event.security_context.derived_paths,
    toolParams: payload.arguments,
    correlationSource,
    guardEventId: event.event_id,
    traceId: event.trace_id,
    gateState: "evaluating",
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
  cache.set(callId, state);
  return state;
}

/** Strip transport-only strong binding data before correlation state storage. */
export function receiptEvaluation(
  evaluation: GuardEvaluationResponse,
): ReceiptEvaluation {
  return {
    decision: evaluation.decision,
    approval: evaluation.approval,
    policy_audit_id: evaluation.policy_audit_id,
  };
}

export function mergeRuntimeFields(
  value: object,
  state: SessionState,
): JsonObject {
  const record = { ...asRecord(value) };
  record.userTask = stringMaybe(record.userTask) ?? state.userTask;
  record.sourceTrust = stringMaybe(record.sourceTrust) ?? state.sourceTrust;
  record.sourceType = stringMaybe(record.sourceType) ?? state.sourceType;
  record.provider = stringMaybe(record.provider) ?? state.provider;
  record.model = stringMaybe(record.model) ?? state.model;
  record.runId = stringMaybe(record.runId) ?? state.runId;
  record.sessionId = stringMaybe(record.sessionId) ?? state.sessionId;
  record.taskId = stringMaybe(record.taskId ?? record.task_id) ?? state.taskId;
  const toolName = stringMaybe(record.toolName);
  const runtimePolicy = toolName
    ? state.toolRuntimePolicies?.[toolName]
    : undefined;
  if (
    runtimePolicy &&
    Object.keys(asRecord(record.runtimePolicy ?? record.runtime_policy))
      .length === 0
  ) {
    record.runtimePolicy = runtimePolicy;
  }
  return record;
}

export function cacheState(
  cache: Map<string, SessionState>,
  event: unknown,
  context: unknown,
): SessionState | undefined {
  const states = cacheKeys(event, context)
    .map((key) => cache.get(key))
    .filter((state): state is SessionState => state !== undefined);
  if (states.length === 0) {
    return undefined;
  }
  return Object.assign({}, ...states);
}

export function cacheKeys(event: unknown, context: unknown): string[] {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  return uniqueStrings([
    stringMaybe(eventRecord.sessionKey),
    stringMaybe(contextRecord.sessionKey),
    stringMaybe(eventRecord.runId),
    stringMaybe(contextRecord.runId),
    stringMaybe(eventRecord.sessionId),
    stringMaybe(contextRecord.sessionId),
    stringMaybe(eventRecord.traceId),
    stringMaybe(contextRecord.traceId),
  ]);
}

export function extractExplicitUserTask(
  ...values: unknown[]
): string | undefined {
  for (const value of values) {
    const explicit = stringMaybe(asRecord(value).userTask);
    if (explicit) {
      return sanitizeTask(explicit);
    }
  }
  return undefined;
}

export function extractUserTask(
  event: unknown,
  context: unknown,
  options: TaskExtractionOptions = {},
): string | undefined {
  const values = [event, context];
  const explicit = extractExplicitUserTask(...values);
  if (explicit) {
    return explicit;
  }
  for (const value of values) {
    const record = asRecord(value);
    const fromMessages =
      userTaskFromMessages(record.messages) ??
      userTaskFromMessages(asRecord(record.prompt).messages);
    if (fromMessages) {
      return sanitizeTask(fromMessages);
    }
  }
  if (options.promptFallback) {
    for (const value of values) {
      const record = asRecord(value);
      const task = stringMaybe(record.prompt) ?? stringMaybe(record.input);
      if (task) {
        return sanitizeTask(task);
      }
    }
  }
  if (options.contentFallback) {
    for (const value of values) {
      const record = asRecord(value);
      const task =
        stringMaybe(record.content) ??
        stringMaybe(record.text) ??
        stringMaybe(record.body) ??
        stringMaybe(record.message);
      if (task) {
        return sanitizeTask(task);
      }
    }
  }
  return undefined;
}

export function userTaskFromMessages(value: unknown): string | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  for (const item of [...value].reverse()) {
    const record = asRecord(item);
    const role = stringMaybe(record.role)?.toLowerCase();
    if (role && role !== "user") {
      continue;
    }
    const content = stringMaybe(record.content) ?? stringMaybe(record.text);
    if (content) {
      return content;
    }
  }
  return undefined;
}

export function sanitizeTask(value: string): string {
  const redacted = redactUnknownCredentials(value).value;
  const task =
    typeof redacted === "string" ? redacted : stringPreview(redacted);
  return task.length > 1000 ? `${task.slice(0, 1000)}...` : task;
}

export function setLimited<T>(
  cache: Map<string, T>,
  key: string,
  value: T,
  limit = 200,
): void {
  if (!cache.has(key) && cache.size >= limit) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) {
      cache.delete(oldest);
    }
  }
  cache.set(key, value);
}

export function uniqueStrings(values: Array<string | undefined>): string[] {
  return [
    ...new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.length > 0,
      ),
    ),
  ];
}

export function asRecord(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function stringMaybe(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function firstNonEmptyString(
  ...values: Array<string | undefined>
): string | undefined {
  for (const value of values) {
    if (value) {
      return value;
    }
  }
  return undefined;
}
