import type {
  AuditEvent,
  ConfigAuditEvent,
  ConfigAuditFinding,
  DerivedResource,
  GuardEvent,
  JsonObject,
} from "./types.js";
import {
  containsSensitiveCredentialText,
  isExecLikeToolIdentity,
  redactSensitiveCredentials,
} from "./security.js";

type RuntimeSecurityFields = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  derivedResources?: readonly DerivedResourceInput[];
  derivedPaths?: readonly string[];
  [key: string]: unknown;
};

type RuntimeSecurityOptions = {
  promptFallback?: boolean;
  contentFallback?: boolean;
};

type DerivedResourceInput = Partial<DerivedResource> & {
  resourceType?: unknown;
  dataClassification?: unknown;
};

type BeforeToolCallEventInput = RuntimeSecurityFields & {
  toolName: string;
  params?: JsonObject;
  toolKind?: string;
  toolInputKind?: string;
  runId?: string;
  toolCallId?: string;
};

type ToolHookContextInput = RuntimeSecurityFields & {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  channelId?: string;
  provider?: string;
  model?: string;
  toolName?: string;
  toolKind?: string;
  toolInputKind?: string;
  toolCallId?: string;
  toolParams?: JsonObject;
};

type MessageSendingEventInput = RuntimeSecurityFields & {
  to: string;
  content: string;
  replyToId?: string | number;
  threadId?: string | number;
  metadata?: JsonObject;
};

type MessageHookContextInput = RuntimeSecurityFields & {
  channelId?: string;
  accountId?: string;
  conversationId?: string;
  sessionKey?: string;
  runId?: string;
  messageId?: string;
  senderId?: string;
};

type ToolResultPersistEventInput = RuntimeSecurityFields & {
  toolName?: string;
  toolKind?: string;
  toolInputKind?: string;
  toolCallId?: string;
  runId?: string;
  result?: unknown;
  message?: unknown;
  willEnterContext?: boolean;
  willPersist?: boolean;
};

type PromptBuildEventInput = RuntimeSecurityFields & {
  prompt?: unknown;
  messages?: unknown;
  context?: unknown;
  sanitized?: boolean;
  willEnterContext?: boolean;
};

type ModelHookEventInput = RuntimeSecurityFields & {
  prompt?: unknown;
  input?: unknown;
  output?: unknown;
  response?: unknown;
  content?: unknown;
  messages?: unknown;
  assistantTexts?: unknown;
  lastAssistant?: unknown;
  provider?: string;
  model?: string;
  sanitized?: boolean;
  toolPlan?: unknown;
  toolCalls?: unknown;
};

type BeforeInstallEventInput = RuntimeSecurityFields & {
  request?: JsonObject & {
    targetType?: string;
    targetId?: string;
    manifest?: unknown;
    config?: unknown;
  };
  targetType?: string;
  targetId?: string;
  runId?: string;
  agentId?: string;
  manifest?: unknown;
  config?: unknown;
};

type RuntimeObservationContextInput = {
  runId?: string;
  sessionKey?: string;
  sessionId?: string;
  agentId?: string;
  channelId?: string;
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  model?: string;
  provider?: string;
  derivedResources?: readonly DerivedResourceInput[];
  derivedPaths?: readonly string[];
  [key: string]: unknown;
};

const PREVIEW_LIMIT = 2000;
const SENSITIVE_KEY_PATTERN = /token|secret|password|authorization|credential/i;

export function buildToolCallGuardEvent(
  event: BeforeToolCallEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = event.runId ?? context.runId ?? null;
  const callId = event.toolCallId ?? context.toolCallId ?? createLocalId("call");
  const security = runtimeSecurityFields(event, context);
  const derivedResources = derivedResourcesForTool(event, context);
  const derivedPaths = derivedPathTargets(event, context, derivedResources);

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type: "tool_call_proposed",
    runtime: "openclaw",
    trace_id: firstNonEmpty(runId, callId),
    case_id: null,
    attack_type: null,
    is_malicious: null,
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      user_task: security.userTask,
      source_type: security.sourceType,
      source_trust: security.sourceTrust,
      channel: context.channelId ?? null,
      sender_id: null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: "before_tool_call",
      model_intent: null,
      context_sources: [],
      derived_paths: derivedPaths,
      metadata: {
        session_key: context.sessionKey ?? null,
        tool_kind: event.toolKind ?? context.toolKind ?? null,
        tool_input_kind: event.toolInputKind ?? context.toolInputKind ?? null,
      },
    },
    payload: {
      tool: {
        name: event.toolName,
        category: "tool",
        kind: event.toolKind ?? context.toolKind ?? event.toolName,
        input_kind: event.toolInputKind ?? context.toolInputKind ?? null,
        call_id: callId,
      },
      arguments: event.params ?? {},
      derived_resources: derivedResources,
    },
    metadata: {
      openclaw_hook: "before_tool_call",
      session_key: context.sessionKey ?? null,
    },
  };
}

export function buildMessageSendGuardEvent(
  event: MessageSendingEventInput,
  context: MessageHookContextInput = {},
): GuardEvent {
  const traceId = firstNonEmpty(context.runId, context.sessionKey, context.messageId, String(event.threadId ?? ""));
  const security = runtimeSecurityFields(event, context);
  const derivedResources = derivedResourcesForMessage(event, context);

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type: "message_send_proposed",
    runtime: "openclaw",
    trace_id: traceId,
    case_id: null,
    attack_type: null,
    is_malicious: null,
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      user_task: security.userTask,
      source_type: security.sourceType,
      source_trust: security.sourceTrust,
      channel: context.channelId ?? "unknown",
      sender_id: context.senderId ?? null,
      session_id: null,
      run_id: context.runId ?? null,
      agent_id: "main",
      current_step: "message_sending",
      model_intent: null,
      context_sources: [],
      derived_paths: derivedPathTargets(event, context, derivedResources),
      metadata: {
        account_id: context.accountId ?? null,
        conversation_id: context.conversationId ?? null,
        session_key: context.sessionKey ?? null,
        message_id: context.messageId ?? null,
        thread_id: event.threadId ?? null,
        reply_to_id: event.replyToId ?? null,
      },
    },
    payload: {
      channel: context.channelId ?? "unknown",
      recipient: event.to,
      content_preview: truncate(event.content, PREVIEW_LIMIT),
      contains_sensitive_data: false,
      sanitized: false,
      derived_resources: derivedResources,
    },
    metadata: {
      openclaw_hook: "message_sending",
      message_metadata: event.metadata ?? {},
    },
  };
}

export function buildToolResultGuardEvent(
  event: ToolResultPersistEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = event.runId ?? context.runId ?? null;
  const callId = event.toolCallId ?? context.toolCallId ?? createLocalId("call");
  const toolName = event.toolName ?? context.toolName ?? "unknown";
  const rawResultPreview = resultContentPreview(event.result ?? event.message);
  const resultPreview = truncate(rawResultPreview, PREVIEW_LIMIT);
  const security = runtimeSecurityFields(event, context);
  const derivedResources = derivedResourcesForToolResult(event, context, toolName);
  const derivedPaths = derivedPathTargets(event, context, derivedResources);

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type: "tool_result_produced",
    runtime: "openclaw",
    trace_id: firstNonEmpty(runId, callId),
    case_id: null,
    attack_type: null,
    is_malicious: null,
    timestamp: new Date().toISOString(),
    pre_execution: false,
    security_context: {
      user_task: security.userTask,
      source_type: security.sourceType,
      source_trust: security.sourceTrust,
      channel: context.channelId ?? null,
      sender_id: null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: "tool_result_persist",
      model_intent: null,
      context_sources: [],
      derived_paths: derivedPaths,
      metadata: {
        session_key: context.sessionKey ?? null,
      },
    },
    payload: {
      tool: {
        name: toolName,
        category: "tool",
        kind: event.toolKind ?? context.toolKind ?? toolName,
        input_kind: event.toolInputKind ?? context.toolInputKind ?? null,
        call_id: callId,
      },
      result: {
        content_preview: resultPreview,
        content_type: resultContentType(event.result ?? event.message),
        size_bytes: byteLength(rawResultPreview),
      },
      will_enter_context: event.willEnterContext ?? true,
      will_persist: event.willPersist ?? true,
      sanitized: false,
      contains_sensitive_data: containsSensitiveText(resultPreview),
      contains_instruction_like_text: containsInstructionLikeText(resultPreview),
      derived_resources: derivedResources,
    },
    metadata: {
      openclaw_hook: "tool_result_persist",
      session_key: context.sessionKey ?? null,
    },
  };
}

export function buildContextGuardEvent(
  hookName: string,
  event: PromptBuildEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = context.runId ?? null;
  const security = runtimeSecurityFields(event, context, { promptFallback: true });
  const sourceSummaries = contextSourceSummaries(event);
  const sources = sourceSummaries.length > 0 ? sourceSummaries : [stringPreview(event.prompt ?? event.context)];

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type: "context_assembled",
    runtime: "openclaw",
    trace_id: firstNonEmpty(runId, context.sessionKey, context.sessionId),
    case_id: null,
    attack_type: null,
    is_malicious: null,
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      user_task: security.userTask,
      source_type: security.sourceType,
      source_trust: security.sourceTrust,
      channel: context.channelId ?? null,
      sender_id: null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: hookName,
      model_intent: null,
      context_sources: [],
      derived_paths: uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []),
      metadata: {
        session_key: context.sessionKey ?? null,
      },
    },
    payload: {
      sources: sources.map((summary, index) => ({
        source_id: `openclaw:${hookName}:${index + 1}`,
        source_type: security.sourceType,
        source_trust: security.sourceTrust,
        summary: truncate(summary, PREVIEW_LIMIT),
        contains_instruction_like_text: containsInstructionLikeText(summary),
        contains_sensitive_data: containsSensitiveText(summary),
      })),
      will_enter_context: event.willEnterContext ?? true,
      sanitized: event.sanitized === true,
    },
    metadata: {
      openclaw_hook: hookName,
      session_key: context.sessionKey ?? null,
    },
  };
}

export function buildModelGuardEvent(
  hookName: "llm_input" | "llm_output",
  event: ModelHookEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = context.runId ?? null;
  const security = runtimeSecurityFields(event, context, { promptFallback: hookName === "llm_input" });
  const phase = hookName === "llm_input" ? "input" : "output";
  const content = modelContentPreview(hookName, event);
  const provider = event.provider ?? context.provider ?? null;
  const model = event.model ?? context.model ?? null;

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type: phase === "input" ? "model_input_prepared" : "model_output_produced",
    runtime: "openclaw",
    trace_id: firstNonEmpty(runId, context.sessionKey, context.sessionId),
    case_id: null,
    attack_type: null,
    is_malicious: null,
    timestamp: new Date().toISOString(),
    pre_execution: phase === "input",
    security_context: {
      user_task: security.userTask,
      source_type: security.sourceType,
      source_trust: security.sourceTrust,
      channel: context.channelId ?? null,
      sender_id: null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: hookName,
      model_intent: null,
      context_sources: [],
      derived_paths: uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []),
      metadata: {
        session_key: context.sessionKey ?? null,
      },
    },
    payload: {
      phase,
      content_preview: truncate(content, PREVIEW_LIMIT),
      provider,
      model,
      contains_instruction_like_text: containsInstructionLikeText(content),
      contains_sensitive_data: containsSensitiveText(content),
      sanitized: event.sanitized === true,
      tool_plan: modelToolPlan(event),
    },
    metadata: {
      openclaw_hook: hookName,
      session_key: context.sessionKey ?? null,
    },
  };
}

export function buildBeforeInstallConfigAuditEvent(
  event: BeforeInstallEventInput,
  context: RuntimeObservationContextInput = {},
): ConfigAuditEvent {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const request = asRecord(event.request);
  const targetType = stringValue(request.targetType ?? event.targetType, "plugin");
  const targetId = stringValue(request.targetId ?? event.targetId, "unknown");
  const manifest = asRecord(request.manifest ?? event.manifest);
  const config = asRecord(request.config ?? event.config ?? manifest.config);
  const hooks = asRecord(config.hooks ?? manifest.hooks);
  const permissions = asRecord(config.permissions ?? manifest.permissions);
  const findings = buildInstallFindings({ targetId, hooks, permissions });
  const security = runtimeSecurityFields(eventRecord, contextRecord);
  const runId = firstNonEmpty(
    stringMaybe(contextRecord.runId),
    stringMaybe(eventRecord.runId),
    stringMaybe(request.runId),
    targetId,
  );

  return {
    runtime: "openclaw",
    target_type: targetType,
    target_id: targetId,
    action: "before_install",
    findings,
    metadata: {
      manifest_id: stringValue(manifest.id, targetId),
      trace_id: runId,
      ...definedMetadata({
        user_task: security.userTask,
        source_type: security.sourceType,
        source_trust: security.sourceTrust,
        run_id: runId,
        agent_id: stringMaybe(eventRecord.agentId) ?? stringMaybe(contextRecord.agentId),
        current_step: "before_install",
      }),
    },
  };
}

export function buildRuntimeObservationAuditEvent(
  hookName: string,
  event: unknown = {},
  context: RuntimeObservationContextInput = {},
): AuditEvent {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const security = runtimeSecurityFields(eventRecord, contextRecord);
  const resourceTargets = runtimeObservationResourceTargets(hookName, eventRecord, contextRecord);
  const traceId = firstNonEmpty(
    stringMaybe(context.runId),
    stringMaybe(eventRecord.runId),
    stringMaybe(context.sessionKey),
    stringMaybe(eventRecord.sessionKey),
    stringMaybe(context.sessionId),
    stringMaybe(eventRecord.sessionId),
    stringMaybe(eventRecord.id),
  );

  return {
    schema_version: "0.3",
    trace_id: traceId,
    runtime: "openclaw",
    stage: hookName,
    event_type: "runtime_observation",
    summary: `OpenClaw ${hookName} observation`,
    decision: "allow",
    risk_score: 0,
    severity: "low",
    blocked: false,
    reason: "Observation only.",
    resource_targets: resourceTargets,
    rule_hits: [],
    links: {},
    metadata: {
      openclaw_hook: hookName,
      ...definedMetadata({
        user_task: security.userTask,
        source_trust: security.sourceTrust,
        source_type: security.sourceType,
        run_id: stringMaybe(eventRecord.runId) ?? stringMaybe(contextRecord.runId),
        agent_id: stringMaybe(eventRecord.agentId) ?? stringMaybe(contextRecord.agentId),
        current_step: hookName,
        model: stringMaybe(eventRecord.model) ?? stringMaybe(contextRecord.model),
        provider: stringMaybe(eventRecord.provider) ?? stringMaybe(contextRecord.provider),
      }),
      ...(resourceTargets.length > 0 ? { derived_paths: resourceTargets } : {}),
      event: sanitizeJson(event),
      context: sanitizeJson(context),
    },
  };
}

function runtimeObservationResourceTargets(
  hookName: string,
  event: RuntimeSecurityFields & JsonObject,
  context: RuntimeSecurityFields & JsonObject,
): string[] {
  const explicitResources = normalizeDerivedResources(event.derivedResources ?? context.derivedResources);
  if (explicitResources.length > 0) {
    return uniqueStrings(explicitResources.map((resource) => resource.target));
  }
  const paths = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (paths.length > 0) {
    return paths;
  }
  const model = stringMaybe(event.model) ?? stringMaybe(context.model);
  if (model && hookName.startsWith("model_call_")) {
    return [model];
  }
  return [];
}

function definedMetadata(values: Record<string, unknown>): JsonObject {
  const metadata: JsonObject = {};
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "") {
      metadata[key] = value;
    }
  }
  return metadata;
}

function firstNonEmpty(...values: Array<string | null | undefined>): string {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return createLocalId("trace");
}

function createLocalId(prefix: string): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `${prefix}_${crypto.randomUUID()}`;
  }
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2)}`;
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

function runtimeSecurityFields(
  event: RuntimeSecurityFields,
  context: RuntimeSecurityFields,
  options: RuntimeSecurityOptions = {},
): { userTask: string; sourceTrust: string; sourceType: string } {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  return {
    userTask: extractRuntimeUserTask([eventRecord, contextRecord], options) ?? "",
    sourceTrust: stringMaybe(eventRecord.sourceTrust) ?? stringMaybe(contextRecord.sourceTrust) ?? "trusted",
    sourceType: stringMaybe(eventRecord.sourceType) ?? stringMaybe(contextRecord.sourceType) ?? "openclaw",
  };
}

function extractRuntimeUserTask(
  values: readonly JsonObject[],
  options: RuntimeSecurityOptions,
): string | undefined {
  for (const value of values) {
    const explicit = stringMaybe(value.userTask);
    if (explicit) {
      return sanitizeUserTask(explicit);
    }
  }
  for (const value of values) {
    const fromMessages = userTaskFromMessages(value.messages) ?? userTaskFromMessages(asRecord(value.prompt).messages);
    if (fromMessages) {
      return sanitizeUserTask(fromMessages);
    }
  }
  if (options.promptFallback) {
    for (const value of values) {
      const prompt = stringMaybe(value.prompt) ?? stringMaybe(value.input);
      if (prompt) {
        return sanitizeUserTask(prompt);
      }
    }
  }
  if (options.contentFallback) {
    for (const value of values) {
      const content = stringMaybe(value.content)
        ?? stringMaybe(value.text)
        ?? stringMaybe(value.body)
        ?? stringMaybe(value.message);
      if (content) {
        return sanitizeUserTask(content);
      }
    }
  }
  return undefined;
}

function userTaskFromMessages(value: unknown): string | undefined {
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

function sanitizeUserTask(value: string): string {
  const redacted = redactSensitiveCredentials(value);
  return redacted.length > 1000 ? `${redacted.slice(0, 1000)}...` : redacted;
}

function derivedResourcesForTool(event: BeforeToolCallEventInput, context: ToolHookContextInput): DerivedResource[] {
  const explicit = normalizeDerivedResources(event.derivedResources ?? context.derivedResources);
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (derivedTargets.length > 0) {
    return derivedTargets.map((target) =>
      inferDerivedResource({
        toolName: event.toolName,
        toolKind: event.toolKind ?? context.toolKind,
        toolInputKind: event.toolInputKind ?? context.toolInputKind,
        params: event.params ?? {},
        target,
      }),
    );
  }
  const command = toolCommandText(event.params ?? {});
  if (
    command &&
    isExecLikeToolIdentity({
      toolName: event.toolName,
      toolKind: event.toolKind ?? context.toolKind,
      toolInputKind: event.toolInputKind ?? context.toolInputKind,
    })
  ) {
    return [
      {
        resource_type: "process",
        operation: "execute",
        target: redactSensitiveCredentials(command),
        data_classification: null,
        direction: "local",
      },
    ];
  }
  return [];
}

function derivedResourcesForToolResult(
  event: ToolResultPersistEventInput,
  context: ToolHookContextInput,
  toolName: string,
): DerivedResource[] {
  const explicit = normalizeDerivedResources(event.derivedResources ?? context.derivedResources);
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (derivedTargets.length === 0) {
    return [];
  }
  return derivedTargets.map((target) =>
    inferDerivedResource({
      toolName,
      toolKind: event.toolKind ?? context.toolKind,
      toolInputKind: event.toolInputKind ?? context.toolInputKind,
      params: context.toolParams ?? {},
      target,
    }),
  );
}

function derivedResourcesForMessage(event: MessageSendingEventInput, context: MessageHookContextInput): DerivedResource[] {
  const explicit = normalizeDerivedResources(event.derivedResources ?? context.derivedResources);
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (derivedTargets.length > 0) {
    return derivedTargets.map((target) => ({
      resource_type: "message",
      operation: "send",
      target,
      data_classification: null,
      direction: "outbound",
    }));
  }
  return [
    {
      resource_type: "message",
      operation: "send",
      target: event.to,
      data_classification: null,
      direction: "outbound",
    },
  ];
}

function derivedPathTargets(
  event: RuntimeSecurityFields,
  context: RuntimeSecurityFields,
  resources: readonly DerivedResource[],
): string[] {
  const explicitPaths = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (explicitPaths.length > 0) {
    return explicitPaths;
  }
  return uniqueStrings(resources.map((resource) => resource.target));
}

function normalizeDerivedResources(values: readonly DerivedResourceInput[] | undefined): DerivedResource[] {
  if (!Array.isArray(values)) {
    return [];
  }
  const resources: DerivedResource[] = [];
  for (const value of values) {
    const record = asRecord(value);
    const target = stringMaybe(record.target);
    if (!target) {
      continue;
    }
    resources.push({
      resource_type: stringValue(record.resource_type ?? record.resourceType, "resource"),
      operation: stringValue(record.operation, "unknown"),
      target,
      data_classification: stringMaybe(record.data_classification ?? record.dataClassification) ?? null,
      direction: stringValue(record.direction, "local"),
    });
  }
  return resources;
}

function inferDerivedResource(input: {
  toolName: string;
  toolKind?: string;
  toolInputKind?: string;
  params: JsonObject;
  target: string;
}): DerivedResource {
  const toolName = input.toolName.toLowerCase();
  const toolIdentity = `${input.toolName} ${input.toolKind ?? ""} ${input.toolInputKind ?? ""}`.toLowerCase();
  const method = stringMaybe(input.params.method)?.toUpperCase();
  if (toolName === "call_api" || toolIdentity.includes("api") || toolIdentity.includes("http") || /^https?:\/\//i.test(input.target)) {
    return {
      resource_type: "api",
      operation: method ?? "request",
      target: input.target,
      data_classification: null,
      direction: "outbound",
    };
  }
  if (toolIdentity.includes("memory") || input.target.startsWith("memory://")) {
    return {
      resource_type: "memory",
      operation: operationFromToolIdentity(toolIdentity, "write", "read", "search"),
      target: input.target,
      data_classification: null,
      direction: "local",
    };
  }
  if (toolIdentity.includes("message") || toolIdentity.includes("send") || toolIdentity.includes("email")) {
    return {
      resource_type: "message",
      operation: "send",
      target: input.target,
      data_classification: null,
      direction: "outbound",
    };
  }
  if (
    isExecLikeToolIdentity({
      toolName: input.toolName,
      toolKind: input.toolKind,
      toolInputKind: input.toolInputKind,
    }) ||
    toolIdentity.includes("exec") ||
    toolIdentity.includes("shell") ||
    toolIdentity.includes("command") ||
    toolIdentity.includes("code")
  ) {
    return {
      resource_type: "process",
      operation: "execute",
      target: redactSensitiveCredentials(input.target),
      data_classification: null,
      direction: "local",
    };
  }
  return {
    resource_type: "file",
    operation: operationFromToolIdentity(toolIdentity, "write", "read"),
    target: input.target,
    data_classification: null,
    direction: "local",
  };
}

function operationFromToolIdentity(identity: string, writeOperation: string, readOperation: string, searchOperation?: string): string {
  if (identity.includes("write") || identity.includes("create") || identity.includes("update")) {
    return writeOperation;
  }
  if (searchOperation && identity.includes("search")) {
    return searchOperation;
  }
  if (identity.includes("read") || identity.includes("fetch") || identity.includes("get")) {
    return readOperation;
  }
  return "unknown";
}

function truncate(value: string, limit: number): string {
  return value.length <= limit ? value : value.slice(0, limit);
}

function buildInstallFindings(input: {
  targetId: string;
  hooks: JsonObject;
  permissions: JsonObject;
}): ConfigAuditFinding[] {
  const findings: ConfigAuditFinding[] = [];
  if (input.hooks.allowConversationAccess === true || input.permissions.allowConversationAccess === true) {
    findings.push({
      severity: "high",
      category: "openclaw.plugin",
      title: "Raw conversation access enabled",
      subject: `${input.targetId}.hooks.allowConversationAccess`,
      description: "Plugin can read raw conversation content.",
      evidence: ["allowConversationAccess=true"],
      recommendation: "Disable raw conversation access unless the plugin is trusted and reviewed.",
    });
  }
  if (input.hooks.allowPromptInjection === true || input.permissions.allowPromptInjection === true) {
    findings.push({
      severity: "critical",
      category: "openclaw.plugin",
      title: "Prompt injection override enabled",
      subject: `${input.targetId}.hooks.allowPromptInjection`,
      description: "Plugin can bypass prompt-injection controls.",
      evidence: ["allowPromptInjection=true"],
      recommendation: "Remove prompt-injection bypass permissions.",
    });
  }
  if (input.permissions.shell === true || input.permissions.exec === true || input.permissions.command === true) {
    findings.push({
      severity: "high",
      category: "openclaw.plugin",
      title: "Command execution permission enabled",
      subject: `${input.targetId}.permissions.exec`,
      description: "Plugin requests command execution capability.",
      evidence: ["exec-like permission enabled"],
      recommendation: "Require explicit review before installing plugins with command execution.",
    });
  }
  return findings;
}

function containsInstructionLikeText(value: string): boolean {
  return /ignore\s+(all\s+)?previous\s+instructions|system\s+prompt|send\s+(the\s+)?token|developer\s+message/i.test(
    value,
  );
}

function containsSensitiveText(value: string): boolean {
  return (
    /token\s*=|api[_-]?key|password|secret|authorization/i.test(value) ||
    containsSensitiveCredentialText(value)
  );
}

function contextSourceSummaries(event: PromptBuildEventInput): string[] {
  if (!Array.isArray(event.messages)) {
    return [];
  }
  return event.messages
    .map((item) => {
      const record = asRecord(item);
      return stringPreview(record.content ?? record.text ?? item);
    })
    .filter((item) => item.length > 0);
}

function modelContentPreview(hookName: "llm_input" | "llm_output", event: ModelHookEventInput): string {
  if (hookName === "llm_input") {
    return stringPreview(event.prompt ?? event.input ?? event.content ?? event.messages);
  }
  return stringPreview(event.output ?? event.response ?? event.content ?? event.assistantTexts ?? event.lastAssistant ?? event.messages);
}

function modelToolPlan(event: ModelHookEventInput): JsonObject[] {
  const toolPlan = event.toolPlan ?? event.toolCalls;
  if (!Array.isArray(toolPlan)) {
    return [];
  }
  return toolPlan.map((item) => asRecord(item));
}

function resultContentPreview(value: unknown): string {
  return stringPreview(value);
}

function stringPreview(value: unknown): string {
  const record = asRecord(value);
  const content = record.content ?? record.text ?? record.output ?? value;
  if (typeof content === "string") {
    return content;
  }
  if (content === null || content === undefined) {
    return "";
  }
  try {
    return JSON.stringify(content);
  } catch {
    return String(content);
  }
}

function resultContentType(value: unknown): string {
  const record = asRecord(value);
  return stringMaybe(record.contentType ?? record.mimeType ?? record.type) ?? "text/plain";
}

function toolCommandText(params: JsonObject): string {
  return stringMaybe(params.command ?? params.cmd ?? params.code) ?? "";
}

function asRecord(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function stringValue(value: unknown, fallback: string): string {
  const parsed = stringMaybe(value);
  return parsed ?? fallback;
}

function stringMaybe(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function sanitizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJson(item));
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  const sanitized: JsonObject = {};
  for (const [key, nestedValue] of Object.entries(value)) {
    sanitized[key] = SENSITIVE_KEY_PATTERN.test(key) ? "[redacted]" : sanitizeJson(nestedValue);
  }
  return sanitized;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
