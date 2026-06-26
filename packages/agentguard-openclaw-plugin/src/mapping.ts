import type { AuditEvent, ConfigAuditEvent, ConfigAuditFinding, GuardEvent, JsonObject } from "./types.js";

type BeforeToolCallEventInput = {
  toolName: string;
  params?: JsonObject;
  toolKind?: string;
  toolInputKind?: string;
  runId?: string;
  toolCallId?: string;
  derivedPaths?: readonly string[];
};

type ToolHookContextInput = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  channelId?: string;
  toolName?: string;
  toolKind?: string;
  toolInputKind?: string;
  toolCallId?: string;
};

type MessageSendingEventInput = {
  to: string;
  content: string;
  replyToId?: string | number;
  threadId?: string | number;
  metadata?: JsonObject;
};

type MessageHookContextInput = {
  channelId?: string;
  accountId?: string;
  conversationId?: string;
  sessionKey?: string;
  runId?: string;
  messageId?: string;
  senderId?: string;
};

type ToolResultPersistEventInput = {
  toolName?: string;
  toolKind?: string;
  toolInputKind?: string;
  toolCallId?: string;
  runId?: string;
  result?: unknown;
  message?: unknown;
  willEnterContext?: boolean;
  willPersist?: boolean;
  derivedPaths?: readonly string[];
};

type BeforeInstallEventInput = {
  request?: JsonObject & {
    targetType?: string;
    targetId?: string;
    manifest?: unknown;
    config?: unknown;
  };
  targetType?: string;
  targetId?: string;
  manifest?: unknown;
  config?: unknown;
};

type RuntimeObservationContextInput = {
  runId?: string;
  sessionKey?: string;
  sessionId?: string;
  agentId?: string;
  channelId?: string;
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
  const derivedPaths = uniqueStrings(event.derivedPaths ?? []);

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
      user_task: "",
      source_type: "openclaw",
      source_trust: "trusted",
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
      derived_resources: derivedPaths.map((target) => ({
        resource_type: "file",
        operation: "unknown",
        target,
        data_classification: null,
        direction: "local",
      })),
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
      user_task: "",
      source_type: "openclaw",
      source_trust: "trusted",
      channel: context.channelId ?? "unknown",
      sender_id: context.senderId ?? null,
      session_id: null,
      run_id: context.runId ?? null,
      agent_id: "main",
      current_step: "message_sending",
      model_intent: null,
      context_sources: [],
      derived_paths: [],
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
      derived_resources: [],
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
  const derivedPaths = uniqueStrings(event.derivedPaths ?? []);

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
      user_task: "",
      source_type: "openclaw",
      source_trust: "trusted",
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
      will_enter_context: event.willEnterContext ?? false,
      will_persist: event.willPersist ?? false,
      sanitized: false,
      contains_sensitive_data: false,
      contains_instruction_like_text: containsInstructionLikeText(resultPreview),
      derived_resources: derivedPaths.map((target) => ({
        resource_type: "file",
        operation: "unknown",
        target,
        data_classification: null,
        direction: "local",
      })),
    },
    metadata: {
      openclaw_hook: "tool_result_persist",
      session_key: context.sessionKey ?? null,
    },
  };
}

export function buildBeforeInstallConfigAuditEvent(event: BeforeInstallEventInput): ConfigAuditEvent {
  const request = asRecord(event.request);
  const targetType = stringValue(request.targetType ?? event.targetType, "plugin");
  const targetId = stringValue(request.targetId ?? event.targetId, "unknown");
  const manifest = asRecord(request.manifest ?? event.manifest);
  const config = asRecord(request.config ?? event.config ?? manifest.config);
  const hooks = asRecord(config.hooks ?? manifest.hooks);
  const permissions = asRecord(config.permissions ?? manifest.permissions);
  const findings = buildInstallFindings({ targetId, hooks, permissions });

  return {
    runtime: "openclaw",
    target_type: targetType,
    target_id: targetId,
    action: "before_install",
    findings,
    metadata: {
      manifest_id: stringValue(manifest.id, targetId),
    },
  };
}

export function buildRuntimeObservationAuditEvent(
  hookName: string,
  event: unknown = {},
  context: RuntimeObservationContextInput = {},
): AuditEvent {
  const eventRecord = asRecord(event);
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
    resource_targets: [],
    rule_hits: [],
    links: {},
    metadata: {
      openclaw_hook: hookName,
      event: sanitizeJson(event),
      context: sanitizeJson(context),
    },
  };
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

function resultContentPreview(value: unknown): string {
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
