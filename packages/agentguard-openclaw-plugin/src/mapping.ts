import type { GuardEvent, JsonObject } from "./types.js";

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

const PREVIEW_LIMIT = 2000;

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
