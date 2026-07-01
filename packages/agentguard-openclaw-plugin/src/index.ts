import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import {
  GuardApiClient,
  buildPluginConfig,
  decisionToMessageResult,
  decisionToToolResult,
  failClosedMessageResult,
  failClosedToolResult,
  logDiagnostic,
} from "./guard-api-client.js";
import {
  buildBeforeInstallConfigAuditEvent,
  buildContextGuardEvent,
  buildMessageSendGuardEvent,
  buildModelGuardEvent,
  buildRuntimeObservationAuditEvent,
  buildToolCallGuardEvent,
  buildToolResultGuardEvent,
} from "./mapping.js";
import {
  containsSensitiveCredentialText,
  redactUnknownCredentials,
  stringPreview,
} from "./security.js";
import type { DerivedResource, GuardEvent, JsonObject, OpenClawPluginConfigInput } from "./types.js";

const PLUGIN_VERSION = "0.1.0";

const OBSERVATION_HOOKS = [
  "gateway_start",
  "gateway_stop",
  "session_start",
  "session_end",
  "before_compaction",
  "after_compaction",
  "subagent_spawned",
  "subagent_ended",
  "model_call_started",
  "model_call_ended",
  "cron_changed",
  "resolve_exec_env",
] as const;

const PROMPT_MODEL_HOOKS = ["before_prompt_build", "llm_input", "llm_output"] as const;
const BLOCKING_HOOKS = ["before_tool_call", "message_sending", "before_install"] as const;
const ALL_REGISTERED_HOOKS = [
  ...BLOCKING_HOOKS,
  ...PROMPT_MODEL_HOOKS,
  "tool_result_persist",
  "message_received",
  "before_message_write",
  "before_agent_finalize",
  ...OBSERVATION_HOOKS,
] as const;

type SessionState = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  provider?: string;
  model?: string;
  runId?: string;
  sessionId?: string;
};

type ToolCallState = {
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
};

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: "agentguard-security",
  name: "AgentGuard Security",
  description: "Evaluates OpenClaw tool calls and outbound messages through AgentGuard Guard API.",
  register(api) {
    const config = buildPluginConfig(api.pluginConfig as OpenClawPluginConfigInput);
    const makeClient = () => new GuardApiClient({ config });
    const sessionState = new Map<string, SessionState>();
    const toolCallState = new Map<string, ToolCallState>();
    const finalizeRevisionKeys = new Set<string>();

    scheduleHeartbeat(config, makeClient);

    api.on(
      "before_tool_call",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const guardEvent = buildToolCallGuardEvent(cached.event, cached.context);
          rememberToolCallState(toolCallState, guardEvent);
          const decision = await client.evaluate(guardEvent);
          return await decisionToToolResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "before_tool_call failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return failClosedToolResult();
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "message_sending",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const guardEvent = buildMessageSendGuardEvent(cached.event, cached.context);
          const decision = await client.evaluate(guardEvent);
          return await decisionToMessageResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "message_sending failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return failClosedMessageResult();
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "before_install",
      async (event) => {
        const client = makeClient();
        try {
          const result = await client.evaluateConfigAudit(buildBeforeInstallConfigAuditEvent(event));
          return result.decision === "block"
            ? { block: true, blockReason: "Blocked by AgentGuard config audit." }
            : undefined;
        } catch (error) {
          logDiagnostic(config, "before_install failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "message_received",
      (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          void client
            .submitRuntimeObservation(buildRuntimeObservationAuditEvent("message_received", cached.event, cached.context))
            .catch((error) => {
              logDiagnostic(config, "message_received observation failed", {
                error: error instanceof Error ? error.message : String(error),
              });
            });
        } catch (error) {
          logDiagnostic(config, "message_received handling failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "before_prompt_build",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          await client.evaluate(buildContextGuardEvent("before_prompt_build", cached.event, cached.context));
        } catch (error) {
          logDiagnostic(config, "before_prompt_build observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_input",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          await client.evaluate(buildModelGuardEvent("llm_input", cached.event, cached.context));
        } catch (error) {
          logDiagnostic(config, "llm_input observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_output",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          await client.evaluate(buildModelGuardEvent("llm_output", cached.event, cached.context));
        } catch (error) {
          logDiagnostic(config, "llm_output observation failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "tool_result_persist",
      (event, context) => {
        const client = makeClient();
        try {
          const cached = withCachedToolContext(sessionState, toolCallState, event, context);
          void client.evaluate(buildToolResultGuardEvent(cached.event, cached.context)).catch((error) => {
            logDiagnostic(config, "tool_result_persist observation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          });
          const message = asRecord(event).message;
          const redacted = redactUnknownCredentials(message);
          if (redacted.changed) {
            return { message: redacted.value as never };
          }
        } catch (error) {
          logDiagnostic(config, "tool_result_persist mapping failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return undefined;
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "before_message_write",
      (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          void client
            .submitRuntimeObservation(buildRuntimeObservationAuditEvent("before_message_write", cached.event, cached.context))
            .catch((error) => {
              logDiagnostic(config, "before_message_write observation failed", {
                error: error instanceof Error ? error.message : String(error),
              });
            });
          const message = asRecord(event).message;
          const redacted = redactUnknownCredentials(message);
          return redacted.changed ? { message: redacted.value as never } : undefined;
        } catch (error) {
          logDiagnostic(config, "before_message_write redaction failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return undefined;
        }
      },
      { priority: 100, timeoutMs: 2000 },
    );

    api.on(
      "before_agent_finalize",
      async (event, context) => {
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const eventRecord = asRecord(cached.event);
          const content = stringMaybe(eventRecord.lastAssistantMessage) ?? stringPreview(eventRecord.messages);
          const guardEvent = buildModelGuardEvent(
            "llm_output",
            {
              ...cached.event,
              output: content,
              provider: stringMaybe(eventRecord.provider) ?? stringMaybe(cached.context.provider),
              model: stringMaybe(eventRecord.model) ?? stringMaybe(cached.context.model),
            },
            cached.context,
          );
          let shouldRevise = containsSensitiveCredentialText(content);
          try {
            const decision = await client.evaluate(guardEvent);
            shouldRevise ||= decision.decision.decision === "deny";
          } catch (error) {
            logDiagnostic(config, "before_agent_finalize evaluation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          }
          if (!shouldRevise) {
            return undefined;
          }
          const revisionKey = firstNonEmptyString(
            stringMaybe(eventRecord.turnId),
            stringMaybe(eventRecord.runId),
            stringMaybe(eventRecord.sessionKey),
            stringMaybe(eventRecord.sessionId),
          );
          if (finalizeRevisionKeys.has(revisionKey)) {
            return undefined;
          }
          finalizeRevisionKeys.add(revisionKey);
          return {
            action: "revise",
            reason: "AgentGuard detected credential exposure in the final assistant message.",
            retry: {
              instruction:
                "Remove all credential, secret, token, and API Key values from the final answer. Replace any credential value with [redacted] and do not reveal environment variable contents.",
              idempotencyKey: `agentguard-credential-redaction:${revisionKey}`,
              maxAttempts: 1,
            },
          };
        } catch (error) {
          logDiagnostic(config, "before_agent_finalize handling failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return undefined;
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    for (const hookName of OBSERVATION_HOOKS) {
      api.on(
        hookName,
        (event: unknown, context: Record<string, unknown>) => {
          const client = makeClient();
          try {
            const eventRecord = asRecord(event);
            const contextRecord = asRecord(context);
            rememberSessionState(sessionState, eventRecord, contextRecord);
            const cached = withCachedRuntimeFields(sessionState, eventRecord, contextRecord);
            void client
              .submitRuntimeObservation(buildRuntimeObservationAuditEvent(hookName, cached.event, cached.context))
              .catch((error) => {
                logDiagnostic(config, "runtime observation submit failed", {
                  hookName,
                  error: error instanceof Error ? error.message : String(error),
                });
              });
          } catch (error) {
            logDiagnostic(config, "runtime observation mapping failed", {
              hookName,
              error: error instanceof Error ? error.message : String(error),
            });
            return undefined;
          }
          return undefined;
        },
        { priority: 0, timeoutMs: 2000 },
      );
    }
  },
});

function rememberSessionState(
  cache: Map<string, SessionState>,
  event: unknown,
  context: unknown,
): void {
  const key = cacheKey(event, context);
  if (!key) {
    return;
  }
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const existing = cache.get(key) ?? {};
  const next: SessionState = {
    ...existing,
    userTask: extractUserTask(event, context) ?? existing.userTask,
    sourceTrust: stringMaybe(eventRecord.sourceTrust) ?? stringMaybe(contextRecord.sourceTrust) ?? existing.sourceTrust,
    sourceType: stringMaybe(eventRecord.sourceType) ?? stringMaybe(contextRecord.sourceType) ?? existing.sourceType,
    provider: stringMaybe(eventRecord.provider) ?? stringMaybe(contextRecord.provider) ?? existing.provider,
    model: stringMaybe(eventRecord.model) ?? stringMaybe(contextRecord.model) ?? existing.model,
    runId: stringMaybe(eventRecord.runId) ?? stringMaybe(contextRecord.runId) ?? existing.runId,
    sessionId: stringMaybe(eventRecord.sessionId) ?? stringMaybe(contextRecord.sessionId) ?? existing.sessionId,
  };
  setLimited(cache, key, next);
}

function withCachedRuntimeFields<T extends object, C extends object>(
  cache: Map<string, SessionState>,
  event: T,
  context: C,
): { event: T & JsonObject; context: C & JsonObject } {
  const state = cacheState(cache, event, context);
  if (!state) {
    return { event: event as T & JsonObject, context: context as C & JsonObject };
  }
  return {
    event: mergeRuntimeFields(event, state) as T & JsonObject,
    context: mergeRuntimeFields(context, state) as C & JsonObject,
  };
}

function withCachedToolContext<T extends object, C extends object>(
  sessionCache: Map<string, SessionState>,
  toolCache: Map<string, ToolCallState>,
  event: T,
  context: C,
): { event: T & JsonObject; context: C & JsonObject } {
  const cached = withCachedRuntimeFields(sessionCache, event, context);
  const eventRecord = { ...asRecord(cached.event) };
  const contextRecord = { ...asRecord(cached.context) };
  const callId = stringMaybe(eventRecord.toolCallId) ?? stringMaybe(contextRecord.toolCallId);
  const toolState = callId ? toolCache.get(callId) : undefined;
  if (!toolState) {
    return cached;
  }
  eventRecord.toolName = stringMaybe(eventRecord.toolName) ?? toolState.toolName;
  eventRecord.toolKind = stringMaybe(eventRecord.toolKind) ?? toolState.toolKind;
  eventRecord.toolInputKind = stringMaybe(eventRecord.toolInputKind) ?? toolState.toolInputKind;
  eventRecord.toolCallId = stringMaybe(eventRecord.toolCallId) ?? toolState.toolCallId;
  eventRecord.runId = stringMaybe(eventRecord.runId) ?? toolState.runId;
  eventRecord.userTask = stringMaybe(eventRecord.userTask) ?? toolState.userTask;
  eventRecord.sourceTrust = stringMaybe(eventRecord.sourceTrust) ?? toolState.sourceTrust;
  eventRecord.sourceType = stringMaybe(eventRecord.sourceType) ?? toolState.sourceType;
  if (!Array.isArray(eventRecord.derivedResources)) {
    eventRecord.derivedResources = toolState.derivedResources;
  }
  if (!Array.isArray(eventRecord.derivedPaths)) {
    eventRecord.derivedPaths = toolState.derivedPaths;
  }
  contextRecord.toolName = stringMaybe(contextRecord.toolName) ?? toolState.toolName;
  contextRecord.toolKind = stringMaybe(contextRecord.toolKind) ?? toolState.toolKind;
  contextRecord.toolInputKind = stringMaybe(contextRecord.toolInputKind) ?? toolState.toolInputKind;
  contextRecord.toolCallId = stringMaybe(contextRecord.toolCallId) ?? toolState.toolCallId;
  contextRecord.runId = stringMaybe(contextRecord.runId) ?? toolState.runId;
  contextRecord.userTask = stringMaybe(contextRecord.userTask) ?? toolState.userTask;
  contextRecord.sourceTrust = stringMaybe(contextRecord.sourceTrust) ?? toolState.sourceTrust;
  contextRecord.sourceType = stringMaybe(contextRecord.sourceType) ?? toolState.sourceType;
  contextRecord.derivedResources = Array.isArray(contextRecord.derivedResources)
    ? contextRecord.derivedResources
    : toolState.derivedResources;
  contextRecord.derivedPaths = Array.isArray(contextRecord.derivedPaths)
    ? contextRecord.derivedPaths
    : toolState.derivedPaths;
  contextRecord.toolParams = toolState.toolParams;
  return { event: eventRecord as T & JsonObject, context: contextRecord as C & JsonObject };
}

function rememberToolCallState(cache: Map<string, ToolCallState>, event: GuardEvent): void {
  if (event.event_type !== "tool_call_proposed" || !("tool" in event.payload) || !("arguments" in event.payload)) {
    return;
  }
  const payload = event.payload;
  const callId = payload.tool.call_id;
  setLimited(cache, callId, {
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
  });
}

function mergeRuntimeFields(value: object, state: SessionState): JsonObject {
  const record = { ...asRecord(value) };
  record.userTask = stringMaybe(record.userTask) ?? state.userTask;
  record.sourceTrust = stringMaybe(record.sourceTrust) ?? state.sourceTrust;
  record.sourceType = stringMaybe(record.sourceType) ?? state.sourceType;
  record.provider = stringMaybe(record.provider) ?? state.provider;
  record.model = stringMaybe(record.model) ?? state.model;
  record.runId = stringMaybe(record.runId) ?? state.runId;
  record.sessionId = stringMaybe(record.sessionId) ?? state.sessionId;
  return record;
}

function cacheState(cache: Map<string, SessionState>, event: unknown, context: unknown): SessionState | undefined {
  const key = cacheKey(event, context);
  return key ? cache.get(key) : undefined;
}

function cacheKey(event: unknown, context: unknown): string | undefined {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  return firstNonEmptyString(
    stringMaybe(eventRecord.sessionKey),
    stringMaybe(contextRecord.sessionKey),
    stringMaybe(eventRecord.runId),
    stringMaybe(contextRecord.runId),
    stringMaybe(eventRecord.sessionId),
    stringMaybe(contextRecord.sessionId),
    stringMaybe(eventRecord.traceId),
    stringMaybe(contextRecord.traceId),
  );
}

function extractUserTask(...values: unknown[]): string | undefined {
  for (const value of values) {
    const explicit = stringMaybe(asRecord(value).userTask);
    if (explicit) {
      return sanitizeTask(explicit);
    }
  }
  for (const value of values) {
    const fromMessages = userTaskFromMessages(asRecord(value).messages);
    if (fromMessages) {
      return sanitizeTask(fromMessages);
    }
  }
  for (const value of values) {
    const record = asRecord(value);
    const task = stringMaybe(record.content)
      ?? stringMaybe(record.text)
      ?? stringMaybe(record.body)
      ?? stringMaybe(record.prompt)
      ?? stringMaybe(record.input)
      ?? stringMaybe(record.message);
    if (task) {
      return sanitizeTask(task);
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

function sanitizeTask(value: string): string {
  const redacted = redactUnknownCredentials(value).value;
  const task = typeof redacted === "string" ? redacted : stringPreview(redacted);
  return task.length > 1000 ? `${task.slice(0, 1000)}...` : task;
}

function setLimited<T>(cache: Map<string, T>, key: string, value: T, limit = 200): void {
  if (!cache.has(key) && cache.size >= limit) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) {
      cache.delete(oldest);
    }
  }
  cache.set(key, value);
}

function asRecord(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function stringMaybe(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function firstNonEmptyString(...values: Array<string | undefined>): string {
  for (const value of values) {
    if (value) {
      return value;
    }
  }
  return "unknown";
}

function scheduleHeartbeat(config: ReturnType<typeof buildPluginConfig>, makeClient: () => GuardApiClient): void {
  if (!config.adapterToken) {
    return;
  }
  const submit = () => {
    void makeClient()
      .submitHeartbeat({
        pluginVersion: PLUGIN_VERSION,
        runtimeVersion: runtimeVersion(),
        hooks: [...ALL_REGISTERED_HOOKS],
        capabilities: {
          event_types: [
            "tool_call_proposed",
            "context_assembled",
            "model_input_prepared",
            "model_output_produced",
            "tool_result_produced",
            "memory_write_proposed",
            "message_send_proposed",
          ],
          blocking_hooks: [...BLOCKING_HOOKS, "before_agent_finalize"],
          observation_hooks: [...OBSERVATION_HOOKS, "message_received"],
          redaction_hooks: ["tool_result_persist", "before_message_write", "before_agent_finalize"],
          fail_closed_stages: config.failClosedStages,
          redaction: config.redaction,
        },
      })
      .catch((error) => {
        logDiagnostic(config, "heartbeat submit failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      });
  };
  unrefTimer(setTimeout(submit, 0));
  unrefTimer(setInterval(submit, config.heartbeatIntervalMs));
}

function runtimeVersion(): string {
  return "2026.6.6";
}

function unrefTimer(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>): void {
  if (typeof timer === "object" && timer !== null && "unref" in timer) {
    (timer as { unref: () => void }).unref();
  }
}

export default plugin;
