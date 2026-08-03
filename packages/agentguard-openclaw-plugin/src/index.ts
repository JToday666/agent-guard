import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";
import type { PluginHookName } from "openclaw/plugin-sdk/types";

import {
  OPENCLAW_ENFORCEMENT_HOOKS,
  OPENCLAW_OBSERVATION_HOOKS,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";
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
} from "./mapping.js";
import {
  containsSensitiveCredentialText,
  redactUnknownCredentials,
  sanitizePersistentInstructionPoisoning,
  stringPreview,
} from "./security.js";
import type {
  DerivedResource,
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
  OpenClawPluginConfigInput,
} from "./types.js";

const PLUGIN_VERSION = "0.1.0";

type SessionState = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  provider?: string;
  model?: string;
  runId?: string;
  sessionId?: string;
  toolRuntimePolicies?: Record<string, JsonObject>;
};

type TaskExtractionOptions = {
  promptFallback?: boolean;
  contentFallback?: boolean;
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
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const guardEvent = buildToolCallGuardEvent(cached.event, cached.context);
          rememberToolCallState(toolCallState, guardEvent);
          const decision = await client.evaluate(guardEvent);
          if (isObserve(config)) {
            return undefined;
          }
          return await decisionToToolResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "before_tool_call failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return isObserve(config) ? undefined : failClosedToolResult();
        }
      },
      { priority: 100, timeoutMs: blockingApprovalHookTimeoutMs(config) },
    );

    api.on(
      "message_sending",
      async (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context);
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const guardEvent = buildMessageSendGuardEvent(cached.event, cached.context);
          const decision = await client.evaluate(guardEvent);
          if (isObserve(config)) {
            return undefined;
          }
          return await decisionToMessageResult(decision, {
            waitForApproval: (approvalId) => client.waitForApproval(approvalId, config.approvalWaitBudgetMs),
          });
        } catch (error) {
          logDiagnostic(config, "message_sending failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return isObserve(config) ? undefined : failClosedMessageResult();
        }
      },
      { priority: 100, timeoutMs: blockingApprovalHookTimeoutMs(config) },
    );

    api.on(
      "before_install",
      async (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          const result = await client.evaluateConfigAudit(buildBeforeInstallConfigAuditEvent(event, context));
          if (isObserve(config)) {
            return undefined;
          }
          return result.decision === "block"
            ? { block: true, blockReason: "Blocked by AgentGuard config audit." }
            : undefined;
        } catch (error) {
          logDiagnostic(config, "before_install failed closed", {
            error: error instanceof Error ? error.message : String(error),
          });
          return isObserve(config)
            ? undefined
            : { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
        }
      },
      { priority: 100, timeoutMs: 10_000 },
    );

    api.on(
      "message_received",
      (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context, { contentFallback: true });
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
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context, { promptFallback: true });
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const decision = await client.evaluate(buildContextGuardEvent("before_prompt_build", cached.event, cached.context));
          if (shouldRuntimeBlock(config, decision)) {
            return decisionToBlockResult(decision) as never;
          }
        } catch (error) {
          logDiagnostic(config, "before_prompt_build enforcement failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          if (shouldFailClosedRuntimeStage(config, "before_prompt_build")) {
            return failClosedBlockResult() as never;
          }
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_input",
      async (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        try {
          rememberSessionState(sessionState, event, context, { promptFallback: true });
          const cached = withCachedRuntimeFields(sessionState, event, context);
          const decision = await client.evaluate(buildModelGuardEvent("llm_input", cached.event, cached.context));
          if (shouldRuntimeBlock(config, decision)) {
            return decisionToBlockResult(decision) as never;
          }
        } catch (error) {
          logDiagnostic(config, "llm_input enforcement failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          if (shouldFailClosedRuntimeStage(config, "llm_input")) {
            return failClosedBlockResult() as never;
          }
        }
        return undefined;
      },
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "llm_output",
      async (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
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
      ((event: object, context: object) => {
        if (isDisabled(config)) {
          return undefined;
        }
        const client = makeClient();
        let message: unknown;
        try {
          const cached = withCachedToolContext(sessionState, toolCallState, event, context);
          message = asRecord(event).message;
          const redacted = redactUnknownCredentials(message);
          const sanitized = sanitizePersistentInstructionPoisoning(redacted.value);
          void client
            .submitRuntimeObservation(
              buildRuntimeObservationAuditEvent(
                "tool_result_persist",
                { ...cached.event, message: sanitized.value },
                cached.context,
              ),
            )
            .catch((error) => {
              logDiagnostic(config, "tool_result_persist observation failed", {
                error: error instanceof Error ? error.message : String(error),
              });
            });
          if (isEnforcing(config) && (redacted.changed || sanitized.changed)) {
            return { message: sanitized.value as never };
          }
        } catch (error) {
          logDiagnostic(config, "tool_result_persist enforcement failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          if (shouldFailClosedRuntimeStage(config, "tool_result_persist")) {
            return { message: quarantinedToolResultMessage(message, "AgentGuard is unavailable; quarantined by fail-closed policy.") as never };
          }
          return undefined;
        }
        return undefined;
      }) as never,
      { priority: 0, timeoutMs: 2000 },
    );

    api.on(
      "before_message_write",
      (event, context) => {
        if (isDisabled(config)) {
          return undefined;
        }
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
          return isEnforcing(config) && redacted.changed ? { message: redacted.value as never } : undefined;
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
        if (isDisabled(config)) {
          return undefined;
        }
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
          let revisionReason = shouldRevise
            ? "AgentGuard detected credential exposure in the final assistant message."
            : "";
          try {
            const decision = await client.evaluate(guardEvent);
            if (shouldRuntimeBlock(config, decision)) {
              shouldRevise = true;
              revisionReason = safeDecisionMessage(decision);
            }
          } catch (error) {
            logDiagnostic(config, "before_agent_finalize evaluation failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          }
          if (!isEnforcing(config) || !shouldRevise) {
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
            reason: revisionReason || "AgentGuard detected unsafe content in the final assistant message.",
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

    for (const hookName of OPENCLAW_OBSERVATION_HOOKS as readonly PluginHookName[]) {
      api.on(
        hookName,
        (event: unknown, context: Record<string, unknown>) => {
          if (isDisabled(config)) {
            return undefined;
          }
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
  const sourceTrust = stringMaybe(eventRecord.sourceTrust ?? eventRecord.source_trust)
    ?? stringMaybe(contextRecord.sourceTrust ?? contextRecord.source_trust)
    ?? existing.sourceTrust;
  const sourceType = stringMaybe(eventRecord.sourceType ?? eventRecord.source_type)
    ?? stringMaybe(contextRecord.sourceType ?? contextRecord.source_type)
    ?? existing.sourceType;
  const trustedRuntimePolicy = sourceTrust === "trusted";
  const extractedRuntimePolicies = trustedRuntimePolicy ? extractToolRuntimePolicies(event, context) : {};
  const toolRuntimePolicies = mergeToolRuntimePolicies(existing.toolRuntimePolicies, extractedRuntimePolicies);
  const next: SessionState = {
    ...existing,
    userTask: explicitUserTask ?? existing.userTask ?? fallbackUserTask,
    sourceTrust,
    sourceType,
    provider: stringMaybe(eventRecord.provider) ?? stringMaybe(contextRecord.provider) ?? existing.provider,
    model: stringMaybe(eventRecord.model) ?? stringMaybe(contextRecord.model) ?? existing.model,
    runId: stringMaybe(eventRecord.runId) ?? stringMaybe(contextRecord.runId) ?? existing.runId,
    sessionId: stringMaybe(eventRecord.sessionId) ?? stringMaybe(contextRecord.sessionId) ?? existing.sessionId,
    toolRuntimePolicies: Object.keys(toolRuntimePolicies).length > 0 ? toolRuntimePolicies : existing.toolRuntimePolicies,
  };
  for (const key of keys) {
    setLimited(cache, key, next);
  }
}

function extractToolRuntimePolicies(...values: unknown[]): Record<string, JsonObject> {
  const policies: Record<string, JsonObject> = {};
  for (const value of values) {
    collectToolRuntimePolicies(value, policies);
  }
  return policies;
}

function collectToolRuntimePolicies(
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

function collectToolDescriptorPolicy(value: unknown, policies: Record<string, JsonObject>): void {
  const record = asRecord(value);
  const toolName = stringMaybe(record.name ?? record.toolName ?? record.tool_name);
  const runtimePolicy = normalizedRuntimePolicy(record.runtime_policy ?? record.runtimePolicy);
  if (toolName && runtimePolicy) {
    policies[toolName] = {
      ...(policies[toolName] ?? {}),
      ...runtimePolicy,
    };
  }
}

function normalizedRuntimePolicy(value: unknown): JsonObject | undefined {
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
    } else if (typeof field === "boolean" || typeof field === "string" || typeof field === "number") {
      policy[key] = field;
    }
  }
  return Object.keys(policy).length > 0 ? policy : undefined;
}

function mergeToolRuntimePolicies(
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
  const toolName = stringMaybe(record.toolName);
  const runtimePolicy = toolName ? state.toolRuntimePolicies?.[toolName] : undefined;
  if (runtimePolicy && Object.keys(asRecord(record.runtimePolicy ?? record.runtime_policy)).length === 0) {
    record.runtimePolicy = runtimePolicy;
  }
  return record;
}

function cacheState(cache: Map<string, SessionState>, event: unknown, context: unknown): SessionState | undefined {
  const states = cacheKeys(event, context)
    .map((key) => cache.get(key))
    .filter((state): state is SessionState => state !== undefined);
  if (states.length === 0) {
    return undefined;
  }
  return Object.assign({}, ...states);
}

function cacheKeys(event: unknown, context: unknown): string[] {
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

function extractExplicitUserTask(...values: unknown[]): string | undefined {
  for (const value of values) {
    const explicit = stringMaybe(asRecord(value).userTask);
    if (explicit) {
      return sanitizeTask(explicit);
    }
  }
  return undefined;
}

function extractUserTask(
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
    const fromMessages = userTaskFromMessages(record.messages) ?? userTaskFromMessages(asRecord(record.prompt).messages);
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
      const task = stringMaybe(record.content)
        ?? stringMaybe(record.text)
        ?? stringMaybe(record.body)
        ?? stringMaybe(record.message);
      if (task) {
        return sanitizeTask(task);
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

function uniqueStrings(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === "string" && value.length > 0))];
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

function isDisabled(config: ReturnType<typeof buildPluginConfig>): boolean {
  return config.enforcementMode === "disabled";
}

function isObserve(config: ReturnType<typeof buildPluginConfig>): boolean {
  return config.enforcementMode === "observe";
}

function isEnforcing(config: ReturnType<typeof buildPluginConfig>): boolean {
  return config.enforcementMode === "enforce";
}

function blockingApprovalHookTimeoutMs(config: ReturnType<typeof buildPluginConfig>): number {
  return Math.max(10_000, config.approvalWaitBudgetMs + 2_000);
}

function shouldRuntimeBlock(config: ReturnType<typeof buildPluginConfig>, response: GuardEvaluationResponse): boolean {
  return isEnforcing(config) && response.decision.decision !== "allow";
}

function shouldFailClosedRuntimeStage(config: ReturnType<typeof buildPluginConfig>, stage: string): boolean {
  return isEnforcing(config) && config.failClosedStages.includes(stage);
}

function decisionToBlockResult(response: GuardEvaluationResponse): { block: true; blockReason: string } {
  return {
    block: true,
    blockReason: safeDecisionMessage(response),
  };
}

function failClosedBlockResult(): { block: true; blockReason: string } {
  return {
    block: true,
    blockReason: "AgentGuard is unavailable; blocked by fail-closed policy.",
  };
}

function safeDecisionMessage(response: GuardEvaluationResponse): string {
  return response.decision.safe_message || response.decision.reason || "Blocked by AgentGuard policy.";
}

function quarantinedToolResultMessage(original: unknown, reason: string): unknown {
  const safeContent = `[AgentGuard quarantined this tool result before persistence. ${reason}]`;
  if (typeof original === "string") {
    return safeContent;
  }
  if (Array.isArray(original)) {
    return safeContent;
  }
  const record = asRecord(original);
  if (Object.keys(record).length === 0) {
    return safeContent;
  }
  if ("content" in record) {
    return { ...record, content: safeContent };
  }
  if ("text" in record) {
    return { ...record, text: safeContent };
  }
  if ("message" in record) {
    return { ...record, message: safeContent };
  }
  return safeContent;
}

function scheduleHeartbeat(config: ReturnType<typeof buildPluginConfig>, makeClient: () => GuardApiClient): void {
  if (!config.adapterToken || isDisabled(config)) {
    return;
  }
  const submit = () => {
    void makeClient()
      .submitHeartbeat({
        pluginVersion: PLUGIN_VERSION,
        runtimeVersion: runtimeVersion(),
        hooks: [...OPENCLAW_REQUIRED_HOOKS],
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
          blocking_hooks: [...OPENCLAW_ENFORCEMENT_HOOKS],
          observation_hooks: [...OPENCLAW_OBSERVATION_HOOKS, "message_received"],
          redaction_hooks: ["tool_result_persist", "before_message_write", "before_agent_finalize"],
          fail_closed_stages: config.failClosedStages,
          enforcement_mode: config.enforcementMode,
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
