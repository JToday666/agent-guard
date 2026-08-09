import type {
  AuditEvent,
  ConfigAuditEvent,
  ConfigAuditFinding,
  DerivedResource,
  GuardEvent,
  JsonObject,
} from "../types.js";
import {
  containsSensitiveCredentialText,
  isExecLikeToolIdentity,
  redactSensitiveCredentials,
} from "../security.js";

export type RuntimeSecurityFields = {
  userTask?: string;
  sourceTrust?: string;
  sourceType?: string;
  derivedResources?: readonly DerivedResourceInput[];
  derivedPaths?: readonly string[];
  [key: string]: unknown;
};

export type RuntimeSecurityOptions = {
  promptFallback?: boolean;
  contentFallback?: boolean;
};

export type DerivedResourceInput = Partial<DerivedResource> & {
  resourceType?: unknown;
  dataClassification?: unknown;
};

export type BeforeToolCallEventInput = RuntimeSecurityFields & {
  toolName: string;
  params?: JsonObject;
  arguments?: JsonObject;
  input?: JsonObject;
  toolInput?: JsonObject;
  toolKind?: string;
  toolInputKind?: string;
  runId?: string;
  toolCallId?: string;
};

export type ToolHookContextInput = RuntimeSecurityFields & {
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

export type MessageSendingEventInput = RuntimeSecurityFields & {
  to: string;
  content: string;
  replyToId?: string | number;
  threadId?: string | number;
  metadata?: JsonObject;
};

export type MessageHookContextInput = RuntimeSecurityFields & {
  channelId?: string;
  accountId?: string;
  conversationId?: string;
  sessionKey?: string;
  runId?: string;
  messageId?: string;
  senderId?: string;
};

export type ToolResultPersistEventInput = RuntimeSecurityFields & {
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

export type PromptBuildEventInput = RuntimeSecurityFields & {
  prompt?: unknown;
  systemPrompt?: unknown;
  messages?: unknown;
  context?: unknown;
  sanitized?: boolean;
  willEnterContext?: boolean;
};

export type ModelHookEventInput = RuntimeSecurityFields & {
  prompt?: unknown;
  systemPrompt?: unknown;
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

export type BeforeInstallEventInput = RuntimeSecurityFields & {
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

export type RuntimeObservationContextInput = {
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

export const PREVIEW_LIMIT = 2000;
export const SENSITIVE_KEY_PATTERN =
  /token|secret|password|authorization|credential/i;
import { stringPreview } from "./content.js";
import { isHttpUrl, normalizeDerivedResources } from "./resources.js";

export function runtimeObservationResourceTargets(
  hookName: string,
  event: RuntimeSecurityFields & JsonObject,
  context: RuntimeSecurityFields & JsonObject,
): string[] {
  const explicitResources = normalizeDerivedResources(
    event.derivedResources ?? context.derivedResources,
  );
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
  switch (hookName) {
    case "gateway_start":
    case "gateway_stop":
      return runtimeResourceTargets(
        event.gatewayId,
        context.gatewayId,
        "openclaw-gateway",
      );
    case "session_start":
    case "session_end":
    case "message_received":
    case "before_message_write":
      return runtimeResourceTargets(
        event.messageId,
        context.messageId,
        event.sessionKey,
        context.sessionKey,
        event.sessionId,
        context.sessionId,
      );
    case "before_compaction":
    case "after_compaction":
      return runtimeResourceTargets(
        event.sessionFile,
        context.sessionFile,
        event.sessionKey,
        context.sessionKey,
        event.sessionId,
        context.sessionId,
        "context-compaction",
      );
    case "subagent_spawned":
    case "subagent_ended":
      return runtimeResourceTargets(
        event.subagentId,
        context.subagentId,
        event.sessionKey,
        context.sessionKey,
      );
    case "cron_changed":
      return runtimeResourceTargets(
        event.cronId,
        context.cronId,
        "openclaw-cron",
      );
    case "resolve_exec_env":
      return runtimeResourceTargets(
        event.command,
        context.command,
        event.cwd,
        context.cwd,
        "exec-env",
      );
    default:
      return runtimeResourceTargets(
        event.targetId,
        context.targetId,
        event.runId,
        context.runId,
        `openclaw:${hookName}`,
      );
  }
}

export function runtimeObservationUserTask(
  hookName: string,
  explicit: string,
): string {
  if (explicit) {
    return explicit;
  }
  switch (hookName) {
    case "gateway_start":
    case "gateway_stop":
      return "OpenClaw gateway lifecycle";
    case "session_start":
    case "session_end":
      return "OpenClaw session lifecycle";
    case "before_compaction":
    case "after_compaction":
      return "OpenClaw context compaction";
    case "subagent_spawned":
    case "subagent_ended":
      return "OpenClaw subagent lifecycle";
    case "cron_changed":
      return "OpenClaw cron configuration update";
    case "resolve_exec_env":
      return "OpenClaw execution environment resolution";
    case "message_received":
      return "OpenClaw inbound message handling";
    case "before_message_write":
      return "OpenClaw transcript persistence";
    default:
      return "OpenClaw runtime observation";
  }
}

export function runtimeResourceTargets(...values: unknown[]): string[] {
  for (const value of values) {
    const target = runtimeResourceTarget(value);
    if (target) {
      return [target];
    }
  }
  return [];
}

export function runtimeResourceTarget(value: unknown): string | undefined {
  const preview = redactSensitiveCredentials(stringPreview(value)).trim();
  if (!preview) {
    return undefined;
  }
  return preview.length > 240 ? `${preview.slice(0, 240)}...` : preview;
}

export function definedMetadata(values: Record<string, unknown>): JsonObject {
  const metadata: JsonObject = {};
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "") {
      metadata[key] = value;
    }
  }
  return metadata;
}

export function runtimePolicyForTool(
  event: RuntimeSecurityFields,
  context: RuntimeSecurityFields,
): JsonObject | undefined {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  for (const value of [
    eventRecord.runtimePolicy,
    eventRecord.runtime_policy,
    contextRecord.runtimePolicy,
    contextRecord.runtime_policy,
  ]) {
    const policy = sanitizedRuntimePolicy(value);
    if (policy) {
      return policy;
    }
  }

  const toolName =
    stringMaybe(eventRecord.toolName) ?? stringMaybe(contextRecord.toolName);
  if (!toolName) {
    return undefined;
  }
  for (const mapValue of [
    eventRecord.toolRuntimePolicies,
    eventRecord.tool_runtime_policies,
    contextRecord.toolRuntimePolicies,
    contextRecord.tool_runtime_policies,
  ]) {
    const policy = sanitizedRuntimePolicy(asRecord(mapValue)[toolName]);
    if (policy) {
      return policy;
    }
  }
  return undefined;
}

export function sanitizedRuntimePolicy(value: unknown): JsonObject | undefined {
  const record = asRecord(value);
  const policy: JsonObject = {};
  const copyKeys = [
    "browser_expected",
    "tool_manifest_scoped",
    "declared_tools",
    "mcp_boundary_required",
  ];
  for (const key of copyKeys) {
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

export function firstNonEmpty(
  ...values: Array<string | null | undefined>
): string {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return createLocalId("trace");
}

export function createLocalId(prefix: string): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `${prefix}_${crypto.randomUUID()}`;
  }
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2)}`;
}

export function uniqueStrings(
  values: ReadonlyArray<string | null | undefined>,
): string[] {
  return [
    ...new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.length > 0,
      ),
    ),
  ];
}

export function runtimeSecurityFields(
  event: RuntimeSecurityFields,
  context: RuntimeSecurityFields,
  options: RuntimeSecurityOptions = {},
): { userTask: string; sourceTrust: string; sourceType: string } {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const sourceType =
    stringMaybe(eventRecord.sourceType ?? eventRecord.source_type) ??
    stringMaybe(contextRecord.sourceType ?? contextRecord.source_type) ??
    "openclaw";
  const explicitTrust =
    stringMaybe(eventRecord.sourceTrust ?? eventRecord.source_trust) ??
    stringMaybe(contextRecord.sourceTrust ?? contextRecord.source_trust);
  return {
    userTask:
      extractRuntimeUserTask([eventRecord, contextRecord], options) ?? "",
    sourceTrust:
      explicitTrust ?? inferSourceTrust(eventRecord, contextRecord, sourceType),
    sourceType,
  };
}

export function inferSourceTrust(
  event: RuntimeSecurityFields & JsonObject,
  context: RuntimeSecurityFields & JsonObject,
  sourceType: string,
): string {
  const normalizedType = sourceType.toLowerCase();
  if (isUntrustedSourceType(normalizedType)) {
    return "untrusted";
  }
  const resources = normalizeDerivedResources(
    event.derivedResources ?? context.derivedResources,
  );
  if (
    resources.some((resource) =>
      resourceLooksLikeInboundExternalContent(resource),
    )
  ) {
    return "untrusted";
  }
  const paths = uniqueStrings(event.derivedPaths ?? context.derivedPaths ?? []);
  if (paths.some(isHttpUrl) && runtimeContentWillEnterContext(event, context)) {
    return "untrusted";
  }
  if (isTrustedSourceType(normalizedType)) {
    return "trusted";
  }
  return "trusted";
}

export function isUntrustedSourceType(value: string): boolean {
  return [
    "retrieved",
    "retrieval",
    "rag",
    "tool_result",
    "web",
    "web_fetch",
    "browser",
    "search",
    "search_result",
    "remote",
    "external",
    "document",
  ].some((marker) => value.includes(marker));
}

export function isTrustedSourceType(value: string): boolean {
  return [
    "trusted",
    "user",
    "system",
    "developer",
    "openclaw",
    "runtime",
    "plugin_manifest",
  ].some((marker) => value === marker || value.startsWith(`${marker}_`));
}

export function resourceLooksLikeInboundExternalContent(
  resource: DerivedResource,
): boolean {
  if (resource.direction.toLowerCase() !== "inbound") {
    return false;
  }
  const type = resource.resource_type.toLowerCase();
  return (
    isHttpUrl(resource.target) ||
    ["api", "web", "browser", "search", "document", "tool_result"].some(
      (marker) => type.includes(marker),
    )
  );
}

export function runtimeContentWillEnterContext(
  event: RuntimeSecurityFields & JsonObject,
  context: RuntimeSecurityFields & JsonObject,
): boolean {
  if (event.willEnterContext === true || context.willEnterContext === true) {
    return true;
  }
  return Boolean(
    event.prompt ??
    event.messages ??
    event.context ??
    event.result ??
    event.output ??
    context.prompt ??
    context.messages ??
    context.context ??
    context.result ??
    context.output,
  );
}

export function extractRuntimeUserTask(
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
    const fromMessages =
      userTaskFromMessages(value.messages) ??
      userTaskFromMessages(asRecord(value.prompt).messages);
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
      const content =
        stringMaybe(value.content) ??
        stringMaybe(value.text) ??
        stringMaybe(value.body) ??
        stringMaybe(value.message);
      if (content) {
        return sanitizeUserTask(content);
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

export function sanitizeUserTask(value: string): string {
  const redacted = redactSensitiveCredentials(value);
  return redacted.length > 1000 ? `${redacted.slice(0, 1000)}...` : redacted;
}

export function asRecord(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function stringValue(value: unknown, fallback: string): string {
  const parsed = stringMaybe(value);
  return parsed ?? fallback;
}

export function stringMaybe(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function sanitizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJson(item));
  }
  if (typeof value === "string") {
    return redactSensitiveCredentials(value, PREVIEW_LIMIT);
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  const sanitized: JsonObject = {};
  for (const [key, nestedValue] of Object.entries(value)) {
    sanitized[key] = SENSITIVE_KEY_PATTERN.test(key)
      ? "[redacted]"
      : sanitizeJson(nestedValue);
  }
  return sanitized;
}

export function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
