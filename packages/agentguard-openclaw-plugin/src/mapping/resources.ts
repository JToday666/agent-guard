import type { DerivedResource, JsonObject } from "../types.js";
import {
  containsSensitiveCredentialText,
  isExecLikeToolIdentity,
  redactSensitiveCredentials,
} from "../security.js";
import type {
  BeforeToolCallEventInput,
  DerivedResourceInput,
  MessageHookContextInput,
  MessageSendingEventInput,
  RuntimeSecurityFields,
  ToolHookContextInput,
  ToolResultPersistEventInput,
} from "./common.js";
import {
  asRecord,
  inferSourceTrust,
  runtimeResourceTargets,
  sanitizeJson,
  stringMaybe,
  stringValue,
  uniqueStrings,
} from "./common.js";
import {
  browserTargetText,
  toolCommandText,
  toolTargetText,
} from "./content.js";

export function derivedResourcesForTool(
  event: BeforeToolCallEventInput,
  context: ToolHookContextInput,
  toolArgs: JsonObject,
): DerivedResource[] {
  const explicit = normalizeDerivedResources(
    event.derivedResources ?? context.derivedResources,
  );
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(
    event.derivedPaths ?? context.derivedPaths ?? [],
  );
  if (derivedTargets.length > 0) {
    return derivedTargets.map((target) =>
      inferDerivedResource({
        toolName: event.toolName,
        toolKind: event.toolKind ?? context.toolKind,
        toolInputKind: event.toolInputKind ?? context.toolInputKind,
        params: toolArgs,
        target,
      }),
    );
  }
  if (event.toolName === "mcp_call") {
    const resources = derivedResourcesForMcpCall(toolArgs);
    if (resources.length > 0) {
      return resources;
    }
  }
  const browserTarget = browserTargetText(toolArgs);
  if (
    isBrowserToolIdentity(
      event.toolName,
      event.toolKind ?? context.toolKind,
      event.toolInputKind ?? context.toolInputKind,
    ) &&
    browserTarget
  ) {
    return [
      {
        resource_type: "browser",
        operation: browserOperation(
          event.toolName,
          event.toolKind ?? context.toolKind,
        ),
        target: browserTarget,
        data_classification: null,
        direction: "runtime",
      },
    ];
  }
  const command = toolCommandText(toolArgs);
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
  const argumentTarget = toolTargetText(toolArgs);
  if (argumentTarget) {
    return [
      inferDerivedResource({
        toolName: event.toolName,
        toolKind: event.toolKind ?? context.toolKind,
        toolInputKind: event.toolInputKind ?? context.toolInputKind,
        params: toolArgs,
        target: argumentTarget,
      }),
    ];
  }
  return [];
}

export function derivedResourcesForMcpCall(
  toolArgs: JsonObject,
): DerivedResource[] {
  const server = stringMaybe(
    toolArgs.server ?? toolArgs.mcp_server ?? toolArgs.target_server,
  );
  const tool = stringMaybe(
    toolArgs.tool ?? toolArgs.toolName ?? toolArgs.name ?? toolArgs.target_tool,
  );
  const resources: DerivedResource[] = [];
  if (server || tool) {
    resources.push({
      resource_type: "mcp_tool",
      operation: "call",
      target:
        server && tool ? `${server}.${tool}` : (tool ?? server ?? "unknown"),
      data_classification: null,
      direction: "outbound",
    });
  }

  const nestedArguments = asRecord(
    toolArgs.arguments ?? toolArgs.args ?? toolArgs.params,
  );
  for (const target of urlTargetsFromJson(nestedArguments)) {
    resources.push({
      resource_type: "api",
      operation: "POST",
      target,
      data_classification: null,
      direction: "outbound",
    });
  }
  return resources;
}

export function urlTargetsFromJson(value: unknown, depth = 0): string[] {
  if (depth > 8) {
    return [];
  }
  const direct = stringMaybe(value);
  if (direct && isHttpUrl(direct)) {
    return [direct];
  }
  if (Array.isArray(value)) {
    return uniqueStrings(
      value.flatMap((item) => urlTargetsFromJson(item, depth + 1)),
    );
  }
  const record = asRecord(value);
  return uniqueStrings(
    Object.values(record).flatMap((item) =>
      urlTargetsFromJson(item, depth + 1),
    ),
  );
}

export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function derivedResourcesForToolResult(
  event: ToolResultPersistEventInput,
  context: ToolHookContextInput,
  toolName: string,
): DerivedResource[] {
  const explicit = normalizeDerivedResources(
    event.derivedResources ?? context.derivedResources,
  );
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(
    event.derivedPaths ?? context.derivedPaths ?? [],
  );
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

export function derivedResourcesForMessage(
  event: MessageSendingEventInput,
  context: MessageHookContextInput,
): DerivedResource[] {
  const explicit = normalizeDerivedResources(
    event.derivedResources ?? context.derivedResources,
  );
  if (explicit.length > 0) {
    return explicit;
  }
  const derivedTargets = uniqueStrings(
    event.derivedPaths ?? context.derivedPaths ?? [],
  );
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

export function derivedPathTargets(
  event: RuntimeSecurityFields,
  context: RuntimeSecurityFields,
  resources: readonly DerivedResource[],
): string[] {
  const explicitPaths = uniqueStrings(
    event.derivedPaths ?? context.derivedPaths ?? [],
  );
  if (explicitPaths.length > 0) {
    return explicitPaths;
  }
  return uniqueStrings(resources.map((resource) => resource.target));
}

export function normalizeDerivedResources(
  values: readonly DerivedResourceInput[] | undefined,
): DerivedResource[] {
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
      resource_type: stringValue(
        record.resource_type ?? record.resourceType,
        "resource",
      ),
      operation: stringValue(record.operation, "unknown"),
      target,
      data_classification:
        stringMaybe(record.data_classification ?? record.dataClassification) ??
        null,
      direction: stringValue(record.direction, "local"),
    });
  }
  return resources;
}

export function inferDerivedResource(input: {
  toolName: string;
  toolKind?: string;
  toolInputKind?: string;
  params: JsonObject;
  target: string;
}): DerivedResource {
  const toolName = input.toolName.toLowerCase();
  const toolIdentity =
    `${input.toolName} ${input.toolKind ?? ""} ${input.toolInputKind ?? ""}`.toLowerCase();
  const method = stringMaybe(input.params.method)?.toUpperCase();
  if (
    isBrowserToolIdentity(input.toolName, input.toolKind, input.toolInputKind)
  ) {
    return {
      resource_type: "browser",
      operation: browserOperation(input.toolName, input.toolKind),
      target: input.target,
      data_classification: null,
      direction: "runtime",
    };
  }
  if (
    toolName === "call_api" ||
    toolIdentity.includes("api") ||
    toolIdentity.includes("http") ||
    /^https?:\/\//i.test(input.target)
  ) {
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
      operation: operationFromToolIdentity(
        toolIdentity,
        "write",
        "read",
        "search",
      ),
      target: input.target,
      data_classification: null,
      direction: "local",
    };
  }
  if (
    toolIdentity.includes("message") ||
    toolIdentity.includes("send") ||
    toolIdentity.includes("email")
  ) {
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

export function operationFromToolIdentity(
  identity: string,
  writeOperation: string,
  readOperation: string,
  searchOperation?: string,
): string {
  if (
    identity.includes("write") ||
    identity.includes("create") ||
    identity.includes("update")
  ) {
    return writeOperation;
  }
  if (searchOperation && identity.includes("search")) {
    return searchOperation;
  }
  if (
    identity.includes("read") ||
    identity.includes("fetch") ||
    identity.includes("get")
  ) {
    return readOperation;
  }
  return "unknown";
}

export function isBrowserToolIdentity(
  toolName: string,
  toolKind?: string,
  toolInputKind?: string,
): boolean {
  const identity =
    `${toolName} ${toolKind ?? ""} ${toolInputKind ?? ""}`.toLowerCase();
  return identity.includes("browser");
}

export function browserOperation(toolName: string, toolKind?: string): string {
  const identity = `${toolName} ${toolKind ?? ""}`.toLowerCase();
  if (
    identity.includes("input") ||
    identity.includes("fill") ||
    identity.includes("type")
  ) {
    return "input";
  }
  if (
    identity.includes("click") ||
    identity.includes("submit") ||
    identity.includes("publish")
  ) {
    return "click";
  }
  if (
    identity.includes("extract") ||
    identity.includes("inspect") ||
    identity.includes("read")
  ) {
    return "extract";
  }
  if (
    identity.includes("start") ||
    identity.includes("navigate") ||
    identity.includes("open")
  ) {
    return "open";
  }
  return "browser";
}
