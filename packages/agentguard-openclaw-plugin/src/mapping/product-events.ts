import { types } from "node:util";
import { posix } from "node:path";
import type { GuardEvent, JsonObject } from "../types.js";
import {
  restrictedCanonicalJson,
  restrictedDigest,
} from "../runtime/canonical.js";
import { OpenClawProductActivationError } from "../runtime/product-manifest.js";

export type NativeProductToolCall = Readonly<{
  toolName: string;
  toolCallId: string;
  runId: string;
  sessionKey: string;
  agentId: string;
  argumentsJson: string;
}>;
/** Supplied by the trusted model boundary, never copied from hook metadata. */
export type OpenClawProductActionOrigin = Readonly<{
  modelOutputAuditId: string;
  modelSourceRef: string;
  callId: string;
  runId: string;
  argumentsDigest: string;
  taskId: string;
  userTask: string;
  traceId: string;
  visibleSourceRefs: readonly string[];
}>;
export type OpenClawProductToolProfile = Readonly<{
  agentId: string;
  workspaceRoot: string;
  memoryNamespace: string;
  inboxUrl: string;
}>;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const KEYS: Record<string, readonly string[]> = {
  read: ["path"],
  write: ["content", "path"],
  edit: ["edits", "path"],
  exec: ["command"],
  process: ["action"],
  agentguard_memory_read: ["key"],
  agentguard_memory_write: ["key", "value"],
  message: ["action", "channel", "message", "target"],
};
export function productActionError(code = "native_action_invalid"): never {
  throw new OpenClawProductActivationError(code);
}
/** Bounded own-data snapshot; no getter, proxy, toJSON or prototype execution. */
export function snapshotProductJson(value: unknown): unknown {
  let count = 0;
  const active = new Set<object>();
  const copy = (item: unknown, depth: number): unknown => {
    if (++count > 10000 || depth > 24) productActionError();
    if (item === null || typeof item !== "object") {
      restrictedCanonicalJson(item);
      return item;
    }
    if (types.isProxy(item) || active.has(item)) productActionError();
    const proto = Object.getPrototypeOf(item);
    if (!Array.isArray(item) && proto !== Object.prototype && proto !== null)
      productActionError();
    if (Object.getOwnPropertySymbols(item).length) productActionError();
    active.add(item);
    const fields = Object.getOwnPropertyDescriptors(item);
    if (
      Array.isArray(item) &&
      (item.length > 10000 || Object.keys(fields).length !== item.length + 1)
    )
      productActionError();
    const result: JsonObject | unknown[] = Array.isArray(item)
      ? new Array(item.length)
      : Object.create(null);
    for (const [key, field] of Object.entries(fields)) {
      if (!("value" in field)) productActionError();
      if (Array.isArray(item) && key === "length") continue;
      if (Array.isArray(item) && !/^(0|[1-9][0-9]*)$/u.test(key))
        productActionError();
      Object.defineProperty(result, key, {
        value: copy(field.value, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    active.delete(item);
    return result;
  };
  try {
    const result = copy(value, 0);
    if (Buffer.byteLength(restrictedCanonicalJson(result)) > 256 * 1024)
      productActionError();
    return result;
  } catch {
    return productActionError();
  }
}
export function readNativeProductFields(value: unknown): JsonObject {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value)
  )
    productActionError();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) productActionError();
  if (Object.getOwnPropertySymbols(value).length) productActionError();
  const result: JsonObject = Object.create(null);
  for (const [key, field] of Object.entries(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (!("value" in field)) productActionError();
    result[key] = field.value;
  }
  return result;
}
export function readNativeProductToolCall(
  event: unknown,
  context: unknown,
): NativeProductToolCall {
  const e = readNativeProductFields(event),
    c = readNativeProductFields(context);
  for (const key of ["toolName", "toolCallId", "runId"]) {
    if (
      typeof e[key] !== "string" ||
      !ID.test(e[key] as string) ||
      e[key] !== c[key]
    )
      productActionError("native_identity_mismatch");
  }
  if (
    typeof c.agentId !== "string" ||
    !ID.test(c.agentId) ||
    typeof c.sessionKey !== "string" ||
    !ID.test(c.sessionKey)
  )
    productActionError("native_identity_missing");
  if (e.toolKind || c.toolKind || e.toolInputKind || c.toolInputKind)
    productActionError("native_tool_not_admitted");
  const args = snapshotProductJson(e.params) as JsonObject;
  const name = e.toolName as string;
  const keys = KEYS[name];
  if (
    !keys ||
    !args ||
    Array.isArray(args) ||
    Object.keys(args).sort().join("|") !== keys.join("|")
  )
    productActionError("native_arguments_invalid");
  for (const [key, value] of Object.entries(args)) {
    if (key !== "edits" && (typeof value !== "string" || value.length > 32768))
      productActionError("native_arguments_invalid");
  }
  if (
    "path" in args &&
    (typeof args.path !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(args.path))
  )
    productActionError("native_arguments_invalid");
  if (
    "key" in args &&
    (typeof args.key !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(args.key))
  )
    productActionError("native_arguments_invalid");
  if (name === "exec" && args.command !== "node marker.mjs")
    productActionError("native_arguments_invalid");
  if (name === "process" && args.action !== "list")
    productActionError("native_arguments_invalid");
  if (
    name === "message" &&
    (args.action !== "send" ||
      args.channel !== "agentguard-fixture" ||
      args.target !== "fixture-inbox")
  )
    productActionError("native_arguments_invalid");
  if (name === "edit") {
    if (
      !Array.isArray(args.edits) ||
      args.edits.length < 1 ||
      args.edits.length > 8
    )
      productActionError("native_arguments_invalid");
    for (const raw of args.edits) {
      const edit = readNativeProductFields(raw);
      if (
        Object.keys(edit).sort().join("|") !== "newText|oldText" ||
        typeof edit.oldText !== "string" ||
        !edit.oldText ||
        typeof edit.newText !== "string" ||
        Math.max(edit.oldText.length, edit.newText.length) > 32768
      )
        productActionError("native_arguments_invalid");
    }
  }
  return Object.freeze({
    toolName: name,
    toolCallId: e.toolCallId as string,
    runId: e.runId as string,
    sessionKey: c.sessionKey,
    agentId: c.agentId,
    argumentsJson: restrictedCanonicalJson(args),
  });
}
export function readNativeProductAfter(
  event: unknown,
): Readonly<{ failed: boolean; result: unknown }> {
  const e = readNativeProductFields(event);
  if (e.error !== undefined && typeof e.error !== "string")
    productActionError("native_terminal_invalid");
  const result =
    e.result === undefined ? undefined : snapshotProductJson(e.result);
  return {
    failed:
      (typeof e.error === "string" && e.error.length > 0) ||
      nativeResultFailed(result),
    result,
  };
}
/** Pinned Host tool-result-error contract, on already snapshotted JSON only.
 * Keep failure signals separate from falsy successful values and text content. */
function nativeResultFailed(result: unknown): boolean {
  if (!result || typeof result !== "object" || Array.isArray(result))
    return false;
  const raw = result as JsonObject;
  if (raw.isError === true) return true;
  const details = raw.details;
  if (!details || typeof details !== "object" || Array.isArray(details))
    return false;
  const d = details as JsonObject;
  if (
    d.ok === false ||
    d.success === false ||
    d.timedOut === true ||
    Boolean(d.error)
  )
    return true;
  if (typeof d.exitCode === "number" && d.exitCode !== 0) return true;
  const status =
    typeof d.status === "string" ? d.status.trim().toLowerCase() : "";
  return (
    d.ok !== true &&
    d.success !== true &&
    [
      "error",
      "failed",
      "failure",
      "timeout",
      "timed_out",
      "blocked",
      "denied",
      "forbidden",
      "unavailable",
      "approval-unavailable",
      "disabled",
      "aborted",
      "cancelled",
      "canceled",
      "killed",
      "invalid",
    ].includes(status)
  );
}
export function nativeProductCallKey(call: NativeProductToolCall): string {
  return restrictedCanonicalJson([
    call.agentId,
    call.sessionKey,
    call.runId,
    call.toolCallId,
  ]);
}
export function buildProductToolEvent(
  call: NativeProductToolCall,
  rawOrigin: OpenClawProductActionOrigin,
  profile: OpenClawProductToolProfile,
): GuardEvent {
  const origin = snapshotProductJson(
    rawOrigin,
  ) as unknown as OpenClawProductActionOrigin;
  if (
    call.agentId !== profile.agentId ||
    !posix.isAbsolute(profile.workspaceRoot) ||
    profile.workspaceRoot === "/" ||
    posix.normalize(profile.workspaceRoot) !== profile.workspaceRoot ||
    profile.workspaceRoot.includes("\\") ||
    profile.workspaceRoot.includes("\0") ||
    profile.memoryNamespace !== `${profile.workspaceRoot}/memory.sqlite` ||
    !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/inbox$/u.test(profile.inboxUrl) ||
    Number(new URL(profile.inboxUrl).port) > 65535
  )
    productActionError("native_profile_invalid");
  if (
    origin.callId !== call.toolCallId ||
    origin.runId !== call.runId ||
    origin.argumentsDigest !==
      restrictedDigest(JSON.parse(call.argumentsJson)) ||
    !ID.test(origin.modelOutputAuditId) ||
    !ID.test(origin.traceId) ||
    !ID.test(origin.taskId) ||
    typeof origin.userTask !== "string" ||
    !origin.userTask ||
    typeof origin.modelSourceRef !== "string" ||
    !origin.modelSourceRef.startsWith("source:model:") ||
    !Array.isArray(origin.visibleSourceRefs) ||
    origin.visibleSourceRefs.length > 256 ||
    new Set(origin.visibleSourceRefs).size !==
      origin.visibleSourceRefs.length ||
    !origin.visibleSourceRefs.includes(origin.modelSourceRef) ||
    origin.visibleSourceRefs.some(
      (x) => typeof x !== "string" || !x || x.length > 1024,
    )
  )
    productActionError("native_origin_invalid");
  const args = JSON.parse(call.argumentsJson) as JsonObject;
  const name = call.toolName;
  const eventType =
    name === "message"
      ? "message_send_proposed"
      : name === "agentguard_memory_write"
        ? "memory_write_proposed"
        : "tool_call_proposed";
  const eventId = `evt_oc_${restrictedDigest([call, origin.modelOutputAuditId]).slice(7)}`;
  const category = name.startsWith("agentguard_memory_")
    ? "memory"
    : name === "message"
      ? "message"
      : ["exec", "process"].includes(name)
        ? "process"
        : "file";
  const target =
    "path" in args
      ? `${profile.workspaceRoot}/${args.path}`
      : "key" in args
        ? `${profile.memoryNamespace}/${args.key}`
        : name === "message"
          ? profile.inboxUrl
          : profile.workspaceRoot;
  const resource = {
    resource_type: category,
    operation: name.includes("read")
      ? "read"
      : name === "message"
        ? "send"
        : name === "process"
          ? "list"
          : "write",
    target,
    direction: name === "message" ? "outbound" : "internal",
  };
  let payload: JsonObject;
  if (name === "message")
    payload = {
      channel: args.channel,
      recipient: args.target,
      content_preview: args.message,
      contains_sensitive_data:
        /(?:password|api[_-]?key|secret|token)\s*[:=]|-----BEGIN .*PRIVATE KEY/iu.test(
          args.message as string,
        ),
      sanitized: false,
      derived_resources: [resource],
    };
  else if (name === "agentguard_memory_write")
    payload = {
      action_id: call.toolCallId,
      memory: {
        namespace: profile.memoryNamespace,
        key: args.key,
        value_preview: args.value,
        source_trust: "unknown",
        operation: "write",
      },
      will_persist: true,
      requires_approval: true,
    };
  else
    payload = {
      tool: { name, category, call_id: call.toolCallId },
      arguments: args,
      derived_resources: [resource],
    };
  const event = {
    schema_version: "0.3",
    event_id: eventId,
    event_type: eventType,
    runtime: "openclaw",
    trace_id: origin.traceId,
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      user_task: origin.userTask,
      source_type: "model",
      source_trust: "unknown",
      agent_id: profile.agentId,
      session_key: call.sessionKey,
      run_id: call.runId,
      current_step: eventType,
      context_sources: [],
      derived_paths: [target],
      visible_source_refs: [...origin.visibleSourceRefs],
      metadata: {},
    },
    payload,
    metadata: {
      task_id: origin.taskId,
      native_full_content: true,
      product_model_content: {
        model_output_audit_id: origin.modelOutputAuditId,
        model_source_ref: origin.modelSourceRef,
        call_id: call.toolCallId,
      },
      ...(eventType !== "tool_call_proposed"
        ? { product_tool_call: { tool_name: name, call_id: call.toolCallId } }
        : {}),
    },
  };
  return freezeProductValue(event) as unknown as GuardEvent;
}
export function productCanonicalActionId(event: GuardEvent): string {
  if (event.event_type === "message_send_proposed")
    return `act_${event.event_id}`;
  const p = event.payload as JsonObject;
  return (
    event.event_type === "memory_write_proposed"
      ? p.action_id
      : (p.tool as JsonObject).call_id
  ) as string;
}
export function freezeProductValue<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) freezeProductValue(item);
    Object.freeze(value);
  }
  return value;
}
