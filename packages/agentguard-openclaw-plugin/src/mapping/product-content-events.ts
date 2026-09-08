import { randomUUID } from "node:crypto";
import {
  snapshotProductNativeData,
  verifyProductNativeToolArgumentText,
} from "../runtime/product-native-stream.js";
import type {
  GuardEvent,
  JsonObject,
  GuardEvaluationResponse,
} from "../types.js";
import type {
  ProductContentBinding,
  ProductContextSource,
  ProductPreparedContext,
  FrozenNativeModelInput,
} from "../runtime/product-content-types.js";
import {
  freezeProductValue,
  snapshotProductJson,
  readNativeProductFields,
  productActionError,
  type NativeProductToolCall,
} from "./product-events.js";
import {
  restrictedCanonicalJson,
  restrictedDigest,
} from "../runtime/canonical.js";

export function productContentText(value: unknown): string {
  const snapshot = snapshotProductJson(value);
  const text =
    typeof snapshot === "string" ? snapshot : restrictedCanonicalJson(snapshot);
  if (Buffer.byteLength(text) > 64 * 1024)
    productActionError("native_content_too_large");
  return text;
}
function flags(text: string): {
  contains_instruction_like_text: boolean;
  contains_sensitive_data: boolean;
} {
  return {
    contains_instruction_like_text:
      /ignore (?:all |previous )?instructions|system override|developer message|bypass (?:guard|security)/iu.test(
        text,
      ),
    contains_sensitive_data:
      /(?:password|api[_-]?key|secret|token)\s*[:=]|-----BEGIN .*PRIVATE KEY/iu.test(
        text,
      ),
  };
}
function event(
  binding: ProductContentBinding,
  type: GuardEvent["event_type"],
  payload: JsonObject,
  refs: readonly string[] = [],
  metadata: JsonObject = {},
): GuardEvent {
  const value = {
    schema_version: "0.3",
    event_id: `evt_oc_${randomUUID().replaceAll("-", "")}`,
    event_type: type,
    runtime: "openclaw",
    trace_id: binding.traceId,
    timestamp: new Date().toISOString(),
    pre_execution: !["model_output_produced", "tool_result_produced"].includes(
      type,
    ),
    security_context: {
      user_task: binding.userTask,
      source_type: type === "tool_result_produced" ? "tool_result" : "user",
      source_trust: type === "tool_result_produced" ? "untrusted" : "trusted",
      agent_id: binding.agentId,
      session_id: binding.sessionKey,
      session_key: binding.sessionKey,
      current_step: type,
      context_sources: [],
      derived_paths: [],
      visible_source_refs: [...refs],
      metadata: {},
    },
    payload,
    metadata: {
      task_id: binding.taskId,
      native_full_content: true,
      ...metadata,
    },
  };
  if (Buffer.byteLength(restrictedCanonicalJson(value)) > 128 * 1024)
    productActionError("native_content_too_large");
  return freezeProductValue(value) as unknown as GuardEvent;
}
export function buildProductContextEvent(
  binding: ProductContentBinding,
  sources: readonly ProductContextSource[],
): GuardEvent {
  const frozen = snapshotProductJson(sources) as ProductContextSource[];
  if (frozen.length < 1 || frozen.length > 20)
    productActionError("native_context_sources_invalid");
  return event(binding, "context_assembled", {
    sources: frozen.map((source, sequence_index) => {
      const summary = productContentText(source.content);
      return {
        source_id: source.source_id,
        source_type: source.source_type,
        source_trust: source.source_trust,
        role: source.role,
        sequence_index,
        content_digest: restrictedDigest(source.content),
        summary,
        ...flags(summary),
      };
    }),
    will_enter_context: true,
    sanitized: false,
  });
}
export function buildProductModelEvent(
  binding: ProductContentBinding,
  phase: "input" | "output",
  content: unknown,
  context: ProductPreparedContext,
  inputPolicyAuditId?: string,
): GuardEvent {
  const text = productContentText(content);
  if (phase === "output" && !inputPolicyAuditId)
    productActionError("native_model_parent_missing");
  return event(
    binding,
    phase === "input" ? "model_input_prepared" : "model_output_produced",
    {
      phase,
      content_preview: text,
      provider: binding.provider,
      model: binding.modelId,
      ...flags(text),
      sanitized: false,
      tool_plan: [],
      ...(phase === "input"
        ? {
            context_plan_id: context.planId,
            context_plan_digest: context.planDigest,
            context_ref: context.contextRef,
            visible_source_refs: [...context.visibleSourceRefs],
          }
        : {}),
    },
    context.visibleSourceRefs,
    phase === "output"
      ? { product_model_input_audit_id: inputPolicyAuditId }
      : {},
  );
}
export function buildProductResultEvent(
  binding: ProductContentBinding,
  call: NativeProductToolCall,
  action: GuardEvent,
  evaluation: GuardEvaluationResponse,
  result: unknown,
): GuardEvent {
  const text = productContentText(result);
  const original = action.security_context as unknown as JsonObject;
  const refs = original.visible_source_refs;
  if (!Array.isArray(refs) || !evaluation.policy_audit_id)
    productActionError("native_result_parent_missing");
  const category = call.toolName.startsWith("agentguard_memory_")
    ? "memory"
    : call.toolName === "message"
      ? "message"
      : ["exec", "process"].includes(call.toolName)
        ? "process"
        : "file";
  return event(
    binding,
    "tool_result_produced",
    {
      tool: { name: call.toolName, call_id: call.toolCallId, category },
      result: {
        content_preview: text,
        content_type: "application/json",
        size_bytes: Buffer.byteLength(text),
      },
      will_enter_context: true,
      will_persist: true,
      sanitized: false,
      ...flags(text),
      derived_resources: [],
    },
    refs as string[],
    {
      product_tool_result: {
        action_event_id: action.event_id,
        action_policy_audit_id: evaluation.policy_audit_id,
      },
    },
  );
}

/** Complete native AssistantMessage -> exact model content commitment, no dropped blocks. */
export function normalizeProductModelOutput(raw: unknown): Readonly<{
  message: unknown;
  projection: JsonObject;
  call?: Readonly<{ id: string; name: string; args: JsonObject }>;
}> {
  const message = readNativeProductFields(snapshotProductNativeData(raw));
  if (
    message.role !== "assistant" ||
    !Array.isArray(message.content) ||
    !["stop", "toolUse"].includes(message.stopReason as string)
  )
    productActionError("native_model_output_invalid");
  if (
    Object.keys(message).some(
      (k) =>
        ![
          "role",
          "content",
          "api",
          "provider",
          "model",
          "responseModel",
          "responseId",
          "usage",
          "stopReason",
          "timestamp",
        ].includes(k),
    )
  )
    productActionError("native_model_output_invalid");
  productContentText(message.content);
  const content: unknown[] = [];
  const calls: {
    id: string;
    name: string;
    args: JsonObject;
    type: "tool_call";
  }[] = [];
  for (const rawBlock of message.content) {
    const block = readNativeProductFields(rawBlock);
    if (block.type === "text") {
      if (
        typeof block.text !== "string" ||
        Object.keys(block).some(
          (k) => !["type", "text", "textSignature"].includes(k),
        )
      )
        productActionError("native_model_output_invalid");
      content.push(block);
    } else if (block.type === "thinking") {
      if (
        typeof block.thinking !== "string" ||
        Object.keys(block).some(
          (k) =>
            !["type", "thinking", "thinkingSignature", "redacted"].includes(k),
        )
      )
        productActionError("native_model_output_invalid");
      content.push(block);
    } else if (block.type === "toolCall") {
      if (
        Object.keys(block).some(
          (k) =>
            ![
              "type",
              "id",
              "name",
              "arguments",
              "thoughtSignature",
              "partialArgs",
            ].includes(k),
        ) ||
        typeof block.id !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(block.id) ||
        typeof block.name !== "string"
      )
        productActionError("native_model_output_invalid");
      const args = readNativeProductFields(block.arguments);
      if (block.partialArgs !== undefined) {
        verifyProductNativeToolArgumentText(block.partialArgs, args);
        content.push({
          type: "tool_argument_text",
          call_id: block.id,
          text: block.partialArgs,
        });
      }
      calls.push({ id: block.id, name: block.name, args, type: "tool_call" });
      // Signature is transport metadata, but still retain it in the full inspected content.
      if (block.thoughtSignature !== undefined)
        content.push({ type: "tool_signature", value: block.thoughtSignature });
    } else productActionError("native_model_output_invalid");
  }
  if (
    calls.length > 1 ||
    calls.length > 0 !== (message.stopReason === "toolUse")
  )
    productActionError("native_model_output_invalid");
  const projection = { content, tool_calls: calls, invalid_tool_calls: [] };
  productContentText(projection);
  return freezeProductValue({
    message,
    projection,
    ...(calls[0] ? { call: calls[0] } : {}),
  });
}

export function freezeProductModelInput(
  raw: FrozenNativeModelInput,
): FrozenNativeModelInput {
  const input = readNativeProductFields(snapshotProductNativeData(raw));
  if (
    Object.keys(input).sort().join("|") !==
      "messages|modelId|provider|systemPrompt|tools" ||
    typeof input.provider !== "string" ||
    typeof input.modelId !== "string" ||
    typeof input.systemPrompt !== "string" ||
    !Array.isArray(input.messages) ||
    !Array.isArray(input.tools)
  )
    productActionError("native_model_input_invalid");
  productContentText({
    ...input,
    messages: (input.messages as unknown[]).map((raw) => {
      const message = readNativeProductFields(raw);
      return message.role === "assistant"
        ? { role: "assistant", content: message.content }
        : message;
    }),
  });
  return freezeProductValue(input) as FrozenNativeModelInput;
}

/** Core memory normalizer segment escaping, not URL percent encoding. */
export function productMemorySourceId(namespace: string, key: string): string {
  if (
    !namespace ||
    !key ||
    namespace.length > 4096 ||
    key.length > 256 ||
    /[\u0000-\u001f]/u.test(namespace + key)
  )
    productActionError("native_memory_identity_invalid");
  const escape = (value: string): string =>
    value.replaceAll("\\", "\\\\").replaceAll("/", "\\/");
  return `memory://${escape(namespace)}/${escape(key)}`;
}
