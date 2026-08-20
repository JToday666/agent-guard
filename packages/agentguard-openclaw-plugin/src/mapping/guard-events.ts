import type { GuardEvent, JsonObject } from "../types.js";
import { redactSensitiveCredentials } from "../security.js";
import {
  RuntimeSecurityFields,
  RuntimeSecurityOptions,
  DerivedResourceInput,
  BeforeToolCallEventInput,
  ToolHookContextInput,
  MessageSendingEventInput,
  MessageHookContextInput,
  ToolResultPersistEventInput,
  PromptBuildEventInput,
  ModelHookEventInput,
  BeforeInstallEventInput,
  RuntimeObservationContextInput,
  PREVIEW_LIMIT,
  SENSITIVE_KEY_PATTERN,
  runtimeObservationResourceTargets,
  runtimeObservationUserTask,
  runtimeResourceTargets,
  runtimeResourceTarget,
  definedMetadata,
  runtimePolicyForTool,
  sanitizedRuntimePolicy,
  firstNonEmpty,
  createLocalId,
  uniqueStrings,
  runtimeSecurityFields,
  inferSourceTrust,
  isUntrustedSourceType,
  isTrustedSourceType,
  resourceLooksLikeInboundExternalContent,
  runtimeContentWillEnterContext,
  extractRuntimeUserTask,
  userTaskFromMessages,
  sanitizeUserTask,
  derivedResourcesForTool,
  derivedResourcesForMcpCall,
  urlTargetsFromJson,
  isHttpUrl,
  derivedResourcesForToolResult,
  derivedResourcesForMessage,
  derivedPathTargets,
  normalizeDerivedResources,
  inferDerivedResource,
  operationFromToolIdentity,
  isBrowserToolIdentity,
  browserOperation,
  truncate,
  buildInstallFindings,
  containsInstructionLikeText,
  containsSensitiveText,
  contextSourceSummaries,
  modelContentPreview,
  modelToolPlan,
  resultContentPreview,
  stringPreview,
  resultContentType,
  ragAnswerProvenanceForToolResult,
  toolCommandText,
  toolArguments,
  browserTargetText,
  toolTargetText,
  asRecord,
  stringValue,
  stringMaybe,
  sanitizeJson,
  byteLength,
} from "./internal.js";

export function buildToolCallGuardEvent(
  event: BeforeToolCallEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = event.runId ?? context.runId ?? null;
  const callId =
    event.toolCallId ?? context.toolCallId ?? createLocalId("call");
  // ⑥ hook 语境映射：工具调用由 agent 运行时发起。
  const security = runtimeSecurityFields(event, context, {
    sourceTypeFallback: "runtime_agent",
  });
  const toolArgs = toolArguments(event, context);
  const derivedResources = derivedResourcesForTool(event, context, toolArgs);
  const derivedPaths = derivedPathTargets(event, context, derivedResources);
  const runtimePolicy = runtimePolicyForTool(event, context);
  const taskId = stringMaybe(context.taskId ?? context.task_id);
  const securityMetadata: JsonObject = {
    session_key: context.sessionKey ?? null,
    tool_kind: event.toolKind ?? context.toolKind ?? null,
    tool_input_kind: event.toolInputKind ?? context.toolInputKind ?? null,
  };
  const eventMetadata: JsonObject = {
    openclaw_hook: "before_tool_call",
    session_key: context.sessionKey ?? null,
    ...(taskId ? { task_id: taskId } : {}),
  };
  if (runtimePolicy) {
    securityMetadata.runtime_policy = runtimePolicy;
    eventMetadata.runtime_policy = runtimePolicy;
  }

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
      session_key: context.sessionKey ?? null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: "before_tool_call",
      model_intent: null,
      context_sources: [],
      derived_paths: derivedPaths,
      metadata: securityMetadata,
    },
    payload: {
      tool: {
        name: event.toolName,
        category: "tool",
        kind: event.toolKind ?? context.toolKind ?? event.toolName,
        input_kind: event.toolInputKind ?? context.toolInputKind ?? null,
        call_id: callId,
      },
      arguments: toolArgs,
      derived_resources: derivedResources,
    },
    metadata: eventMetadata,
  };
}

export function buildMessageSendGuardEvent(
  event: MessageSendingEventInput,
  context: MessageHookContextInput = {},
): GuardEvent {
  const traceId = firstNonEmpty(
    context.runId,
    context.sessionKey,
    context.messageId,
    String(event.threadId ?? ""),
  );
  // ⑥ hook 语境映射：外发消息内容由 agent 运行时产出。
  const security = runtimeSecurityFields(event, context, {
    sourceTypeFallback: "runtime_agent",
  });
  const taskId = stringMaybe(context.taskId ?? context.task_id);
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
      conversation_id: context.conversationId ?? null,
      session_key: context.sessionKey ?? null,
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
      contains_sensitive_data: containsSensitiveText(event.content),
      sanitized: false,
      derived_resources: derivedResources,
    },
    metadata: {
      openclaw_hook: "message_sending",
      message_metadata: event.metadata ?? {},
      ...(taskId ? { task_id: taskId } : {}),
    },
  };
}

export function buildToolResultGuardEvent(
  event: ToolResultPersistEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = event.runId ?? context.runId ?? null;
  const callId =
    event.toolCallId ?? context.toolCallId ?? createLocalId("call");
  const toolName = event.toolName ?? context.toolName ?? "unknown";
  const rawResultPreview = resultContentPreview(event.result ?? event.message);
  const resultPreview = truncate(rawResultPreview, PREVIEW_LIMIT);
  // ⑥ hook 语境映射：工具执行结果属非受信外部内容。
  const security = runtimeSecurityFields(event, context, {
    sourceTypeFallback: "tool_result",
  });
  const derivedResources = derivedResourcesForToolResult(
    event,
    context,
    toolName,
  );
  const derivedPaths = derivedPathTargets(event, context, derivedResources);
  const ragAnswerProvenance = ragAnswerProvenanceForToolResult(
    event.result ?? event.message,
    toolName,
  );

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
      session_key: context.sessionKey ?? null,
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
      contains_instruction_like_text:
        containsInstructionLikeText(resultPreview),
      derived_resources: derivedResources,
    },
    metadata: {
      openclaw_hook: "tool_result_persist",
      session_key: context.sessionKey ?? null,
      ...(ragAnswerProvenance
        ? { rag_answer_provenance: ragAnswerProvenance }
        : {}),
    },
  };
}

export function buildContextGuardEvent(
  hookName: string,
  event: PromptBuildEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = context.runId ?? null;
  const security = runtimeSecurityFields(event, context, {
    promptFallback: true,
    // ⑥ hook 语境映射：上下文组装由运行时编排。
    sourceTypeFallback: "runtime_context",
  });
  // ⑨ CT 信封连线：trusted task claim 必须随事件上报，服务端据此
  // 解析权威 TaskFact/Snapshot 构造 ct_transient_facts 信封。
  const taskId = stringMaybe(context.taskId ?? context.task_id);
  const sourceSummaries = contextSourceSummaries(event);
  const sources =
    sourceSummaries.length > 0
      ? sourceSummaries
      : [stringPreview(event.prompt ?? event.context)];

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
      session_key: context.sessionKey ?? null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: hookName,
      model_intent: null,
      context_sources: [],
      derived_paths: uniqueStrings(
        event.derivedPaths ?? context.derivedPaths ?? [],
      ),
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
      ...(taskId ? { task_id: taskId } : {}),
    },
  };
}

export function buildModelGuardEvent(
  hookName: "before_agent_run" | "llm_input" | "llm_output",
  event: ModelHookEventInput,
  context: ToolHookContextInput = {},
): GuardEvent {
  const runId = context.runId ?? null;
  const security = runtimeSecurityFields(event, context, {
    promptFallback: hookName !== "llm_output",
    // ⑥ hook 语境映射：输入面属运行时上下文汇编，输出面属模型面。
    sourceTypeFallback:
      hookName === "llm_output" ? "runtime_model" : "runtime_context",
  });
  const phase = hookName === "llm_output" ? "output" : "input";
  const content = modelContentPreview(hookName, event);
  const provider = event.provider ?? context.provider ?? null;
  const model = event.model ?? context.model ?? null;
  // ⑨ CT 信封连线：与 context/tool 事件同口径上报 trusted task claim。
  const taskId = stringMaybe(context.taskId ?? context.task_id);

  return {
    schema_version: "0.3",
    event_id: createLocalId("evt"),
    event_type:
      phase === "input" ? "model_input_prepared" : "model_output_produced",
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
      session_key: context.sessionKey ?? null,
      session_id: context.sessionId ?? null,
      run_id: runId,
      agent_id: context.agentId ?? "main",
      current_step: hookName,
      // ⑦ 仅模型输出面上报意图摘要（脱敏 + ≤200 字符）。
      model_intent:
        phase === "output" ? buildModelIntentSummary(event, content) : null,
      context_sources: [],
      derived_paths: uniqueStrings(
        event.derivedPaths ?? context.derivedPaths ?? [],
      ),
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
      ...(taskId ? { task_id: taskId } : {}),
    },
  };
}

const MODEL_INTENT_LIMIT = 200;

/**
 * ⑦ model_output_produced 意图摘要：优先取计划中的 tool_calls 名称
 * 列表，其次取输出文本预览；复用 redactSensitiveCredentials 做凭据
 * 脱敏与长度截断（≤200 字符），无内容时返回 null（正常无数据）。
 */
function buildModelIntentSummary(
  event: ModelHookEventInput,
  content: string,
): string | null {
  const parts: string[] = [];
  const toolNames = modelToolPlan(event)
    .map((item) => stringValue(item.name ?? item.tool, ""))
    .filter((name) => name.length > 0);
  if (toolNames.length > 0) {
    parts.push(`planned tool_calls: ${toolNames.join(", ")}`);
  }
  const textPreview = content.trim();
  if (textPreview) {
    parts.push(textPreview);
  }
  if (parts.length === 0) {
    return null;
  }
  const intent = redactSensitiveCredentials(
    parts.join(" | "),
    MODEL_INTENT_LIMIT,
  ).trim();
  return intent.length > 0 ? intent : null;
}
