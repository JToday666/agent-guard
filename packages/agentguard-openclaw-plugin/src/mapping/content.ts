import type { ConfigAuditFinding, JsonObject } from "../types.js";
import {
  containsSensitiveCredentialText,
  isExecLikeToolIdentity,
  redactSensitiveCredentials,
} from "../security.js";
import type {
  BeforeToolCallEventInput,
  ModelHookEventInput,
  PromptBuildEventInput,
  ToolHookContextInput,
} from "./common.js";
import {
  asRecord,
  byteLength,
  sanitizeJson,
  stringMaybe,
  stringValue,
} from "./common.js";

export function truncate(value: string, limit: number): string {
  return value.length <= limit ? value : value.slice(0, limit);
}

export function buildInstallFindings(input: {
  targetId: string;
  hooks: JsonObject;
  permissions: JsonObject;
}): ConfigAuditFinding[] {
  const findings: ConfigAuditFinding[] = [];
  if (
    input.hooks.allowConversationAccess === true ||
    input.permissions.allowConversationAccess === true
  ) {
    findings.push({
      severity: "high",
      category: "openclaw.plugin",
      title: "Raw conversation access enabled",
      subject: `${input.targetId}.hooks.allowConversationAccess`,
      description: "Plugin can read raw conversation content.",
      evidence: ["allowConversationAccess=true"],
      recommendation:
        "Disable raw conversation access unless the plugin is trusted and reviewed.",
    });
  }
  if (
    input.hooks.allowPromptInjection === true ||
    input.permissions.allowPromptInjection === true
  ) {
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
  if (
    input.permissions.shell === true ||
    input.permissions.exec === true ||
    input.permissions.command === true
  ) {
    findings.push({
      severity: "high",
      category: "openclaw.plugin",
      title: "Command execution permission enabled",
      subject: `${input.targetId}.permissions.exec`,
      description: "Plugin requests command execution capability.",
      evidence: ["exec-like permission enabled"],
      recommendation:
        "Require explicit review before installing plugins with command execution.",
    });
  }
  return findings;
}

export function containsInstructionLikeText(value: string): boolean {
  return (
    /ignore\s+(all\s+)?previous\s+instructions|ignore\s+developer\s+instructions|disregard\s+previous/i.test(
      value,
    ) ||
    /override\s+the\s+system|system\s+message|developer\s+message|send\s+(the\s+)?token/i.test(
      value,
    ) ||
    /persist\s+this\s+rule|remember\s+this\s+rule|store\s+this\s+rule|save\s+this\s+rule/i.test(
      value,
    ) ||
    /remember\s+this\s+instruction|store\s+this\s+instruction|save\s+this\s+instruction/i.test(
      value,
    ) ||
    /from\s+now\s+on|next\s+time|for\s+all\s+future|future\s+(tasks|requests|reports|runs|sessions)/i.test(
      value,
    ) ||
    /always\s+send|send\s+reports\s+externally|route\s+future\s+reports/i.test(
      value,
    ) ||
    /never\s+(mention|reveal|tell)|hide\s+this\s+rule|do\s+not\s+mention\s+this\s+rule/i.test(
      value,
    ) ||
    /identityverify|market-segment-submit|support-profile-confirm|managed-device\s+support\s+profile/i.test(
      value,
    ) ||
    /lead-verification-relax|reduce\s+verification\s+controls|weaken\s+verification/i.test(
      value,
    )
  );
}

export function containsSensitiveText(value: string): boolean {
  return (
    /token\s*=|api[_-]?key|password|secret|authorization/i.test(value) ||
    containsSensitiveCredentialText(value)
  );
}

export function contextSourceSummaries(event: PromptBuildEventInput): string[] {
  const messages = Array.isArray(event.messages)
    ? event.messages.map((item) => {
        const record = asRecord(item);
        return stringPreview(record.content ?? record.text ?? item);
      })
    : [];
  return [
    ...messages,
    stringPreview(event.prompt),
    stringPreview(event.context),
  ].filter(
    (item, index, values) => item.length > 0 && values.indexOf(item) === index,
  );
}

export function modelContentPreview(
  hookName: "before_agent_run" | "llm_input" | "llm_output",
  event: ModelHookEventInput,
): string {
  if (hookName !== "llm_output") {
    return [
      stringPreview(event.systemPrompt),
      stringPreview(event.prompt ?? event.input ?? event.content),
      stringPreview(event.messages),
    ]
      .filter((item) => item.length > 0)
      .join("\n");
  }
  return stringPreview(
    event.output ??
      event.response ??
      event.content ??
      event.assistantTexts ??
      event.lastAssistant ??
      event.messages,
  );
}

export function modelToolPlan(event: ModelHookEventInput): JsonObject[] {
  const toolPlan = event.toolPlan ?? event.toolCalls;
  if (!Array.isArray(toolPlan)) {
    return [];
  }
  return toolPlan.map((item) => asRecord(item));
}

export function resultContentPreview(value: unknown): string {
  return stringPreview(value);
}

export function stringPreview(value: unknown): string {
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

export function resultContentType(value: unknown): string {
  const record = asRecord(value);
  return (
    stringMaybe(record.contentType ?? record.mimeType ?? record.type) ??
    "text/plain"
  );
}

export function ragAnswerProvenanceForToolResult(
  value: unknown,
  toolName: string,
): JsonObject | null {
  if (toolName !== "rag_answer") {
    return null;
  }
  const record = asRecord(value);
  const answerSource = stringMaybe(
    record.answer_source ??
      record.answerSource ??
      record.source ??
      record.answer_source_type ??
      record.answerSourceType,
  );
  const contexts = Array.isArray(record.contexts)
    ? record.contexts.filter((item) => stringPreview(item).length > 0)
    : [];
  const contextDocs = Array.isArray(record.context_docs)
    ? record.context_docs.filter((item) => stringPreview(item).length > 0)
    : [];
  const evidence =
    record.evidence ?? record.citations ?? record.sources ?? record.memory_refs;
  const hasContextEvidence =
    contexts.length > 0 || contextDocs.length > 0 || Boolean(evidence);
  if (!answerSource && !hasContextEvidence) {
    return null;
  }
  return {
    answer_source: answerSource ?? null,
    context_count: contexts.length + contextDocs.length,
    has_context_evidence: hasContextEvidence,
  };
}

export function toolCommandText(params: JsonObject): string {
  return stringMaybe(params.command ?? params.cmd ?? params.code) ?? "";
}

export function toolArguments(
  event: BeforeToolCallEventInput,
  context: ToolHookContextInput,
): JsonObject {
  for (const value of [
    event.params,
    event.arguments,
    event.input,
    event.toolInput,
    context.toolParams,
  ]) {
    const record = asRecord(value);
    if (Object.keys(record).length > 0) {
      return record;
    }
  }
  return {};
}

export function browserTargetText(params: JsonObject): string {
  return (
    stringMaybe(
      params.selector ??
        params.url ??
        params.text ??
        params.sessionId ??
        params.session_id ??
        params.target,
    ) ?? ""
  );
}

export function toolTargetText(params: JsonObject): string {
  return (
    stringMaybe(
      params.path ??
        params.file ??
        params.filePath ??
        params.filename ??
        params.url ??
        params.uri ??
        params.endpoint ??
        params.selector ??
        params.text ??
        params.sessionId ??
        params.session_id ??
        params.target ??
        params.key ??
        params.name,
    ) ?? ""
  );
}
