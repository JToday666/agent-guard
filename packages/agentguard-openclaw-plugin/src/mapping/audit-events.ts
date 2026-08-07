import type { AuditEvent, ConfigAuditEvent } from "../types.js";
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

export function buildBeforeInstallConfigAuditEvent(
  event: BeforeInstallEventInput,
  context: RuntimeObservationContextInput = {},
): ConfigAuditEvent {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const request = asRecord(event.request);
  const targetType = stringValue(
    request.targetType ?? event.targetType,
    "plugin",
  );
  const targetId = stringValue(request.targetId ?? event.targetId, "unknown");
  const manifest = asRecord(request.manifest ?? event.manifest);
  const config = asRecord(request.config ?? event.config ?? manifest.config);
  const hooks = asRecord(config.hooks ?? manifest.hooks);
  const permissions = asRecord(config.permissions ?? manifest.permissions);
  const findings = buildInstallFindings({ targetId, hooks, permissions });
  const security = runtimeSecurityFields(eventRecord, contextRecord);
  const runId = firstNonEmpty(
    stringMaybe(contextRecord.runId),
    stringMaybe(eventRecord.runId),
    stringMaybe(request.runId),
    targetId,
  );

  return {
    runtime: "openclaw",
    target_type: targetType,
    target_id: targetId,
    action: "before_install",
    findings,
    metadata: {
      manifest_id: stringValue(manifest.id, targetId),
      trace_id: runId,
      ...definedMetadata({
        user_task: security.userTask,
        source_type: security.sourceType,
        source_trust: security.sourceTrust,
        run_id: runId,
        agent_id:
          stringMaybe(eventRecord.agentId) ??
          stringMaybe(contextRecord.agentId),
        current_step: "before_install",
      }),
    },
  };
}

export function buildRuntimeObservationAuditEvent(
  hookName: string,
  event: unknown = {},
  context: RuntimeObservationContextInput = {},
): AuditEvent {
  const eventRecord = asRecord(event);
  const contextRecord = asRecord(context);
  const security = runtimeSecurityFields(eventRecord, contextRecord);
  const userTask = runtimeObservationUserTask(hookName, security.userTask);
  const resourceTargets = runtimeObservationResourceTargets(
    hookName,
    eventRecord,
    contextRecord,
  );
  const traceId = firstNonEmpty(
    stringMaybe(context.runId),
    stringMaybe(eventRecord.runId),
    stringMaybe(context.sessionKey),
    stringMaybe(eventRecord.sessionKey),
    stringMaybe(context.sessionId),
    stringMaybe(eventRecord.sessionId),
    stringMaybe(eventRecord.id),
  );
  const timestamp = new Date().toISOString();
  // §8.3/§14：observation 不携带策略结论，顶层策略字段一律置 null；
  // evidence 只补齐必填的 intervention/execution/side_effects/result 块。
  const eventId =
    stringMaybe(eventRecord.id) ?? createLocalId("runtime_event");

  return {
    schema_version: "0.4",
    record_type: "runtime_observation",
    trace_id: traceId,
    runtime: "openclaw",
    timestamp,
    stage: hookName,
    event_type: "runtime_observation",
    summary: `OpenClaw ${hookName} observation`,
    decision: null,
    risk_score: null,
    severity: null,
    blocked: null,
    reason: "Observation only.",
    resource_targets: resourceTargets,
    rule_hits: [],
    links: { event_id: eventId },
    metadata: {
      openclaw_hook: hookName,
      ...definedMetadata({
        user_task: userTask,
        source_trust: security.sourceTrust,
        source_type: security.sourceType,
        run_id:
          stringMaybe(eventRecord.runId) ?? stringMaybe(contextRecord.runId),
        agent_id:
          stringMaybe(eventRecord.agentId) ??
          stringMaybe(contextRecord.agentId),
        current_step: hookName,
        model:
          stringMaybe(eventRecord.model) ?? stringMaybe(contextRecord.model),
        provider:
          stringMaybe(eventRecord.provider) ??
          stringMaybe(contextRecord.provider),
      }),
      ...(resourceTargets.length > 0 ? { derived_paths: resourceTargets } : {}),
      event: sanitizeJson(event),
      context: sanitizeJson(context),
    },
    evidence: {
      guard_event: null,
      guard_decision: null,
      policy: null,
      intervention: {
        type: "audit_observation",
        reason: "该 Hook 只记录事实，不改变执行路径",
      },
      execution: {
        status: "unknown",
        receipt_recorded: true,
        invoked_at: null,
        completed_at: timestamp,
        error: null,
        tool_result_entered_context: null,
        persisted: null,
      },
      side_effects: {
        measurement_status: "unknown",
        count: null,
        summary: null,
      },
      result: {
        disposition: "unknown",
        summary: null,
        sanitized: null,
      },
      approval: {
        approval_id: null,
        status: "not_required",
        decision: null,
        resolved_at: null,
      },
    },
  };
}
