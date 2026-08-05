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

  return {
    schema_version: "0.3",
    trace_id: traceId,
    runtime: "openclaw",
    stage: hookName,
    event_type: "runtime_observation",
    summary: `OpenClaw ${hookName} observation`,
    decision: "allow",
    risk_score: 0,
    severity: "low",
    blocked: false,
    reason: "Observation only.",
    resource_targets: resourceTargets,
    rule_hits: [],
    links: {},
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
  };
}
