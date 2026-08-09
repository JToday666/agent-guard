import assert from "node:assert/strict";
import test from "node:test";

import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../../../../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import {
  mapApproval,
  mapAdapterStatus,
  mapAuditEvent,
  mapAuditIntegrity,
  mapConfigAuditFindingRecord,
  mapEvaluationRun,
  mapHealth,
  mapPolicyHistory,
  mapPolicySummary,
  mapProvenance,
  mapTraceDetail,
} from "./guard-api-mappers.ts";
import type { GuardAuditIntegrityDto } from "./guard-api-types.ts";

test("maps Guard API audit evidence without inventing missing fields", () => {
  const event = mapAuditEvent({
    audit_id: "audit_1",
    schema_version: "0.3",
    trace_id: "trace_1",
    case_id: "PI-001",
    runtime: "langgraph",
    timestamp: "2026-06-22T06:30:00Z",
    stage: "before_tool_call",
    event_type: "tool_call_proposed",
    attack_type: "prompt_injection",
    is_malicious: true,
    summary: "Agent attempted to call read_file",
    decision: "deny",
    risk_score: 95,
    severity: "critical",
    blocked: true,
    resource_targets: ["/private/token.txt"],
    rule_hits: ["P001_sensitive_file_access"],
    reason: "Sensitive resource",
    links: {
      action_id: "action_1",
      approval_id: "app_1",
      decision_id: "decision_1",
      event_id: "event_1",
    },
    integrity: {
      canonicalization: "json:v1",
      event_hash: "hash_1",
      prev_hash: null,
      sequence: 41,
    },
    latency_ms: 3,
    metadata: { tool: "read_file" },
  });

  assert.equal(event.id, "audit_1");
  assert.equal(event.auditSequence, 41);
  assert.equal(event.tool, "read_file");
  assert.equal(event.resource, "/private/token.txt");
  assert.equal(event.userTask, null);
  assert.equal(event.approvalId, "app_1");
  assert.equal(event.actionId, "action_1");
  assert.equal(event.decisionId, "decision_1");
  assert.equal(event.eventId, "event_1");
  assert.equal(event.recordType, "policy_evaluation");
  assert.deepEqual(event.resourceTargets, ["/private/token.txt"]);
});

test("maps missing and degraded health facts without inventing availability", () => {
  assert.deepEqual(mapHealth({ status: "ok" }, "2026-08-07T00:00:00Z"), {
    api: "online",
    database: "unknown",
    checkedAt: "2026-08-07T00:00:00Z",
  });
  assert.deepEqual(mapHealth({ status: "degraded", database: "error" }, "2026-08-07T00:00:01Z"), {
    api: "online",
    database: "offline",
    checkedAt: "2026-08-07T00:00:01Z",
  });
  assert.deepEqual(mapHealth({ status: "future" }, "2026-08-07T00:00:02Z"), {
    api: "unknown",
    database: "unknown",
    checkedAt: "2026-08-07T00:00:02Z",
  });
});

test("maps sparse audit DTOs without throwing on missing arrays or records", () => {
  const event = mapAuditEvent({
    audit_id: "audit_sparse",
    schema_version: "0.3",
    trace_id: "trace_sparse",
    case_id: null,
    runtime: "langgraph",
    timestamp: "2026-06-22T06:30:00Z",
    stage: "before_tool_call",
    event_type: "tool_call_proposed",
    attack_type: null,
    is_malicious: null,
    decision: "allow",
    risk_score: 0,
    severity: "low",
    blocked: false,
    reason: "Allowed",
    latency_ms: null,
  } as unknown as Parameters<typeof mapAuditEvent>[0]);

  assert.equal(event.id, "audit_sparse");
  assert.equal(event.resource, "未提供");
  assert.equal(event.approvalId, undefined);
  assert.deepEqual(event.resourceTargets, []);
  assert.deepEqual(event.ruleHits, []);
  assert.equal(event.userTask, null);
  assert.equal(event.agentAction, "tool_call_proposed");
});

test("maps missing security fields to unknown instead of safe defaults", () => {
  const event = mapAuditEvent({
    audit_id: "audit_missing_security_fields",
    trace_id: "trace_missing_security_fields",
    timestamp: "2026-06-22T06:30:00Z",
    event_type: "runtime_outcome",
  } as unknown as Parameters<typeof mapAuditEvent>[0]);

  assert.equal(event.decision, "unknown");
  assert.equal(event.riskScore, null);
  assert.equal(event.severity, "unknown");
  assert.equal(event.blocked, null);
  assert.equal(event.runtime, "unknown");
  assert.equal(event.recordType, "runtime_outcome");
});

test("does not infer an unknown legacy event type as a policy evaluation", () => {
  const event = mapAuditEvent({
    audit_id: "audit_unknown_legacy",
    trace_id: "trace_unknown_legacy",
    timestamp: "2026-06-22T06:30:00Z",
    event_type: "adapter_custom_observation",
    decision: "deny",
  } as unknown as Parameters<typeof mapAuditEvent>[0]);

  assert.equal(event.recordType, "unknown");
  assert.equal(event.auditSequence, null);
});

test("keeps AuditEvent 0.3 inference and 0.4 record type classification", () => {
  const legacy = mapAuditEvent({
    audit_id: "audit_legacy_policy",
    schema_version: "0.3",
    trace_id: "trace_compat",
    timestamp: "2026-06-22T06:30:00Z",
    event_type: "tool_call_proposed",
    decision: "deny",
  } as unknown as Parameters<typeof mapAuditEvent>[0]);
  const current = mapAuditEvent({
    audit_id: "audit_runtime_outcome",
    schema_version: "0.4",
    trace_id: "trace_compat",
    timestamp: "2026-06-22T06:31:00Z",
    event_type: "runtime_outcome",
    record_type: "runtime_outcome",
    decision: null,
    risk_score: null,
    severity: null,
    blocked: null,
  } as unknown as Parameters<typeof mapAuditEvent>[0]);

  assert.equal(legacy.recordType, "policy_evaluation");
  assert.equal(current.recordType, "runtime_outcome");
  assert.equal(current.decision, "unknown");
  assert.equal(current.blocked, null);
});

test("maps P1 audit metadata into readable action and resource fields", () => {
  const event = mapAuditEvent({
    audit_id: "audit_p1",
    schema_version: "0.3",
    trace_id: "trace_p1",
    case_id: "PI-101",
    runtime: "langgraph",
    timestamp: "2026-06-22T06:30:00Z",
    stage: "before_tool_call",
    event_type: "memory_write_proposed",
    attack_type: "memory_poisoning",
    is_malicious: true,
    summary: "Agent evaluated memory_write_proposed",
    decision: "ask",
    risk_score: 66,
    severity: "medium",
    blocked: true,
    resource_targets: ["user_preferences/report_delivery_rule", "context:email_001"],
    rule_hits: ["P104_memory_poisoning"],
    reason: "Memory write requires review",
    links: {},
    latency_ms: 4,
    metadata: {
      action_name: "memory_write_proposed",
      memory_namespace: "user_preferences",
      memory_key: "report_delivery_rule",
    },
  });

  assert.equal(event.tool, "memory_write_proposed");
  assert.equal(event.resource, "user_preferences/report_delivery_rule 等 2 项");
  assert.deepEqual(event.resourceTargets, [
    "user_preferences/report_delivery_rule",
    "context:email_001",
  ]);
});

test("prefers canonical action metadata over legacy tool metadata", () => {
  const event = mapAuditEvent({
    audit_id: "audit_p1_message",
    schema_version: "0.3",
    trace_id: "trace_p1_message",
    case_id: "PI-105",
    runtime: "openclaw",
    timestamp: "2026-06-22T06:30:00Z",
    stage: "before_tool_call",
    event_type: "message_send_proposed",
    attack_type: "exfiltration",
    is_malicious: true,
    summary: "",
    decision: "deny",
    risk_score: 88,
    severity: "high",
    blocked: true,
    resource_targets: [],
    rule_hits: ["P005_external_send"],
    reason: "External recipient",
    links: {},
    latency_ms: 5,
    metadata: {
      action_name: "message_send_proposed",
      channel: "email",
      recipient: "attacker@example.invalid",
      tool: "legacy_tool_name",
    },
  });

  assert.equal(event.tool, "message_send_proposed");
  assert.equal(event.agentAction, "message_send_proposed");
  assert.equal(event.resource, "email/at***@example.invalid");
  assert.deepEqual(event.resourceTargets, ["email/at***@example.invalid"]);
});

test("maps a resolved allow_once approval to an allowed view state", () => {
  const approval = mapApproval({
    approval_id: "app_1",
    trace_id: "trace_1",
    tool_call_id: "call_1",
    requesting_principal_id: "adapter",
    runtime: "langgraph",
    agent_id: "main",
    status: "resolved",
    decision_options: ["allow_once", "deny"],
    decision: "allow_once",
    tool: "send_email",
    resource: "external@example.com",
    reason: "External send",
    risk_score: 62,
    severity: "medium",
    created_at: "2026-06-22T06:30:00Z",
    expires_at: "2026-06-22T06:45:00Z",
    resolved_at: "2026-06-22T06:31:00Z",
  });

  assert.equal(approval.status, "allowed");
});

test("preserves approval subject compatibility fields", () => {
  const approval = mapApproval({
    approval_id: "app_2",
    trace_id: "trace_2",
    subject_id: "evt_p1",
    subject_type: "memory_write_proposed",
    action_id: "evt_p1",
    action_name: "memory_write_proposed",
    tool_call_id: "evt_p1",
    requesting_principal_id: "adapter",
    runtime: "langgraph",
    agent_id: "main",
    status: "pending",
    decision_options: ["allow_once", "deny"],
    decision: null,
    tool: "memory_write_proposed",
    resource: "memory:user_preferences/report_delivery_rule",
    reason: "Memory write requires review",
    risk_score: 66,
    severity: "medium",
    created_at: "2026-06-22T06:30:00Z",
    expires_at: "2026-06-22T06:45:00Z",
    resolved_at: null,
  });

  assert.equal(approval.subjectId, "evt_p1");
  assert.equal(approval.subjectType, "memory_write_proposed");
  assert.equal(approval.actionName, "memory_write_proposed");
});

test("maps trace detail response through existing event and approval mappers", () => {
  const detail = mapTraceDetail({
    trace_id: "trace_1",
    audit_events: [
      {
        audit_id: "audit_2",
        schema_version: "0.3",
        trace_id: "trace_1",
        case_id: "PI-001",
        runtime: "langgraph",
        timestamp: "2026-06-22T06:31:00Z",
        stage: "before_tool_call",
        event_type: "tool_call_proposed",
        attack_type: "prompt_injection",
        is_malicious: true,
        summary: "Agent attempted to call send_email",
        decision: "ask",
        risk_score: 62,
        severity: "medium",
        blocked: true,
        resource_targets: ["external@example.invalid"],
        rule_hits: ["P005_external_send"],
        reason: "External send",
        links: {},
        latency_ms: 4,
        metadata: { tool: "send_email" },
      },
      {
        audit_id: "audit_1",
        schema_version: "0.3",
        trace_id: "trace_1",
        case_id: "PI-001",
        runtime: "langgraph",
        timestamp: "2026-06-22T06:30:00Z",
        stage: "before_tool_call",
        event_type: "tool_call_proposed",
        attack_type: "prompt_injection",
        is_malicious: true,
        summary: "Agent attempted to call read_file",
        decision: "deny",
        risk_score: 95,
        severity: "critical",
        blocked: true,
        resource_targets: ["/private/token.txt"],
        rule_hits: ["P001_sensitive_file_access"],
        reason: "Sensitive resource",
        links: {},
        latency_ms: 3,
        metadata: { tool: "read_file" },
      },
    ],
    approvals: [],
    audit_window: { limit: 1000, returned_count: 2, has_more: true },
    metrics: {
      event_count: 1,
      allow_count: 0,
      deny_count: 1,
      ask_count: 0,
      blocked_count: 1,
      block_rate: 1,
      fpr: null,
      fnr: 0.25,
      average_latency_ms: 3,
    },
  });

  assert.equal(detail.id, "trace_1");
  assert.deepEqual(detail.auditWindow, { limit: 1000, returnedCount: 2, hasMore: true });
  assert.deepEqual(
    detail.events.map((event) => event.id),
    ["audit_1", "audit_2"],
  );
  assert.equal("aggregateMetrics" in detail, false);
});

test("maps sparse trace detail responses without creating an unused metrics model", () => {
  const detail = mapTraceDetail({
    trace_id: "trace_sparse",
  } as unknown as Parameters<typeof mapTraceDetail>[0]);

  assert.equal(detail.id, "trace_sparse");
  assert.deepEqual(detail.events, []);
  assert.deepEqual(detail.approvals, []);
  assert.deepEqual(detail.auditWindow, { limit: 0, returnedCount: 0, hasMore: null });
  assert.equal("aggregateMetrics" in detail, false);
});

test("maps current policy with latest history metadata", () => {
  const history = mapPolicyHistory([
    {
      revision: 3,
      updated_at: "2026-06-22T06:30:00Z",
      updated_by: "dashboard",
      bundle_id: "default",
      version: "p0",
    },
  ]);
  const summary = mapPolicySummary(
    {
      bundle_id: "default",
      version: "p1",
      disabled_rules: ["P001_sensitive_file_access"],
      rule_overrides: { P005_external_send: { decision: "deny" } },
      tool_profiles: {
        read_file: {
          categories: ["tool", "file"],
          kinds: ["read_file"],
          operations: ["read"],
          directions: ["local"],
        },
      },
    },
    history,
  );

  assert.equal(summary.bundleId, "default");
  assert.equal(summary.version, "p1");
  assert.equal(summary.revision, 3);
  assert.equal(summary.disabledRuleCount, 1);
  assert.equal(summary.ruleOverrideCount, 1);
  assert.equal(summary.toolProfileCount, 1);
});

test("maps an empty audit integrity chain with a null head hash", () => {
  const dto: GuardAuditIntegrityDto = {
    valid: true,
    event_count: 0,
    head_hash: null,
    first_broken_audit_id: null,
  };

  assert.deepEqual(mapAuditIntegrity(dto), {
    valid: true,
    eventCount: 0,
    headHash: null,
    firstBrokenAuditId: null,
  });
});

test("maps latest evaluation run without inheriting audit metrics", () => {
  const evaluation = mapEvaluationRun({
    run_id: "eval_20260628",
    run_at: "2026-06-28T00:00:00+00:00",
    dataset_id: "attackbench",
    dataset_version: "v1",
    asr_before: 0.72,
    asr_after: 0.08,
    per_attack: {
      prompt_injection: { asr_before: 0.8, asr_after: 0.1 },
      memory_poisoning: { asr_before: 0.58, asr_after: null },
    },
    cases: [
      {
        case_id: "PI-001",
        attack_type: "prompt_injection",
        runtime: "openclaw",
        expected_decision: "deny",
        actual_decision: "ask",
        blocked: true,
        attack_success: false,
        trace_id: "trace_eval_001",
      },
    ],
  });

  assert.equal(evaluation.runId, "eval_20260628");
  assert.equal(evaluation.datasetLabel, "attackbench / v1");
  assert.equal(evaluation.asrBefore, 0.72);
  assert.equal(evaluation.asrAfter, 0.08);
  assert.equal(evaluation.perAttack[0]?.attackType, "prompt_injection");
  assert.equal("reduction" in evaluation.perAttack[0]!, false);
  assert.equal("reduction" in evaluation.perAttack[1]!, false);
  assert.equal(evaluation.cases[0]?.traceId, "trace_eval_001");
  assert.equal(evaluation.cases[0]?.attackSuccess, false);
  assert.equal("blockRate" in evaluation, false);
});

test("maps config audit finding records with display-ready fields", () => {
  const record = mapConfigAuditFindingRecord({
    runtime: "openclaw",
    target_type: "plugin_config",
    target_id: "agentguard-security",
    trace_id: "trace_cfg_findings",
    event_id: "cfg_findings",
    timestamp: "2026-06-28T00:00:00+00:00",
    finding: {
      finding_id: "finding_cfg_high",
      severity: "high",
      category: "openclaw.plugin",
      title: "Raw conversation access enabled",
      subject: "hooks.allowConversationAccess",
      description: "Plugin can read raw conversation content.",
      evidence: ["allowConversationAccess=true"],
      recommendation: "Disable raw conversation access unless required.",
    },
  });

  assert.equal(record.runtime, "openclaw");
  assert.equal(record.targetId, "agentguard-security");
  assert.equal(record.finding.title, "Raw conversation access enabled");
  assert.deepEqual(record.finding.evidence, ["allowConversationAccess=true"]);
});

test("maps sparse config findings with safe display fallbacks", () => {
  const record = mapConfigAuditFindingRecord({
    runtime: "openclaw",
    target_type: "plugin_config",
    target_id: "agentguard-security",
    trace_id: "trace_cfg_sparse",
    event_id: "cfg_sparse",
    timestamp: "2026-06-28T00:00:00+00:00",
    finding: {
      finding_id: "finding_sparse",
      severity: "medium",
      title: "Hook coverage changed",
    },
  } as unknown as Parameters<typeof mapConfigAuditFindingRecord>[0]);

  assert.equal(record.finding.category, "未分类");
  assert.equal(record.finding.subject, "未提供");
  assert.equal(record.finding.description, "未提供");
  assert.deepEqual(record.finding.evidence, []);
  assert.equal(record.finding.recommendation, null);
});

test("maps OpenClaw adapter status with hook coverage", () => {
  const status = mapAdapterStatus({
    status: "loaded",
    loaded: true,
    hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
    expected_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
    last_verified_at: "2026-06-28T00:00:00+00:00",
    last_heartbeat_at: "2026-06-28T00:01:00+00:00",
    error: null,
    source: "agentguardctl",
    plugin_version: "0.1.0",
    runtime_version: "2026.6.6",
    capabilities: { event_types: ["tool_call_proposed"] },
    hooks: [...OPENCLAW_REQUIRED_HOOKS],
    fail_closed_stages: ["before_install"],
  });

  assert.equal(status.loaded, true);
  assert.equal(status.hookCoverage, 1);
  assert.equal(status.pluginVersion, "0.1.0");
  assert.deepEqual(status.failClosedStages, ["before_install"]);
});

test("maps sparse adapter and provenance responses with safe defaults", () => {
  const status = mapAdapterStatus({
    status: "unknown",
    loaded: false,
    hook_count: null,
    last_verified_at: null,
    error: null,
    source: null,
  } as unknown as Parameters<typeof mapAdapterStatus>[0]);

  assert.equal(status.expectedHookCount, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.equal(status.hookCoverage, null);
  assert.deepEqual(status.capabilities, {});
  assert.deepEqual(status.hooks, []);
  assert.deepEqual(status.failClosedStages, []);

  const provenance = mapProvenance({
    trace_id: "trace_sparse",
  } as unknown as Parameters<typeof mapProvenance>[0]);

  assert.equal(provenance.traceId, "trace_sparse");
  assert.deepEqual(provenance.nodes, []);
  assert.deepEqual(provenance.edges, []);
});
