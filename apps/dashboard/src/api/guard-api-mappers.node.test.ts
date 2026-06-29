import assert from "node:assert/strict";
import test from "node:test";

import {
  mapApproval,
  mapAuditEvent,
  mapAuditIntegrity,
  mapPolicyHistory,
  mapPolicySummary,
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
    links: { approval_id: "app_1" },
    latency_ms: 3,
    metadata: { tool: "read_file" },
  });

  assert.equal(event.id, "audit_1");
  assert.equal(event.tool, "read_file");
  assert.equal(event.resource, "/private/token.txt");
  assert.equal(event.userTask, null);
  assert.equal(event.approvalId, "app_1");
  assert.deepEqual(event.resourceTargets, ["/private/token.txt"]);
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
    resource_targets: [
      "user_preferences/report_delivery_rule",
      "context:email_001",
    ],
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
    approval_nonce: "nonce_1",
  });

  assert.equal(approval.status, "allowed");
  assert.equal(approval.approvalNonce, "nonce_1");
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
  assert.deepEqual(
    detail.events.map((event) => event.id),
    ["audit_1", "audit_2"],
  );
  assert.equal(detail.metrics.fnr, 0.25);
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
