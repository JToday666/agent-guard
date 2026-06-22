import assert from "node:assert/strict";
import test from "node:test";

import { mapApproval, mapAuditEvent } from "./guard-api-mappers.ts";

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
