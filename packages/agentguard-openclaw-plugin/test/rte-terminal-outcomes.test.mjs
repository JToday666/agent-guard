// PR-RTE-03 — terminal outcome receipt mapping tests (contract 03 §6, 02 §9-§10).
// Asserts the OpenClaw evidence口径 for execution_completed/execution_failed:
// no entered_context/persisted assertions from the after hook, bounded error
// strings, runtime_observation vs enforcement_violation intervention types.
import assert from "node:assert/strict";
import test from "node:test";
import { buildRuntimeOutcomeAuditEvent } from "../dist/mapping/audit-outcomes.js";

const GUARD_EVENT = {
  event_id: "evt_rte_outcome_001",
  schema_version: "0.4",
  record_type: "guard_event",
  event_type: "tool_call_proposed",
  runtime: "openclaw",
  trace_id: "trace_rte_outcome",
  timestamp: "2026-08-15T00:00:00Z",
  pre_execution: true,
  security_context: {
    agent_id: "agent_rte",
    user_task: "probe",
    source_type: "tool",
    source_trust: "untrusted",
    run_id: "run_rte",
    current_step: "tool_call",
    context_sources: [],
    derived_paths: ["file:///workspace/notes.txt"],
    metadata: {},
  },
  payload: {
    tool: {
      name: "spike_probe",
      category: "tool",
      kind: "probe",
      input_kind: null,
      call_id: "call-rte-200",
    },
    arguments: {},
    derived_resources: [],
  },
  metadata: {},
};

const EVALUATION = {
  decision: {
    decision_id: "dec_rte_outcome_001",
    decision: "allow",
    risk_score: 10,
    severity: "low",
    reason: "allowed",
    rule_hits: [],
  },
  approval: null,
  policy_audit_id: "audit_policy_rte_outcome_001",
};

test("execution_completed: OpenClaw口径 keeps context/persist unknown and disposition unknown", () => {
  const receipt = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    EVALUATION,
    "execution_completed",
    {
      interventionType: "runtime_observation",
      invokedAt: "2026-08-15T00:00:01Z",
      completedAt: "2026-08-15T00:00:02Z",
      stage: "after_tool_call",
    },
  );

  assert.equal(receipt.metadata.outcome_kind, "execution_completed");
  assert.equal(
    receipt.audit_id,
    "audit_outcome_evt_rte_outcome_001_execution_completed",
  );
  assert.equal(receipt.links.action_id, "call-rte-200");
  assert.equal(receipt.evidence.intervention.type, "runtime_observation");
  assert.equal(receipt.evidence.execution.status, "executed");
  assert.equal(receipt.evidence.execution.error, null);
  assert.equal(receipt.evidence.execution.invoked_at, "2026-08-15T00:00:01Z");
  assert.equal(receipt.evidence.execution.completed_at, "2026-08-15T00:00:02Z");
  // §6: after hook 不能证明 result 进入上下文或已持久化。
  assert.equal(receipt.evidence.execution.tool_result_entered_context, null);
  assert.equal(receipt.evidence.execution.persisted, null);
  assert.equal(receipt.evidence.result.disposition, "unknown");
  assert.equal(receipt.evidence.side_effects.measurement_status, "not_measured");
  assert.equal(receipt.evidence.side_effects.count, null);
  assert.equal(receipt.evidence.approval.status, "not_required");
});

test("execution_failed: error is a bounded non-empty string; disposition not_applicable", () => {
  const receipt = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    EVALUATION,
    "execution_failed",
    { error: "HTTP 503 from upstream", stage: "after_tool_call" },
  );

  assert.equal(receipt.metadata.outcome_kind, "execution_failed");
  assert.equal(receipt.evidence.execution.status, "failed");
  assert.equal(receipt.evidence.execution.error, "HTTP 503 from upstream");
  assert.equal(receipt.evidence.result.disposition, "not_applicable");
  assert.equal(receipt.evidence.execution.tool_result_entered_context, null);
  assert.equal(receipt.evidence.execution.persisted, null);
});

test("execution_failed: missing error falls back to a bounded placeholder and long errors are truncated", () => {
  const fallback = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    EVALUATION,
    "execution_failed",
    { error: null, stage: "after_tool_call" },
  );
  assert.equal(fallback.evidence.execution.error, "unknown tool failure");

  const long = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    EVALUATION,
    "execution_failed",
    { error: "x".repeat(5000), stage: "after_tool_call" },
  );
  assert.equal(long.evidence.execution.error.length, 2003);
  assert.ok(long.evidence.execution.error.endsWith("..."));
});

test("enforcement_violation: contradiction path keeps the real terminal fact with the violation intervention type (02 §10)", () => {
  const receipt = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    {
      ...EVALUATION,
      decision: { ...EVALUATION.decision, decision: "deny" },
    },
    "execution_completed",
    {
      interventionType: "enforcement_violation",
      reason: "gate expected block but the runtime observed real execution",
      stage: "after_tool_call",
    },
  );

  assert.equal(receipt.metadata.outcome_kind, "execution_completed");
  assert.equal(receipt.evidence.intervention.type, "enforcement_violation");
  assert.equal(receipt.evidence.execution.status, "executed");
  // policy decision remains deny on the receipt top level.
  assert.equal(receipt.decision, "deny");
  assert.equal(receipt.blocked, true);
});

test("terminal receipts carry approval evidence when the gate released through allow_once", () => {
  const receipt = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    EVALUATION,
    "execution_completed",
    {
      stage: "after_tool_call",
      approval: {
        approvalId: "appr_rte_100",
        status: "allowed",
        decision: "allow_once",
        resolvedAt: "2026-08-15T00:00:00.500Z",
      },
    },
  );

  assert.equal(receipt.links.approval_id, "appr_rte_100");
  assert.equal(receipt.evidence.approval.status, "allowed");
  assert.equal(receipt.evidence.approval.decision, "allow_once");
});

test("existing kinds keep their intervention.type == kind behavior", () => {
  const receipt = buildRuntimeOutcomeAuditEvent(
    GUARD_EVENT,
    {
      ...EVALUATION,
      decision: { ...EVALUATION.decision, decision: "deny" },
    },
    "pre_execution_deny",
  );
  assert.equal(receipt.evidence.intervention.type, "pre_execution_deny");
  assert.equal(receipt.evidence.execution.status, "not_invoked");
});
