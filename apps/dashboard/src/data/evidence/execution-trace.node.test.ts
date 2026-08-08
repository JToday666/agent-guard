import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { mapApproval, mapAuditEvent } from "../../api/guard-api-mappers.ts";
import type { GuardApprovalDto, GuardAuditEventDto } from "../../api/guard-api-types.ts";
import type { ApprovalRequest, NormalizedAuditEvidence } from "../../types/dashboard.ts";
import { buildTraceEvidenceViewModel } from "./trace-evidence.ts";
import { buildExecutionTrace, shouldContinueTracePolling } from "./execution-trace.ts";

interface FixtureSnapshot {
  included_audit_ids: string[];
  approval: { status: "pending" | "resolved"; decision: "allow_once" | null };
  expected_code_action: {
    decision: "ask";
    approval: "pending" | "allowed_once";
    execution: "unknown" | "executed";
    phase: "waiting_approval" | "approval_released" | "waiting_receipt" | "terminal";
    status_label: string;
  };
}

interface RuntimeFixture {
  source_facts: {
    trace_id: string;
    audit_events: GuardAuditEventDto[];
    approvals: GuardApprovalDto[];
  };
  expected_projection: {
    snapshots: FixtureSnapshot[];
  };
}

const fixture = JSON.parse(
  readFileSync(
    new URL("../../../../../tests/fixtures/runtime_safety_trace_v04.json", import.meta.url),
    "utf8",
  ),
) as RuntimeFixture;

function currentApproval(snapshot?: FixtureSnapshot): ApprovalRequest[] {
  const source = fixture.source_facts.approvals[0];
  if (!source) return [];
  if (!snapshot) return [mapApproval(source)];
  return [
    mapApproval({
      ...source,
      status: snapshot.approval.status,
      decision: snapshot.approval.decision,
      resolved_at: snapshot.approval.status === "resolved" ? source.resolved_at : null,
    }),
  ];
}

function normalizedEvents(
  includedAuditIds?: readonly string[],
  approvals = currentApproval(),
): NormalizedAuditEvidence[] {
  const included = includedAuditIds ? new Set(includedAuditIds) : null;
  const rows = fixture.source_facts.audit_events
    .filter((event) => !included || included.has(event.audit_id))
    .map(mapAuditEvent);
  return buildTraceEvidenceViewModel(fixture.source_facts.trace_id, rows, approvals, null).events;
}

test("projects the frozen runtime trace into two stable actions", () => {
  const trace = buildExecutionTrace(normalizedEvents(), currentApproval());

  assert.equal(trace.lifecycleState, "completed");
  assert.equal(trace.actions.length, 2);
  assert.deepEqual(
    trace.actions.map((action) => action.actionId),
    ["call_memory_read_001", "call_code_exec_001"],
  );

  const memory = trace.actions[0]!;
  assert.equal(memory.displayName, "读取记忆");
  assert.equal(memory.decision, "allow");
  assert.equal(memory.approval, "not_required");
  assert.equal(memory.execution, "executed");
  assert.equal(memory.phase, "terminal");

  const code = trace.actions[1]!;
  assert.equal(code.displayName, "执行代码");
  assert.equal(code.decision, "ask");
  assert.equal(code.approval, "allowed_once");
  assert.equal(code.execution, "executed");
  assert.equal(code.phase, "terminal");
  assert.deepEqual(
    code.policyChecks.map((check) => check.auditId),
    ["audit_policy_code_exec_001"],
  );
  assert.equal(shouldContinueTracePolling(trace), false);
});

test("keeps decision, approval and execution as three independent facts", () => {
  for (const snapshot of fixture.expected_projection.snapshots) {
    const approvals = currentApproval(snapshot);
    const trace = buildExecutionTrace(
      normalizedEvents(snapshot.included_audit_ids, approvals),
      approvals,
    );
    const code = trace.actions.find((action) => action.actionId === "call_code_exec_001");
    assert.ok(code);
    assert.equal(code.decision, snapshot.expected_code_action.decision);
    assert.equal(code.approval, snapshot.expected_code_action.approval);
    assert.equal(code.execution, snapshot.expected_code_action.execution);
    assert.equal(code.phase, snapshot.expected_code_action.phase);
    assert.equal(code.statusLabel, snapshot.expected_code_action.status_label);
  }
});

test("requires an explicit start observation before showing running", () => {
  const beforeStart = fixture.expected_projection.snapshots.find(
    (snapshot) => snapshot.expected_code_action.phase === "approval_released",
  )!;
  const started = fixture.expected_projection.snapshots.find(
    (snapshot) => snapshot.expected_code_action.phase === "waiting_receipt",
  )!;

  assert.equal(
    buildExecutionTrace(
      normalizedEvents(beforeStart.included_audit_ids, currentApproval(beforeStart)),
      currentApproval(beforeStart),
    ).actions.at(-1)?.statusLabel,
    "已放行，等待运行",
  );
  assert.equal(
    buildExecutionTrace(
      normalizedEvents(started.included_audit_ids, currentApproval(started)),
      currentApproval(started),
    ).actions.at(-1)?.statusLabel,
    "正在执行",
  );
});

test("does not guess a primary decision from a broken policy audit link", () => {
  const events = normalizedEvents();
  const corrupted = events.map((event) =>
    event.auditId === "audit_outcome_code_exec_001"
      ? { ...event, policyAuditId: "audit_missing" }
      : event,
  );
  const code = buildExecutionTrace(corrupted, currentApproval()).actions.at(-1)!;

  assert.equal(code.decision, "unknown");
  assert.equal(code.primaryAuditId, null);
  assert.equal(code.execution, "executed");
});

test("deduplicates policy checks and omits records without action_id", () => {
  const events = normalizedEvents();
  const policy = events.find((event) => event.auditId === "audit_policy_memory_read_001")!;
  const duplicate = { ...policy, auditId: "audit_policy_memory_read_retry" };
  const withoutAction = { ...policy, actionId: null, auditId: "audit_without_action" };
  const trace = buildExecutionTrace([...events, duplicate, withoutAction], currentApproval());

  assert.equal(trace.actions.length, 2);
  assert.equal(trace.actions[0]?.policyChecks.length, 1);
  assert.equal(
    trace.actions.some((action) => action.auditIds.includes("audit_without_action")),
    false,
  );
});
