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

function evidence(
  base: NormalizedAuditEvidence,
  overrides: Partial<NormalizedAuditEvidence>,
): NormalizedAuditEvidence {
  return {
    ...base,
    actionId: null,
    approval: {
      approvalId: null,
      resolvedAt: null,
      status: "not_required",
    },
    decision: "allow",
    decisionId: null,
    execution: {
      completedAt: null,
      error: null,
      invokedAt: null,
      persisted: null,
      receiptRecorded: false,
      status: "unknown",
      toolResultEnteredContext: null,
    },
    intervention: "none",
    policyAuditId: null,
    recordType: "policy_evaluation",
    toolName: null,
    ...overrides,
  };
}

test("projects the two-action regression fixture without treating it as a product whitelist", () => {
  const trace = buildExecutionTrace(normalizedEvents(), currentApproval());

  assert.equal(trace.lifecycleState, "completed");
  assert.equal(trace.steps.length, 2);
  assert.deepEqual(
    trace.steps.map((step) => step.actionId),
    ["call_memory_read_001", "call_code_exec_001"],
  );

  const memory = trace.steps[0]!;
  assert.equal(memory.displayName, "读取记忆");
  assert.equal(memory.kind, "action");
  assert.equal(memory.decision, "allow");
  assert.equal(memory.approval, "not_required");
  assert.equal(memory.execution, "executed");
  assert.equal(memory.phase, "terminal");

  const code = trace.steps[1]!;
  assert.equal(code.displayName, "执行代码");
  assert.equal(code.kind, "action");
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
    const code = trace.steps.find((step) => step.actionId === "call_code_exec_001");
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
    ).steps.at(-1)?.statusLabel,
    "已放行，等待运行",
  );
  assert.equal(
    buildExecutionTrace(
      normalizedEvents(started.included_audit_ids, currentApproval(started)),
      currentApproval(started),
    ).steps.at(-1)?.statusLabel,
    "正在执行",
  );
});

test("does not guess a primary decision from a broken policy audit link", () => {
  const corrupted = normalizedEvents().map((event) =>
    event.auditId === "audit_outcome_code_exec_001"
      ? { ...event, policyAuditId: "audit_missing" }
      : event,
  );
  const code = buildExecutionTrace(corrupted, currentApproval()).steps.at(-1)!;

  assert.equal(code.decision, "unknown");
  assert.equal(code.primaryAuditId, code.auditIds[0]);
  assert.equal(code.execution, "executed");
});

test("deduplicates policy checks before grouping and keeps distinct checkpoints", () => {
  const events = normalizedEvents();
  const policy = events.find((event) => event.auditId === "audit_policy_memory_read_001")!;
  const duplicate = { ...policy, auditId: "audit_policy_memory_read_retry" };
  const checkpoint = evidence(policy, {
    actionId: null,
    auditId: "audit_context",
    decisionId: "decision_context",
    eventId: "event_context",
    eventType: "context_assembled",
  });
  const trace = buildExecutionTrace([...events, duplicate, checkpoint], currentApproval());
  const context = trace.steps.find((step) => step.category === "context");

  assert.equal(trace.steps.length, 3);
  assert.equal(trace.steps[0]?.policyChecks.length, 1);
  assert.equal(context?.kind, "checkpoint");
  assert.equal(context?.statusLabel, "安全检查已完成");
});

test("shows every supported GuardEvent once while grouping one action lifecycle", () => {
  const base = normalizedEvents()[0]!;
  const rows: NormalizedAuditEvidence[] = [
    evidence(base, {
      auditId: "audit_context",
      chainIndex: 101,
      decisionId: "decision_context",
      eventId: "event_context",
      eventType: "context_assembled",
      occurredAt: "2026-08-08T08:00:01Z",
    }),
    evidence(base, {
      auditId: "audit_model_input",
      chainIndex: 102,
      decisionId: "decision_model_input",
      eventId: "event_model_input",
      eventType: "model_input_prepared",
      occurredAt: "2026-08-08T08:00:02Z",
    }),
    evidence(base, {
      actionId: "call_complete_matrix",
      auditId: "audit_tool",
      chainIndex: 103,
      decisionId: "decision_tool",
      eventId: "event_tool",
      eventType: "tool_call_proposed",
      occurredAt: "2026-08-08T08:00:03Z",
      toolName: "read_file",
    }),
    evidence(base, {
      actionId: "call_complete_matrix",
      auditId: "audit_tool_started",
      chainIndex: 104,
      decision: "unknown",
      eventId: "event_tool",
      eventType: "tool_call_started",
      occurredAt: "2026-08-08T08:00:04Z",
      recordType: "runtime_observation",
      stage: "tool_call_started",
      toolName: "read_file",
    }),
    evidence(base, {
      actionId: "call_complete_matrix",
      auditId: "audit_tool_result",
      chainIndex: 105,
      decisionId: "decision_tool_result",
      eventId: "event_tool_result",
      eventType: "tool_result_produced",
      occurredAt: "2026-08-08T08:00:05Z",
      toolName: "read_file",
    }),
    evidence(base, {
      actionId: "call_complete_matrix",
      auditId: "audit_tool_outcome",
      chainIndex: 106,
      decisionId: "decision_tool_result",
      eventId: "event_tool_result",
      eventType: "tool_call_completed",
      execution: {
        ...base.execution,
        completedAt: "2026-08-08T08:00:06Z",
        receiptRecorded: true,
        status: "executed",
      },
      occurredAt: "2026-08-08T08:00:06Z",
      policyAuditId: "audit_tool_result",
      recordType: "runtime_outcome",
      toolName: "read_file",
    }),
    evidence(base, {
      actionId: "event_model_output",
      auditId: "audit_model_output",
      chainIndex: 107,
      decisionId: "decision_model_output",
      eventId: "event_model_output",
      eventType: "model_output_produced",
      occurredAt: "2026-08-08T08:00:07Z",
    }),
    evidence(base, {
      actionId: "event_memory",
      auditId: "audit_memory",
      chainIndex: 108,
      decisionId: "decision_memory",
      eventId: "event_memory",
      eventType: "memory_write_proposed",
      occurredAt: "2026-08-08T08:00:08Z",
    }),
    evidence(base, {
      actionId: "event_message",
      auditId: "audit_message",
      chainIndex: 109,
      decisionId: "decision_message",
      eventId: "event_message",
      eventType: "message_send_proposed",
      occurredAt: "2026-08-08T08:00:09Z",
    }),
  ];

  const trace = buildExecutionTrace(rows);
  const tool = trace.steps.find((step) => step.actionId === "call_complete_matrix");
  const policyEventIds = trace.steps.flatMap((step) =>
    step.events.flatMap((event) =>
      event.recordType === "policy_evaluation" && event.eventId ? [event.eventId] : [],
    ),
  );

  assert.deepEqual(policyEventIds, [
    "event_context",
    "event_model_input",
    "event_tool",
    "event_tool_result",
    "event_model_output",
    "event_memory",
    "event_message",
  ]);
  assert.equal(trace.steps.length, 6);
  assert.equal(tool?.kind, "action");
  assert.deepEqual(tool?.eventIds, ["event_tool", "event_tool_result"]);
  assert.deepEqual(
    tool?.events.map((event) => event.eventType),
    ["tool_call_proposed", "tool_call_started", "tool_result_produced", "tool_call_completed"],
  );
  assert.equal(trace.steps.find((step) => step.category === "context")?.phase, "checked");
  assert.equal(trace.steps.find((step) => step.category === "model_input")?.phase, "checked");
  assert.equal(trace.steps.find((step) => step.category === "model_output")?.kind, "checkpoint");
  assert.equal(
    trace.steps.find((step) => step.category === "memory")?.receiptExpectation,
    "required",
  );
  assert.equal(
    trace.steps.find((step) => step.category === "message")?.receiptExpectation,
    "required",
  );
});

test("uses a stable checkpoint fallback for a future policy event", () => {
  const base = normalizedEvents()[0]!;
  const future = evidence(base, {
    auditId: "audit_future",
    decisionId: "decision_future",
    eventId: "event_future",
    eventType: "future_guard_checkpoint",
  });

  const trace = buildExecutionTrace([future]);

  assert.equal(trace.steps.length, 1);
  assert.equal(trace.steps[0]?.kind, "checkpoint");
  assert.equal(trace.steps[0]?.category, "unknown");
  assert.equal(trace.steps[0]?.eventId, "event_future");
});

test("stops after an explicit lifecycle terminal even when a receipt is missing", () => {
  const base = normalizedEvents()[0]!;
  const action = evidence(base, {
    actionId: "call_missing_receipt",
    auditId: "audit_action",
    decisionId: "decision_action",
    eventId: "event_action",
    eventType: "tool_call_proposed",
    toolName: "read_file",
  });
  const completed = evidence(base, {
    auditId: "audit_trace_completed",
    decision: "unknown",
    eventId: "event_trace_completed",
    eventType: "trace_completed",
    recordType: "runtime_observation",
    stage: "trace_completed",
  });

  const observing = buildExecutionTrace([action]);
  const terminal = buildExecutionTrace([action, completed]);

  assert.equal(shouldContinueTracePolling(observing), true);
  assert.equal(shouldContinueTracePolling(terminal), false);
  assert.equal(terminal.steps.length, 1);
  assert.equal(terminal.steps[0]?.phase, "evaluated");
});
