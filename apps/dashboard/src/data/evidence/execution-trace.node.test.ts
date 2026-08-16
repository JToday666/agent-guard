import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { mapApproval, mapAuditEvent } from "../../api/guard-api-mappers.ts";
import type { GuardApprovalDto, GuardAuditEventDto } from "../../api/guard-api-types.ts";
import type { ApprovalRequest, NormalizedAuditEvidence } from "../../types/dashboard.ts";
import { createDashboardDataSourceDescriptor } from "../sources/dashboard-data-source.ts";
import { buildTraceEvidenceViewModel } from "./trace-evidence.ts";
import {
  buildExecutionTrace,
  buildRuntimeSupervisionViewModel,
  shouldContinueTracePolling,
} from "./execution-trace.ts";

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
      resolution_source: snapshot.approval.status === "resolved" ? source.resolution_source : null,
      resolved_by: snapshot.approval.status === "resolved" ? source.resolved_by : null,
      resolution_reason: snapshot.approval.status === "resolved" ? source.resolution_reason : null,
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

function buildTrace(
  events: readonly NormalizedAuditEvidence[],
  approvals: readonly ApprovalRequest[] = [],
) {
  return buildExecutionTrace(events, approvals, {
    elementSourceMode: "mock",
    traceId: fixture.source_facts.trace_id,
  });
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

function completeV21Coverage() {
  const domains = [
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
  ];
  return Object.fromEntries(
    domains.map((domain) => [
      domain,
      {
        as_of_sequence: null,
        domain,
        projector_version: "v21-09.projector.1",
        reason_codes: [],
        status: "complete",
      },
    ]),
  );
}

test("projects the two-action regression fixture without treating it as a product whitelist", () => {
  const trace = buildTrace(normalizedEvents(), currentApproval());

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
  assert.equal(code.supervision.officialDecision.decision, "ask");
  assert.equal(code.supervision.approval.decision, "allow_once");
  assert.equal(code.supervision.enforcement.availability, "unavailable");
  assert.equal(code.supervision.execution.status, "executed");
  assert.equal(code.supervision.execution.receiptRecorded, true);
  assert.equal(code.supervision.v21Assessment.availability, "unavailable");
  assert.equal(code.supervision.action?.argumentSummary, null);
  assert.deepEqual(
    code.policyChecks.map((check) => check.auditId),
    ["audit_policy_code_exec_001"],
  );
  assert.equal(shouldContinueTracePolling(trace), false);
});

test("keeps decision, approval and execution as three independent facts", () => {
  for (const snapshot of fixture.expected_projection.snapshots) {
    const approvals = currentApproval(snapshot);
    const trace = buildTrace(normalizedEvents(snapshot.included_audit_ids, approvals), approvals);
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
    buildTrace(
      normalizedEvents(beforeStart.included_audit_ids, currentApproval(beforeStart)),
      currentApproval(beforeStart),
    ).steps.at(-1)?.statusLabel,
    "已放行，等待运行",
  );
  assert.equal(
    buildTrace(
      normalizedEvents(started.included_audit_ids, currentApproval(started)),
      currentApproval(started),
    ).steps.at(-1)?.statusLabel,
    "正在执行",
  );
  const running = buildTrace(
    normalizedEvents(started.included_audit_ids, currentApproval(started)),
    currentApproval(started),
  ).steps.at(-1)!;
  assert.equal(running.supervision.activityState, "running");
  assert.equal(running.supervision.execution.status, "unknown");
  assert.equal(running.supervision.execution.receiptRecorded, false);
});

test("does not guess a primary decision from a broken policy audit link", () => {
  const corrupted = normalizedEvents().map((event) =>
    event.auditId === "audit_outcome_code_exec_001"
      ? { ...event, policyAuditId: "audit_missing" }
      : event,
  );
  const code = buildTrace(corrupted, currentApproval()).steps.at(-1)!;

  assert.equal(code.decision, "unknown");
  assert.equal(code.primaryAuditId, code.auditIds[0]);
  assert.equal(code.execution, "unknown");
  assert.equal(code.supervision.officialDecision.decision, "unknown");
  assert.equal(code.supervision.execution.availability, "partial");
  assert.equal(code.supervision.controlIntegrity.status, "correlation_conflict");
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
  const trace = buildTrace([...events, duplicate, checkpoint], currentApproval());
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

  const trace = buildTrace(rows);
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

  const trace = buildTrace([future]);

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

  const observing = buildTrace([action]);
  const terminal = buildTrace([action, completed]);

  assert.equal(shouldContinueTracePolling(observing), true);
  assert.equal(shouldContinueTracePolling(terminal), false);
  assert.equal(terminal.steps.length, 1);
  assert.equal(terminal.steps[0]?.phase, "evaluated");
  assert.equal(observing.lifecycleSupervision.confirmedTerminal, false);
  assert.equal(terminal.lifecycleSupervision.confirmedTerminal, true);
});

test("does not confirm a terminal lifecycle from conflicting duplicate audit ids", () => {
  const base = normalizedEvents()[0]!;
  const action = evidence(base, {
    actionId: "mock_action_lifecycle_conflict",
    auditId: "audit_lifecycle_conflict_action",
    decision: "allow",
    decisionId: "decision_lifecycle_conflict",
    eventId: "event_lifecycle_conflict_action",
    eventType: "tool_call_proposed",
    toolName: "read_file",
  });
  const completed = evidence(base, {
    auditId: "audit_lifecycle_conflict_terminal",
    eventId: "event_lifecycle_conflict_terminal",
    eventType: "trace_completed",
    recordType: "runtime_observation",
    resultSummary: "completed-a",
    stage: "trace_completed",
  });
  const conflictingCompleted = { ...completed, resultSummary: "completed-b" };

  const trace = buildTrace([action, completed, conflictingCompleted]);

  assert.equal(trace.lifecycleSupervision.confirmedTerminal, false);
  assert.equal(trace.lifecycleSupervision.completionReason, "生命周期审计记录冲突，终态未确认");
  assert.equal(shouldContinueTracePolling(trace), true);
});

test("keeps deny, enforcement and execution proof independent", () => {
  const base = normalizedEvents()[0]!;
  const denied = evidence(base, {
    actionId: "mock_action_denied_without_receipt",
    auditId: "audit_denied_without_receipt",
    decision: "deny",
    decisionId: "decision_denied_without_receipt",
    eventId: "event_denied_without_receipt",
    eventType: "tool_call_proposed",
    toolName: "send_message",
  });

  const step = buildTrace([denied]).steps[0]!;

  assert.equal(step.supervision.officialDecision.decision, "deny");
  assert.equal(step.supervision.enforcement.availability, "unavailable");
  assert.equal(step.supervision.enforcement.gateState, "unknown");
  assert.equal(step.supervision.execution.availability, "unavailable");
  assert.equal(step.supervision.execution.status, "unknown");
  assert.equal(step.supervision.execution.receiptRecorded, false);
});

test("fails closed when more than one runtime receipt can close an action", () => {
  const base = normalizedEvents()[0]!;
  const policy = evidence(base, {
    actionId: "mock_action_receipt_conflict",
    auditId: "audit_receipt_conflict_policy",
    decision: "allow",
    decisionId: "decision_receipt_conflict",
    eventId: "event_receipt_conflict",
    eventType: "tool_call_proposed",
    toolName: "write_file",
  });
  const receipt = (auditId: string, status: "executed" | "not_invoked") =>
    evidence(base, {
      actionId: "mock_action_receipt_conflict",
      auditId,
      decision: "unknown",
      eventId: "event_receipt_conflict",
      eventType: status === "executed" ? "tool_call_completed" : "tool_call_not_invoked",
      execution: {
        ...base.execution,
        receiptRecorded: true,
        status,
      },
      policyAuditId: policy.auditId,
      recordType: "runtime_outcome",
      toolName: "write_file",
    });

  const step = buildTrace([
    policy,
    receipt("audit_receipt_conflict_a", "executed"),
    receipt("audit_receipt_conflict_b", "not_invoked"),
  ]).steps[0]!;

  assert.equal(step.execution, "unknown");
  assert.equal(step.supervision.execution.availability, "partial");
  assert.equal(step.supervision.execution.receiptRecorded, false);
  assert.equal(step.supervision.controlIntegrity.status, "correlation_conflict");
});

test("requires receipt event and decision links to match the selected policy", () => {
  const corrupted = normalizedEvents().map((event) =>
    event.auditId === "audit_outcome_code_exec_001"
      ? { ...event, decisionId: "decision_for_another_action" }
      : event,
  );

  const step = buildTrace(corrupted, currentApproval()).steps.at(-1)!;

  assert.equal(step.supervision.officialDecision.decision, "ask");
  assert.equal(step.supervision.execution.availability, "partial");
  assert.equal(step.supervision.execution.status, "unknown");
  assert.equal(step.supervision.execution.receiptRecorded, false);
  assert.equal(step.supervision.controlIntegrity.status, "correlation_conflict");
});

test("marks duplicate audit ids with different content as an identity conflict", () => {
  const base = normalizedEvents()[0]!;
  const policy = evidence(base, {
    actionId: "mock_action_duplicate_audit",
    auditId: "audit_duplicate_identity",
    decision: "allow",
    decisionId: "decision_duplicate_identity",
    eventId: "event_duplicate_identity",
    eventType: "tool_call_proposed",
    toolName: "read_file",
  });
  const conflictingDuplicate = { ...policy, decision: "deny" as const };

  const trace = buildTrace([policy, conflictingDuplicate]);
  const reversedTrace = buildTrace([conflictingDuplicate, policy]);
  const step = trace.steps[0]!;

  assert.equal(step.supervision.officialDecision.availability, "partial");
  assert.equal(step.supervision.officialDecision.decision, "unknown");
  assert.equal(step.supervision.semantics.availability, "partial");
  assert.equal(step.supervision.controlIntegrity.status, "correlation_conflict");
  assert.deepEqual(step.supervision.controlIntegrity.reasonCodes, ["DUPLICATE_AUDIT_ID_CONFLICT"]);
  assert.deepEqual(trace, reversedTrace);
});

test("confirms a control violation when runtime progress follows denied approval", () => {
  const base = normalizedEvents()[0]!;
  const policy = evidence(base, {
    actionId: "mock_action_started_after_approval_deny",
    approval: {
      approvalId: "approval_started_after_deny",
      resolvedAt: "2026-08-09T08:00:01Z",
      status: "denied",
    },
    auditId: "audit_started_after_approval_deny",
    decision: "ask",
    decisionId: "decision_started_after_approval_deny",
    eventId: "event_started_after_approval_deny",
    eventType: "tool_call_proposed",
    toolName: "send_message",
  });
  const started = evidence(base, {
    actionId: policy.actionId,
    auditId: "audit_runtime_started_after_approval_deny",
    eventId: policy.eventId,
    eventType: "tool_call_started",
    recordType: "runtime_observation",
    stage: "tool_call_started",
    toolName: policy.toolName,
  });

  const step = buildTrace([policy, started]).steps[0]!;

  assert.equal(step.supervision.approval.status, "denied");
  assert.equal(step.supervision.activityState, "running");
  assert.equal(step.supervision.execution.status, "unknown");
  assert.equal(step.supervision.controlIntegrity.status, "confirmed_violation");
  assert.deepEqual(step.supervision.controlIntegrity.reasonCodes, [
    "APPROVAL_DENY_FOLLOWED_BY_RUNTIME_PROGRESS",
  ]);
  assert.ok(
    step.supervision.controlIntegrity.sourceRefs.some(
      (source) => source.id === "audit_runtime_started_after_approval_deny",
    ),
  );
  const sourceIdentities = step.supervision.controlIntegrity.sourceRefs.map(
    (source) => `${source.id}\u0000${source.traceId}`,
  );
  assert.equal(new Set(sourceIdentities).size, sourceIdentities.length);
});

test("projects a valid V21-09 record only as verified shadow evidence", () => {
  const base = normalizedEvents()[0]!;
  const baseRaw = base.raw as Record<string, unknown>;
  const baseEvidence = (baseRaw.evidence ?? {}) as Record<string, unknown>;
  const shadow = evidence(base, {
    actionId: "mock_action_v21_shadow",
    auditId: "audit_v21_shadow",
    decision: "allow",
    decisionId: "decision_v21_shadow",
    eventId: "event_v21_shadow",
    eventType: "tool_call_proposed",
    raw: {
      ...baseRaw,
      evidence: {
        ...baseEvidence,
        decision_v21: {
          schema_version: "2.1",
          payload: {
            assessment_id: "assessment_shadow_001",
            coverage: completeV21Coverage(),
            degradation_ids: [],
            divergence_category: "legacy_allow_v21_deny",
            final_decision: "allow",
            legacy_decision: "allow",
            mode: "shadow",
            v21_fast_disposition: "CLEAR_DENY",
          },
        },
      },
    },
    toolName: "call_api",
  });

  const step = buildTrace([shadow]).steps[0]!;

  assert.equal(step.supervision.officialDecision.decision, "allow");
  assert.equal(step.supervision.v21Assessment.decisionAuthority, "shadow");
  assert.equal(step.supervision.v21Assessment.authorityVerification, "verified");
  assert.equal(step.supervision.v21Assessment.fastDisposition, "CLEAR_DENY");
  assert.equal(step.supervision.v21Assessment.recordedFinalDecision, "allow");
  assert.equal(step.supervision.v21Assessment.coverage.behavior, "complete");
});

test("does not verify shadow evidence that disagrees with the official decision", () => {
  const base = normalizedEvents()[0]!;
  const raw = base.raw as Record<string, unknown>;
  const shadow = evidence(base, {
    actionId: "mock_action_v21_shadow_mismatch",
    auditId: "audit_v21_shadow_mismatch",
    decision: "deny",
    decisionId: "decision_v21_shadow_mismatch",
    eventId: "event_v21_shadow_mismatch",
    eventType: "tool_call_proposed",
    raw: {
      ...raw,
      evidence: {
        ...((raw.evidence ?? {}) as Record<string, unknown>),
        decision_v21: {
          schema_version: "2.1",
          payload: {
            assessment_id: "assessment_shadow_mismatch",
            coverage: completeV21Coverage(),
            degradation_ids: [],
            divergence_category: null,
            final_decision: "allow",
            legacy_decision: "allow",
            mode: "shadow",
            v21_fast_disposition: "CLEAR_ALLOW",
          },
        },
      },
    },
    toolName: "call_api",
  });

  const step = buildTrace([shadow]).steps[0]!;

  assert.equal(step.supervision.officialDecision.decision, "deny");
  assert.equal(step.supervision.v21Assessment.decisionAuthority, "none");
  assert.equal(step.supervision.v21Assessment.authorityVerification, "conflicted");
});

test("builds a deterministic supervision wrapper without a second action projection", () => {
  const events = normalizedEvents();
  const approvals = currentApproval();
  const input = {
    approvals,
    dataSource: createDashboardDataSourceDescriptor({ isProduction: false, viteMode: "mock" }),
    elementSourceMode: "mock" as const,
    events,
    traceId: fixture.source_facts.trace_id,
  };

  const first = buildRuntimeSupervisionViewModel(input);
  const second = buildRuntimeSupervisionViewModel(input);

  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, "runtime-supervision/0.1");
  assert.equal(first.execution.steps.length, 2);
  assert.equal(first.temporalState, "historical");
  assert.equal(first.provenancePresentation.nodes.length, 0);
});

test("reports partial receipt completeness when one required action lacks a receipt", () => {
  const events = normalizedEvents().filter(
    (event) => event.auditId !== "audit_outcome_code_exec_001",
  );
  const viewModel = buildRuntimeSupervisionViewModel({
    approvals: currentApproval(),
    dataSource: createDashboardDataSourceDescriptor({ isProduction: false, viteMode: "mock" }),
    elementSourceMode: "mock",
    events,
    traceId: fixture.source_facts.trace_id,
  });

  assert.equal(viewModel.completeness.runtimeReceipts, "partial");
  assert.equal(viewModel.capabilities.runtimeReceipts, "partial");
});
