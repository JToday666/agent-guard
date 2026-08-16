import assert from "node:assert/strict";
import test from "node:test";

import { mapTraceDetail } from "../../api/guard-api-mappers.ts";
import type { GuardTraceDetailDto } from "../../api/guard-api-types.ts";
import type {
  ApprovalRequest,
  ProvenanceWindow,
  TraceApprovalWindow,
  TraceAuditWindow,
} from "../../types/dashboard.ts";
import { createDashboardDataSourceDescriptor } from "../sources/dashboard-data-source.ts";
import { approvals, auditEvents } from "../sources/mock-data.ts";
import { projectApprovalBasis } from "./approval-basis-projector.ts";
import {
  buildExecutionTrace,
  buildRuntimeSupervisionViewModel,
  buildRuntimeSupervisionViewModelSafely,
} from "./execution-trace.ts";
import { buildTraceEvidenceViewModel } from "./trace-evidence.ts";

const TRACE_ID = "trace_002";

function projectionFixture() {
  const approval = approvals.find((item) => item.traceId === TRACE_ID)!;
  const rows = auditEvents.filter((event) => event.traceId === TRACE_ID);
  const events = buildTraceEvidenceViewModel(TRACE_ID, rows, [approval], null).events;
  const execution = buildExecutionTrace(events, [approval], {
    elementSourceMode: "mock",
    traceId: TRACE_ID,
  });
  const step = execution.steps.find((item) => item.approvalId === approval.id)!;
  return { approval, events, execution, step };
}

const completeAuditWindow: TraceAuditWindow = {
  hasMore: false,
  limit: 1000,
  nextCursor: null,
  returnedCount: 2,
  snapshotId: "snapshot-trace-002",
};

const completeApprovalWindow: TraceApprovalWindow = {
  hasMore: false,
  limit: 1000,
  returnedCount: 1,
};

const completeProvenanceWindow: ProvenanceWindow = {
  edgeLimit: 2000,
  edgesHaveMore: false,
  hasMore: false,
  nodeLimit: 1000,
  nodesHaveMore: false,
  returnedEdgeCount: 2,
  returnedNodeCount: 2,
};

function liveTraceResponse(): GuardTraceDetailDto {
  return {
    trace_id: "trace_live_basis",
    audit_events: [
      {
        audit_id: "audit_policy_live_basis",
        schema_version: "0.4",
        trace_id: "trace_live_basis",
        case_id: null,
        runtime: "langgraph",
        timestamp: "2026-08-16T01:00:00Z",
        stage: "before_tool_call",
        event_type: "tool_call_proposed",
        attack_type: null,
        is_malicious: null,
        summary: "Agent proposed send_email",
        decision: "ask",
        risk_score: 62,
        severity: "medium",
        blocked: true,
        resource_targets: ["recipient@example.invalid"],
        rule_hits: ["P005_external_send"],
        reason: "External send requires review",
        links: {
          action_id: "call_live_basis",
          approval_id: "approval_live_basis",
          decision_id: "decision_live_basis",
          event_id: "event_live_basis",
        },
        latency_ms: 3,
        metadata: { action_name: "send_email" },
        record_type: "policy_evaluation",
        evidence: {
          policy: {
            bundle_id: "default",
            canonical_digest: `sha256:${"a".repeat(64)}`,
            revision: 7,
            version: "p7",
          },
        },
      },
    ],
    approvals: [
      {
        approval_id: "approval_live_basis",
        trace_id: "trace_live_basis",
        subject_id: "call_live_basis",
        subject_type: "tool_call",
        action_id: "call_live_basis",
        action_name: "send_email",
        requesting_principal_id: "principal_live_basis",
        runtime: "langgraph",
        agent_id: "agent_live_basis",
        status: "pending",
        decision_options: ["allow_once", "deny"],
        decision: null,
        resource: "recipient@example.invalid",
        reason: "External send requires review",
        risk_score: 62,
        severity: "medium",
        evidence: {
          event: {
            event_id: "event_live_basis",
            event_type: "tool_call_proposed",
            trace_id: "trace_live_basis",
            runtime: "langgraph",
            source_type: "user",
            source_trust: "trusted",
            resource_targets: ["recipient@example.invalid"],
          },
          decision: {
            decision_id: "decision_live_basis",
            decision: "ask",
            risk_score: 62,
            severity: "medium",
            reason: "External send requires review",
            rule_hits: [{ rule_id: "P005_external_send" }],
          },
        },
        created_at: "2026-08-16T01:00:00Z",
        expires_at: "2026-08-16T01:15:00Z",
        resolved_at: null,
      },
    ],
    audit_window: {
      has_more: false,
      limit: 1000,
      next_cursor: null,
      returned_count: 1,
      snapshot_id: "snapshot-live-basis",
    },
    approval_window: { has_more: false, limit: 1000, returned_count: 1 },
  };
}

test("projects one recorded basis from the execution projector selected ASK", () => {
  const { approval, step } = projectionFixture();
  const basis = projectApprovalBasis({ approval, step, traceId: TRACE_ID });

  assert.equal(basis.completeness, "recorded");
  assert.deepEqual(basis.missingReasons, []);
  assert.equal(basis.approvalId, approval.id);
  assert.equal(basis.actionId, step.actionId);
  assert.equal(basis.sourceContext.eventId, approval.eventId);
  assert.equal(basis.officialDecision.decision, "ask");
  assert.equal(basis.officialDecision.policyAuditId, step.primaryAuditId);
  assert.equal(basis.resolution.decision, "allow_once");
  assert.equal(basis.resolution.resolutionSource, "human");
  assert.equal(basis.v21Assessment, step.supervision.v21Assessment);
  assert.equal(basis.enforcement, step.supervision.enforcement);
  assert.equal("execution" in basis, false);
});

test("keeps old approval payloads visible but makes their basis unavailable", () => {
  const { approval, step } = projectionFixture();
  const oldApproval: ApprovalRequest = { ...approval, evidence: null };
  const basis = projectApprovalBasis({ approval: oldApproval, step, traceId: TRACE_ID });

  assert.equal(basis.completeness, "unavailable");
  assert.ok(basis.missingReasons.includes("APPROVAL_EVIDENCE_UNAVAILABLE"));
});

test("fails closed when nested evidence identity disagrees with the selected step", () => {
  const { approval, step } = projectionFixture();
  const mismatched: ApprovalRequest = {
    ...approval,
    evidence: { ...approval.evidence!, eventTraceId: "trace_other" },
  };
  const basis = projectApprovalBasis({ approval: mismatched, step, traceId: TRACE_ID });

  assert.equal(basis.completeness, "unavailable");
  assert.ok(basis.missingReasons.includes("APPROVAL_EVIDENCE_TRACE_ID_MISMATCH"));
});

test("fails closed when approval decision facts disagree with official evidence", () => {
  const { approval, step } = projectionFixture();
  const mismatched: ApprovalRequest = {
    ...approval,
    evidence: { ...approval.evidence!, riskScore: approval.riskScore - 1 },
  };
  const basis = projectApprovalBasis({ approval: mismatched, step, traceId: TRACE_ID });

  assert.equal(basis.completeness, "unavailable");
  assert.ok(basis.missingReasons.includes("APPROVAL_EVIDENCE_DECISION_FACTS_MISMATCH"));
});

test("fails closed when approval lifecycle and selected-step resolution diverge", () => {
  const { approval, step } = projectionFixture();
  const inconsistent: ApprovalRequest = { ...approval, status: "pending" };
  const basis = projectApprovalBasis({ approval: inconsistent, step, traceId: TRACE_ID });

  assert.equal(basis.completeness, "unavailable");
  assert.ok(basis.missingReasons.includes("APPROVAL_LIFECYCLE_INVALID"));
  assert.ok(basis.missingReasons.includes("APPROVAL_RESOLUTION_MISMATCH"));
});

test("marks a correlated basis partial when any evidence window is truncated", () => {
  const { approval, step } = projectionFixture();
  const basis = projectApprovalBasis({
    approval,
    step,
    traceId: TRACE_ID,
    windowTruncationReasons: ["TRACE_AUDIT_WINDOW_TRUNCATED"],
  });

  assert.equal(basis.completeness, "partial");
  assert.deepEqual(basis.missingReasons, ["TRACE_AUDIT_WINDOW_TRUNCATED"]);
});

test("integrates recorded basis into the runtime supervision VM and honors the flag", () => {
  const { approval, events } = projectionFixture();
  const common = {
    approvalWindow: completeApprovalWindow,
    approvals: [approval],
    auditWindow: completeAuditWindow,
    dataSource: createDashboardDataSourceDescriptor({ isProduction: false, viteMode: "mock" }),
    elementSourceMode: "mock" as const,
    events,
    provenanceWindow: completeProvenanceWindow,
    traceId: TRACE_ID,
  };
  const enabled = buildRuntimeSupervisionViewModel({ ...common, approvalBasisEnabled: true });
  const disabled = buildRuntimeSupervisionViewModel({ ...common, approvalBasisEnabled: false });

  assert.equal(enabled.approvalBasisById[approval.id]?.completeness, "recorded");
  assert.equal(enabled.capabilities.approvalBasis, "recorded");
  assert.deepEqual(disabled.approvalBasisById, {});
  assert.equal(disabled.capabilities.approvalBasis, "unavailable");
  assert.deepEqual(disabled.execution, enabled.execution);
});

test("maps and enriches one complete live Trace into a recorded basis", () => {
  const detail = mapTraceDetail(liveTraceResponse());
  const approval = detail.approvals[0]!;
  assert.equal(approval.eventId, "event_live_basis");
  assert.equal(approval.policyAuditId, "audit_policy_live_basis");
  assert.equal(approval.decisionId, "decision_live_basis");

  const events = buildTraceEvidenceViewModel(
    detail.id,
    detail.events,
    detail.approvals,
    null,
  ).events;
  const supervision = buildRuntimeSupervisionViewModel({
    approvalBasisEnabled: true,
    approvalWindow: detail.approvalWindow,
    approvals: detail.approvals,
    auditWindow: detail.auditWindow,
    dataSource: createDashboardDataSourceDescriptor({
      isProduction: false,
      runtimeSupervisionS1Enabled: true,
      viteMode: "development",
    }),
    elementSourceMode: "live",
    events,
    traceId: detail.id,
  });

  assert.equal(supervision.approvalBasisById.approval_live_basis?.completeness, "recorded");
  assert.equal(supervision.capabilities.approvalBasis, "recorded");
});

test("propagates Trace, Approval and Provenance truncation to root and basis completeness", () => {
  const { approval, events } = projectionFixture();
  const viewModel = buildRuntimeSupervisionViewModel({
    approvalBasisEnabled: true,
    approvalWindow: { ...completeApprovalWindow, hasMore: true },
    approvals: [approval],
    auditWindow: { ...completeAuditWindow, hasMore: true },
    dataSource: createDashboardDataSourceDescriptor({ isProduction: false, viteMode: "mock" }),
    elementSourceMode: "mock",
    events,
    provenanceWindow: { ...completeProvenanceWindow, hasMore: true },
    traceId: TRACE_ID,
  });

  assert.equal(viewModel.completeness.auditEvents, "partial");
  assert.equal(viewModel.completeness.approvals, "partial");
  assert.equal(viewModel.completeness.provenance, "partial");
  assert.deepEqual(viewModel.completeness.truncatedReasons, [
    "TRACE_AUDIT_WINDOW_TRUNCATED",
    "TRACE_APPROVAL_WINDOW_TRUNCATED",
    "PROVENANCE_WINDOW_TRUNCATED",
  ]);
  assert.equal(viewModel.approvalBasisById[approval.id]?.completeness, "partial");
  assert.equal(viewModel.capabilities.approvalBasis, "partial");
  assert.ok(viewModel.warnings.some((warning) => warning.code === "window_truncated"));
});

test("contains projection failure so the independent Audit view can still render", () => {
  const { approval, events } = projectionFixture();
  const viewModel = buildRuntimeSupervisionViewModelSafely({
    approvals: [approval],
    dataSource: createDashboardDataSourceDescriptor({ isProduction: false, viteMode: "mock" }),
    elementSourceMode: "mock",
    events,
    traceId: "",
  });

  assert.deepEqual(viewModel.execution.steps, []);
  assert.ok(viewModel.warnings.some((warning) => warning.code === "projection_failed"));
});
