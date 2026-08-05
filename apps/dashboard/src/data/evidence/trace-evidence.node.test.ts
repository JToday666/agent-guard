import assert from "node:assert/strict";
import test from "node:test";

import type { AuditEventRow } from "../../types/dashboard";
import { approvals, auditEvents } from "../sources/mock-data.ts";
import { buildTraceEvidenceViewModel } from "./trace-evidence.ts";

const integrity = {
  eventCount: auditEvents.length,
  firstBrokenAuditId: null,
  headHash: "hash",
  valid: true,
};

function buildMockEvidence(traceId: string) {
  return buildTraceEvidenceViewModel(
    traceId,
    auditEvents.filter((event) => event.traceId === traceId),
    approvals.filter((approval) => approval.traceId === traceId),
    integrity,
  );
}

test("normalizes the five intervention classes without collapsing their meanings", () => {
  const expected = new Map([
    ["trace_001", "pre_execution_deny"],
    ["trace_002", "approval_release"],
    ["trace_003", "audit_observation"],
    ["trace_004", "tool_result_quarantine"],
    ["trace_008", "model_output_revision"],
  ]);

  for (const [traceId, intervention] of expected) {
    const evidence = buildMockEvidence(traceId);
    assert.equal(evidence.primary?.intervention, intervention, traceId);
  }

  assert.equal(buildMockEvidence("trace_001").primary?.execution.status, "not_invoked");
  assert.equal(buildMockEvidence("trace_001").primary?.sideEffects.count, 0);
  assert.equal(buildMockEvidence("trace_002").primary?.execution.status, "executed");
  assert.equal(buildMockEvidence("trace_002").primary?.approval.status, "allowed");
  assert.equal(buildMockEvidence("trace_004").primary?.resultDisposition, "quarantined");
  assert.equal(
    buildMockEvidence("trace_004").primary?.sideEffects.measurementStatus,
    "not_measured",
  );
  assert.equal(buildMockEvidence("trace_008").primary?.resultDisposition, "modified");
});

test("does not infer execution or zero side effects from deny and blocked", () => {
  const event: AuditEventRow = {
    actionId: "action_sparse",
    agentAction: "read_file('/sensitive')",
    auditSequence: 1,
    attackType: "prompt_injection",
    blocked: true,
    caseId: "PI-SPARSE",
    decision: "deny",
    decisionId: "decision_sparse",
    eventId: "event_sparse",
    eventType: "tool_call_proposed",
    id: "audit_sparse_policy",
    isMalicious: true,
    occurredAt: "2026-06-07T12:00:00+08:00",
    reason: "策略拒绝",
    resource: "/sensitive",
    resourceTargets: ["/sensitive"],
    riskScore: 90,
    ruleHits: ["P001_sensitive_file_access"],
    runtime: "langgraph",
    severity: "high",
    stage: "before_tool_call",
    time: "12:00",
    tool: "read_file",
    traceId: "trace_sparse",
    userTask: "总结文档",
    raw: {
      audit_id: "audit_sparse_policy",
      blocked: true,
      decision: "deny",
      evidence: {
        guard_decision: { decision: "deny", reason: "策略拒绝", risk_score: 90 },
      },
      links: { decision_id: "decision_sparse", event_id: "event_sparse" },
      record_type: "policy_evaluation",
      risk_score: 90,
      rule_hits: ["P001_sensitive_file_access"],
    },
    recordType: "policy_evaluation",
  };

  const evidence = buildTraceEvidenceViewModel("trace_sparse", [event], [], null);
  assert.equal(evidence.primary?.decision, "deny");
  assert.equal(evidence.primary?.execution.status, "unknown");
  assert.equal(evidence.primary?.execution.receiptRecorded, false);
  assert.equal(evidence.primary?.sideEffects.count, null);
  assert.equal(evidence.primary?.sideEffects.measurementStatus, "unknown");
  assert.equal(
    evidence.facts.find((fact) => fact.id === "execution")?.availability,
    "not_recorded",
  );
  assert.equal(evidence.facts.find((fact) => fact.id === "side_effects")?.value, "未记录");
  assert.equal(evidence.conclusion.title, "策略决定：拒绝");
});

test("merges duplicate policy evaluations logically while retaining raw audit rows", () => {
  const original = auditEvents.find(
    (event) =>
      event.traceId === "trace_001" &&
      (event.raw as { record_type?: string }).record_type === "policy_evaluation",
  )!;
  const duplicateRaw = structuredClone(original.raw) as Record<string, unknown>;
  duplicateRaw.audit_id = "evt_20260607_001_duplicate";
  const duplicate: AuditEventRow = {
    ...original,
    id: "evt_20260607_001_duplicate",
    occurredAt: "2026-06-07T12:01:00.050+08:00",
    raw: duplicateRaw,
  };
  const rows = [...auditEvents.filter((event) => event.traceId === "trace_001"), duplicate];
  const evidence = buildTraceEvidenceViewModel("trace_001", rows, [], integrity);

  assert.equal(evidence.originalAuditCount, 3);
  assert.equal(evidence.logicalAuditCount, 2);
  assert.equal(evidence.duplicatePolicyAuditCount, 1);
  assert.equal(evidence.events.length, 3);
});

test("reads only the canonical AuditEvent integrity metadata", () => {
  const original = auditEvents.find((event) => event.traceId === "trace_001")!;
  const raw = structuredClone(original.raw) as Record<string, unknown>;
  const evidenceRecord = raw.evidence as Record<string, unknown>;
  evidenceRecord.audit = {
    chain_index: 999,
    entry_hash: "deprecated-entry",
    previous_hash: "deprecated-previous",
  };
  raw.chain_index = 998;
  raw.entry_hash = "deprecated-root-entry";
  raw.previous_hash = "deprecated-root-previous";
  raw.integrity = {
    canonicalization: "json:v1",
    event_hash: "canonical-entry",
    prev_hash: "canonical-previous",
    sequence: 42,
  };

  const normalized = buildTraceEvidenceViewModel(
    original.traceId,
    [{ ...original, raw }],
    [],
    integrity,
  ).events[0]!;

  assert.equal(normalized.chainIndex, 42);
  assert.equal(normalized.entryHash, "canonical-entry");
  assert.equal(normalized.previousHash, "canonical-previous");
});
