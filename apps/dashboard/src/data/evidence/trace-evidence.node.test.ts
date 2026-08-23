import assert from "node:assert/strict";
import test from "node:test";

import type { AuditEventRow, AuditIntegrity } from "../../types/dashboard";
import { approvals, auditEvents } from "../sources/mock-data.ts";
import { buildTraceEvidenceViewModel, getContentPreviewDisplay } from "./trace-evidence.ts";

const integrity: AuditIntegrity = {
  anchor: {
    checkpointHash: "b".repeat(64),
    checkpointHeadHash: "a".repeat(64),
    checkpointSequence: auditEvents.length,
    checkpointedAt: "2026-06-28T08:30:00Z",
    enabled: true,
    errorCode: null,
    keyId: "test-key-2026",
    lag: 0,
    status: "current",
  },
  canonicalization: "jcs:rfc8785",
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
  assert.equal(
    evidence.facts.find((fact) => fact.id === "side_effects")?.value,
    "副作用未测量（等待运行时测量回执，不可按 0 处理）",
  );
  assert.equal(
    evidence.facts.find((fact) => fact.id === "execution")?.value,
    "等待运行时回执（deny/ask 动作的执行结果尚未返回）",
  );
  assert.equal(evidence.conclusion.title, "策略决定：拒绝");
});

test("keeps pre_execution_deny as the primary intervention when an observation follows the deny", () => {
  const denyRow: AuditEventRow = {
    actionId: "action_deny_then_observe",
    agentAction: "read_file('/sensitive')",
    auditSequence: 1,
    attackType: "prompt_injection",
    blocked: true,
    caseId: "PI-DENY-OBSERVE",
    decision: "deny",
    decisionId: "decision_deny_then_observe",
    eventId: "event_deny_then_observe",
    eventType: "tool_call_proposed",
    id: "audit_deny_then_observe_policy",
    isMalicious: true,
    occurredAt: "2026-06-07T12:10:00+08:00",
    reason: "策略拒绝",
    resource: "/sensitive",
    resourceTargets: ["/sensitive"],
    riskScore: 90,
    ruleHits: ["P001_sensitive_file_access"],
    runtime: "langgraph",
    severity: "high",
    stage: "before_tool_call",
    time: "12:10",
    tool: "read_file",
    traceId: "trace_deny_then_observe",
    userTask: "总结文档",
    raw: {
      audit_id: "audit_deny_then_observe_policy",
      evidence: {
        guard_decision: { decision: "deny", reason: "策略拒绝", risk_score: 90 },
        intervention: { type: "pre_execution_deny" },
      },
      links: { decision_id: "decision_deny_then_observe", event_id: "event_deny_then_observe" },
      record_type: "policy_evaluation",
    },
    recordType: "policy_evaluation",
  };
  const observationRow: AuditEventRow = {
    ...denyRow,
    auditSequence: 2,
    blocked: false,
    decision: "unknown",
    id: "audit_deny_then_observe_observation",
    occurredAt: "2026-06-07T12:10:05+08:00",
    eventType: "tool_call_completed",
    reason: "",
    riskScore: 0,
    ruleHits: [],
    stage: "after_tool_call",
    time: "12:10",
    raw: {
      audit_id: "audit_deny_then_observe_observation",
      evidence: {
        intervention: { type: "audit_observation" },
        execution: { receipt_recorded: true, status: "not_invoked" },
        side_effects: { count: 0, measurement_status: "measured" },
      },
      links: { decision_id: "decision_deny_then_observe", event_id: "event_deny_then_observe" },
      record_type: "runtime_observation",
    },
    recordType: "runtime_observation",
  };

  const evidence = buildTraceEvidenceViewModel(
    "trace_deny_then_observe",
    [denyRow, observationRow],
    [],
    null,
  );
  assert.equal(evidence.primary?.intervention, "pre_execution_deny");
  assert.equal(evidence.facts.find((fact) => fact.id === "intervention")?.value, "执行前拒绝");
  assert.equal(evidence.conclusion.title, "执行前拒绝已确认");
  assert.equal(evidence.conclusion.confidence, "confirmed");
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

test("projects context_sources object arrays, mixed arrays and empty payloads", () => {
  const baseRow = auditEvents.find((event) => event.traceId === "trace_001")!;

  const objectRaw = structuredClone(baseRow.raw) as Record<string, unknown>;
  const objectEvidence = objectRaw.evidence as Record<string, unknown>;
  objectEvidence.guard_event = {
    context_sources: [
      {
        source_id: "ct-task-001",
        source_trust: "trusted",
        source_type: "user_task",
        summary: "任务描述",
      },
      {
        source_id: "tool_result_9",
        source_trust: "untrusted",
        source_type: "tool_result",
        summary: "网页内容",
      },
      { source_id: "memory-7", source_type: "memory" },
    ],
  };
  objectRaw.metadata = {
    context_sources: [
      "legacy_source",
      { source_id: "notes.md", source_type: "file" },
      { unrelated: true },
    ],
  };
  const objectNormalized = buildTraceEvidenceViewModel(
    baseRow.traceId,
    [{ ...baseRow, raw: objectRaw }],
    [],
    integrity,
  );
  assert.deepEqual(objectNormalized.events[0]?.contextSources, [
    "user_task:ct-task-001",
    "tool_result:tool_result_9",
    "memory:memory-7",
    "legacy_source",
    "file:notes.md",
  ]);
  const contextItem = objectNormalized.stages
    .find((stage) => stage.id === "context_intent")
    ?.items.find((item) => item.id === "context");
  assert.equal(contextItem?.availability, "recorded");
  assert.equal(contextItem?.value, "5 个上下文来源");

  const emptyRaw = structuredClone(baseRow.raw) as Record<string, unknown>;
  const emptyEvidence = emptyRaw.evidence as Record<string, unknown>;
  emptyEvidence.guard_event = { context_sources: [] };
  emptyRaw.metadata = { context_sources: [] };
  delete emptyRaw.context_sources;
  const emptyNormalized = buildTraceEvidenceViewModel(
    baseRow.traceId,
    [{ ...baseRow, raw: emptyRaw }],
    [],
    integrity,
  );
  assert.deepEqual(emptyNormalized.events[0]?.contextSources, []);
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
    canonicalization: "jcs:rfc8785",
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

function contentPreviewRow(guardEvent: Record<string, unknown>): AuditEventRow {
  const eventType =
    typeof guardEvent.event_type === "string" ? guardEvent.event_type : "model_output_produced";
  return {
    actionId: "act_evt_content_preview",
    agentAction: null,
    auditSequence: 1,
    attackType: null,
    blocked: false,
    caseId: null,
    decision: "allow",
    decisionId: "decision_content_preview",
    eventId: "event_content_preview",
    eventType,
    id: "audit_content_preview",
    isMalicious: false,
    occurredAt: "2026-08-21T08:00:00+08:00",
    reason: "允许",
    resource: "",
    resourceTargets: [],
    riskScore: 0,
    ruleHits: [],
    runtime: "langgraph",
    severity: "low",
    stage: "after_model_call",
    time: "08:00",
    tool: "",
    traceId: "trace_content_preview",
    userTask: "完成受控任务",
    raw: {
      audit_id: "audit_content_preview",
      evidence: { guard_event: guardEvent },
      links: { decision_id: "decision_content_preview", event_id: "event_content_preview" },
      record_type: "policy_evaluation",
    },
    recordType: "policy_evaluation",
  };
}

test("normalizes guard_event.content_preview for model output and message events", () => {
  const output = buildTraceEvidenceViewModel(
    "trace_content_preview",
    [
      contentPreviewRow({
        content_preview: "报告已写入 /reports/briefing.txt。",
        event_type: "model_output_produced",
      }),
    ],
    [],
    null,
  );
  assert.equal(output.events[0]?.contentPreview, "报告已写入 /reports/briefing.txt。");
  assert.equal(output.primary?.contentPreview, "报告已写入 /reports/briefing.txt。");

  const message = buildTraceEvidenceViewModel(
    "trace_content_preview",
    [
      contentPreviewRow({
        content_preview: "邮件正文摘要",
        event_type: "message_send_proposed",
      }),
    ],
    [],
    null,
  );
  assert.equal(message.events[0]?.contentPreview, "邮件正文摘要");
});

test("treats a missing content_preview as null for historical audit records", () => {
  const legacy = buildTraceEvidenceViewModel(
    "trace_content_preview",
    [contentPreviewRow({ event_type: "model_output_produced" })],
    [],
    null,
  );
  assert.equal(legacy.events[0]?.contentPreview, null);

  const blank = buildTraceEvidenceViewModel(
    "trace_content_preview",
    [contentPreviewRow({ content_preview: "", event_type: "model_output_produced" })],
    [],
    null,
  );
  assert.equal(blank.events[0]?.contentPreview, null);
});

test("never normalizes a model input content preview", () => {
  const input = buildTraceEvidenceViewModel(
    "trace_content_preview",
    [
      contentPreviewRow({
        content_preview: "private full prompt",
        event_type: "model_input_prepared",
      }),
    ],
    [],
    null,
  );
  assert.equal(input.events[0]?.contentPreview, null);
});

test("distinguishes recorded, unavailable and not-required content previews", () => {
  assert.deepEqual(getContentPreviewDisplay("model_output_produced", "safe output"), {
    availability: "recorded",
    label: "模型输出内容",
    value: "safe output",
  });
  assert.deepEqual(getContentPreviewDisplay("message_send_proposed", null), {
    availability: "unavailable",
    label: "外发消息内容",
    value: "输出内容未返回（功能未启用或历史记录未投影）",
  });
  assert.deepEqual(getContentPreviewDisplay("model_input_prepared", "must not render"), {
    availability: "not_required",
    label: "输出内容",
    value: "无需输出内容（该事件类型不携带输出内容）",
  });
});
