import assert from "node:assert/strict";
import test from "node:test";

import { mapEvaluationRun } from "../../api/guard-api-mappers.ts";
import type { GuardEvaluationRunDto } from "../../api/guard-api-types.ts";
import { projectPreEnableReport } from "./pre-enable-report.ts";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const ratio = (numerator: number, denominator: number) => ({
  numerator,
  denominator,
  value: denominator ? numerator / denominator : null,
});

function reportPayload(): Record<string, unknown> {
  return {
    schema_version: "pre-enable-report/1.0",
    report_mode: "observational",
    official_decision_source: "current",
    v2_decision_mode: "shadow",
    benign_ask_source: "v2_shadow",
    receipt_eligibility: {
      schema_version: "receipt-eligibility/1.0",
      eligibility_revision: "c10-revision-1",
      runtime_profile: "reference-langgraph",
      eligible_action_keys: ["action-1", "action-2", "action-3"],
      evidence_refs: ["profile:reference-langgraph:receipt-eligibility:c10"],
      eligibility_digest: digest("a"),
    },
    eligible_action_count: 3,
    terminal_receipt_count: 1,
    unknown_attack_outcome_count: 1,
    receipt_coverage: ratio(1, 3),
    link_conflicts: ratio(1, 3),
    official_v2_divergence: ratio(3, 3),
    divergence_categories: [
      { category: "legacy_allow__v21_clear_deny", count: 1 },
      { category: "legacy_allow__v21_defer", count: 1 },
      { category: "legacy_ask__v21_clear_allow", count: 1 },
    ],
    degraded_divergence_count: 0,
    unexplained_divergence_count: 0,
    divergence_explanation_coverage: ratio(3, 3),
    benign_ask: ratio(1, 2),
    decision_label_coverage: ratio(3, 3),
    decision_label_availability: "available",
    final_asr: ratio(1, 2),
    attack_outcome_coverage: ratio(2, 3),
    final_asr_availability: "partial",
    latency: {
      method: "nearest_rank",
      sample_coverage: ratio(2, 3),
      average_ms: 20,
      p50_ms: 10,
      p95_ms: 30,
      p99_ms: 30,
      max_ms: 30,
    },
    failure_injection: [
      {
        check_id: "fi-snapshot-read-failure",
        kind: "failure_injection",
        status: "passed",
        evidence_refs: [
          "test:tests/test_v21_09_pipeline.py::test_pipeline_phase_a_snapshot_read_failure_component_failure",
        ],
        reason_code: "snapshot_read_failure_degrades_component",
      },
    ],
    flag_rollback: [
      {
        check_id: "rollback-v2-shadow-off",
        kind: "flag_rollback",
        status: "passed",
        evidence_refs: [
          "test:tests/test_v21_09_pipeline.py::test_pipeline_flag_off_response_byte_identical",
        ],
        reason_code: "v2_shadow_flag_off_official_unchanged",
      },
    ],
    functional_evidence_status: "passed",
    effect_gate: {
      status: "skipped",
      mode: "observational",
      numerical_thresholds_applied: false,
      reason: "effect_metrics_are_observational",
    },
    formal_gate_b: "not_asserted",
  };
}

test("projects the complete C10 report with every ratio denominator intact", () => {
  const report = projectPreEnableReport(reportPayload());

  assert.equal(report.availability, "recorded");
  assert.equal(report.officialDecisionSource, "current");
  assert.equal(report.v2DecisionMode, "shadow");
  assert.equal(report.formalGateB, "not_asserted");
  assert.equal(report.effectMode, "observational");
  assert.equal(report.numericalThresholdsApplied, false);
  assert.deepEqual(report.receiptCoverage, ratio(1, 3));
  assert.deepEqual(report.linkConflicts, ratio(1, 3));
  assert.deepEqual(report.officialV2Divergence, ratio(3, 3));
  assert.deepEqual(report.divergenceExplanationCoverage, ratio(3, 3));
  assert.deepEqual(report.benignAsk, ratio(1, 2));
  assert.deepEqual(report.decisionLabelCoverage, ratio(3, 3));
  assert.deepEqual(report.finalAsr, ratio(1, 2));
  assert.deepEqual(report.attackOutcomeCoverage, ratio(2, 3));
  assert.deepEqual(report.latency?.sampleCoverage, ratio(2, 3));
  assert.equal(report.failureInjection[0]?.evidenceRefCount, 1);
  assert.equal(report.flagRollback[0]?.status, "passed");
});

test("maps pre_enable_report into the existing EvaluationRun domain", () => {
  const mapped = mapEvaluationRun({
    run_id: "run_c10_1",
    run_at: "2026-08-17T08:00:00Z",
    dataset_id: "frozen-70",
    dataset_version: "1.0",
    pre_enable_report: reportPayload(),
  } as unknown as GuardEvaluationRunDto);

  assert.equal(mapped.preEnableReport.availability, "recorded");
  assert.equal(mapped.preEnableReport.receiptEligibility?.runtimeProfile, "reference-langgraph");
  assert.deepEqual(mapped.preEnableReport.finalAsr, ratio(1, 2));
});

test("keeps an absent report explicitly unavailable", () => {
  const report = projectPreEnableReport(undefined);

  assert.equal(report.availability, "unavailable");
  assert.deepEqual(report.missingReasons, ["PRE_ENABLE_REPORT_NOT_RECORDED"]);
  assert.equal(report.formalGateB, null);
});

test("rejects a fake Gate B assertion instead of rendering it", () => {
  const payload = reportPayload();
  payload.formal_gate_b = "passed";
  payload.credential = "sk-live-never-render-this";

  const report = projectPreEnableReport(payload);

  assert.equal(report.availability, "unavailable");
  assert.equal(report.formalGateB, null);
  assert.doesNotMatch(JSON.stringify(report), /passed|sk-live|credential/);
});

test("degrades one malformed ratio to partial while retaining independent evidence", () => {
  const payload = reportPayload();
  payload.receipt_coverage = { numerator: 2, denominator: 3, value: 0.1 };

  const report = projectPreEnableReport(payload);

  assert.equal(report.availability, "partial");
  assert.equal(report.receiptCoverage, null);
  assert.deepEqual(report.linkConflicts, ratio(1, 3));
  assert.deepEqual(report.finalAsr, ratio(1, 2));
  assert.ok(report.missingReasons.includes("RECEIPT_COVERAGE_INVALID"));
});

test("does not pass through unknown fields or unsafe evidence values", () => {
  const payload = reportPayload();
  payload.unknown_extension = { runtime_binding: `hmac-sha256:${"4".repeat(64)}` };
  const checks = payload.failure_injection as Array<Record<string, unknown>>;
  checks[0]!.reason_code = "credential=sk-live-never-render-this";

  const report = projectPreEnableReport(payload);
  const serialized = JSON.stringify(report);

  assert.equal(report.availability, "partial");
  assert.deepEqual(report.failureInjection, []);
  assert.ok(report.missingReasons.includes("PRE_ENABLE_REPORT_STRICT_FIELDS_INVALID"));
  assert.ok(report.missingReasons.includes("FAILURE_INJECTION_INVALID"));
  assert.doesNotMatch(serialized, /runtime_binding|hmac-sha256|sk-live|credential=/);
});

test("rejects non-finite latency without hiding the other observational metrics", () => {
  const payload = reportPayload();
  (payload.latency as Record<string, unknown>).average_ms = Number.POSITIVE_INFINITY;

  const report = projectPreEnableReport(payload);

  assert.equal(report.availability, "partial");
  assert.equal(report.latency, null);
  assert.deepEqual(report.attackOutcomeCoverage, ratio(2, 3));
  assert.ok(report.missingReasons.includes("LATENCY_INVALID"));
});
