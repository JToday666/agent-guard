import type {
  PreEnableDivergenceCategory,
  PreEnableEvidenceCheck,
  PreEnableLatencySummary,
  PreEnableMetricAvailability,
  PreEnableRatioMetric,
  PreEnableReceiptEligibility,
  PreEnableReportPresentation,
} from "../../types/dashboard.ts";

type UnknownRecord = Record<string, unknown>;

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SAFE_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;
const FORBIDDEN_DISPLAY_RE =
  /authorization[_-]?fingerprint|fingerprint|runtime[_-]?binding|lease[_-]?token|nonce|token|secret|password|credential/i;
const OPAQUE_VALUE_RE =
  /(?:hmac-sha256|lease-v1):[0-9a-f]{64}|agt_tok_[0-9a-f]{32}|bearer[:\s_-][A-Za-z0-9._-]{8,}|\bsk-[A-Za-z0-9._-]{8,}\b|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/i;
const DIVERGENCE_CATEGORIES = new Set([
  "legacy_allow__v21_defer",
  "legacy_allow__v21_clear_deny",
  "legacy_ask__v21_clear_allow",
  "legacy_ask__v21_clear_deny",
  "legacy_deny__v21_clear_allow",
  "legacy_deny__v21_defer",
  "degraded_no_snapshot",
  "degraded_component_failure",
  "degraded_stale_judgment",
]);
const DEGRADED_CATEGORIES = new Set([
  "degraded_no_snapshot",
  "degraded_component_failure",
  "degraded_stale_judgment",
]);
const TOP_LEVEL_KEYS = [
  "schema_version",
  "report_mode",
  "official_decision_source",
  "v2_decision_mode",
  "benign_ask_source",
  "receipt_eligibility",
  "eligible_action_count",
  "terminal_receipt_count",
  "unknown_attack_outcome_count",
  "receipt_coverage",
  "link_conflicts",
  "official_v2_divergence",
  "divergence_categories",
  "degraded_divergence_count",
  "unexplained_divergence_count",
  "divergence_explanation_coverage",
  "benign_ask",
  "decision_label_coverage",
  "decision_label_availability",
  "final_asr",
  "attack_outcome_coverage",
  "final_asr_availability",
  "latency",
  "failure_injection",
  "flag_rollback",
  "functional_evidence_status",
  "effect_gate",
  "formal_gate_b",
] as const;

class InvalidReport extends Error {}

function unavailable(reason = "PRE_ENABLE_REPORT_NOT_RECORDED"): PreEnableReportPresentation {
  return {
    availability: "unavailable",
    missingReasons: [reason],
    reportMode: null,
    officialDecisionSource: null,
    v2DecisionMode: null,
    benignAskSource: null,
    formalGateB: null,
    effectMode: null,
    numericalThresholdsApplied: null,
    receiptEligibility: null,
    eligibleActionCount: null,
    terminalReceiptCount: null,
    unknownAttackOutcomeCount: null,
    receiptCoverage: null,
    linkConflicts: null,
    officialV2Divergence: null,
    divergenceCategories: [],
    degradedDivergenceCount: null,
    unexplainedDivergenceCount: null,
    divergenceExplanationCoverage: null,
    benignAsk: null,
    decisionLabelCoverage: null,
    decisionLabelAvailability: null,
    finalAsr: null,
    attackOutcomeCoverage: null,
    finalAsrAvailability: null,
    latency: null,
    failureInjection: [],
    flagRollback: [],
    functionalEvidenceStatus: null,
  };
}

function record(value: unknown): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidReport("expected object");
  }
  return value as UnknownRecord;
}

function exactKeys(value: UnknownRecord, keys: readonly string[]): void {
  const expected = new Set(keys);
  if (
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
    Object.keys(value).some((key) => !expected.has(key))
  ) {
    throw new InvalidReport("strict fields mismatch");
  }
}

function safeToken(value: unknown, maxLength = 256): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maxLength ||
    !SAFE_TOKEN_RE.test(value) ||
    FORBIDDEN_DISPLAY_RE.test(value) ||
    OPAQUE_VALUE_RE.test(value)
  ) {
    throw new InvalidReport("unsafe display token");
  }
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new InvalidReport("invalid digest");
  }
  return value;
}

function count(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new InvalidReport("invalid count");
  }
  return value as number;
}

function finiteNumber(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new InvalidReport("invalid finite number");
  }
  return value;
}

function nullableFinite(value: unknown): number | null {
  return value === null ? null : finiteNumber(value);
}

function parseRatio(value: unknown): PreEnableRatioMetric {
  const ratio = record(value);
  exactKeys(ratio, ["numerator", "denominator", "value"]);
  const numerator = count(ratio.numerator);
  const denominator = count(ratio.denominator);
  if (numerator > denominator) throw new InvalidReport("ratio exceeds denominator");
  const expected = denominator ? numerator / denominator : null;
  const supplied = ratio.value;
  if (
    (expected === null && supplied !== null) ||
    (expected !== null &&
      (typeof supplied !== "number" ||
        !Number.isFinite(supplied) ||
        Math.abs(supplied - expected) > 1e-12))
  ) {
    throw new InvalidReport("ratio value mismatch");
  }
  return { numerator, denominator, value: expected };
}

function stringList(
  value: unknown,
  options: { sorted?: boolean; minimum?: number } = {},
): string[] {
  if (!Array.isArray(value) || value.length < (options.minimum ?? 0)) {
    throw new InvalidReport("invalid string list");
  }
  const result = value.map((item) => safeToken(item));
  if (new Set(result).size !== result.length) throw new InvalidReport("duplicate list value");
  if (options.sorted && result.some((item, index) => index > 0 && result[index - 1]! > item)) {
    throw new InvalidReport("list is not canonical");
  }
  return result;
}

function parseEligibility(value: unknown): PreEnableReceiptEligibility {
  const descriptor = record(value);
  exactKeys(descriptor, [
    "schema_version",
    "eligibility_revision",
    "runtime_profile",
    "eligible_action_keys",
    "evidence_refs",
    "eligibility_digest",
  ]);
  if (descriptor.schema_version !== "receipt-eligibility/1.0") {
    throw new InvalidReport("unknown eligibility version");
  }
  const eligibleActionKeys = stringList(descriptor.eligible_action_keys, { sorted: true });
  stringList(descriptor.evidence_refs, { minimum: 1, sorted: true });
  return {
    eligibilityRevision: safeToken(descriptor.eligibility_revision, 128),
    runtimeProfile: safeToken(descriptor.runtime_profile, 128),
    eligibilityDigest: digest(descriptor.eligibility_digest),
    eligibleActionCount: eligibleActionKeys.length,
  };
}

function parseMetricAvailability(value: unknown): PreEnableMetricAvailability {
  if (value === "available" || value === "partial" || value === "unavailable") return value;
  throw new InvalidReport("unknown metric availability");
}

function expectedMetricAvailability(metric: PreEnableRatioMetric): PreEnableMetricAvailability {
  if (metric.numerator === 0) return "unavailable";
  return metric.numerator < metric.denominator ? "partial" : "available";
}

function parseDivergenceCategories(value: unknown): PreEnableDivergenceCategory[] {
  if (!Array.isArray(value)) throw new InvalidReport("invalid divergence categories");
  const result = value.map((item) => {
    const category = record(item);
    exactKeys(category, ["category", "count"]);
    if (typeof category.category !== "string" || !DIVERGENCE_CATEGORIES.has(category.category)) {
      throw new InvalidReport("unknown divergence category");
    }
    const categoryCount = count(category.count);
    if (categoryCount < 1) throw new InvalidReport("empty divergence category");
    return { category: category.category, count: categoryCount };
  });
  if (
    new Set(result.map((item) => item.category)).size !== result.length ||
    result.some((item, index) => index > 0 && result[index - 1]!.category > item.category)
  ) {
    throw new InvalidReport("divergence categories are not canonical");
  }
  return result;
}

function parseLatency(value: unknown): PreEnableLatencySummary {
  const latency = record(value);
  exactKeys(latency, [
    "method",
    "sample_coverage",
    "average_ms",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "max_ms",
  ]);
  if (latency.method !== "nearest_rank") throw new InvalidReport("unknown latency method");
  const sampleCoverage = parseRatio(latency.sample_coverage);
  const averageMs = nullableFinite(latency.average_ms);
  const p50Ms = nullableFinite(latency.p50_ms);
  const p95Ms = nullableFinite(latency.p95_ms);
  const p99Ms = nullableFinite(latency.p99_ms);
  const maxMs = nullableFinite(latency.max_ms);
  const values = [averageMs, p50Ms, p95Ms, p99Ms, maxMs];
  if (sampleCoverage.numerator === 0 && values.some((item) => item !== null)) {
    throw new InvalidReport("latency values without samples");
  }
  if (sampleCoverage.numerator > 0) {
    if (values.some((item) => item === null)) throw new InvalidReport("latency values missing");
    if (p50Ms! > p95Ms! || p95Ms! > p99Ms! || p99Ms! > maxMs! || averageMs! > maxMs!) {
      throw new InvalidReport("latency values are inconsistent");
    }
  }
  return { method: "nearest_rank", sampleCoverage, averageMs, p50Ms, p95Ms, p99Ms, maxMs };
}

function parseChecks(
  value: unknown,
  expectedKind: PreEnableEvidenceCheck["kind"],
): PreEnableEvidenceCheck[] {
  if (!Array.isArray(value) || value.length === 0)
    throw new InvalidReport("evidence checks missing");
  const result = value.map((item) => {
    const check = record(item);
    exactKeys(check, ["check_id", "kind", "status", "evidence_refs", "reason_code"]);
    if (check.kind !== expectedKind || (check.status !== "passed" && check.status !== "failed")) {
      throw new InvalidReport("invalid evidence check status");
    }
    const status: PreEnableEvidenceCheck["status"] = check.status;
    const refs = stringList(check.evidence_refs, { minimum: 1, sorted: true });
    return {
      checkId: safeToken(check.check_id, 128),
      kind: expectedKind,
      status,
      reasonCode: safeToken(check.reason_code, 128),
      evidenceRefCount: refs.length,
    };
  });
  if (new Set(result.map((item) => item.checkId)).size !== result.length) {
    throw new InvalidReport("duplicate evidence check");
  }
  if (result.some((item, index) => index > 0 && result[index - 1]!.checkId > item.checkId)) {
    throw new InvalidReport("evidence checks are not canonical");
  }
  return result;
}

function parseSection<T>(
  root: UnknownRecord,
  key: string,
  reason: string,
  reasons: Set<string>,
  parse: (value: unknown) => T,
): T | null {
  try {
    return parse(root[key]);
  } catch {
    reasons.add(reason);
    return null;
  }
}

function optionalCount(
  root: UnknownRecord,
  key: string,
  reason: string,
  reasons: Set<string>,
): number | null {
  return parseSection(root, key, reason, reasons, count);
}

export function projectPreEnableReport(value: unknown): PreEnableReportPresentation {
  if (value === undefined || value === null) return unavailable();
  let root: UnknownRecord;
  try {
    root = record(value);
  } catch {
    return unavailable("PRE_ENABLE_REPORT_INVALID");
  }
  if (
    root.schema_version !== "pre-enable-report/1.0" ||
    root.report_mode !== "observational" ||
    root.official_decision_source !== "current" ||
    root.v2_decision_mode !== "shadow" ||
    root.benign_ask_source !== "v2_shadow" ||
    root.formal_gate_b !== "not_asserted"
  ) {
    return unavailable("PRE_ENABLE_REPORT_IDENTITY_INVALID");
  }
  const effectGate = (() => {
    try {
      const gate = record(root.effect_gate);
      exactKeys(gate, ["status", "mode", "numerical_thresholds_applied", "reason"]);
      if (
        gate.status !== "skipped" ||
        gate.mode !== "observational" ||
        gate.numerical_thresholds_applied !== false ||
        gate.reason !== "effect_metrics_are_observational"
      ) {
        throw new InvalidReport("invalid effect gate");
      }
      return true;
    } catch {
      return false;
    }
  })();
  if (!effectGate) return unavailable("PRE_ENABLE_EFFECT_MODE_INVALID");

  const reasons = new Set<string>();
  if (
    TOP_LEVEL_KEYS.some((key) => !Object.prototype.hasOwnProperty.call(root, key)) ||
    Object.keys(root).some((key) => !(TOP_LEVEL_KEYS as readonly string[]).includes(key))
  ) {
    reasons.add("PRE_ENABLE_REPORT_STRICT_FIELDS_INVALID");
  }
  const receiptEligibility = parseSection(
    root,
    "receipt_eligibility",
    "RECEIPT_ELIGIBILITY_INVALID",
    reasons,
    parseEligibility,
  );
  const eligibleActionCount = optionalCount(
    root,
    "eligible_action_count",
    "ELIGIBLE_ACTION_COUNT_INVALID",
    reasons,
  );
  const terminalReceiptCount = optionalCount(
    root,
    "terminal_receipt_count",
    "TERMINAL_RECEIPT_COUNT_INVALID",
    reasons,
  );
  const unknownAttackOutcomeCount = optionalCount(
    root,
    "unknown_attack_outcome_count",
    "UNKNOWN_ATTACK_OUTCOME_COUNT_INVALID",
    reasons,
  );
  const receiptCoverage = parseSection(
    root,
    "receipt_coverage",
    "RECEIPT_COVERAGE_INVALID",
    reasons,
    parseRatio,
  );
  const linkConflicts = parseSection(
    root,
    "link_conflicts",
    "LINK_CONFLICTS_INVALID",
    reasons,
    parseRatio,
  );
  const officialV2Divergence = parseSection(
    root,
    "official_v2_divergence",
    "DIVERGENCE_INVALID",
    reasons,
    parseRatio,
  );
  const divergenceCategories =
    parseSection(
      root,
      "divergence_categories",
      "DIVERGENCE_CATEGORIES_INVALID",
      reasons,
      parseDivergenceCategories,
    ) ?? [];
  const degradedDivergenceCount = optionalCount(
    root,
    "degraded_divergence_count",
    "DEGRADED_DIVERGENCE_COUNT_INVALID",
    reasons,
  );
  const unexplainedDivergenceCount = optionalCount(
    root,
    "unexplained_divergence_count",
    "UNEXPLAINED_DIVERGENCE_COUNT_INVALID",
    reasons,
  );
  const divergenceExplanationCoverage = parseSection(
    root,
    "divergence_explanation_coverage",
    "DIVERGENCE_EXPLANATION_COVERAGE_INVALID",
    reasons,
    parseRatio,
  );
  const benignAsk = parseSection(root, "benign_ask", "BENIGN_ASK_INVALID", reasons, parseRatio);
  const decisionLabelCoverage = parseSection(
    root,
    "decision_label_coverage",
    "DECISION_LABEL_COVERAGE_INVALID",
    reasons,
    parseRatio,
  );
  const decisionLabelAvailability = parseSection(
    root,
    "decision_label_availability",
    "DECISION_LABEL_AVAILABILITY_INVALID",
    reasons,
    parseMetricAvailability,
  );
  const finalAsr = parseSection(root, "final_asr", "FINAL_ASR_INVALID", reasons, parseRatio);
  const attackOutcomeCoverage = parseSection(
    root,
    "attack_outcome_coverage",
    "ATTACK_OUTCOME_COVERAGE_INVALID",
    reasons,
    parseRatio,
  );
  const finalAsrAvailability = parseSection(
    root,
    "final_asr_availability",
    "FINAL_ASR_AVAILABILITY_INVALID",
    reasons,
    parseMetricAvailability,
  );
  const latency = parseSection(root, "latency", "LATENCY_INVALID", reasons, parseLatency);
  const failureInjection =
    parseSection(root, "failure_injection", "FAILURE_INJECTION_INVALID", reasons, (item) =>
      parseChecks(item, "failure_injection"),
    ) ?? [];
  const flagRollback =
    parseSection(root, "flag_rollback", "FLAG_ROLLBACK_INVALID", reasons, (item) =>
      parseChecks(item, "flag_rollback"),
    ) ?? [];
  const functionalEvidenceStatus =
    root.functional_evidence_status === "passed" || root.functional_evidence_status === "failed"
      ? root.functional_evidence_status
      : null;
  if (functionalEvidenceStatus === null) reasons.add("FUNCTIONAL_EVIDENCE_STATUS_INVALID");

  if (
    receiptEligibility &&
    eligibleActionCount !== null &&
    receiptEligibility.eligibleActionCount !== eligibleActionCount
  ) {
    reasons.add("RECEIPT_ELIGIBILITY_COUNT_CONFLICT");
  }
  if (
    receiptCoverage &&
    (receiptCoverage.denominator !== eligibleActionCount ||
      receiptCoverage.numerator !== terminalReceiptCount)
  ) {
    reasons.add("RECEIPT_COVERAGE_COUNT_CONFLICT");
  }
  if (linkConflicts && linkConflicts.denominator !== eligibleActionCount) {
    reasons.add("LINK_CONFLICT_DENOMINATOR_CONFLICT");
  }
  if (
    terminalReceiptCount !== null &&
    eligibleActionCount !== null &&
    linkConflicts &&
    terminalReceiptCount + linkConflicts.numerator > eligibleActionCount
  ) {
    reasons.add("RECEIPT_STATE_COUNT_CONFLICT");
  }
  const categorizedDivergence = divergenceCategories.reduce((sum, item) => sum + item.count, 0);
  if (
    officialV2Divergence &&
    unexplainedDivergenceCount !== null &&
    categorizedDivergence + unexplainedDivergenceCount !== officialV2Divergence.numerator
  ) {
    reasons.add("DIVERGENCE_CATEGORY_COUNT_CONFLICT");
  }
  const expectedDegraded = divergenceCategories
    .filter((item) => DEGRADED_CATEGORIES.has(item.category))
    .reduce((sum, item) => sum + item.count, 0);
  if (degradedDivergenceCount !== null && degradedDivergenceCount !== expectedDegraded) {
    reasons.add("DEGRADED_DIVERGENCE_COUNT_CONFLICT");
  }
  if (
    divergenceExplanationCoverage &&
    officialV2Divergence &&
    (divergenceExplanationCoverage.denominator !== officialV2Divergence.numerator ||
      divergenceExplanationCoverage.numerator !== categorizedDivergence)
  ) {
    reasons.add("DIVERGENCE_EXPLANATION_COUNT_CONFLICT");
  }
  if (
    decisionLabelCoverage &&
    officialV2Divergence &&
    decisionLabelCoverage.denominator !== officialV2Divergence.denominator
  ) {
    reasons.add("DECISION_LABEL_DENOMINATOR_CONFLICT");
  }
  if (
    benignAsk &&
    decisionLabelCoverage &&
    benignAsk.denominator > decisionLabelCoverage.numerator
  ) {
    reasons.add("BENIGN_ASK_DENOMINATOR_CONFLICT");
  }
  if (
    decisionLabelCoverage &&
    decisionLabelAvailability &&
    decisionLabelAvailability !== expectedMetricAvailability(decisionLabelCoverage)
  ) {
    reasons.add("DECISION_LABEL_AVAILABILITY_CONFLICT");
  }
  if (
    finalAsr &&
    attackOutcomeCoverage &&
    finalAsr.denominator !== attackOutcomeCoverage.numerator
  ) {
    reasons.add("FINAL_ASR_DENOMINATOR_CONFLICT");
  }
  if (
    attackOutcomeCoverage &&
    unknownAttackOutcomeCount !== null &&
    attackOutcomeCoverage.numerator + unknownAttackOutcomeCount !==
      attackOutcomeCoverage.denominator
  ) {
    reasons.add("ATTACK_OUTCOME_COUNT_CONFLICT");
  }
  if (
    attackOutcomeCoverage &&
    finalAsrAvailability &&
    finalAsrAvailability !== expectedMetricAvailability(attackOutcomeCoverage)
  ) {
    reasons.add("FINAL_ASR_AVAILABILITY_CONFLICT");
  }
  const allChecks = [...failureInjection, ...flagRollback];
  if (new Set(allChecks.map((check) => check.checkId)).size !== allChecks.length) {
    reasons.add("EVIDENCE_CHECK_ID_CONFLICT");
  }
  const expectedFunctionalStatus = allChecks.some((check) => check.status === "failed")
    ? "failed"
    : "passed";
  if (allChecks.length && functionalEvidenceStatus !== expectedFunctionalStatus) {
    reasons.add("FUNCTIONAL_EVIDENCE_STATUS_CONFLICT");
  }

  return {
    availability: reasons.size ? "partial" : "recorded",
    missingReasons: [...reasons].sort(),
    reportMode: "observational",
    officialDecisionSource: "current",
    v2DecisionMode: "shadow",
    benignAskSource: "v2_shadow",
    formalGateB: "not_asserted",
    effectMode: "observational",
    numericalThresholdsApplied: false,
    receiptEligibility,
    eligibleActionCount,
    terminalReceiptCount,
    unknownAttackOutcomeCount,
    receiptCoverage,
    linkConflicts,
    officialV2Divergence,
    divergenceCategories,
    degradedDivergenceCount,
    unexplainedDivergenceCount,
    divergenceExplanationCoverage,
    benignAsk,
    decisionLabelCoverage,
    decisionLabelAvailability,
    finalAsr,
    attackOutcomeCoverage,
    finalAsrAvailability,
    latency,
    failureInjection,
    flagRollback,
    functionalEvidenceStatus,
  };
}
