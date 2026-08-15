import type {
  ActionSummary,
  ActivityState,
  ApprovalPresentation,
  Availability,
  ContentIngressSummary,
  ControlIntegrityPresentation,
  CtFlowRelation,
  DecisionAuthority,
  DisplayEvidenceSemantics,
  DisplayFactAuthority,
  ElementSourceMode,
  EnforcementPresentation,
  EvidenceCertainty,
  EvidenceLocator,
  ExecutionPresentation,
  ExecutionStepSupervisionDetails,
  NormalizedCtSourceType,
  OfficialDecisionPresentation,
  ProvenanceEdgePresentation,
  ProvenanceNodePresentation,
  ProvenancePresentationViewModel,
  SupervisionWarning,
  V21AssessmentPresentation,
} from "../../types/runtime-supervision.ts";

const FIXTURE_SCHEMA_VERSION = "runtime-supervision-fixture/0.1" as const;
const SUPERVISION_SCHEMA_VERSION = "runtime-supervision/0.1" as const;
const AUDIT_SCHEMA_VERSION = "0.4" as const;
const SOURCE_FIXTURE_PATH = "tests/fixtures/runtime_safety_trace_v04.json" as const;

export interface RuntimeSupervisionFixtureMetadata {
  fixtureSchemaVersion: typeof FIXTURE_SCHEMA_VERSION;
  fixtureId: string;
  purpose: "contract_projection" | "ui_preview";
  sourceMode: "mock";
  derivedFrom: [typeof SOURCE_FIXTURE_PATH];
  contractVersions: {
    supervision: typeof SUPERVISION_SCHEMA_VERSION;
    audit: typeof AUDIT_SCHEMA_VERSION;
  };
  containsSyntheticFacts: true;
  safeForDemoSandbox: true;
}

export interface SupervisionProjectionCase {
  caseId: string;
  description: string;
  expectations: string[];
  supervision: ExecutionStepSupervisionDetails;
}

export interface SupervisionProjectionFixture {
  fixtureKind: "supervision_projection";
  metadata: RuntimeSupervisionFixtureMetadata & {
    fixtureId: "rsc_supervision_projection_v01";
    purpose: "contract_projection";
  };
  sourceTraceId: "trace_runtime_safety_demo_001";
  traceId: "mock_trace_supervision_projection_v01";
  elementSourceMode: "mock";
  cases: SupervisionProjectionCase[];
}

export interface ContextIngressPreviewFixture {
  fixtureKind: "context_ingress_preview";
  metadata: RuntimeSupervisionFixtureMetadata & {
    fixtureId: "rsc_context_ingress_preview_v01";
    purpose: "ui_preview";
  };
  traceId: "mock_trace_context_ingress_preview_v01";
  userTask: string;
  sourceUri: string;
  fakeCredential: "DEMO_CREDENTIAL_NOT_VALID";
  highImpactActionId: `mock_action_${string}`;
  executionGraphEdges: [];
  contentIngressSummary: ContentIngressSummary;
  provenancePresentation: ProvenancePresentationViewModel;
}

export type RuntimeSupervisionFixture = SupervisionProjectionFixture | ContextIngressPreviewFixture;

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;

export type LoadedRuntimeSupervisionFixture = DeepReadonly<RuntimeSupervisionFixture>;

export class RuntimeSupervisionFixtureValidationError extends Error {
  readonly path: string;

  constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "RuntimeSupervisionFixtureValidationError";
    this.path = path;
  }
}

type JsonRecord = Record<string, unknown>;

function fail(path: string, message: string): never {
  throw new RuntimeSupervisionFixtureValidationError(path, message);
}

function strictObject(value: unknown, path: string, expectedKeys: readonly string[]): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail(path, "expected an object");
  }

  const record = value as JsonRecord;
  const actualKeys = Object.keys(record).sort();
  const sortedExpected = [...expectedKeys].sort();
  const missing = sortedExpected.filter((key) => !Object.hasOwn(record, key));
  const extra = actualKeys.filter((key) => !sortedExpected.includes(key));
  if (missing.length > 0 || extra.length > 0) {
    return fail(
      path,
      `object keys do not match schema (missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"})`,
    );
  }
  return record;
}

function stringValue(value: unknown, path: string, options?: { nonEmpty?: boolean }): string {
  if (typeof value !== "string") return fail(path, "expected a string");
  if (options?.nonEmpty && value.length === 0) return fail(path, "must not be empty");
  return value;
}

function literalValue<T extends string | boolean>(value: unknown, expected: T, path: string): T {
  if (value !== expected) return fail(path, `expected ${JSON.stringify(expected)}`);
  return expected;
}

function enumValue<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  path: string,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    return fail(path, `expected one of: ${allowed.join(", ")}`);
  }
  return value as T[number];
}

function nullableString(value: unknown, path: string): string | null {
  return value === null ? null : stringValue(value, path, { nonEmpty: true });
}

function nullableNumber(value: unknown, path: string): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value))
    return fail(path, "expected a finite number or null");
  return value;
}

function nullableBoolean(value: unknown, path: string): boolean | null {
  if (value === null || typeof value === "boolean") return value;
  return fail(path, "expected a boolean or null");
}

function arrayValue<T>(
  value: unknown,
  path: string,
  parseItem: (item: unknown, itemPath: string) => T,
): T[] {
  if (!Array.isArray(value)) return fail(path, "expected an array");
  return value.map((item, index) => parseItem(item, `${path}[${index}]`));
}

function stringArray(value: unknown, path: string): string[] {
  return arrayValue(value, path, (item, itemPath) =>
    stringValue(item, itemPath, { nonEmpty: true }),
  );
}

function utcTimestamp(value: unknown, path: string): string {
  const timestamp = stringValue(value, path, { nonEmpty: true });
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp) ||
    Number.isNaN(Date.parse(timestamp))
  ) {
    return fail(path, "expected a fixed RFC3339 UTC timestamp with millisecond precision");
  }
  return timestamp;
}

function nullableUtcTimestamp(value: unknown, path: string): string | null {
  return value === null ? null : utcTimestamp(value, path);
}

const AVAILABILITY = ["recorded", "partial", "unavailable", "not_applicable"] as const;
const CERTAINTY = ["confirmed", "supported", "possible", "unknown"] as const;
const DECISION_AUTHORITY = ["official", "shadow", "none"] as const;
const FACT_AUTHORITY = [
  "authoritative",
  "trusted_claim",
  "untrusted_claim",
  "model_judgment",
  "none",
] as const;
const ELEMENT_SOURCE_MODE = ["live", "replay", "mock"] as const;
const LOCATOR_KIND = [
  "audit",
  "event",
  "action",
  "decision",
  "approval",
  "receipt",
  "lease",
  "consumption",
  "provenance_node",
  "fact",
  "snapshot",
  "state_delta",
] as const;

function parseLocator(value: unknown, path: string): EvidenceLocator {
  const record = strictObject(value, path, ["kind", "id", "trace_id"]);
  return {
    kind: enumValue(record.kind, LOCATOR_KIND, `${path}.kind`),
    id: stringValue(record.id, `${path}.id`, { nonEmpty: true }),
    traceId: stringValue(record.trace_id, `${path}.trace_id`, { nonEmpty: true }),
  };
}

function parseSemantics(value: unknown, path: string): DisplayEvidenceSemantics {
  const record = strictObject(value, path, [
    "element_source_mode",
    "availability",
    "certainty",
    "decision_authority",
    "fact_authority",
    "derived_for_display",
    "source_refs",
  ]);
  const semantics = {
    elementSourceMode: enumValue(
      record.element_source_mode,
      ELEMENT_SOURCE_MODE,
      `${path}.element_source_mode`,
    ),
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    certainty: enumValue(record.certainty, CERTAINTY, `${path}.certainty`),
    decisionAuthority: enumValue(
      record.decision_authority,
      DECISION_AUTHORITY,
      `${path}.decision_authority`,
    ),
    factAuthority: enumValue(record.fact_authority, FACT_AUTHORITY, `${path}.fact_authority`),
    derivedForDisplay: literalValue(
      record.derived_for_display,
      true,
      `${path}.derived_for_display`,
    ),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  } satisfies DisplayEvidenceSemantics;
  if (semantics.elementSourceMode !== "mock") {
    return fail(`${path}.element_source_mode`, "synthetic Preview evidence must remain mock");
  }
  return semantics;
}

function parseAction(value: unknown, path: string): ActionSummary {
  const record = strictObject(value, path, [
    "action_id",
    "action_name",
    "subject_type",
    "resource_targets",
    "argument_summary",
    "occurred_at",
    "source_refs",
  ]);
  const actionId = stringValue(record.action_id, `${path}.action_id`, { nonEmpty: true });
  if (!actionId.startsWith("mock_action_")) {
    return fail(`${path}.action_id`, "synthetic actions must use the mock_action_ namespace");
  }
  if (record.argument_summary !== null) {
    return fail(
      `${path}.argument_summary`,
      "S0 fixtures must not carry or reconstruct raw arguments",
    );
  }
  return {
    actionId,
    actionName: nullableString(record.action_name, `${path}.action_name`),
    subjectType: nullableString(record.subject_type, `${path}.subject_type`),
    resourceTargets: stringArray(record.resource_targets, `${path}.resource_targets`),
    argumentSummary: null,
    occurredAt: nullableUtcTimestamp(record.occurred_at, `${path}.occurred_at`),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseOfficialDecision(value: unknown, path: string): OfficialDecisionPresentation {
  const record = strictObject(value, path, [
    "availability",
    "decision_authority",
    "decision_id",
    "decision",
    "policy_audit_id",
    "risk_score",
    "severity",
    "rule_ids",
    "reason_codes",
    "reason",
    "source_refs",
  ]);
  return {
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    decisionAuthority: literalValue(
      record.decision_authority,
      "official",
      `${path}.decision_authority`,
    ),
    decisionId: nullableString(record.decision_id, `${path}.decision_id`),
    decision: enumValue(
      record.decision,
      ["allow", "ask", "deny", "unknown"] as const,
      `${path}.decision`,
    ),
    policyAuditId: nullableString(record.policy_audit_id, `${path}.policy_audit_id`),
    riskScore: nullableNumber(record.risk_score, `${path}.risk_score`),
    severity: enumValue(
      record.severity,
      ["low", "medium", "high", "critical", "unknown"] as const,
      `${path}.severity`,
    ),
    ruleIds: stringArray(record.rule_ids, `${path}.rule_ids`),
    reasonCodes: stringArray(record.reason_codes, `${path}.reason_codes`),
    reason: nullableString(record.reason, `${path}.reason`),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function unavailableV21Assessment(): V21AssessmentPresentation {
  return {
    availability: "unavailable",
    decisionAuthority: "none",
    authorityVerification: "unverified",
    mode: "unknown",
    assessmentId: null,
    fastDisposition: null,
    recordedFinalDecision: null,
    legacyDecision: null,
    coverage: {},
    degradationIds: [],
    divergenceCategory: null,
    rollout: {
      availability: "unavailable",
      rolloutId: null,
      rolloutRevision: null,
      rolloutDigest: null,
      configAuditId: null,
      routingCatalogEpoch: null,
      routingCatalogDigest: null,
      changeType: "unknown",
      previousConfigAuditId: null,
      rollbackOfConfigAuditId: null,
      mode: "unknown",
      authority: "none",
      scopeKind: "unknown",
      matchedCaseId: null,
      matchedCohortId: null,
      cohortRevision: null,
      cohortDigest: null,
      scopeMembershipRef: null,
      runtime: null,
      runtimeProfile: null,
      policyRevision: null,
      policyDigest: null,
      migrationRule: null,
      enabledPathIds: [],
      matchedPathIds: [],
      matchedRuleIds: [],
      ownershipTransferRevision: null,
      ownershipTransferDigest: null,
      ownershipValidationStatus: "unknown",
      matchedRuleOwnershipRefs: [],
      runtimeProfileAttestation: null,
      snapshotSchemaVersion: null,
      projectorVersion: null,
      snapshotEligibilityRevision: null,
      snapshotEligibilityDigest: null,
      snapshotEligibilityStatus: "unknown",
      snapshotEligibilityReasonCodes: [],
      snapshotId: null,
      snapshotDigest: null,
      stateVersion: null,
      effectiveAt: null,
      scopeMatch: "unknown",
      reasonCodes: ["ROLLOUT_EVIDENCE_UNAVAILABLE"],
      sourceRefs: [],
    },
    sourceRefs: [],
  };
}

function parseApproval(value: unknown, path: string): ApprovalPresentation {
  const record = strictObject(value, path, [
    "availability",
    "approval_id",
    "status",
    "decision",
    "resolution_source",
    "created_at",
    "expires_at",
    "resolved_at",
    "source_refs",
  ]);
  return {
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    approvalId: nullableString(record.approval_id, `${path}.approval_id`),
    status: enumValue(
      record.status,
      ["pending", "allowed", "denied", "expired", "unknown"] as const,
      `${path}.status`,
    ),
    decision:
      record.decision === null
        ? null
        : enumValue(record.decision, ["allow_once", "deny"] as const, `${path}.decision`),
    resolutionSource:
      record.resolution_source === null
        ? null
        : enumValue(
            record.resolution_source,
            ["human", "llm", "system"] as const,
            `${path}.resolution_source`,
          ),
    createdAt: nullableUtcTimestamp(record.created_at, `${path}.created_at`),
    expiresAt: nullableUtcTimestamp(record.expires_at, `${path}.expires_at`),
    resolvedAt: nullableUtcTimestamp(record.resolved_at, `${path}.resolved_at`),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseEnforcement(value: unknown, path: string): EnforcementPresentation {
  const record = strictObject(value, path, [
    "availability",
    "gate_state",
    "binding_check_status",
    "lease_consume_outcome",
    "lease_id",
    "consumption_id",
    "reason_codes",
    "source_refs",
  ]);
  return {
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    gateState: enumValue(
      record.gate_state,
      [
        "evaluating",
        "allowed",
        "approval_pending",
        "approval_released",
        "blocked",
        "timed_out",
        "binding_failed",
        "unknown",
      ] as const,
      `${path}.gate_state`,
    ),
    bindingCheckStatus: enumValue(
      record.binding_check_status,
      ["not_applicable", "not_performed", "passed", "failed", "unknown"] as const,
      `${path}.binding_check_status`,
    ),
    leaseConsumeOutcome: enumValue(
      record.lease_consume_outcome,
      [
        "not_applicable",
        "not_attempted",
        "consumed",
        "expired",
        "revoked",
        "rejected",
        "unknown",
      ] as const,
      `${path}.lease_consume_outcome`,
    ),
    leaseId: nullableString(record.lease_id, `${path}.lease_id`),
    consumptionId: nullableString(record.consumption_id, `${path}.consumption_id`),
    reasonCodes: stringArray(record.reason_codes, `${path}.reason_codes`),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseExecution(value: unknown, path: string): ExecutionPresentation {
  const record = strictObject(value, path, [
    "availability",
    "status",
    "receipt_recorded",
    "invoked_at",
    "completed_at",
    "tool_result_entered_context",
    "persisted",
    "side_effect_measurement",
    "side_effect_count",
    "source_refs",
  ]);
  const receiptRecorded =
    typeof record.receipt_recorded === "boolean"
      ? record.receipt_recorded
      : fail(`${path}.receipt_recorded`, "expected a boolean");
  const sideEffectCount = nullableNumber(record.side_effect_count, `${path}.side_effect_count`);
  if (sideEffectCount !== null && (!Number.isInteger(sideEffectCount) || sideEffectCount < 0)) {
    return fail(`${path}.side_effect_count`, "must be a non-negative integer or null");
  }
  return {
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    status: enumValue(
      record.status,
      ["not_invoked", "executed", "failed", "unknown"] as const,
      `${path}.status`,
    ),
    receiptRecorded,
    invokedAt: nullableUtcTimestamp(record.invoked_at, `${path}.invoked_at`),
    completedAt: nullableUtcTimestamp(record.completed_at, `${path}.completed_at`),
    toolResultEnteredContext: nullableBoolean(
      record.tool_result_entered_context,
      `${path}.tool_result_entered_context`,
    ),
    persisted: nullableBoolean(record.persisted, `${path}.persisted`),
    sideEffectMeasurement: enumValue(
      record.side_effect_measurement,
      ["measured", "not_measured", "not_applicable", "unknown"] as const,
      `${path}.side_effect_measurement`,
    ),
    sideEffectCount,
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseControlIntegrity(value: unknown, path: string): ControlIntegrityPresentation {
  const record = strictObject(value, path, ["status", "reason_codes", "source_refs"]);
  return {
    status: enumValue(
      record.status,
      [
        "no_violation_observed",
        "suspected",
        "confirmed_violation",
        "correlation_conflict",
        "unknown",
      ] as const,
      `${path}.status`,
    ),
    reasonCodes: stringArray(record.reason_codes, `${path}.reason_codes`),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

const NORMALIZED_CT_SOURCE_TYPES = [
  "user",
  "web",
  "email",
  "tool_result",
  "mcp",
  "rag",
  "memory",
  "file",
  "model",
  "runtime",
  "other",
] as const satisfies readonly NormalizedCtSourceType[];

function parseContentIngressSummary(value: unknown, path: string): ContentIngressSummary {
  const record = strictObject(value, path, [
    "availability",
    "stable_source_refs",
    "raw_source_types",
    "normalized_ct_source_types",
    "ct_normalization_availability",
    "trust_labels",
    "taints",
    "provenance_node_ids",
  ]);
  return {
    availability: enumValue(record.availability, AVAILABILITY, `${path}.availability`),
    stableSourceRefs: stringArray(record.stable_source_refs, `${path}.stable_source_refs`),
    rawSourceTypes: stringArray(record.raw_source_types, `${path}.raw_source_types`),
    normalizedCtSourceTypes: arrayValue(
      record.normalized_ct_source_types,
      `${path}.normalized_ct_source_types`,
      (item, itemPath) => enumValue(item, NORMALIZED_CT_SOURCE_TYPES, itemPath),
    ),
    ctNormalizationAvailability: enumValue(
      record.ct_normalization_availability,
      AVAILABILITY,
      `${path}.ct_normalization_availability`,
    ),
    trustLabels: arrayValue(record.trust_labels, `${path}.trust_labels`, (item, itemPath) =>
      enumValue(item, ["trusted", "untrusted", "unknown"] as const, itemPath),
    ),
    taints: stringArray(record.taints, `${path}.taints`),
    provenanceNodeIds: stringArray(record.provenance_node_ids, `${path}.provenance_node_ids`),
  };
}

function parseSupervision(value: unknown, path: string): ExecutionStepSupervisionDetails {
  const record = strictObject(value, path, [
    "step_key",
    "activity_state",
    "semantics",
    "action",
    "official_decision",
    "v21_assessment",
    "approval",
    "enforcement",
    "execution",
    "control_integrity",
    "content_ingress_summary",
  ]);
  const stepKey = stringValue(record.step_key, `${path}.step_key`, { nonEmpty: true });
  if (!stepKey.startsWith("action:mock_action_") && !stepKey.startsWith("event:mock_event_")) {
    return fail(
      `${path}.step_key`,
      "synthetic step keys must use action:mock_action_ or event:mock_event_",
    );
  }
  const action = record.action === null ? null : parseAction(record.action, `${path}.action`);
  if (action && stepKey !== `action:${action.actionId}`) {
    return fail(`${path}.step_key`, "must match the attached action id");
  }
  literalValue(record.v21_assessment, "unavailable", `${path}.v21_assessment`);
  return {
    stepKey: stepKey as ExecutionStepSupervisionDetails["stepKey"],
    activityState: enumValue(
      record.activity_state,
      ["pending", "running", "waiting", "settled", "failed", "unknown"] as const,
      `${path}.activity_state`,
    ) as ActivityState,
    semantics: parseSemantics(record.semantics, `${path}.semantics`),
    action,
    officialDecision: parseOfficialDecision(record.official_decision, `${path}.official_decision`),
    v21Assessment: unavailableV21Assessment(),
    approval: parseApproval(record.approval, `${path}.approval`),
    enforcement: parseEnforcement(record.enforcement, `${path}.enforcement`),
    execution: parseExecution(record.execution, `${path}.execution`),
    controlIntegrity: parseControlIntegrity(record.control_integrity, `${path}.control_integrity`),
    contentIngressSummary: parseContentIngressSummary(
      record.content_ingress_summary,
      `${path}.content_ingress_summary`,
    ),
  };
}

function parseMetadata(record: JsonRecord, path: string): RuntimeSupervisionFixtureMetadata {
  const derivedFrom = arrayValue(record.derived_from, `${path}.derived_from`, (item, itemPath) =>
    literalValue(item, SOURCE_FIXTURE_PATH, itemPath),
  );
  if (derivedFrom.length !== 1)
    return fail(`${path}.derived_from`, "must contain exactly the frozen source fixture");
  const contractVersions = strictObject(record.contract_versions, `${path}.contract_versions`, [
    "supervision",
    "audit",
  ]);
  return {
    fixtureSchemaVersion: literalValue(
      record.fixture_schema_version,
      FIXTURE_SCHEMA_VERSION,
      `${path}.fixture_schema_version`,
    ),
    fixtureId: stringValue(record.fixture_id, `${path}.fixture_id`, { nonEmpty: true }),
    purpose: enumValue(
      record.purpose,
      ["contract_projection", "ui_preview"] as const,
      `${path}.purpose`,
    ),
    sourceMode: literalValue(record.source_mode, "mock", `${path}.source_mode`),
    derivedFrom: [SOURCE_FIXTURE_PATH],
    contractVersions: {
      supervision: literalValue(
        contractVersions.supervision,
        SUPERVISION_SCHEMA_VERSION,
        `${path}.contract_versions.supervision`,
      ),
      audit: literalValue(
        contractVersions.audit,
        AUDIT_SCHEMA_VERSION,
        `${path}.contract_versions.audit`,
      ),
    },
    containsSyntheticFacts: literalValue(
      record.contains_synthetic_facts,
      true,
      `${path}.contains_synthetic_facts`,
    ),
    safeForDemoSandbox: literalValue(
      record.safe_for_demo_sandbox,
      true,
      `${path}.safe_for_demo_sandbox`,
    ),
  };
}

function assertProjectionSemantics(fixture: SupervisionProjectionFixture): void {
  if (fixture.cases.length < 3)
    return fail("$.cases", "must cover approved, denied, and conflict projections");
  const caseIds = new Set<string>();
  for (const [index, item] of fixture.cases.entries()) {
    const path = `$.cases[${index}]`;
    if (caseIds.has(item.caseId)) return fail(`${path}.case_id`, "must be unique");
    caseIds.add(item.caseId);
    if (item.supervision.semantics.elementSourceMode !== "mock") {
      return fail(`${path}.supervision.semantics.element_source_mode`, "must be mock");
    }
    const execution = item.supervision.execution;
    const receiptRefs = execution.sourceRefs.filter(({ kind }) => kind === "receipt");
    if (execution.receiptRecorded && receiptRefs.length !== 1) {
      return fail(
        `${path}.supervision.execution.source_refs`,
        "a recorded runtime outcome requires exactly one receipt",
      );
    }
    if (
      execution.status !== "unknown" &&
      (!execution.receiptRecorded || receiptRefs.length !== 1)
    ) {
      return fail(
        `${path}.supervision.execution`,
        "terminal execution status requires one unique recorded receipt",
      );
    }
  }

  const askAllowed = fixture.cases.find(
    ({ supervision }) =>
      supervision.officialDecision.decision === "ask" &&
      supervision.approval.decision === "allow_once",
  );
  if (!askAllowed) return fail("$.cases", "must preserve ASK after allow_once approval");
  const denied = fixture.cases.find(
    ({ supervision }) => supervision.officialDecision.decision === "deny",
  );
  if (!denied) return fail("$.cases", "must include a DENY projection");
  if (
    denied.supervision.enforcement.gateState === "blocked" ||
    denied.supervision.execution.status === "not_invoked"
  ) {
    return fail("$.cases", "DENY must not synthesize blocked or not_invoked evidence");
  }
  if (
    !fixture.cases.some(
      ({ supervision }) => supervision.controlIntegrity.status === "correlation_conflict",
    )
  ) {
    return fail("$.cases", "must include an explicit correlation conflict");
  }
}

function parseProjectionFixture(
  record: JsonRecord,
  metadata: RuntimeSupervisionFixtureMetadata,
): SupervisionProjectionFixture {
  literalValue(record.fixture_kind, "supervision_projection", "$.fixture_kind");
  literalValue(metadata.fixtureId, "rsc_supervision_projection_v01", "$.fixture_id");
  literalValue(metadata.purpose, "contract_projection", "$.purpose");
  const fixture: SupervisionProjectionFixture = {
    fixtureKind: "supervision_projection",
    metadata: {
      ...metadata,
      fixtureId: "rsc_supervision_projection_v01",
      purpose: "contract_projection",
    },
    sourceTraceId: literalValue(
      record.source_trace_id,
      "trace_runtime_safety_demo_001",
      "$.source_trace_id",
    ),
    traceId: literalValue(record.trace_id, "mock_trace_supervision_projection_v01", "$.trace_id"),
    elementSourceMode: literalValue(record.element_source_mode, "mock", "$.element_source_mode"),
    cases: arrayValue(record.cases, "$.cases", (item, path) => {
      const itemRecord = strictObject(item, path, [
        "case_id",
        "description",
        "expectations",
        "supervision",
      ]);
      return {
        caseId: stringValue(itemRecord.case_id, `${path}.case_id`, { nonEmpty: true }),
        description: stringValue(itemRecord.description, `${path}.description`, { nonEmpty: true }),
        expectations: stringArray(itemRecord.expectations, `${path}.expectations`),
        supervision: parseSupervision(itemRecord.supervision, `${path}.supervision`),
      };
    }),
  };
  assertProjectionSemantics(fixture);
  return fixture;
}

const CT_FLOW_RELATIONS = [
  "received_from",
  "read_from",
  "derived_from",
  "assembled_into",
  "influenced_by",
  "returned_by",
  "written_to",
  "persisted_to",
  "loaded_from_memory",
  "sent_to",
] as const satisfies readonly CtFlowRelation[];

function parseProvenanceNode(value: unknown, path: string): ProvenanceNodePresentation {
  const baseKeys = [
    "provenance_node_id",
    "node_kind",
    "ref_type",
    "ref_id",
    "taints",
    "display_mode",
    "safe_excerpt",
    "semantics",
  ] as const;
  const preliminary = value as JsonRecord;
  const nodeKind = enumValue(
    preliminary?.node_kind,
    ["source", "context", "model_input", "memory", "action", "other"] as const,
    `${path}.node_kind`,
  );
  const extraKeysByKind = {
    source: [
      "raw_source_type",
      "normalized_ct_source_type",
      "ct_normalization_availability",
      "trust",
      "verification_state",
    ],
    context: ["scope_digest", "manifest_event_id"],
    model_input: ["event_id", "context_ref", "model_call_ref"],
    memory: ["memory_ref", "trust", "fact_authority"],
    action: ["action_id"],
    other: [],
  } as const;
  const record = strictObject(value, path, [...baseKeys, ...extraKeysByKind[nodeKind]]);
  const base = {
    provenanceNodeId: stringValue(record.provenance_node_id, `${path}.provenance_node_id`, {
      nonEmpty: true,
    }),
    nodeKind,
    refType: stringValue(record.ref_type, `${path}.ref_type`, { nonEmpty: true }),
    refId: stringValue(record.ref_id, `${path}.ref_id`, { nonEmpty: true }),
    taints: stringArray(record.taints, `${path}.taints`),
    displayMode: enumValue(
      record.display_mode,
      ["excerpt", "metadata_only", "redacted", "unavailable"] as const,
      `${path}.display_mode`,
    ),
    safeExcerpt: nullableString(record.safe_excerpt, `${path}.safe_excerpt`),
    semantics: parseSemantics(record.semantics, `${path}.semantics`),
  };
  switch (nodeKind) {
    case "source":
      return {
        ...base,
        nodeKind,
        rawSourceType: nullableString(record.raw_source_type, `${path}.raw_source_type`),
        normalizedCtSourceType: nullableString(
          record.normalized_ct_source_type,
          `${path}.normalized_ct_source_type`,
        ),
        ctNormalizationAvailability: enumValue(
          record.ct_normalization_availability,
          AVAILABILITY,
          `${path}.ct_normalization_availability`,
        ),
        trust: enumValue(
          record.trust,
          ["trusted", "untrusted", "unknown"] as const,
          `${path}.trust`,
        ),
        verificationState: enumValue(
          record.verification_state,
          ["verified", "unverified", "not_applicable", "unknown"] as const,
          `${path}.verification_state`,
        ),
      };
    case "context":
      return {
        ...base,
        nodeKind,
        scopeDigest: stringValue(record.scope_digest, `${path}.scope_digest`, { nonEmpty: true }),
        manifestEventId: nullableString(record.manifest_event_id, `${path}.manifest_event_id`),
      };
    case "model_input":
      return {
        ...base,
        nodeKind,
        eventId: stringValue(record.event_id, `${path}.event_id`, { nonEmpty: true }),
        contextRef: stringValue(record.context_ref, `${path}.context_ref`, { nonEmpty: true }),
        modelCallRef: nullableString(record.model_call_ref, `${path}.model_call_ref`),
      };
    case "memory":
      return {
        ...base,
        nodeKind,
        memoryRef: stringValue(record.memory_ref, `${path}.memory_ref`, { nonEmpty: true }),
        trust: enumValue(
          record.trust,
          ["trusted", "untrusted", "unknown"] as const,
          `${path}.trust`,
        ),
        factAuthority: enumValue(
          record.fact_authority,
          ["authoritative", "trusted_claim", "untrusted_claim", "model_judgment"] as const,
          `${path}.fact_authority`,
        ),
      };
    case "action": {
      const actionId = stringValue(record.action_id, `${path}.action_id`, { nonEmpty: true });
      if (!actionId.startsWith("mock_action_"))
        return fail(`${path}.action_id`, "must use the mock_action_ namespace");
      return { ...base, nodeKind, actionId };
    }
    case "other":
      return { ...base, nodeKind };
  }
}

function parseProvenanceEdge(value: unknown, path: string): ProvenanceEdgePresentation {
  const record = strictObject(value, path, [
    "edge_id",
    "source_node_id",
    "target_node_id",
    "wire_relation",
    "ct_flow_relation",
    "legacy_relation_type",
    "certainty",
    "flow_strength",
    "flow_origin",
    "coverage",
    "source_refs",
  ]);
  const ctFlowRelation =
    record.ct_flow_relation === null
      ? null
      : enumValue(record.ct_flow_relation, CT_FLOW_RELATIONS, `${path}.ct_flow_relation`);
  return {
    edgeId: stringValue(record.edge_id, `${path}.edge_id`, { nonEmpty: true }),
    sourceNodeId: stringValue(record.source_node_id, `${path}.source_node_id`, { nonEmpty: true }),
    targetNodeId: stringValue(record.target_node_id, `${path}.target_node_id`, { nonEmpty: true }),
    wireRelation: stringValue(record.wire_relation, `${path}.wire_relation`, { nonEmpty: true }),
    ctFlowRelation,
    legacyRelationType: nullableString(record.legacy_relation_type, `${path}.legacy_relation_type`),
    certainty: enumValue(record.certainty, CERTAINTY, `${path}.certainty`),
    flowStrength: enumValue(
      record.flow_strength,
      ["exact", "strong", "possible", "unknown"] as const,
      `${path}.flow_strength`,
    ),
    flowOrigin: enumValue(
      record.flow_origin,
      ["observed", "deterministic", "semantic_inferred", "unknown"] as const,
      `${path}.flow_origin`,
    ),
    coverage: enumValue(
      record.coverage,
      ["complete", "partial", "stale", "unknown", "not_applicable"] as const,
      `${path}.coverage`,
    ),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseWarning(value: unknown, path: string): SupervisionWarning {
  const record = strictObject(value, path, ["code", "severity", "message", "source_refs"]);
  return {
    code: enumValue(
      record.code,
      [
        "identity_conflict",
        "correlation_conflict",
        "window_truncated",
        "unsupported_contract",
        "projection_failed",
        "mixed_source_mode",
      ] as const,
      `${path}.code`,
    ),
    severity: enumValue(record.severity, ["info", "warning", "error"] as const, `${path}.severity`),
    message: stringValue(record.message, `${path}.message`, { nonEmpty: true }),
    sourceRefs: arrayValue(record.source_refs, `${path}.source_refs`, parseLocator),
  };
}

function parseProvenance(value: unknown, path: string): ProvenancePresentationViewModel {
  const record = strictObject(value, path, ["contract_kind", "nodes", "edges", "warnings"]);
  const presentation = {
    contractKind: enumValue(
      record.contract_kind,
      ["legacy", "ct-provenance/1.0", "mixed"] as const,
      `${path}.contract_kind`,
    ),
    nodes: arrayValue(record.nodes, `${path}.nodes`, parseProvenanceNode),
    edges: arrayValue(record.edges, `${path}.edges`, parseProvenanceEdge),
    warnings: arrayValue(record.warnings, `${path}.warnings`, parseWarning),
  } satisfies ProvenancePresentationViewModel;

  const nodeIds = new Set<string>();
  for (const [index, node] of presentation.nodes.entries()) {
    if (nodeIds.has(node.provenanceNodeId)) {
      return fail(`${path}.nodes[${index}].provenance_node_id`, "must be unique");
    }
    nodeIds.add(node.provenanceNodeId);
  }
  const edgeIds = new Set<string>();
  for (const [index, edge] of presentation.edges.entries()) {
    if (edgeIds.has(edge.edgeId)) return fail(`${path}.edges[${index}].edge_id`, "must be unique");
    edgeIds.add(edge.edgeId);
    if (!nodeIds.has(edge.sourceNodeId) || !nodeIds.has(edge.targetNodeId)) {
      return fail(`${path}.edges[${index}]`, "must reference existing provenance nodes");
    }
  }
  return presentation;
}

function assertContextIngressPath(fixture: ContextIngressPreviewFixture): void {
  const source = fixture.provenancePresentation.nodes.find(({ nodeKind }) => nodeKind === "source");
  const context = fixture.provenancePresentation.nodes.find(
    ({ nodeKind }) => nodeKind === "context",
  );
  const modelInput = fixture.provenancePresentation.nodes.find(
    ({ nodeKind }) => nodeKind === "model_input",
  );
  const action = fixture.provenancePresentation.nodes.find(
    (node) => node.nodeKind === "action" && node.actionId === fixture.highImpactActionId,
  );
  if (!source || !context || !modelInput || !action) {
    return fail(
      "$.provenance_presentation.nodes",
      "must contain Web Source, Context, Model Input, and high-impact Action nodes",
    );
  }
  const expectedPairs = [
    [source.provenanceNodeId, context.provenanceNodeId],
    [context.provenanceNodeId, modelInput.provenanceNodeId],
    [modelInput.provenanceNodeId, action.provenanceNodeId],
  ];
  for (const [sourceNodeId, targetNodeId] of expectedPairs) {
    const matched = fixture.provenancePresentation.edges.some(
      (edge) =>
        edge.sourceNodeId === sourceNodeId &&
        edge.targetNodeId === targetNodeId &&
        edge.ctFlowRelation === "assembled_into" &&
        edge.wireRelation === "assembled_into",
    );
    if (!matched)
      return fail(
        "$.provenance_presentation.edges",
        "must preserve the explicit assembled_into ingress path",
      );
  }
  if (!fixture.contentIngressSummary.provenanceNodeIds.includes(source.provenanceNodeId)) {
    return fail(
      "$.content_ingress_summary.provenance_node_ids",
      "must reference the Web Source provenance node",
    );
  }
}

function parseContextIngressFixture(
  record: JsonRecord,
  metadata: RuntimeSupervisionFixtureMetadata,
): ContextIngressPreviewFixture {
  literalValue(record.fixture_kind, "context_ingress_preview", "$.fixture_kind");
  literalValue(metadata.fixtureId, "rsc_context_ingress_preview_v01", "$.fixture_id");
  literalValue(metadata.purpose, "ui_preview", "$.purpose");
  const sourceUri = stringValue(record.source_uri, "$.source_uri", { nonEmpty: true });
  let parsedUri: URL;
  try {
    parsedUri = new URL(sourceUri);
  } catch {
    return fail("$.source_uri", "expected a valid URL");
  }
  if (parsedUri.protocol !== "https:" || !parsedUri.hostname.endsWith(".test")) {
    return fail("$.source_uri", "Preview sources must use an HTTPS .test domain");
  }
  const highImpactActionId = stringValue(record.high_impact_action_id, "$.high_impact_action_id", {
    nonEmpty: true,
  });
  if (!highImpactActionId.startsWith("mock_action_")) {
    return fail("$.high_impact_action_id", "must use the mock_action_ namespace");
  }
  const executionGraphEdges = arrayValue(
    record.execution_graph_edges,
    "$.execution_graph_edges",
    () =>
      fail("$.execution_graph_edges", "content and causal edges belong only in Mock Provenance"),
  );
  if (executionGraphEdges.length !== 0) return fail("$.execution_graph_edges", "must remain empty");
  const fixture: ContextIngressPreviewFixture = {
    fixtureKind: "context_ingress_preview",
    metadata: {
      ...metadata,
      fixtureId: "rsc_context_ingress_preview_v01",
      purpose: "ui_preview",
    },
    traceId: literalValue(record.trace_id, "mock_trace_context_ingress_preview_v01", "$.trace_id"),
    userTask: stringValue(record.user_task, "$.user_task", { nonEmpty: true }),
    sourceUri,
    fakeCredential: literalValue(
      record.fake_credential,
      "DEMO_CREDENTIAL_NOT_VALID",
      "$.fake_credential",
    ),
    highImpactActionId: highImpactActionId as `mock_action_${string}`,
    executionGraphEdges: [],
    contentIngressSummary: parseContentIngressSummary(
      record.content_ingress_summary,
      "$.content_ingress_summary",
    ),
    provenancePresentation: parseProvenance(
      record.provenance_presentation,
      "$.provenance_presentation",
    ),
  };
  assertContextIngressPath(fixture);
  return fixture;
}

function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}

/**
 * Validates and loads a dev/test-only fixture imported by the Preview provider.
 * Invalid, ambiguous, or authority-upgrading input throws immediately.
 */
export function loadRuntimeSupervisionFixture(input: unknown): LoadedRuntimeSupervisionFixture {
  const preliminary = input as JsonRecord;
  const fixtureKind = enumValue(
    preliminary?.fixture_kind,
    ["supervision_projection", "context_ingress_preview"] as const,
    "$.fixture_kind",
  );
  const expectedKeys =
    fixtureKind === "supervision_projection"
      ? [
          "fixture_schema_version",
          "fixture_id",
          "purpose",
          "source_mode",
          "derived_from",
          "contract_versions",
          "contains_synthetic_facts",
          "safe_for_demo_sandbox",
          "fixture_kind",
          "source_trace_id",
          "trace_id",
          "element_source_mode",
          "cases",
        ]
      : [
          "fixture_schema_version",
          "fixture_id",
          "purpose",
          "source_mode",
          "derived_from",
          "contract_versions",
          "contains_synthetic_facts",
          "safe_for_demo_sandbox",
          "fixture_kind",
          "trace_id",
          "user_task",
          "source_uri",
          "fake_credential",
          "high_impact_action_id",
          "execution_graph_edges",
          "content_ingress_summary",
          "provenance_presentation",
        ];
  const record = strictObject(input, "$", expectedKeys);
  const metadata = parseMetadata(record, "$");
  const fixture =
    fixtureKind === "supervision_projection"
      ? parseProjectionFixture(record, metadata)
      : parseContextIngressFixture(record, metadata);
  return deepFreeze(fixture);
}

export const runtimeSupervisionFixtureContract = Object.freeze({
  fixtureSchemaVersion: FIXTURE_SCHEMA_VERSION,
  supervisionSchemaVersion: SUPERVISION_SCHEMA_VERSION,
  auditSchemaVersion: AUDIT_SCHEMA_VERSION,
  sourceFixturePath: SOURCE_FIXTURE_PATH,
});

// Re-exported for fixture consumers that need to type locally assembled data.
export type RuntimeSupervisionFixtureDisplaySemantics = {
  sourceMode: ElementSourceMode;
  availability: Availability;
  certainty: EvidenceCertainty;
  decisionAuthority: DecisionAuthority;
  factAuthority: DisplayFactAuthority;
};
