import type {
  ApprovalRequest,
  ExecutionApprovalStatus,
  ExecutionPhase,
  ExecutionStepCategory,
  NormalizedAuditEvidence,
  NormalizedResourceEvidence,
} from "../../types/dashboard.ts";
import type {
  ActivityState,
  ApprovalPresentation,
  ControlIntegrityPresentation,
  CompetitionAuthorityPresentation,
  DisplayEvidenceSemantics,
  ElementSourceMode,
  EnforcementPresentation,
  EvidenceLocator,
  ExecutionPresentation,
  ExecutionStepSupervisionDetails,
  OfficialDecisionPresentation,
  V21AssessmentPresentation,
  V21RolloutScopePresentation,
} from "../../types/runtime-supervision.ts";

type StepKey = `action:${string}` | `event:${string}`;
type JsonRecord = Record<string, unknown>;

const ENFORCEMENT_GATE_STATES = [
  "evaluating",
  "allowed",
  "approval_pending",
  "approval_released",
  "blocked",
  "timed_out",
  "binding_failed",
  "unknown",
] as const;

const BINDING_CHECK_STATUSES = [
  "not_applicable",
  "not_performed",
  "passed",
  "failed",
  "unknown",
] as const;

const LEASE_CONSUME_OUTCOMES = [
  "not_applicable",
  "not_attempted",
  "consumed",
  "expired",
  "revoked",
  "rejected",
  "unknown",
] as const;

const ENFORCEMENT_REASON_CODES = new Set([
  "rte-05:binding_exact",
  "rte-05:binding_invalid",
  "rte-05:binding_mismatch",
  "rte-05:approval_not_human",
  "rte-05:approval_not_consumable",
  "rte-05:approval_not_found",
  "rte-05:approval_expired",
  "rte-05:identity_denied",
  "rte-05:approval_timed_out",
  "rte-05:lease_consumed",
  "rte-05:consumption_conflict",
  "rte-05:lease_rejected",
  "rte-05:lease_expired",
  "rte-05:lease_revoked",
  "rte-05:lease_unavailable",
  "rte-05:lease_response_invalid",
  "rte-05:lease_consume_timed_out",
  "rte-05:multiple_binding_conflict",
  "rte-05:correlation_capacity_exhausted",
]);

const ENFORCEMENT_KEYS = new Set([
  "gate_state",
  "binding_check_status",
  "lease_consume_outcome",
  "reason_codes",
]);

const RUNTIME_LINK_KEYS = new Set([
  "event_id",
  "decision_id",
  "policy_audit_id",
  "action_id",
  "approval_id",
  "parent_audit_id",
  "lease_id",
  "consumption_id",
]);

const COMPETITION_PATH_IDS = new Set([
  "credential_unauthorized_external_egress",
  "capability_scope_mismatch_high_impact",
  "required_state_degradation",
  "forged_authority_or_allow_once_mismatch",
]);

type EnforcementGateState = EnforcementPresentation["gateState"];
type BindingCheckStatus = EnforcementPresentation["bindingCheckStatus"];
type LeaseConsumeOutcome = EnforcementPresentation["leaseConsumeOutcome"];

interface ParsedRuntimeLinks {
  eventId: string;
  decisionId: string;
  policyAuditId: string;
  actionId: string;
  approvalId: string | null;
  leaseId: string | null;
  consumptionId: string | null;
}

interface ParsedEnforcement {
  gateState: EnforcementGateState;
  bindingCheckStatus: BindingCheckStatus;
  leaseConsumeOutcome: LeaseConsumeOutcome;
  reasonCodes: string[];
}

export interface SelectedApprovalEvidence {
  conflicted: boolean;
  id: string | null;
  status: ExecutionApprovalStatus;
  request: ApprovalRequest | null;
}

export interface StepSupervisionProjectionInput {
  traceId: string;
  elementSourceMode: ElementSourceMode;
  stepId: string;
  category: ExecutionStepCategory;
  phase: ExecutionPhase;
  actionId: string | null;
  actionName: string | null;
  resources: readonly NormalizedResourceEvidence[];
  stepEvents: readonly NormalizedAuditEvidence[];
  primary: NormalizedAuditEvidence | null;
  policyConflicted: boolean;
  approval: SelectedApprovalEvidence;
  outcome: NormalizedAuditEvidence | null;
  outcomeConflicted: boolean;
  identityConflicted: boolean;
  hasExplicitStart: boolean;
}

function asRecord(value: unknown): JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [];
}

function exactRecord(value: unknown, keys: ReadonlySet<string>): JsonRecord | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as JsonRecord;
  return Object.keys(record).every((key) => keys.has(key)) ? record : null;
}

function identifier(value: unknown, maxLength: number): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength ? value : null;
}

function optionalIdentifier(
  record: JsonRecord,
  key: string,
  maxLength: number,
): string | null | undefined {
  if (!(key in record)) return null;
  return identifier(record[key], maxLength) ?? undefined;
}

function enumMember<T extends string>(value: unknown, values: readonly T[]): T | null {
  return typeof value === "string" && values.includes(value as T) ? (value as T) : null;
}

function parseRuntimeLinks(value: unknown): ParsedRuntimeLinks | null {
  const record = exactRecord(value, RUNTIME_LINK_KEYS);
  if (!record) return null;
  const eventId = identifier(record.event_id, 160);
  const decisionId = identifier(record.decision_id, 160);
  const policyAuditId = identifier(record.policy_audit_id, 256);
  const actionId = identifier(record.action_id, 160);
  const approvalId = optionalIdentifier(record, "approval_id", 160);
  const leaseId = optionalIdentifier(record, "lease_id", 160);
  const consumptionId = optionalIdentifier(record, "consumption_id", 160);
  if (
    !eventId ||
    !decisionId ||
    !policyAuditId ||
    !actionId ||
    approvalId === undefined ||
    leaseId === undefined ||
    consumptionId === undefined ||
    (leaseId === null) !== (consumptionId === null)
  ) {
    return null;
  }
  return {
    eventId,
    decisionId,
    policyAuditId,
    actionId,
    approvalId,
    leaseId,
    consumptionId,
  };
}

function parseEnforcement(value: unknown): ParsedEnforcement | null {
  const record = exactRecord(value, ENFORCEMENT_KEYS);
  if (!record || Object.keys(record).length !== ENFORCEMENT_KEYS.size) return null;
  const gateState = enumMember(record.gate_state, ENFORCEMENT_GATE_STATES);
  const bindingCheckStatus = enumMember(record.binding_check_status, BINDING_CHECK_STATUSES);
  const leaseConsumeOutcome = enumMember(record.lease_consume_outcome, LEASE_CONSUME_OUTCOMES);
  const reasonCodes = Array.isArray(record.reason_codes)
    ? record.reason_codes.filter((value): value is string => typeof value === "string")
    : [];
  if (
    gateState === null ||
    bindingCheckStatus === null ||
    leaseConsumeOutcome === null ||
    gateState === "unknown" ||
    bindingCheckStatus === "unknown" ||
    leaseConsumeOutcome === "unknown" ||
    reasonCodes.length < 1 ||
    reasonCodes.length > 4 ||
    reasonCodes.length !== (record.reason_codes as unknown[] | undefined)?.length ||
    new Set(reasonCodes).size !== reasonCodes.length ||
    reasonCodes.some((code) => !ENFORCEMENT_REASON_CODES.has(code))
  ) {
    return null;
  }
  return { gateState, bindingCheckStatus, leaseConsumeOutcome, reasonCodes };
}

function rawEnvelope(event: NormalizedAuditEvidence): {
  evidence: JsonRecord;
  links: unknown;
} {
  const raw = asRecord(event.raw);
  return { evidence: asRecord(raw.evidence), links: raw.links };
}

function isExplicitStart(event: NormalizedAuditEvidence): boolean {
  return (
    event.recordType === "runtime_observation" &&
    (event.eventType === "tool_call_started" || event.stage === "tool_call_started")
  );
}

function linksMatch(left: ParsedRuntimeLinks, right: ParsedRuntimeLinks): boolean {
  return (
    left.eventId === right.eventId &&
    left.actionId === right.actionId &&
    left.decisionId === right.decisionId &&
    left.policyAuditId === right.policyAuditId &&
    left.approvalId === right.approvalId &&
    left.leaseId === right.leaseId &&
    left.consumptionId === right.consumptionId
  );
}

function partialEnforcement(
  input: StepSupervisionProjectionInput,
  reasonCode: "RTE_05_EVIDENCE_INVALID" | "RTE_05_CORRELATION_CONFLICT",
): EnforcementPresentation {
  const receipts = input.stepEvents.filter((event) => event.recordType === "runtime_outcome");
  return {
    availability: "partial",
    gateState: "unknown",
    bindingCheckStatus: "unknown",
    leaseConsumeOutcome: "unknown",
    leaseId: null,
    consumptionId: null,
    reasonCodes: [reasonCode],
    sourceRefs: auditLocators(receipts, input.traceId),
  };
}

function stepKey(value: string): StepKey {
  if (value.startsWith("action:") || value.startsWith("event:")) return value as StepKey;
  throw new Error(`Execution step uses an unsupported stable key: ${value}`);
}

function locator(
  kind: EvidenceLocator["kind"],
  id: string | null | undefined,
  traceId: string,
): EvidenceLocator[] {
  return id ? [{ kind, id, traceId }] : [];
}

function auditLocators(
  events: readonly NormalizedAuditEvidence[],
  traceId: string,
): EvidenceLocator[] {
  return events.map((event) => ({ kind: "audit", id: event.auditId, traceId }));
}

function uniqueLocators(locators: readonly EvidenceLocator[]): EvidenceLocator[] {
  const seen = new Set<string>();
  return locators.filter((item) => {
    const identity = `${item.id}\u0000${item.traceId}`;
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

function unavailableRollout(): V21RolloutScopePresentation {
  return {
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
  };
}

export function unavailableV21Assessment(
  availability: V21AssessmentPresentation["availability"] = "unavailable",
  authorityVerification: V21AssessmentPresentation["authorityVerification"] = "unverified",
  sourceRefs: EvidenceLocator[] = [],
): V21AssessmentPresentation {
  return {
    availability,
    decisionAuthority: "none",
    authorityVerification,
    mode: "unknown",
    assessmentId: null,
    fastDisposition: null,
    recordedFinalDecision: null,
    legacyDecision: null,
    coverage: {},
    degradationIds: [],
    divergenceCategory: null,
    competitionAuthority: null,
    rollout: unavailableRollout(),
    sourceRefs,
  };
}

function projectCompetitionAuthority(
  evidence: JsonRecord,
  primary: NormalizedAuditEvidence,
): CompetitionAuthorityPresentation | null {
  if (!("decision_authority" in evidence)) return null;
  const envelope = asRecord(evidence.decision_authority);
  if (envelope._budget_dropped === true || envelope.schema_version !== "1.0") return null;
  const payload = asRecord(envelope.payload);
  const authority = asRecord(payload.decision_authority);
  const selectedDecision = asRecord(payload.selected_decision);
  const source = authority.source;
  const mode = authority.mode;
  const selectionBasis = authority.selection_basis;
  const legacyFloorApplied = authority.legacy_floor_applied;
  const approvalRelease = authority.approval_release;
  const activationRefDigest = stringValue(authority.activation_ref_digest);
  const selectedDecisionId = stringValue(selectedDecision.decision_id);
  const selectedDecisionValue = decisionValue(selectedDecision.decision);
  const matchedPathIds = stringArray(authority.matched_path_ids);
  const pathsValid = matchedPathIds.every((pathId) => COMPETITION_PATH_IDS.has(pathId));
  const semanticsValid =
    (source === "current" && selectionBasis === "current" && legacyFloorApplied === false) ||
    (source === "v21" &&
      ((mode === "limited_enable" && selectionBasis === "path_allowlist") ||
        (mode === "active" && selectionBasis === "profile_all")));
  if (
    payload.profile_id !== "competition-langgraph-v2" ||
    (source !== "current" && source !== "v21") ||
    (mode !== "shadow" && mode !== "limited_enable" && mode !== "active") ||
    (selectionBasis !== "current" &&
      selectionBasis !== "path_allowlist" &&
      selectionBasis !== "profile_all") ||
    typeof legacyFloorApplied !== "boolean" ||
    (approvalRelease !== "not_applicable" &&
      approvalRelease !== "strong_binding_required" &&
      approvalRelease !== "forbidden") ||
    activationRefDigest === null ||
    !/^sha256:[0-9a-f]{64}$/.test(activationRefDigest) ||
    !pathsValid ||
    !semanticsValid ||
    selectedDecisionId === null ||
    selectedDecisionValue === null ||
    selectedDecisionId !== primary.decisionId ||
    selectedDecisionValue !== primary.decision
  ) {
    return null;
  }
  return {
    availability: "recorded",
    profileId: "competition-langgraph-v2",
    source,
    mode,
    selectionBasis,
    matchedPathIds: matchedPathIds as CompetitionAuthorityPresentation["matchedPathIds"],
    legacyFloorApplied,
    activationRefDigest,
    approvalRelease,
    selectedDecisionId,
  };
}

function decisionValue(value: unknown): "allow" | "ask" | "deny" | null {
  return value === "allow" || value === "ask" || value === "deny" ? value : null;
}

function projectV21Assessment(
  primary: NormalizedAuditEvidence | null,
  traceId: string,
): V21AssessmentPresentation {
  if (!primary) return unavailableV21Assessment();
  const raw = asRecord(primary.raw);
  const evidence = asRecord(raw.evidence);
  if (!("decision_v21" in evidence)) return unavailableV21Assessment();
  const envelope = asRecord(evidence.decision_v21);
  const sourceRefs = locator("audit", primary.auditId, traceId);
  if (envelope._budget_dropped === true) {
    return unavailableV21Assessment("partial", "unverified", sourceRefs);
  }
  if (envelope.schema_version !== "2.1") {
    return unavailableV21Assessment("partial", "conflicted", sourceRefs);
  }
  const payload = asRecord(envelope.payload);
  const mode = payload.mode;
  const fastDisposition = payload.v21_fast_disposition;
  const recordedFinalDecision = decisionValue(payload.final_decision);
  const legacyDecision = decisionValue(payload.legacy_decision);
  const competitionAuthority = projectCompetitionAuthority(evidence, primary);
  if (
    (mode !== "shadow" && mode !== "limited_enable" && mode !== "active") ||
    (fastDisposition !== "CLEAR_ALLOW" &&
      fastDisposition !== "CLEAR_DENY" &&
      fastDisposition !== "DEFER") ||
    recordedFinalDecision === null
  ) {
    return unavailableV21Assessment("partial", "conflicted", sourceRefs);
  }
  const coverageDomains = [
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
  ] as const;
  const rawCoverage = asRecord(payload.coverage);
  const coverage = Object.fromEntries(
    coverageDomains.flatMap((domain) => {
      const value = asRecord(rawCoverage[domain]);
      const status = value.status;
      const projectorVersion = stringValue(value.projector_version);
      if (
        value.domain !== domain ||
        (status !== "complete" &&
          status !== "partial" &&
          status !== "stale" &&
          status !== "unknown" &&
          status !== "not_applicable") ||
        projectorVersion === null
      ) {
        return [];
      }
      return [[domain, status] as const];
    }),
  );
  const coverageValid = Object.keys(coverage).length === coverageDomains.length;
  const shadowValid =
    mode === "shadow" &&
    coverageValid &&
    recordedFinalDecision === legacyDecision &&
    recordedFinalDecision === primary.decision;
  const officialV21Valid =
    competitionAuthority?.source === "v21" &&
    competitionAuthority.mode === mode &&
    recordedFinalDecision === primary.decision;
  return {
    availability: "recorded",
    decisionAuthority: officialV21Valid ? "official" : shadowValid ? "shadow" : "none",
    authorityVerification:
      officialV21Valid || shadowValid
        ? "verified"
        : mode === "shadow"
          ? "conflicted"
          : "unverified",
    mode,
    assessmentId: stringValue(payload.assessment_id),
    fastDisposition,
    recordedFinalDecision,
    legacyDecision,
    coverage,
    degradationIds: stringArray(payload.degradation_ids),
    divergenceCategory: stringValue(payload.divergence_category),
    competitionAuthority,
    rollout: unavailableRollout(),
    sourceRefs,
  };
}

function projectApproval(input: StepSupervisionProjectionInput): ApprovalPresentation {
  const { approval, stepEvents, traceId } = input;
  const linkedAuditRefs = auditLocators(
    stepEvents.filter((event) => event.approval.approvalId === approval.id),
    traceId,
  );
  const sourceRefs = [...locator("approval", approval.id, traceId), ...linkedAuditRefs];
  if (approval.conflicted) {
    return {
      availability: "partial",
      approvalId: null,
      status: "unknown",
      decision: null,
      resolutionSource: null,
      createdAt: null,
      expiresAt: null,
      resolvedAt: null,
      sourceRefs: auditLocators(stepEvents, traceId),
    };
  }
  if (approval.status === "not_required" && !approval.id) {
    return {
      availability: "not_applicable",
      approvalId: null,
      status: "unknown",
      decision: null,
      resolutionSource: null,
      createdAt: null,
      expiresAt: null,
      resolvedAt: null,
      sourceRefs: [],
    };
  }
  if (approval.status === "unknown" && !approval.id) {
    return {
      availability: "unavailable",
      approvalId: null,
      status: "unknown",
      decision: null,
      resolutionSource: null,
      createdAt: null,
      expiresAt: null,
      resolvedAt: null,
      sourceRefs: [],
    };
  }
  return {
    availability: "recorded",
    approvalId: approval.id,
    status:
      approval.status === "allowed_once"
        ? "allowed"
        : approval.status === "pending" ||
            approval.status === "denied" ||
            approval.status === "expired"
          ? approval.status
          : "unknown",
    decision:
      approval.status === "allowed_once"
        ? "allow_once"
        : approval.status === "denied"
          ? "deny"
          : null,
    resolutionSource: null,
    createdAt: approval.request?.createdAt ?? null,
    expiresAt: approval.request?.expiresAt ?? null,
    resolvedAt: approval.request?.resolvedAt ?? null,
    sourceRefs,
  };
}

function projectOfficialDecision(
  input: StepSupervisionProjectionInput,
): OfficialDecisionPresentation {
  const primary = input.primary;
  const availability = input.policyConflicted ? "partial" : primary ? "recorded" : "unavailable";
  return {
    availability,
    decisionAuthority: "official",
    decisionId: input.policyConflicted ? null : (primary?.decisionId ?? null),
    decision: input.policyConflicted ? "unknown" : (primary?.decision ?? "unknown"),
    policyAuditId: input.policyConflicted ? null : (primary?.auditId ?? null),
    riskScore: input.policyConflicted ? null : (primary?.risk.finalScore ?? null),
    severity: input.policyConflicted ? "unknown" : (primary?.severity ?? "unknown"),
    ruleIds: input.policyConflicted ? [] : (primary?.ruleHits.map((rule) => rule.ruleId) ?? []),
    reasonCodes: input.policyConflicted ? ["POLICY_CORRELATION_CONFLICT"] : [],
    reason: input.policyConflicted ? null : (primary?.decisionReason ?? null),
    sourceRefs: primary
      ? [
          ...locator("audit", primary.auditId, input.traceId),
          ...locator("decision", primary.decisionId, input.traceId),
        ]
      : [],
  };
}

function projectEnforcement(input: StepSupervisionProjectionInput): EnforcementPresentation {
  if (input.outcomeConflicted) {
    return partialEnforcement(input, "RTE_05_CORRELATION_CONFLICT");
  }
  const outcome = input.outcome;
  if (!outcome) {
    return {
      availability: "unavailable",
      gateState: "unknown",
      bindingCheckStatus: "not_performed",
      leaseConsumeOutcome: "not_attempted",
      leaseId: null,
      consumptionId: null,
      reasonCodes: ["RTE_05_EVIDENCE_UNAVAILABLE"],
      sourceRefs: [],
    };
  }
  const raw = rawEnvelope(outcome);
  if (!("enforcement" in raw.evidence)) {
    const links = exactRecord(raw.links, RUNTIME_LINK_KEYS);
    if (links && ("lease_id" in links || "consumption_id" in links)) {
      return partialEnforcement(input, "RTE_05_EVIDENCE_INVALID");
    }
    return {
      availability: "unavailable",
      gateState: "unknown",
      bindingCheckStatus: "not_performed",
      leaseConsumeOutcome: "not_attempted",
      leaseId: null,
      consumptionId: null,
      reasonCodes: ["RTE_05_EVIDENCE_UNAVAILABLE"],
      sourceRefs: locator("receipt", outcome.auditId, input.traceId),
    };
  }
  const enforcement = parseEnforcement(raw.evidence.enforcement);
  const links = parseRuntimeLinks(raw.links);
  if (!enforcement || !links) {
    return partialEnforcement(input, "RTE_05_EVIDENCE_INVALID");
  }
  const selectedIdentityMatches =
    links.eventId === outcome.eventId &&
    links.eventId === input.primary?.eventId &&
    links.actionId === outcome.actionId &&
    links.actionId === input.actionId &&
    links.decisionId === outcome.decisionId &&
    links.decisionId === input.primary?.decisionId &&
    links.policyAuditId === outcome.policyAuditId &&
    links.policyAuditId === input.primary?.auditId &&
    (links.approvalId === null || links.approvalId === input.approval.id);
  if (!selectedIdentityMatches) {
    return partialEnforcement(input, "RTE_05_CORRELATION_CONFLICT");
  }

  const hasLeasePair = links.leaseId !== null && links.consumptionId !== null;
  const consumed = enforcement.leaseConsumeOutcome === "consumed";
  const failedGate = ["blocked", "binding_failed", "timed_out"].includes(enforcement.gateState);
  const released = enforcement.gateState === "approval_released";
  const shapeValid =
    hasLeasePair === consumed &&
    (!released || (enforcement.bindingCheckStatus === "passed" && consumed)) &&
    (!failedGate || outcome.execution.status === "not_invoked") &&
    (!consumed ||
      (links.approvalId !== null &&
        links.approvalId === input.approval.id &&
        input.approval.status === "allowed_once"));
  if (!shapeValid) {
    return partialEnforcement(input, "RTE_05_EVIDENCE_INVALID");
  }

  const starts = input.stepEvents.filter(isExplicitStart);
  if ((released && consumed) || (failedGate && starts.length > 0)) {
    if (starts.length !== 1) {
      return partialEnforcement(input, "RTE_05_CORRELATION_CONFLICT");
    }
    const start = starts[0]!;
    const startLinks = parseRuntimeLinks(rawEnvelope(start).links);
    if (
      !startLinks ||
      !linksMatch(startLinks, links) ||
      start.eventId !== links.eventId ||
      start.actionId !== links.actionId ||
      start.decisionId !== links.decisionId ||
      start.policyAuditId !== links.policyAuditId ||
      start.approval.approvalId !== links.approvalId
    ) {
      return partialEnforcement(input, "RTE_05_CORRELATION_CONFLICT");
    }
  }

  const sourceRefs = uniqueLocators([
    ...locator("receipt", outcome.auditId, input.traceId),
    ...locator("lease", links.leaseId, input.traceId),
    ...locator("consumption", links.consumptionId, input.traceId),
    ...auditLocators(starts, input.traceId),
  ]);
  return {
    availability: "recorded",
    gateState: enforcement.gateState,
    bindingCheckStatus: enforcement.bindingCheckStatus,
    leaseConsumeOutcome: enforcement.leaseConsumeOutcome,
    leaseId: links.leaseId,
    consumptionId: links.consumptionId,
    reasonCodes: enforcement.reasonCodes,
    sourceRefs,
  };
}

function projectExecution(input: StepSupervisionProjectionInput): ExecutionPresentation {
  if (input.outcomeConflicted) {
    return {
      availability: "partial",
      status: "unknown",
      receiptRecorded: false,
      invokedAt: null,
      completedAt: null,
      toolResultEnteredContext: null,
      persisted: null,
      sideEffectMeasurement: "unknown",
      sideEffectCount: null,
      sourceRefs: input.stepEvents
        .filter((event) => event.recordType === "runtime_outcome")
        .flatMap((event) => locator("receipt", event.auditId, input.traceId)),
    };
  }
  const outcome = input.outcome;
  if (!outcome) {
    return {
      availability: "unavailable",
      status: "unknown",
      receiptRecorded: false,
      invokedAt: null,
      completedAt: null,
      toolResultEnteredContext: null,
      persisted: null,
      sideEffectMeasurement: "unknown",
      sideEffectCount: null,
      sourceRefs: [],
    };
  }
  return {
    availability: "recorded",
    status: outcome.execution.status,
    receiptRecorded: outcome.execution.receiptRecorded,
    invokedAt: outcome.execution.invokedAt,
    completedAt: outcome.execution.completedAt,
    toolResultEnteredContext: outcome.execution.toolResultEnteredContext,
    persisted: outcome.execution.persisted,
    sideEffectMeasurement: outcome.sideEffects.measurementStatus,
    sideEffectCount: outcome.sideEffects.count,
    sourceRefs: locator("receipt", outcome.auditId, input.traceId),
  };
}

function activityState(input: StepSupervisionProjectionInput): ActivityState {
  if (input.policyConflicted || input.approval.conflicted || input.outcomeConflicted)
    return "unknown";
  if (input.outcome?.execution.status === "failed") return "failed";
  if (input.outcome) return "settled";
  if (input.hasExplicitStart) return "running";
  if (
    input.approval.status === "pending" ||
    input.phase === "approval_released" ||
    input.phase === "waiting_receipt"
  ) {
    return "waiting";
  }
  if (input.phase === "checked") return "settled";
  return input.primary ? "pending" : "unknown";
}

function projectControlIntegrity(
  input: StepSupervisionProjectionInput,
  official: OfficialDecisionPresentation,
  approval: ApprovalPresentation,
  enforcement: EnforcementPresentation,
  execution: ExecutionPresentation,
): ControlIntegrityPresentation {
  const allRefs = uniqueLocators([
    ...official.sourceRefs,
    ...approval.sourceRefs,
    ...enforcement.sourceRefs,
    ...execution.sourceRefs,
    ...auditLocators(input.stepEvents, input.traceId),
  ]);
  if (input.identityConflicted) {
    return {
      status: "correlation_conflict",
      reasonCodes: ["DUPLICATE_AUDIT_ID_CONFLICT"],
      sourceRefs: allRefs,
    };
  }
  if (input.policyConflicted || input.approval.conflicted || input.outcomeConflicted) {
    return {
      status: "correlation_conflict",
      reasonCodes: ["AMBIGUOUS_STEP_EVIDENCE_CORRELATION"],
      sourceRefs: allRefs,
    };
  }
  if (enforcement.availability === "partial") {
    return {
      status: "correlation_conflict",
      reasonCodes: ["ENFORCEMENT_EVIDENCE_CONFLICT"],
      sourceRefs: allRefs,
    };
  }
  const executionAdvanced =
    input.hasExplicitStart ||
    (execution.receiptRecorded &&
      (execution.status === "executed" || execution.status === "failed"));
  const failedGate =
    enforcement.availability === "recorded" &&
    (enforcement.gateState === "blocked" ||
      enforcement.gateState === "binding_failed" ||
      enforcement.gateState === "timed_out")
      ? enforcement.gateState
      : null;
  if (executionAdvanced && failedGate) {
    return {
      status: "confirmed_violation",
      reasonCodes: [`${failedGate.toUpperCase()}_FOLLOWED_BY_RUNTIME_PROGRESS`],
      sourceRefs: allRefs,
    };
  }
  const prohibitedBy = [
    official.decision === "deny" ? "OFFICIAL_DENY" : null,
    approval.status === "denied" ? "APPROVAL_DENY" : null,
    approval.status === "expired" ? "APPROVAL_EXPIRED" : null,
  ].filter((value): value is string => value !== null);
  if (executionAdvanced && prohibitedBy.length > 0) {
    return {
      status: "suspected",
      reasonCodes: prohibitedBy.map(
        (reason) => `${reason}_FOLLOWED_BY_RUNTIME_PROGRESS_UNVERIFIED`,
      ),
      sourceRefs: allRefs,
    };
  }
  if (execution.receiptRecorded) {
    return { status: "no_violation_observed", reasonCodes: [], sourceRefs: allRefs };
  }
  return {
    status: "unknown",
    reasonCodes: ["RUNTIME_EVIDENCE_UNAVAILABLE"],
    sourceRefs: allRefs,
  };
}

function projectSemantics(
  input: StepSupervisionProjectionInput,
  enforcement: EnforcementPresentation,
): DisplayEvidenceSemantics {
  const conflicted =
    input.identityConflicted ||
    input.policyConflicted ||
    input.approval.conflicted ||
    input.outcomeConflicted ||
    enforcement.availability === "partial";
  return {
    elementSourceMode: input.elementSourceMode,
    availability: conflicted ? "partial" : "recorded",
    certainty: conflicted ? "unknown" : input.primary || input.outcome ? "confirmed" : "supported",
    decisionAuthority: input.primary && !input.policyConflicted ? "official" : "none",
    factAuthority: "none",
    derivedForDisplay: true,
    sourceRefs: auditLocators(input.stepEvents, input.traceId),
  };
}

function projectContentIngress(input: StepSupervisionProjectionInput) {
  const rawSourceTypes = [
    ...new Set(input.stepEvents.flatMap((event) => (event.source.type ? [event.source.type] : []))),
  ];
  const contextSources = [...new Set(input.stepEvents.flatMap((event) => event.contextSources))];
  const trustLabels = [
    ...new Set(
      input.stepEvents.flatMap((event) => {
        const trust = event.source.trustLevel?.toLocaleLowerCase();
        if (!trust) return [];
        if (trust.includes("untrusted")) return ["untrusted" as const];
        if (trust.includes("trusted")) return ["trusted" as const];
        return ["unknown" as const];
      }),
    ),
  ];
  return {
    availability:
      rawSourceTypes.length || contextSources.length
        ? ("recorded" as const)
        : ("unavailable" as const),
    stableSourceRefs: [],
    rawSourceTypes,
    normalizedCtSourceTypes: [],
    ctNormalizationAvailability: "unavailable" as const,
    trustLabels,
    taints: [],
    provenanceNodeIds: [],
  };
}

export function projectExecutionStepSupervision(
  input: StepSupervisionProjectionInput,
): ExecutionStepSupervisionDetails {
  const officialDecision = projectOfficialDecision(input);
  const approval = projectApproval(input);
  const enforcement = projectEnforcement(input);
  const execution = projectExecution(input);
  const actionRefs = locator("action", input.actionId, input.traceId);
  return {
    stepKey: stepKey(input.stepId),
    activityState: activityState(input),
    semantics: projectSemantics(input, enforcement),
    action: input.actionId
      ? {
          actionId: input.actionId,
          actionName: input.actionName,
          subjectType: input.category,
          resourceTargets: input.resources.map((resource) => resource.value),
          argumentSummary: null,
          occurredAt: input.stepEvents[0]?.occurredAt ?? null,
          sourceRefs: actionRefs,
        }
      : null,
    officialDecision,
    v21Assessment: input.policyConflicted
      ? unavailableV21Assessment()
      : projectV21Assessment(input.primary, input.traceId),
    approval,
    enforcement,
    execution,
    controlIntegrity: projectControlIntegrity(
      input,
      officialDecision,
      approval,
      enforcement,
      execution,
    ),
    contentIngressSummary: projectContentIngress(input),
  };
}
