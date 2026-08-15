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
    rollout: unavailableRollout(),
    sourceRefs,
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
  return {
    availability: "recorded",
    decisionAuthority: shadowValid ? "shadow" : "none",
    authorityVerification: shadowValid
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

function projectEnforcement(): EnforcementPresentation {
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
  execution: ExecutionPresentation,
): ControlIntegrityPresentation {
  const allRefs = uniqueLocators([
    ...official.sourceRefs,
    ...approval.sourceRefs,
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
  const executionAdvanced =
    input.hasExplicitStart ||
    (execution.receiptRecorded &&
      (execution.status === "executed" || execution.status === "failed"));
  const prohibitedBy = [
    official.decision === "deny" ? "OFFICIAL_DENY" : null,
    approval.status === "denied" ? "APPROVAL_DENY" : null,
    approval.status === "expired" ? "APPROVAL_EXPIRED" : null,
  ].filter((value): value is string => value !== null);
  if (executionAdvanced && prohibitedBy.length > 0) {
    return {
      status: "confirmed_violation",
      reasonCodes: prohibitedBy.map((reason) => `${reason}_FOLLOWED_BY_RUNTIME_PROGRESS`),
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

function projectSemantics(input: StepSupervisionProjectionInput): DisplayEvidenceSemantics {
  const conflicted =
    input.identityConflicted ||
    input.policyConflicted ||
    input.approval.conflicted ||
    input.outcomeConflicted;
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
  const execution = projectExecution(input);
  const actionRefs = locator("action", input.actionId, input.traceId);
  return {
    stepKey: stepKey(input.stepId),
    activityState: activityState(input),
    semantics: projectSemantics(input),
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
    enforcement: projectEnforcement(),
    execution,
    controlIntegrity: projectControlIntegrity(input, officialDecision, approval, execution),
    contentIngressSummary: projectContentIngress(input),
  };
}
