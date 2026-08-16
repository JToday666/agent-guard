import type { DashboardDataSourceDescriptor } from "../data/sources/dashboard-data-source.ts";
import type { ExecutionTraceViewModel } from "./dashboard.ts";

/**
 * Frozen presentation contracts for the runtime supervision console.
 *
 * These types describe display semantics only. They do not add authority to
 * source facts and must never be serialized back into a Guard API contract.
 */

export type DataSourceMode = "live_api" | "replay" | "mock_preview" | "hybrid_preview";

export type TemporalState = "following" | "historical";

export type ElementSourceMode = "live" | "replay" | "mock";

export type Availability = "recorded" | "partial" | "unavailable" | "not_applicable";

export type EvidenceCertainty = "confirmed" | "supported" | "possible" | "unknown";

export type DecisionAuthority = "official" | "shadow" | "none";

export type DisplayFactAuthority =
  "authoritative" | "trusted_claim" | "untrusted_claim" | "model_judgment" | "none";

// The factory-owned descriptor remains a single contract in the source layer.
export type { DashboardDataSourceDescriptor } from "../data/sources/dashboard-data-source.ts";

export interface EvidenceLocator {
  kind:
    | "audit"
    | "event"
    | "action"
    | "decision"
    | "approval"
    | "receipt"
    | "lease"
    | "consumption"
    | "provenance_node"
    | "fact"
    | "snapshot"
    | "state_delta";
  id: string;
  traceId: string;
}

export interface DisplayEvidenceSemantics {
  elementSourceMode: ElementSourceMode;
  availability: Availability;
  certainty: EvidenceCertainty;
  decisionAuthority: DecisionAuthority;
  factAuthority: DisplayFactAuthority;
  derivedForDisplay: boolean;
  sourceRefs: EvidenceLocator[];
}

export type ActivityState = "pending" | "running" | "waiting" | "settled" | "failed" | "unknown";

export interface ControlIntegrityPresentation {
  status:
    | "no_violation_observed"
    | "suspected"
    | "confirmed_violation"
    | "correlation_conflict"
    | "unknown";
  reasonCodes: string[];
  sourceRefs: EvidenceLocator[];
}

export interface ActionSummary {
  actionId: string;
  actionName: string | null;
  subjectType: string | null;
  resourceTargets: string[];
  argumentSummary: Record<string, unknown> | null;
  occurredAt: string | null;
  sourceRefs: EvidenceLocator[];
}

export interface OfficialDecisionPresentation {
  availability: Availability;
  decisionAuthority: "official";
  decisionId: string | null;
  decision: "allow" | "ask" | "deny" | "unknown";
  policyAuditId: string | null;
  riskScore: number | null;
  severity: "low" | "medium" | "high" | "critical" | "unknown";
  ruleIds: string[];
  reasonCodes: string[];
  reason: string | null;
  sourceRefs: EvidenceLocator[];
}

export type V21RolloutMode = "shadow" | "limited_enable" | "active";

export type V21RolloutChangeType = "initialize" | "enable" | "update" | "promote" | "rollback";

export type EnabledV21PathId =
  | "credential_unauthorized_external_egress"
  | "capability_scope_mismatch_high_impact"
  | "required_state_degradation"
  | "forged_authority_or_allow_once_mismatch";

export interface CohortMembershipPresentation {
  matchedCaseId: string;
  cohortId: string;
  cohortRevision: string;
  cohortDigest: string;
  membershipDigest: string;
  sourceRef: EvidenceLocator;
}

export interface MatchedRuleOwnershipPresentation {
  ruleId: string;
  ownershipTransferRevision: string;
  ownershipTransferDigest: string;
  sourceRef: EvidenceLocator;
}

export interface RuntimeProfileAttestationPresentation {
  attestationId: string;
  runtime: string;
  runtimeProfile: string;
  authenticatedAdapterId: string;
  adapterRegistryRevision: string;
  adapterRegistryDigest: string;
  attestationDigest: string;
  issuedAt: string;
  expiresAt: string;
  sourceRef: EvidenceLocator;
}

export interface V21RolloutScopePresentation {
  availability: Availability;
  rolloutId: string | null;
  rolloutRevision: number | null;
  rolloutDigest: string | null;
  configAuditId: string | null;
  routingCatalogEpoch: number | null;
  routingCatalogDigest: string | null;
  changeType: V21RolloutChangeType | "unknown";
  previousConfigAuditId: string | null;
  rollbackOfConfigAuditId: string | null;
  mode: V21RolloutMode | "unknown";
  authority: DecisionAuthority;
  scopeKind: "case" | "cohort" | "unknown";
  matchedCaseId: string | null;
  matchedCohortId: string | null;
  cohortRevision: string | null;
  cohortDigest: string | null;
  scopeMembershipRef: CohortMembershipPresentation | null;
  runtime: string | null;
  runtimeProfile: string | null;
  policyRevision: number | null;
  policyDigest: string | null;
  migrationRule: "tightening_only" | null;
  enabledPathIds: EnabledV21PathId[];
  matchedPathIds: EnabledV21PathId[];
  matchedRuleIds: string[];
  ownershipTransferRevision: string | null;
  ownershipTransferDigest: string | null;
  ownershipValidationStatus: "passed" | "unknown";
  matchedRuleOwnershipRefs: MatchedRuleOwnershipPresentation[];
  runtimeProfileAttestation: RuntimeProfileAttestationPresentation | null;
  snapshotSchemaVersion: string | null;
  projectorVersion: string | null;
  snapshotEligibilityRevision: string | null;
  snapshotEligibilityDigest: string | null;
  snapshotEligibilityStatus: "passed" | "unknown";
  snapshotEligibilityReasonCodes: string[];
  snapshotId: string | null;
  snapshotDigest: string | null;
  stateVersion: number | null;
  effectiveAt: string | null;
  scopeMatch: "matched" | "not_matched" | "unknown";
  reasonCodes: string[];
  sourceRefs: EvidenceLocator[];
}

export interface V21AssessmentPresentation {
  availability: Availability;
  decisionAuthority: DecisionAuthority;
  authorityVerification: "verified" | "unverified" | "conflicted";
  mode: V21RolloutMode | "unknown";
  assessmentId: string | null;
  fastDisposition: "CLEAR_ALLOW" | "CLEAR_DENY" | "DEFER" | null;
  recordedFinalDecision: "allow" | "ask" | "deny" | null;
  legacyDecision: "allow" | "ask" | "deny" | null;
  coverage: Record<string, string>;
  degradationIds: string[];
  divergenceCategory: string | null;
  rollout: V21RolloutScopePresentation;
  sourceRefs: EvidenceLocator[];
}

export interface ApprovalPresentation {
  availability: Availability;
  approvalId: string | null;
  status: "pending" | "allowed" | "denied" | "expired" | "unknown";
  decision: "allow_once" | "deny" | null;
  resolutionSource: "human" | "llm" | "system" | null;
  createdAt: string | null;
  expiresAt: string | null;
  resolvedAt: string | null;
  sourceRefs: EvidenceLocator[];
}

export interface EnforcementPresentation {
  availability: Availability;
  gateState:
    | "evaluating"
    | "allowed"
    | "approval_pending"
    | "approval_released"
    | "blocked"
    | "timed_out"
    | "binding_failed"
    | "unknown";
  bindingCheckStatus: "not_applicable" | "not_performed" | "passed" | "failed" | "unknown";
  leaseConsumeOutcome:
    | "not_applicable"
    | "not_attempted"
    | "consumed"
    | "expired"
    | "revoked"
    | "rejected"
    | "unknown";
  leaseId: string | null;
  consumptionId: string | null;
  reasonCodes: string[];
  sourceRefs: EvidenceLocator[];
}

export interface ExecutionPresentation {
  availability: Availability;
  status: "not_invoked" | "executed" | "failed" | "unknown";
  receiptRecorded: boolean;
  invokedAt: string | null;
  completedAt: string | null;
  toolResultEnteredContext: boolean | null;
  persisted: boolean | null;
  sideEffectMeasurement: "measured" | "not_measured" | "not_applicable" | "unknown";
  sideEffectCount: number | null;
  sourceRefs: EvidenceLocator[];
}

export type NormalizedCtSourceType =
  | "user"
  | "web"
  | "email"
  | "tool_result"
  | "mcp"
  | "rag"
  | "memory"
  | "file"
  | "model"
  | "runtime"
  | "other";

export interface ContentIngressSummary {
  availability: Availability;
  stableSourceRefs: string[];
  rawSourceTypes: string[];
  normalizedCtSourceTypes: NormalizedCtSourceType[];
  ctNormalizationAvailability: Availability;
  trustLabels: Array<"trusted" | "untrusted" | "unknown">;
  taints: string[];
  provenanceNodeIds: string[];
}

export interface ExecutionStepSupervisionDetails {
  stepKey: `action:${string}` | `event:${string}`;
  activityState: ActivityState;
  semantics: DisplayEvidenceSemantics;
  action: ActionSummary | null;
  officialDecision: OfficialDecisionPresentation;
  v21Assessment: V21AssessmentPresentation;
  approval: ApprovalPresentation;
  enforcement: EnforcementPresentation;
  execution: ExecutionPresentation;
  controlIntegrity: ControlIntegrityPresentation;
  contentIngressSummary: ContentIngressSummary;
}

export type CtFlowRelation =
  | "received_from"
  | "read_from"
  | "derived_from"
  | "assembled_into"
  | "influenced_by"
  | "returned_by"
  | "written_to"
  | "persisted_to"
  | "loaded_from_memory"
  | "sent_to";

export type CtProvenanceNodeKind =
  "source" | "context" | "model_input" | "memory" | "action" | "other";

export interface ProvenanceNodeBasePresentation {
  provenanceNodeId: string;
  nodeKind: CtProvenanceNodeKind;
  refType: string;
  refId: string;
  taints: string[];
  displayMode: "excerpt" | "metadata_only" | "redacted" | "unavailable";
  safeExcerpt: string | null;
  semantics: DisplayEvidenceSemantics;
}

export type ProvenanceNodePresentation =
  | (ProvenanceNodeBasePresentation & {
      nodeKind: "source";
      rawSourceType: string | null;
      normalizedCtSourceType: string | null;
      ctNormalizationAvailability: Availability;
      trust: "trusted" | "untrusted" | "unknown";
      verificationState: "verified" | "unverified" | "not_applicable" | "unknown";
    })
  | (ProvenanceNodeBasePresentation & {
      nodeKind: "context";
      scopeDigest: string;
      manifestEventId: string | null;
    })
  | (ProvenanceNodeBasePresentation & {
      nodeKind: "model_input";
      eventId: string;
      contextRef: string;
      modelCallRef: string | null;
    })
  | (ProvenanceNodeBasePresentation & {
      nodeKind: "memory";
      memoryRef: string;
      trust: "trusted" | "untrusted" | "unknown";
      factAuthority: Exclude<DisplayFactAuthority, "none">;
    })
  | (ProvenanceNodeBasePresentation & { nodeKind: "action"; actionId: string })
  | (ProvenanceNodeBasePresentation & { nodeKind: "other" });

export interface ProvenanceEdgePresentation {
  edgeId: string;
  sourceNodeId: string;
  targetNodeId: string;
  wireRelation: string;
  ctFlowRelation: CtFlowRelation | null;
  legacyRelationType: string | null;
  certainty: EvidenceCertainty;
  flowStrength: "exact" | "strong" | "possible" | "unknown";
  flowOrigin: "observed" | "deterministic" | "semantic_inferred" | "unknown";
  coverage: "complete" | "partial" | "stale" | "unknown" | "not_applicable";
  sourceRefs: EvidenceLocator[];
}

export interface SupervisionWarning {
  code:
    | "identity_conflict"
    | "correlation_conflict"
    | "window_truncated"
    | "unsupported_contract"
    | "projection_failed"
    | "mixed_source_mode";
  severity: "info" | "warning" | "error";
  message: string;
  sourceRefs: EvidenceLocator[];
}

export interface ProvenancePresentationViewModel {
  contractKind: "legacy" | "ct-provenance/1.0" | "mixed";
  nodes: ProvenanceNodePresentation[];
  edges: ProvenanceEdgePresentation[];
  warnings: SupervisionWarning[];
}

export interface TraceLifecycleSupervisionDetails {
  confirmedTerminal: boolean;
  completionReason: string | null;
}

export interface ApprovalRequestFacts {
  subjectId: string;
  subjectType: string;
  actionName: string;
  resourceSummary: string;
  runtime: string;
  agentId: string;
  createdAt: string;
  expiresAt: string;
}

export interface ApprovalContextBasis {
  eventId: string | null;
  eventType: string | null;
  taskPreview: string | null;
  semanticJudgmentAvailability: Availability;
  semanticJudgment: "aligned" | "misaligned" | "uncertain" | null;
  semanticJudgmentProducer: string | null;
  rawSourceTypes: string[];
  normalizedCtSourceTypes: string[];
  sourceTrust: Array<"trusted" | "untrusted" | "unknown">;
  taints: string[];
  resourceTargets: string[];
  factRefs: EvidenceLocator[];
}

export interface ApprovalResolutionBasis {
  status: "pending" | "allowed" | "denied" | "expired" | "unknown";
  decision: "allow_once" | "deny" | null;
  resolutionSource: "human" | "llm" | "system" | null;
  resolvedBy: string | null;
  resolutionReason: string | null;
  resolvedAt: string | null;
}

export interface ApprovalBasisViewModel {
  schemaVersion: "approval-basis/0.1";
  approvalId: string;
  traceId: string;
  actionId: string;
  request: ApprovalRequestFacts;
  officialDecision: OfficialDecisionPresentation;
  v21Assessment: V21AssessmentPresentation;
  sourceContext: ApprovalContextBasis;
  resolution: ApprovalResolutionBasis;
  enforcement: EnforcementPresentation;
  evidenceRefs: EvidenceLocator[];
  completeness: Availability;
  missingReasons: string[];
}

export interface SupervisionCompleteness {
  auditEvents: Availability;
  approvals: Availability;
  provenance: Availability;
  contextManifest: Availability;
  runtimeReceipts: Availability;
  truncatedReasons: string[];
}

export interface SupervisionCapabilities {
  facts: Availability;
  contextManifest: Availability;
  approvalBasis: Availability;
  enforcementEvidence: Availability;
  runtimeReceipts: Availability;
  traceCompare: Availability;
}

/**
 * Lightweight S0 wrapper around the one authoritative execution projection.
 * Empty maps are explicit capability placeholders, not alternate fact stores.
 */
export interface RuntimeSupervisionViewModel {
  schemaVersion: "runtime-supervision/0.1";
  traceId: string;
  dataSource: DashboardDataSourceDescriptor;
  temporalState: TemporalState;
  runtime: string | null;
  agentId: string | null;
  execution: ExecutionTraceViewModel;
  approvalBasisById: Record<string, ApprovalBasisViewModel>;
  contextManifestByEventId: Record<string, never>;
  provenancePresentation: ProvenancePresentationViewModel;
  completeness: SupervisionCompleteness;
  capabilities: SupervisionCapabilities;
  warnings: SupervisionWarning[];
}
