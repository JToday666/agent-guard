import type { ApprovalRequest, ExecutionStepViewModel } from "../../types/dashboard.ts";
import type { ApprovalBasisViewModel, EvidenceLocator } from "../../types/runtime-supervision.ts";

export interface ApprovalBasisProjectionInput {
  traceId: string;
  approval: ApprovalRequest;
  windowTruncationReasons?: readonly string[];
  /**
   * The step already selected by buildExecutionTrace(). The projector must not
   * rescan raw audit events or choose a second policy decision.
   */
  step: ExecutionStepViewModel;
}

function locator(
  kind: EvidenceLocator["kind"],
  id: string | null | undefined,
  traceId: string,
): EvidenceLocator[] {
  return id ? [{ kind, id, traceId }] : [];
}

function uniqueLocators(locators: readonly EvidenceLocator[]): EvidenceLocator[] {
  const seen = new Set<string>();
  return locators.filter((item) => {
    const key = `${item.kind}\u0000${item.id}\u0000${item.traceId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function trustLabel(value: string | null | undefined): "trusted" | "untrusted" | "unknown" {
  const normalized = value?.toLocaleLowerCase() ?? "";
  if (normalized.includes("untrusted")) return "untrusted";
  if (normalized.includes("trusted")) return "trusted";
  return "unknown";
}

function present(value: string | null | undefined): boolean {
  return typeof value === "string" && value.length > 0;
}

function recordedText(value: string | null | undefined): boolean {
  return present(value) && value !== "未提供";
}

function validPolicyDigest(value: string | null | undefined): boolean {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}

function validTimestamp(value: string | null | undefined): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function approvalLifecycleValid(approval: ApprovalRequest): boolean {
  if (!validTimestamp(approval.createdAt) || !validTimestamp(approval.expiresAt)) return false;
  if (Date.parse(approval.expiresAt!) <= Date.parse(approval.createdAt)) return false;
  if (approval.status === "pending") {
    return (
      approval.decision === null &&
      approval.resolvedAt == null &&
      approval.resolutionSource === null &&
      approval.resolvedBy === null &&
      approval.resolutionReason === null
    );
  }
  if (approval.status === "allowed") {
    return approval.decision === "allow_once" && validTimestamp(approval.resolvedAt);
  }
  if (approval.status === "denied") {
    return approval.decision === "deny" && validTimestamp(approval.resolvedAt);
  }
  if (approval.status === "expired") {
    return (
      approval.decision !== "allow_once" &&
      approval.resolvedAt == null &&
      approval.resolutionSource === null &&
      approval.resolvedBy === null &&
      approval.resolutionReason === null
    );
  }
  return false;
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  const normalizedLeft = [...new Set(left)].sort();
  const normalizedRight = [...new Set(right)].sort();
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

function approvalMissingReasons(input: ApprovalBasisProjectionInput): string[] {
  const { approval, step, traceId } = input;
  const official = step.supervision.officialDecision;
  const presentation = step.supervision.approval;
  const evidence = approval.evidence;
  const reasons: string[] = [];

  if (!evidence) reasons.push("APPROVAL_EVIDENCE_UNAVAILABLE");
  if (approval.traceId !== traceId) reasons.push("APPROVAL_TRACE_ID_MISMATCH");
  if (!step.actionId || approval.actionId !== step.actionId) {
    reasons.push("APPROVAL_ACTION_ID_MISMATCH");
  }
  if (step.approvalId !== approval.id || presentation.approvalId !== approval.id) {
    reasons.push("APPROVAL_ID_MISMATCH");
  }
  const expectedPresentationDecision =
    approval.status === "allowed" ? "allow_once" : approval.status === "denied" ? "deny" : null;
  if (
    presentation.availability !== "recorded" ||
    presentation.status !== approval.status ||
    presentation.decision !== expectedPresentationDecision ||
    presentation.createdAt !== approval.createdAt ||
    presentation.expiresAt !== (approval.expiresAt ?? null) ||
    presentation.resolvedAt !== (approval.resolvedAt ?? null)
  ) {
    reasons.push("APPROVAL_RESOLUTION_MISMATCH");
  }
  if (!present(approval.eventId) || !step.eventIds.includes(approval.eventId!)) {
    reasons.push("APPROVAL_EVENT_ID_MISMATCH");
  }
  if (
    !evidence ||
    !present(evidence.eventId) ||
    evidence.eventId !== approval.eventId ||
    !step.eventIds.includes(evidence.eventId ?? "")
  ) {
    reasons.push("APPROVAL_EVIDENCE_EVENT_ID_MISMATCH");
  }
  if (
    !evidence ||
    !present(evidence.eventTraceId) ||
    evidence.eventTraceId !== approval.traceId ||
    evidence.eventTraceId !== traceId
  ) {
    reasons.push("APPROVAL_EVIDENCE_TRACE_ID_MISMATCH");
  }
  if (
    !present(approval.decisionId) ||
    approval.decisionId !== step.decisionId ||
    approval.decisionId !== official.decisionId
  ) {
    reasons.push("APPROVAL_DECISION_ID_MISMATCH");
  }
  if (
    !evidence ||
    !present(evidence.decisionId) ||
    evidence.decisionId !== approval.decisionId ||
    evidence.decisionId !== step.decisionId ||
    evidence.decisionId !== official.decisionId
  ) {
    reasons.push("APPROVAL_EVIDENCE_DECISION_ID_MISMATCH");
  }
  if (
    !present(approval.policyAuditId) ||
    approval.policyAuditId !== step.primaryAuditId ||
    approval.policyAuditId !== official.policyAuditId
  ) {
    reasons.push("APPROVAL_POLICY_AUDIT_ID_MISMATCH");
  }
  if (official.availability !== "recorded" || official.decision !== "ask") {
    reasons.push("OFFICIAL_ASK_UNAVAILABLE");
  }
  if (evidence && evidence.decision !== "ask") {
    reasons.push("APPROVAL_EVIDENCE_DECISION_MISMATCH");
  }
  if (
    evidence &&
    (evidence.riskScore === null ||
      official.riskScore === null ||
      evidence.riskScore !== official.riskScore ||
      evidence.riskScore !== approval.riskScore ||
      evidence.severity === "unknown" ||
      evidence.severity !== official.severity ||
      evidence.severity !== approval.severity ||
      !sameStringSet(evidence.ruleHits, official.ruleIds) ||
      !sameStringSet(evidence.ruleHits, approval.ruleHits))
  ) {
    reasons.push("APPROVAL_EVIDENCE_DECISION_FACTS_MISMATCH");
  }
  if (evidence && (evidence.runtime === "unknown" || evidence.runtime !== approval.runtime)) {
    reasons.push("APPROVAL_EVIDENCE_RUNTIME_MISMATCH");
  }
  if (
    evidence &&
    (!present(evidence.policy.bundleId) ||
      !present(evidence.policy.version) ||
      !validPolicyDigest(evidence.policy.digest))
  ) {
    reasons.push("OFFICIAL_POLICY_REFERENCE_INCOMPLETE");
  }
  if (approval.status === "unknown") reasons.push("APPROVAL_STATUS_UNKNOWN");
  if (!approvalLifecycleValid(approval)) reasons.push("APPROVAL_LIFECYCLE_INVALID");
  if (
    !recordedText(approval.subjectId) ||
    !recordedText(approval.subjectType) ||
    !recordedText(approval.actionName) ||
    !recordedText(approval.resource) ||
    !recordedText(approval.requestingPrincipalId) ||
    approval.runtime === "unknown" ||
    !recordedText(approval.agentId) ||
    !recordedText(approval.createdAt) ||
    !recordedText(approval.expiresAt)
  ) {
    reasons.push("APPROVAL_REQUEST_FACTS_INCOMPLETE");
  }
  reasons.push(...(input.windowTruncationReasons ?? []));

  return [...new Set(reasons)].sort();
}

const UNAVAILABLE_REASONS = new Set([
  "APPROVAL_ACTION_ID_MISMATCH",
  "APPROVAL_DECISION_ID_MISMATCH",
  "APPROVAL_EVIDENCE_DECISION_MISMATCH",
  "APPROVAL_EVIDENCE_DECISION_ID_MISMATCH",
  "APPROVAL_EVIDENCE_DECISION_FACTS_MISMATCH",
  "APPROVAL_EVIDENCE_EVENT_ID_MISMATCH",
  "APPROVAL_EVIDENCE_RUNTIME_MISMATCH",
  "APPROVAL_EVIDENCE_TRACE_ID_MISMATCH",
  "APPROVAL_EVIDENCE_UNAVAILABLE",
  "APPROVAL_EVENT_ID_MISMATCH",
  "APPROVAL_ID_MISMATCH",
  "APPROVAL_LIFECYCLE_INVALID",
  "APPROVAL_POLICY_AUDIT_ID_MISMATCH",
  "APPROVAL_RESOLUTION_MISMATCH",
  "APPROVAL_STATUS_UNKNOWN",
  "APPROVAL_TRACE_ID_MISMATCH",
  "OFFICIAL_ASK_UNAVAILABLE",
  "OFFICIAL_POLICY_REFERENCE_INCOMPLETE",
]);

function basisCompleteness(
  missingReasons: readonly string[],
): ApprovalBasisViewModel["completeness"] {
  if (missingReasons.some((reason) => UNAVAILABLE_REASONS.has(reason))) return "unavailable";
  return missingReasons.length ? "partial" : "recorded";
}

export function projectApprovalBasis(input: ApprovalBasisProjectionInput): ApprovalBasisViewModel {
  const { approval, step, traceId } = input;
  const evidence = approval.evidence;
  const missingReasons = approvalMissingReasons(input);
  const evidenceRefs = uniqueLocators([
    ...locator("approval", approval.id, traceId),
    ...locator("action", step.actionId, traceId),
    ...locator("event", approval.eventId, traceId),
    ...locator("decision", step.supervision.officialDecision.decisionId, traceId),
    ...locator("audit", step.primaryAuditId, traceId),
    ...step.supervision.officialDecision.sourceRefs,
    ...step.supervision.approval.sourceRefs,
  ]);
  const sourceType = evidence?.sourceType ?? null;
  const sourceTrust = evidence?.sourceTrust ?? null;
  const taskPreview =
    evidence?.taskPreview ??
    (approval.userTask && approval.userTask !== "未提供" ? approval.userTask : null);

  return {
    schemaVersion: "approval-basis/0.1",
    approvalId: approval.id,
    traceId,
    actionId: step.actionId ?? approval.actionId,
    request: {
      subjectId: approval.subjectId,
      subjectType: approval.subjectType,
      actionName: approval.actionName,
      resourceSummary: approval.resource,
      runtime: approval.runtime,
      agentId: approval.agentId ?? "",
      createdAt: approval.createdAt,
      expiresAt: approval.expiresAt ?? "",
    },
    officialDecision: step.supervision.officialDecision,
    v21Assessment: step.supervision.v21Assessment,
    sourceContext: {
      eventId: approval.eventId,
      eventType: evidence?.eventType ?? null,
      taskPreview,
      semanticJudgmentAvailability: "unavailable",
      semanticJudgment: null,
      semanticJudgmentProducer: null,
      rawSourceTypes: sourceType ? [sourceType] : [],
      normalizedCtSourceTypes: [],
      sourceTrust: sourceTrust ? [trustLabel(sourceTrust)] : [],
      taints: [],
      resourceTargets: evidence?.resourceTargets ?? [],
      factRefs: [],
    },
    resolution: {
      status: approval.status,
      decision: approval.decision,
      resolutionSource: approval.resolutionSource,
      resolvedBy: approval.resolvedBy,
      resolutionReason: approval.resolutionReason,
      resolvedAt: approval.resolvedAt ?? null,
    },
    enforcement: step.supervision.enforcement,
    evidenceRefs,
    completeness: basisCompleteness(missingReasons),
    missingReasons,
  };
}
