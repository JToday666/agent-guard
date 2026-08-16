import type {
  ApprovalRequest,
  ApprovalRequestEvidence,
  AuditEventRow,
  PolicyReferenceEvidence,
} from "../../types/dashboard";

export interface ApprovalEvidenceFields {
  eventId: string;
  policyAuditId: string;
  traceId: string;
  subject: string;
  action: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function policyEvidence(event: AuditEventRow): PolicyReferenceEvidence {
  const evidence = asRecord(asRecord(event.raw).evidence);
  const policy = asRecord(evidence.policy);
  const revision = policy.revision;
  return {
    bundleId: stringValue(policy.bundle_id),
    version: stringValue(policy.version),
    revision: typeof revision === "number" && Number.isInteger(revision) ? revision : null,
    digest: stringValue(policy.canonical_digest) ?? stringValue(policy.digest),
  };
}

function eventIdentity(event: AuditEventRow): string {
  return JSON.stringify({
    actionId: event.actionId,
    approvalId: event.approvalId,
    decision: event.decision,
    decisionId: event.decisionId,
    eventId: event.eventId,
    id: event.id,
    policy: policyEvidence(event),
    recordType: event.recordType,
    riskScore: event.riskScore,
    ruleHits: event.ruleHits,
    severity: event.severity,
    traceId: event.traceId,
  });
}

function policyClaimMatchesAudit(
  claim: PolicyReferenceEvidence,
  audit: PolicyReferenceEvidence,
): boolean {
  return (
    (claim.bundleId === null || claim.bundleId === audit.bundleId) &&
    (claim.version === null || claim.version === audit.version) &&
    (claim.revision === null || claim.revision === audit.revision) &&
    (claim.digest === null || claim.digest === audit.digest)
  );
}

function selectPolicyAudit(
  approval: ApprovalRequest,
  events: readonly AuditEventRow[],
): AuditEventRow | null {
  const linked = events.filter(
    (event) => event.approvalId === approval.id && event.recordType === "policy_evaluation",
  );
  if (!linked.length) return null;
  const byAuditId = new Map<string, AuditEventRow>();
  for (const event of linked) {
    const previous = byAuditId.get(event.id);
    if (previous && eventIdentity(previous) !== eventIdentity(event)) return null;
    byAuditId.set(event.id, event);
  }
  if (byAuditId.size !== 1) return null;
  const event = [...byAuditId.values()][0]!;
  const auditPolicy = policyEvidence(event);
  if (
    event.traceId !== approval.traceId ||
    event.runtime !== approval.runtime ||
    event.actionId !== approval.actionId ||
    event.decision !== "ask" ||
    (approval.eventId !== null && event.eventId !== approval.eventId) ||
    (approval.decisionId !== null && event.decisionId !== approval.decisionId) ||
    (approval.evidence !== null &&
      (approval.evidence.eventId !== approval.eventId ||
        approval.evidence.eventTraceId !== approval.traceId ||
        approval.evidence.decisionId !== approval.decisionId ||
        approval.evidence.runtime !== approval.runtime ||
        (approval.evidence.eventType !== null && approval.evidence.eventType !== event.eventType) ||
        !policyClaimMatchesAudit(approval.evidence.policy, auditPolicy)))
  ) {
    return null;
  }
  return event;
}

function enrichApprovalEvidence(
  evidence: ApprovalRequestEvidence | null,
  event: AuditEventRow,
): ApprovalRequestEvidence | null {
  if (!evidence) return null;
  return {
    ...evidence,
    taskPreview: event.userTask ?? evidence.taskPreview,
    policy: policyEvidence(event),
  };
}

export function mergeApprovalsWithAuditEvidence(
  approvals: ApprovalRequest[],
  events: AuditEventRow[],
): ApprovalRequest[] {
  return approvals.map((approval) => {
    const event = selectPolicyAudit(approval, events);
    if (!event) return approval;
    return {
      ...approval,
      eventId: approval.eventId ?? event.eventId,
      policyAuditId: event.id,
      decisionId: approval.decisionId ?? event.decisionId,
      userTask: event.userTask ?? approval.userTask,
      agentAction: event.agentAction ?? approval.agentAction,
      ruleHits: event.ruleHits.length ? event.ruleHits : approval.ruleHits,
      evidence: enrichApprovalEvidence(approval.evidence, event),
    };
  });
}

function joinEvidenceParts(parts: Array<string | undefined>): string {
  const present = parts.filter((part): part is string => Boolean(part));
  return present.length ? present.join(" / ") : "未提供";
}

export function formatApprovalEvidenceFields(approval: ApprovalRequest): ApprovalEvidenceFields {
  return {
    eventId: approval.eventId ?? "未提供",
    policyAuditId: approval.policyAuditId ?? "未提供",
    traceId: approval.traceId || "未提供",
    subject: joinEvidenceParts([approval.subjectType, approval.subjectId]),
    action: joinEvidenceParts([approval.actionName, approval.actionId]),
  };
}
