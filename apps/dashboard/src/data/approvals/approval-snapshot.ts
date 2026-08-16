import type { ApprovalRequest } from "../../types/dashboard.ts";

function hasSameStringList(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hasSameEvidence(
  left: ApprovalRequest["evidence"],
  right: ApprovalRequest["evidence"],
): boolean {
  if (!left || !right) return left === right;
  return (
    left.eventId === right.eventId &&
    left.eventTraceId === right.eventTraceId &&
    left.eventType === right.eventType &&
    left.runtime === right.runtime &&
    left.taskPreview === right.taskPreview &&
    left.sourceType === right.sourceType &&
    left.sourceTrust === right.sourceTrust &&
    hasSameStringList(left.resourceTargets, right.resourceTargets) &&
    left.decisionId === right.decisionId &&
    left.decision === right.decision &&
    left.riskScore === right.riskScore &&
    left.severity === right.severity &&
    left.reason === right.reason &&
    hasSameStringList(left.ruleHits, right.ruleHits) &&
    left.policy.bundleId === right.policy.bundleId &&
    left.policy.version === right.policy.version &&
    left.policy.revision === right.policy.revision &&
    left.policy.digest === right.policy.digest
  );
}

/**
 * Compares every display-safe Approval field that can participate in the
 * mutation snapshot. Unknown/raw payload properties are intentionally absent.
 */
export function hasSameApprovalSnapshot(left: ApprovalRequest, right: ApprovalRequest): boolean {
  return (
    left.id === right.id &&
    left.createdAt === right.createdAt &&
    left.status === right.status &&
    left.resource === right.resource &&
    left.riskScore === right.riskScore &&
    left.severity === right.severity &&
    left.reason === right.reason &&
    left.traceId === right.traceId &&
    left.eventId === right.eventId &&
    left.policyAuditId === right.policyAuditId &&
    left.decisionId === right.decisionId &&
    left.subjectId === right.subjectId &&
    left.subjectType === right.subjectType &&
    left.actionId === right.actionId &&
    left.actionName === right.actionName &&
    left.requestingPrincipalId === right.requestingPrincipalId &&
    left.runtime === right.runtime &&
    left.agentId === right.agentId &&
    hasSameStringList(left.decisionOptions, right.decisionOptions) &&
    left.decision === right.decision &&
    left.userTask === right.userTask &&
    left.agentAction === right.agentAction &&
    left.consequence === right.consequence &&
    hasSameStringList(left.ruleHits, right.ruleHits) &&
    hasSameEvidence(left.evidence, right.evidence) &&
    (left.expiresAt ?? null) === (right.expiresAt ?? null) &&
    (left.resolvedAt ?? null) === (right.resolvedAt ?? null) &&
    left.resolutionSource === right.resolutionSource &&
    left.resolvedBy === right.resolvedBy &&
    left.resolutionReason === right.resolutionReason
  );
}

/**
 * The pending endpoint does not carry the derived policy Audit locator. A
 * trace-scoped read may fill that one field, but it may never contradict an
 * already-recorded pending value or change any native Approval/evidence fact.
 */
export function isCompatiblePendingApprovalSnapshot(
  pending: ApprovalRequest,
  traceScoped: ApprovalRequest,
): boolean {
  if (pending.policyAuditId && pending.policyAuditId !== traceScoped.policyAuditId) return false;
  return (
    pending.id === traceScoped.id &&
    pending.createdAt === traceScoped.createdAt &&
    pending.status === traceScoped.status &&
    pending.resource === traceScoped.resource &&
    pending.riskScore === traceScoped.riskScore &&
    pending.severity === traceScoped.severity &&
    pending.reason === traceScoped.reason &&
    pending.traceId === traceScoped.traceId &&
    pending.eventId === traceScoped.eventId &&
    pending.decisionId === traceScoped.decisionId &&
    pending.subjectId === traceScoped.subjectId &&
    pending.subjectType === traceScoped.subjectType &&
    pending.actionId === traceScoped.actionId &&
    pending.actionName === traceScoped.actionName &&
    pending.requestingPrincipalId === traceScoped.requestingPrincipalId &&
    pending.runtime === traceScoped.runtime &&
    pending.agentId === traceScoped.agentId &&
    hasSameStringList(pending.decisionOptions, traceScoped.decisionOptions) &&
    pending.decision === traceScoped.decision &&
    hasSameEvidence(pending.evidence, traceScoped.evidence) &&
    (pending.expiresAt ?? null) === (traceScoped.expiresAt ?? null) &&
    (pending.resolvedAt ?? null) === (traceScoped.resolvedAt ?? null) &&
    pending.resolutionSource === traceScoped.resolutionSource &&
    pending.resolvedBy === traceScoped.resolvedBy &&
    pending.resolutionReason === traceScoped.resolutionReason
  );
}
