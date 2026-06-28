import type {
  ApprovalRequest,
  AuditEventRow,
  EvalMetrics,
  EvaluationSummary,
} from "../types/dashboard.ts";

function hasSameStringList(left: readonly string[], right: readonly string[]) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function hasSameEvent(left: AuditEventRow, right: AuditEventRow): boolean {
  return (
    left.id === right.id &&
    left.occurredAt === right.occurredAt &&
    left.time === right.time &&
    left.decision === right.decision &&
    left.riskScore === right.riskScore &&
    left.severity === right.severity &&
    left.blocked === right.blocked &&
    left.runtime === right.runtime &&
    left.stage === right.stage &&
    left.tool === right.tool &&
    left.resource === right.resource &&
    hasSameStringList(left.resourceTargets, right.resourceTargets) &&
    left.reason === right.reason &&
    left.traceId === right.traceId &&
    left.caseId === right.caseId &&
    left.approvalId === right.approvalId &&
    left.userTask === right.userTask &&
    left.agentAction === right.agentAction &&
    left.attackType === right.attackType &&
    left.latencyMs === right.latencyMs &&
    hasSameStringList(left.ruleHits, right.ruleHits)
  );
}

export function hasSameEventWindow(
  left: readonly AuditEventRow[],
  right: readonly AuditEventRow[],
): boolean {
  return (
    left.length === right.length &&
    left.every((event, index) => hasSameEvent(event, right[index]!))
  );
}

export function hasSameMetrics(left: EvalMetrics, right: EvalMetrics): boolean {
  return (
    left.eventCount === right.eventCount &&
    left.allowCount === right.allowCount &&
    left.denyCount === right.denyCount &&
    left.askCount === right.askCount &&
    left.blockedCount === right.blockedCount &&
    left.blockRate === right.blockRate &&
    left.fpr === right.fpr &&
    left.fnr === right.fnr &&
    left.averageLatencyMs === right.averageLatencyMs
  );
}

export function hasSameEvaluation(
  left: EvaluationSummary,
  right: EvaluationSummary,
): boolean {
  return (
    left.asrBefore === right.asrBefore &&
    left.asrAfter === right.asrAfter &&
    left.blockRate === right.blockRate &&
    left.fpr === right.fpr &&
    left.fnr === right.fnr &&
    left.averageLatencyMs === right.averageLatencyMs
  );
}

function hasSameApproval(
  left: ApprovalRequest,
  right: ApprovalRequest,
): boolean {
  return (
    left.id === right.id &&
    left.createdAt === right.createdAt &&
    left.status === right.status &&
    left.tool === right.tool &&
    left.resource === right.resource &&
    left.riskScore === right.riskScore &&
    left.severity === right.severity &&
    left.reason === right.reason &&
    left.eventId === right.eventId &&
    left.traceId === right.traceId &&
    left.subjectId === right.subjectId &&
    left.subjectType === right.subjectType &&
    left.actionId === right.actionId &&
    left.actionName === right.actionName &&
    left.userTask === right.userTask &&
    left.agentAction === right.agentAction &&
    left.consequence === right.consequence &&
    left.expiresAt === right.expiresAt &&
    left.resolvedAt === right.resolvedAt &&
    hasSameStringList(left.ruleHits, right.ruleHits)
  );
}

export function reconcileApprovals(
  current: ApprovalRequest[],
  incoming: ApprovalRequest[],
): ApprovalRequest[] {
  const hasSameVisibleData =
    current.length === incoming.length &&
    current.every((approval, index) =>
      hasSameApproval(approval, incoming[index]!),
    );
  if (!hasSameVisibleData) return incoming;

  current.forEach((approval, index) => {
    approval.approvalNonce = incoming[index]!.approvalNonce;
  });
  return current;
}
