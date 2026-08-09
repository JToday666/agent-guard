import type {
  ApprovalRequest,
  AuditEventRow,
  AuditWindow,
  EvaluationRun,
  WindowMetrics,
} from "../../types/dashboard";

function hasSameStringList(left: readonly string[], right: readonly string[]) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hasSameEvent(left: AuditEventRow, right: AuditEventRow): boolean {
  return (
    left.id === right.id &&
    left.auditSequence === right.auditSequence &&
    left.eventId === right.eventId &&
    left.decisionId === right.decisionId &&
    left.actionId === right.actionId &&
    left.recordType === right.recordType &&
    left.occurredAt === right.occurredAt &&
    left.time === right.time &&
    left.decision === right.decision &&
    left.riskScore === right.riskScore &&
    left.severity === right.severity &&
    left.blocked === right.blocked &&
    left.runtime === right.runtime &&
    left.stage === right.stage &&
    left.eventType === right.eventType &&
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
    left.isMalicious === right.isMalicious &&
    left.latencyMs === right.latencyMs &&
    hasSameStringList(left.ruleHits, right.ruleHits)
  );
}

export function hasSameEventWindow(
  left: readonly AuditEventRow[],
  right: readonly AuditEventRow[],
): boolean {
  return (
    left.length === right.length && left.every((event, index) => hasSameEvent(event, right[index]!))
  );
}

function hasSameWindowMetrics(left: WindowMetrics, right: WindowMetrics): boolean {
  return (
    left.evaluationCount === right.evaluationCount &&
    left.unknownDecisionCount === right.unknownDecisionCount &&
    left.allowCount === right.allowCount &&
    left.denyCount === right.denyCount &&
    left.askCount === right.askCount &&
    left.interventionCount === right.interventionCount &&
    left.interventionRate === right.interventionRate &&
    left.policyDenyRate === right.policyDenyRate &&
    left.approvalTriggerRate === right.approvalTriggerRate &&
    left.policyFpr === right.policyFpr &&
    left.policyFnr === right.policyFnr &&
    left.benignLabelCount === right.benignLabelCount &&
    left.maliciousLabelCount === right.maliciousLabelCount &&
    left.unlabeledCount === right.unlabeledCount &&
    left.averageDecisionLatencyMs === right.averageDecisionLatencyMs &&
    left.latencySampleCount === right.latencySampleCount &&
    left.duplicatePolicyRecordCount === right.duplicatePolicyRecordCount &&
    left.legacyFallbackCount === right.legacyFallbackCount
  );
}

export function hasSameAuditWindow(left: AuditWindow, right: AuditWindow): boolean {
  return (
    left.scope.kind === right.scope.kind &&
    left.scope.source === right.scope.source &&
    left.scope.limit === right.scope.limit &&
    left.scope.returnedRecordCount === right.scope.returnedRecordCount &&
    left.scope.hasMore === right.scope.hasMore &&
    left.scope.from === right.scope.from &&
    left.scope.to === right.scope.to &&
    left.scope.deduplication === right.scope.deduplication &&
    hasSameEventWindow(left.events, right.events) &&
    hasSameWindowMetrics(left.metrics, right.metrics)
  );
}

export function hasSameEvaluationRun(left: EvaluationRun, right: EvaluationRun): boolean {
  return (
    left.runId === right.runId &&
    left.runAt === right.runAt &&
    left.datasetId === right.datasetId &&
    left.datasetVersion === right.datasetVersion &&
    left.datasetLabel === right.datasetLabel &&
    left.asrBefore === right.asrBefore &&
    left.asrAfter === right.asrAfter &&
    left.perAttack.length === right.perAttack.length &&
    left.perAttack.every((row, index) => {
      const other = right.perAttack[index];
      return (
        other !== undefined &&
        row.attackType === other.attackType &&
        row.asrBefore === other.asrBefore &&
        row.asrAfter === other.asrAfter
      );
    }) &&
    left.cases.length === right.cases.length &&
    left.cases.every((row, index) => {
      const other = right.cases[index];
      return (
        other !== undefined &&
        row.caseId === other.caseId &&
        row.attackType === other.attackType &&
        row.runtime === other.runtime &&
        row.expectedDecision === other.expectedDecision &&
        row.actualDecision === other.actualDecision &&
        row.blocked === other.blocked &&
        row.attackSuccess === other.attackSuccess &&
        row.traceId === other.traceId
      );
    })
  );
}

function hasSameApproval(left: ApprovalRequest, right: ApprovalRequest): boolean {
  return (
    left.id === right.id &&
    left.createdAt === right.createdAt &&
    left.status === right.status &&
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
    current.every((approval, index) => hasSameApproval(approval, incoming[index]!));
  if (!hasSameVisibleData) return incoming;
  return current;
}
