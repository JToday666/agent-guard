import type {
  ApprovalRequest,
  AuditEventRow,
  AuditWindow,
  EvaluationRun,
  WindowMetrics,
} from "../../types/dashboard";
import { hasSameApprovalSnapshot } from "../approvals/approval-snapshot.ts";

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
    left.metricVersion === right.metricVersion &&
    left.deduplication === right.deduplication &&
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
    left.unkeyedPolicyRecordCount === right.unkeyedPolicyRecordCount
  );
}

export function hasSameAuditWindow(left: AuditWindow, right: AuditWindow): boolean {
  return (
    left.scope.kind === right.scope.kind &&
    left.scope.snapshotId === right.scope.snapshotId &&
    left.scope.outcomesAsOf === right.scope.outcomesAsOf &&
    left.scope.order === right.scope.order &&
    left.scope.limit === right.scope.limit &&
    left.scope.returnedRecordCount === right.scope.returnedRecordCount &&
    left.scope.hasMore === right.scope.hasMore &&
    left.scope.nextCursor === right.scope.nextCursor &&
    left.scope.sequenceFrom === right.scope.sequenceFrom &&
    left.scope.sequenceTo === right.scope.sequenceTo &&
    left.scope.occurredFrom === right.scope.occurredFrom &&
    left.scope.occurredTo === right.scope.occurredTo &&
    left.scope.filters.traceId === right.scope.filters.traceId &&
    left.scope.filters.caseId === right.scope.filters.caseId &&
    left.scope.filters.runtime === right.scope.filters.runtime &&
    left.scope.filters.decision === right.scope.filters.decision &&
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
    JSON.stringify(left.preEnableReport) === JSON.stringify(right.preEnableReport) &&
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

export function reconcileApprovals(
  current: ApprovalRequest[],
  incoming: ApprovalRequest[],
): ApprovalRequest[] {
  const hasSameVisibleData =
    current.length === incoming.length &&
    current.every((approval, index) => hasSameApprovalSnapshot(approval, incoming[index]!));
  if (!hasSameVisibleData) return incoming;
  return current;
}
