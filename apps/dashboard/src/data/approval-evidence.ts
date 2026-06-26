import type { ApprovalRequest, AuditEventRow } from "../types/dashboard.ts";

export function mergeApprovalsWithAuditEvidence(
  approvals: ApprovalRequest[],
  events: AuditEventRow[],
): ApprovalRequest[] {
  const eventByApproval = new Map<string, AuditEventRow>();
  for (const event of events) {
    if (event.approvalId) eventByApproval.set(event.approvalId, event);
  }

  return approvals.map((approval) => {
    const event = eventByApproval.get(approval.id);
    if (!event) return approval;
    return {
      ...approval,
      eventId: event.id,
      userTask: event.userTask ?? approval.userTask,
      agentAction: event.agentAction ?? approval.agentAction,
      ruleHits: event.ruleHits.length ? event.ruleHits : approval.ruleHits,
    };
  });
}
