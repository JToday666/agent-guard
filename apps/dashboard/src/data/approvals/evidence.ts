import type { ApprovalRequest, AuditEventRow } from "../../types/dashboard";

export interface ApprovalEvidenceFields {
  eventId: string;
  traceId: string;
  subject: string;
  action: string;
}

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

function joinEvidenceParts(parts: Array<string | undefined>): string {
  const present = parts.filter((part): part is string => Boolean(part));
  return present.length ? present.join(" / ") : "未提供";
}

export function formatApprovalEvidenceFields(approval: ApprovalRequest): ApprovalEvidenceFields {
  return {
    eventId: approval.eventId || "未提供",
    traceId: approval.traceId || "未提供",
    subject: joinEvidenceParts([approval.subjectType, approval.subjectId]),
    action: joinEvidenceParts([approval.actionName, approval.actionId]),
  };
}
