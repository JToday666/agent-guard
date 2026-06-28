import type { RouteLocationRaw } from "vue-router";

import type { ApprovalRequest } from "../types/dashboard";

export interface ApprovalEvidenceRoutes {
  event: RouteLocationRaw | null;
  trace: RouteLocationRaw;
}

export function getApprovalEvidenceRoutes(
  approval: ApprovalRequest,
): ApprovalEvidenceRoutes {
  const path = `/evidence/${encodeURIComponent(approval.traceId)}`;
  return {
    event: approval.eventId
      ? { path, query: { event_id: approval.eventId } }
      : null,
    trace: { path },
  };
}
