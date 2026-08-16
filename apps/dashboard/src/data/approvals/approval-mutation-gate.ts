import {
  isFactoryOwnedDashboardDataSourceDescriptor,
  type DashboardDataSourceDescriptor,
} from "../sources/dashboard-data-source.ts";

export type ApprovalMutationDecision = "allow_once" | "deny";

export type ApprovalMutationSourceMode = "live" | "replay" | "mock";

export interface ApprovalMutationContext {
  targetApprovalId: string;
  approvalId: string;
  basisApprovalId: string;
  temporalState: "following" | "historical";
  readonlyOverride: boolean;
  sessionAuthenticated: boolean;
  csrfReady: boolean;
  approvalStatus: "pending" | "settled" | "unknown";
  approvalUnexpired: boolean;
  basisCompleteness: "recorded" | "partial" | "unavailable" | "not_applicable";
  basisMissingReasons: readonly string[];
  traceId: string;
  approvalTraceId: string;
  actionTraceId: string;
  officialDecisionTraceId: string;
  basisTraceId: string;
  eventId: string;
  basisEventId: string;
  actionId: string;
  basisActionId: string;
  officialDecisionId: string;
  basisDecisionId: string;
  policyAuditId: string;
  basisPolicyAuditId: string;
  officialDecisionValue: "allow" | "ask" | "deny" | "unknown";
  requestedDecision: ApprovalMutationDecision;
  decisionOptions: readonly ApprovalMutationDecision[];
  approvalSource: ApprovalMutationSourceMode;
  actionSource: ApprovalMutationSourceMode;
  officialDecisionSource: ApprovalMutationSourceMode;
  basisSource: ApprovalMutationSourceMode;
}

export type ApprovalMutationSelector = (context: ApprovalMutationContext) => boolean;

function isFactoryOwnedLiveDescriptor(descriptor: DashboardDataSourceDescriptor): boolean {
  try {
    return (
      descriptor.owner === "dashboard_data_source_factory" &&
      isFactoryOwnedDashboardDataSourceDescriptor(descriptor) &&
      descriptor.dataSourceMode === "live_api" &&
      Object.isFrozen(descriptor) &&
      Object.isFrozen(descriptor.capabilities) &&
      descriptor.capabilities.approvalMutation === true &&
      descriptor.capabilities.runtimeSupervisionS1 === true
    );
  } catch {
    return false;
  }
}

function isNonEmptyId(value: string): boolean {
  return value.trim().length > 0;
}

/**
 * Creates the one approval-mutation predicate shared by the store boundary and
 * its read-only UI projection. The descriptor is factory-owned and captured by
 * closure; route state, API payloads, fixtures, and page components cannot
 * replace it or upgrade its capabilities.
 */
export function createApprovalMutationSelector(
  descriptor: DashboardDataSourceDescriptor,
): ApprovalMutationSelector {
  const trustedLiveDescriptor = isFactoryOwnedLiveDescriptor(descriptor);

  return (context) => {
    if (!trustedLiveDescriptor) return false;

    try {
      const ids = [
        context.targetApprovalId,
        context.approvalId,
        context.basisApprovalId,
        context.eventId,
        context.basisEventId,
        context.actionId,
        context.basisActionId,
        context.officialDecisionId,
        context.basisDecisionId,
        context.policyAuditId,
        context.basisPolicyAuditId,
        context.traceId,
        context.approvalTraceId,
        context.actionTraceId,
        context.officialDecisionTraceId,
        context.basisTraceId,
      ];
      const sources = [
        context.approvalSource,
        context.actionSource,
        context.officialDecisionSource,
        context.basisSource,
      ];

      return (
        context.temporalState === "following" &&
        !context.readonlyOverride &&
        context.sessionAuthenticated &&
        context.csrfReady &&
        context.approvalStatus === "pending" &&
        context.approvalUnexpired &&
        context.basisCompleteness === "recorded" &&
        context.basisMissingReasons.length === 0 &&
        context.officialDecisionValue === "ask" &&
        context.decisionOptions.includes(context.requestedDecision) &&
        ids.every(isNonEmptyId) &&
        context.targetApprovalId === context.approvalId &&
        context.approvalId === context.basisApprovalId &&
        context.eventId === context.basisEventId &&
        context.actionId === context.basisActionId &&
        context.officialDecisionId === context.basisDecisionId &&
        context.policyAuditId === context.basisPolicyAuditId &&
        context.approvalTraceId === context.traceId &&
        context.actionTraceId === context.traceId &&
        context.officialDecisionTraceId === context.traceId &&
        context.basisTraceId === context.traceId &&
        sources.every((source) => source === "live")
      );
    } catch {
      return false;
    }
  };
}
