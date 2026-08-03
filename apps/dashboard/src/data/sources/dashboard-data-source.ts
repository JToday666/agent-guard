import type {
  AdapterStatus,
  AggregateMetrics,
  ApprovalRequest,
  ApprovalResolution,
  AuditWindow,
  AuditIntegrity,
  ConfigAuditFindingRecord,
  EvaluationRun,
  HealthStatus,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
} from "../../types/dashboard";

export const AUDIT_EVENT_WINDOW_LIMIT = 500;

export interface EventFilters {
  traceId?: string;
  caseId?: string;
  runtime?: string;
  decision?: string;
}

export interface ConfigAuditFindingFilters {
  traceId?: string;
  targetId?: string;
  targetType?: string;
  severity?: string;
  limit?: number;
}

export interface DashboardDataSource {
  getAuditWindow(filters?: EventFilters, signal?: AbortSignal): Promise<AuditWindow>;
  getAggregateMetrics(filters?: EventFilters, signal?: AbortSignal): Promise<AggregateMetrics>;
  getPendingApprovals(signal?: AbortSignal): Promise<ApprovalRequest[]>;
  resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
    csrfToken: string,
  ): Promise<ApprovalResolution>;
  getHealth(signal?: AbortSignal): Promise<HealthStatus>;
  getLatestEvaluationRun(signal?: AbortSignal): Promise<EvaluationRun>;
  getConfigAuditFindings(
    filters?: ConfigAuditFindingFilters,
    signal?: AbortSignal,
  ): Promise<ConfigAuditFindingRecord[]>;
  getAdapterStatus(adapterId: string, signal?: AbortSignal): Promise<AdapterStatus>;
  getTraceDetail(traceId: string, signal?: AbortSignal): Promise<TraceDetail>;
  getCurrentPolicy(signal?: AbortSignal): Promise<PolicySummary>;
  getPolicyHistory(signal?: AbortSignal): Promise<PolicyHistoryEntry[]>;
  getAuditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity>;
  getTraceProvenance(traceId: string, signal?: AbortSignal): Promise<ProvenanceGraph>;
}
