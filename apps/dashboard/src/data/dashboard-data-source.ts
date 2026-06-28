import type {
  ApprovalRequest,
  ApprovalResolution,
  AuditEventRow,
  AuditIntegrity,
  EvalMetrics,
  EvaluationSummary,
  HealthStatus,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
} from "../types/dashboard";

export interface EventFilters {
  traceId?: string;
  caseId?: string;
  runtime?: string;
  decision?: string;
}

export interface DashboardDataSource {
  getEvents(
    filters?: EventFilters,
    signal?: AbortSignal,
  ): Promise<AuditEventRow[]>;
  getMetrics(
    filters?: EventFilters,
    signal?: AbortSignal,
  ): Promise<EvalMetrics>;
  getPendingApprovals(signal?: AbortSignal): Promise<ApprovalRequest[]>;
  resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
    csrfToken: string,
  ): Promise<ApprovalResolution>;
  getHealth(signal?: AbortSignal): Promise<HealthStatus>;
  getEvaluation(metrics: EvalMetrics): Promise<EvaluationSummary>;
  getTraceDetail(traceId: string, signal?: AbortSignal): Promise<TraceDetail>;
  getCurrentPolicy(signal?: AbortSignal): Promise<PolicySummary>;
  getPolicyHistory(signal?: AbortSignal): Promise<PolicyHistoryEntry[]>;
  getAuditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity>;
  getTraceProvenance(
    traceId: string,
    signal?: AbortSignal,
  ): Promise<ProvenanceGraph>;
}
