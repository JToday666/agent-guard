import type {
  ApprovalRequest,
  ApprovalResolution,
  AuditEventRow,
  EvalMetrics,
  EvaluationSummary,
  HealthStatus,
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
}
