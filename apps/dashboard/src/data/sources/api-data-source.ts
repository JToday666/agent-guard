import type {
  GuardAdapterStatusDto,
  GuardApprovalDto,
  GuardApprovalResolutionDto,
  GuardAuditEventDto,
  GuardAuditIntegrityDto,
  GuardConfigAuditFindingRecordDto,
  GuardEvalMetricsDto,
  GuardEvaluationRunDto,
  GuardPolicyBundleDto,
  GuardPolicyHistoryDto,
  GuardProvenanceDto,
  GuardTraceDetailDto,
} from "../../api/guard-api-types";
import { ApiError, requestHealth, requestJson } from "../../api/guard-http-client";
import {
  emptyEvaluationSummary,
  mapAdapterStatus,
  mapApproval,
  mapAuditEvent,
  mapAuditIntegrity,
  mapConfigAuditFindingRecord,
  mapEvaluationRun,
  mapMetrics,
  mapPolicyHistory,
  mapPolicySummary,
  mapProvenance,
  mapTraceDetail,
} from "../../api/guard-api-mappers";
import { mergeApprovalsWithAuditEvidence } from "../approvals/evidence";
import type {
  ApprovalRequest,
  ApprovalResolution,
  AuditIntegrity,
  ConfigAuditFindingRecord,
  EvalMetrics,
  EvaluationSummary,
  ProvenanceGraph,
} from "../../types/dashboard";
import type { ConfigAuditFindingFilters, DashboardDataSource, EventFilters } from "./dashboard-data-source";

function buildQueryString(filters: EventFilters = {}, includeLimit = false): string {
  const params = new URLSearchParams();
  if (includeLimit) params.set("limit", "500");
  if (filters.traceId) params.set("trace_id", filters.traceId);
  if (filters.caseId) params.set("case_id", filters.caseId);
  if (filters.runtime) params.set("runtime", filters.runtime);
  if (filters.decision) params.set("decision", filters.decision);
  const query = params.toString();
  return query ? `?${query}` : "";
}

function buildConfigFindingQueryString(filters: ConfigAuditFindingFilters = {}): string {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit ?? 20));
  if (filters.traceId) params.set("trace_id", filters.traceId);
  if (filters.targetId) params.set("target_id", filters.targetId);
  if (filters.targetType) params.set("target_type", filters.targetType);
  if (filters.severity) params.set("severity", filters.severity);
  return `?${params.toString()}`;
}

export class ApiDashboardDataSource implements DashboardDataSource {
  async getEvents(filters?: EventFilters, signal?: AbortSignal) {
    const rows = await requestJson<GuardAuditEventDto[]>(`/audit/events${buildQueryString(filters, true)}`, {}, signal);
    return rows.map(mapAuditEvent);
  }

  async getMetrics(filters?: EventFilters, signal?: AbortSignal) {
    const rows = await requestJson<GuardEvalMetricsDto>(`/metrics/eval${buildQueryString(filters)}`, {}, signal);
    return mapMetrics(rows);
  }

  async getPendingApprovals(signal?: AbortSignal) {
    const rows = await requestJson<GuardApprovalDto[]>("/approvals/pending", {}, signal);
    return rows.map(mapApproval);
  }

  async resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
    csrfToken: string,
  ): Promise<ApprovalResolution> {
    if (!approval.approvalNonce) throw new Error("审批凭证缺失，请刷新审批队列");
    const result = await requestJson<GuardApprovalResolutionDto>(`/approvals/${approval.id}/resolve`, {
      method: "POST",
      headers: { "X-AgentGuard-CSRF": csrfToken },
      body: JSON.stringify({
        decision,
        approval_nonce: approval.approvalNonce,
      }),
    });
    return {
      approvalId: result.approval_id,
      status: result.status,
      decision: result.decision,
    };
  }

  async getHealth(signal?: AbortSignal) {
    const result = await requestHealth(signal);
    return {
      api: result.status === "ok" ? ("online" as const) : ("offline" as const),
      database: result.database === "ok" ? ("online" as const) : ("offline" as const),
      checkedAt: new Date().toISOString(),
    };
  }

  async getEvaluation(metrics: EvalMetrics, signal?: AbortSignal): Promise<EvaluationSummary> {
    try {
      return mapEvaluationRun(await requestJson<GuardEvaluationRunDto>("/evaluations/latest", {}, signal), metrics);
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "EVALUATION_NOT_FOUND") {
        return emptyEvaluationSummary(metrics);
      }
      throw reason;
    }
  }

  async getConfigAuditFindings(
    filters: ConfigAuditFindingFilters = {},
    signal?: AbortSignal,
  ): Promise<ConfigAuditFindingRecord[]> {
    const rows = await requestJson<GuardConfigAuditFindingRecordDto[]>(
      `/config-audit/findings${buildConfigFindingQueryString(filters)}`,
      {},
      signal,
    );
    return rows.map(mapConfigAuditFindingRecord);
  }

  async getAdapterStatus(adapterId: string, signal?: AbortSignal) {
    return mapAdapterStatus(
      await requestJson<GuardAdapterStatusDto>(`/adapters/${encodeURIComponent(adapterId)}/status`, {}, signal),
    );
  }

  async getTraceDetail(traceId: string, signal?: AbortSignal) {
    const detail = mapTraceDetail(
      await requestJson<GuardTraceDetailDto>(`/traces/${encodeURIComponent(traceId)}`, {}, signal),
    );
    return {
      ...detail,
      approvals: mergeApprovalsWithAuditEvidence(detail.approvals, detail.events),
    };
  }

  async getCurrentPolicy(signal?: AbortSignal) {
    return mapPolicySummary(await requestJson<GuardPolicyBundleDto>("/policies/current", {}, signal));
  }

  async getPolicyHistory(signal?: AbortSignal) {
    return mapPolicyHistory(await requestJson<GuardPolicyHistoryDto[]>("/policies/history?limit=10", {}, signal));
  }

  async getAuditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity> {
    return mapAuditIntegrity(await requestJson<GuardAuditIntegrityDto>("/audit/integrity", {}, signal));
  }

  async getTraceProvenance(traceId: string, signal?: AbortSignal): Promise<ProvenanceGraph> {
    return mapProvenance(
      await requestJson<GuardProvenanceDto>(`/traces/${encodeURIComponent(traceId)}/provenance`, {}, signal),
    );
  }
}
