import type {
  GuardAdapterStatusDto,
  GuardApprovalDto,
  GuardApprovalResolutionDto,
  GuardAuditIntegrityDto,
  GuardAuditWindowDto,
  GuardConfigAuditFindingRecordDto,
  GuardEvaluationRunDto,
  GuardPolicyBundleDto,
  GuardPolicyHistoryDto,
  GuardProvenanceDto,
  GuardTraceDetailDto,
} from "../../api/guard-api-types";
import {
  ApiError,
  requestConditionalJson,
  requestHealth,
  requestJson,
} from "../../api/guard-http-client";
import {
  emptyEvaluationRun,
  mapAdapterStatus,
  mapApproval,
  mapAuditIntegrity,
  mapAuditWindow,
  mapConfigAuditFindingRecord,
  mapEvaluationRun,
  mapHealth,
  mapPolicyHistory,
  mapPolicySummary,
  mapProvenance,
  mapTraceDetail,
} from "../../api/guard-api-mappers";
import type {
  ApprovalResolution,
  AuditIntegrity,
  ConfigAuditFindingRecord,
} from "../../types/dashboard";
import type {
  ConditionalRequestOptions,
  ConfigAuditFindingFilters,
  ApprovalMutationDataSource,
  DashboardReadDataSource,
  EventFilters,
} from "./dashboard-data-source";
import { AUDIT_EVENT_WINDOW_LIMIT } from "./dashboard-data-source.ts";

function buildQueryString(filters: EventFilters = {}, includeLimit = false): string {
  const params = new URLSearchParams();
  if (includeLimit) params.set("limit", String(AUDIT_EVENT_WINDOW_LIMIT));
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

export class ApiDashboardDataSource implements DashboardReadDataSource, ApprovalMutationDataSource {
  async getAuditWindow(filters?: EventFilters, signal?: AbortSignal) {
    const response = await requestJson<GuardAuditWindowDto>(
      `/audit/window${buildQueryString(filters, true)}`,
      {},
      signal,
    );
    return mapAuditWindow(response);
  }

  async getPendingApprovals(signal?: AbortSignal) {
    const rows = await requestJson<GuardApprovalDto[]>("/approvals/pending", {}, signal);
    return rows.map(mapApproval);
  }

  async resolveApproval(
    approvalId: string,
    decision: "allow_once" | "deny",
    csrfToken: string,
  ): Promise<ApprovalResolution> {
    const result = await requestJson<GuardApprovalResolutionDto>(
      `/approvals/${encodeURIComponent(approvalId)}/resolve`,
      {
        method: "POST",
        headers: { "X-AgentGuard-CSRF": csrfToken },
        body: JSON.stringify({ decision }),
      },
    );
    return {
      approvalId: result.approval_id,
      status: result.status,
      decision: result.decision,
    };
  }

  async getHealth(signal?: AbortSignal) {
    return mapHealth(await requestHealth(signal));
  }

  async getLatestEvaluationRun(signal?: AbortSignal) {
    try {
      return mapEvaluationRun(
        await requestJson<GuardEvaluationRunDto>("/evaluations/latest", {}, signal),
      );
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "EVALUATION_NOT_FOUND") {
        return emptyEvaluationRun();
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
      await requestJson<GuardAdapterStatusDto>(
        `/adapters/${encodeURIComponent(adapterId)}/status`,
        {},
        signal,
      ),
    );
  }

  async getTraceDetail(traceId: string, options: ConditionalRequestOptions = {}) {
    const response = await requestConditionalJson<GuardTraceDetailDto>(
      `/traces/${encodeURIComponent(traceId)}`,
      options.etag,
      {},
      options.signal,
    );
    if (response.status === "not_modified") return response;
    return {
      status: "modified" as const,
      etag: response.etag,
      value: mapTraceDetail(response.value),
    };
  }

  async getCurrentPolicy(signal?: AbortSignal) {
    return mapPolicySummary(
      await requestJson<GuardPolicyBundleDto>("/policies/current", {}, signal),
    );
  }

  async getPolicyHistory(signal?: AbortSignal) {
    return mapPolicyHistory(
      await requestJson<GuardPolicyHistoryDto[]>("/policies/history?limit=10", {}, signal),
    );
  }

  async getAuditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity> {
    return mapAuditIntegrity(
      await requestJson<GuardAuditIntegrityDto>("/audit/integrity", {}, signal),
    );
  }

  async getTraceProvenance(traceId: string, options: ConditionalRequestOptions = {}) {
    const response = await requestConditionalJson<GuardProvenanceDto>(
      `/traces/${encodeURIComponent(traceId)}/provenance`,
      options.etag,
      {},
      options.signal,
    );
    return response.status === "not_modified"
      ? response
      : {
          status: "modified" as const,
          etag: response.etag,
          value: mapProvenance(response.value),
        };
  }
}
