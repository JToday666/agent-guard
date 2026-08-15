import type {
  AdapterStatus,
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

export interface ConditionalRequestOptions {
  etag?: string;
  signal?: AbortSignal;
}

export type ConditionalResource<T> =
  | { status: "modified"; value: T; etag: string | null }
  | { status: "not_modified"; etag: string | null };

export type DashboardDataSourceMode = "live_api" | "mock_preview";

export type DashboardBuildProfile = "production" | "development" | "test";

export interface DashboardDataSourceCapabilities {
  readonly approvalMutation: boolean;
  readonly localReplayImport: boolean;
  readonly syntheticFacts: boolean;
}

export interface DashboardDataSourceDescriptor {
  readonly owner: "dashboard_data_source_factory";
  readonly dataSourceMode: DashboardDataSourceMode;
  readonly buildProfile: DashboardBuildProfile;
  readonly capabilities: Readonly<DashboardDataSourceCapabilities>;
}

export interface DashboardReadDataSource {
  getAuditWindow(filters?: EventFilters, signal?: AbortSignal): Promise<AuditWindow>;
  getPendingApprovals(signal?: AbortSignal): Promise<ApprovalRequest[]>;
  getHealth(signal?: AbortSignal): Promise<HealthStatus>;
  getLatestEvaluationRun(signal?: AbortSignal): Promise<EvaluationRun>;
  getConfigAuditFindings(
    filters?: ConfigAuditFindingFilters,
    signal?: AbortSignal,
  ): Promise<ConfigAuditFindingRecord[]>;
  getAdapterStatus(adapterId: string, signal?: AbortSignal): Promise<AdapterStatus>;
  getTraceDetail(
    traceId: string,
    options?: ConditionalRequestOptions,
  ): Promise<ConditionalResource<TraceDetail>>;
  getCurrentPolicy(signal?: AbortSignal): Promise<PolicySummary>;
  getPolicyHistory(signal?: AbortSignal): Promise<PolicyHistoryEntry[]>;
  getAuditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity>;
  getTraceProvenance(
    traceId: string,
    options?: ConditionalRequestOptions,
  ): Promise<ConditionalResource<ProvenanceGraph>>;
}

export interface ApprovalMutationDataSource {
  resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
    csrfToken: string,
  ): Promise<ApprovalResolution>;
}

export interface DashboardDataSourceHandle {
  readonly descriptor: DashboardDataSourceDescriptor;
  readonly reader: DashboardReadDataSource;
  readonly approvalWriter: ApprovalMutationDataSource | null;
}

export interface DashboardDataSourceRuntimeEnvironment {
  readonly isProduction: boolean;
  readonly viteMode: string;
}

export type ApprovalMutationPermission =
  | {
      readonly permitted: true;
      readonly writer: ApprovalMutationDataSource;
    }
  | {
      readonly code: "mutation_not_permitted";
      readonly permitted: false;
    };

export class DashboardMutationNotPermittedError extends Error {
  readonly code = "mutation_not_permitted" as const;

  constructor() {
    super("当前数据源为只读预览，不能处理审批。");
    this.name = "DashboardMutationNotPermittedError";
  }
}

export function createDashboardDataSourceDescriptor(
  environment: DashboardDataSourceRuntimeEnvironment,
): DashboardDataSourceDescriptor {
  const dataSourceMode: DashboardDataSourceMode =
    !environment.isProduction && environment.viteMode === "mock" ? "mock_preview" : "live_api";
  const capabilities = Object.freeze<DashboardDataSourceCapabilities>({
    approvalMutation: dataSourceMode === "live_api",
    localReplayImport: false,
    syntheticFacts: dataSourceMode === "mock_preview",
  });
  return Object.freeze({
    owner: "dashboard_data_source_factory" as const,
    dataSourceMode,
    buildProfile: environment.isProduction
      ? ("production" as const)
      : environment.viteMode === "test"
        ? ("test" as const)
        : ("development" as const),
    capabilities,
  });
}

export function selectApprovalMutationWriter(
  handle: DashboardDataSourceHandle,
  readOnlyOverride = false,
): ApprovalMutationPermission {
  if (
    readOnlyOverride ||
    handle.descriptor.dataSourceMode !== "live_api" ||
    !handle.descriptor.capabilities.approvalMutation ||
    !handle.approvalWriter
  ) {
    return { code: "mutation_not_permitted", permitted: false };
  }
  return { permitted: true, writer: handle.approvalWriter };
}
