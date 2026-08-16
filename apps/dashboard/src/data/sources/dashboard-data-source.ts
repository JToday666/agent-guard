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
  readonly runtimeSupervisionS1: boolean;
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
    approvalId: string,
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
  readonly runtimeSupervisionS1Enabled?: boolean;
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

  constructor(message = "当前审批不满足安全写入条件，不能提交处理结果。") {
    super(message);
    this.name = "DashboardMutationNotPermittedError";
  }
}

const factoryOwnedDescriptors = new WeakSet<object>();

export function isFactoryOwnedDashboardDataSourceDescriptor(
  descriptor: unknown,
): descriptor is DashboardDataSourceDescriptor {
  return (
    typeof descriptor === "object" && descriptor !== null && factoryOwnedDescriptors.has(descriptor)
  );
}

export function createDashboardDataSourceDescriptor(
  environment: DashboardDataSourceRuntimeEnvironment,
): DashboardDataSourceDescriptor {
  const dataSourceMode: DashboardDataSourceMode =
    !environment.isProduction && environment.viteMode === "mock" ? "mock_preview" : "live_api";
  const runtimeSupervisionS1 =
    dataSourceMode === "live_api" && environment.runtimeSupervisionS1Enabled !== false;
  const capabilities = Object.freeze<DashboardDataSourceCapabilities>({
    approvalMutation: runtimeSupervisionS1,
    localReplayImport: false,
    runtimeSupervisionS1,
    syntheticFacts: dataSourceMode === "mock_preview",
  });
  const descriptor = Object.freeze({
    owner: "dashboard_data_source_factory" as const,
    dataSourceMode,
    buildProfile: environment.isProduction
      ? ("production" as const)
      : environment.viteMode === "test"
        ? ("test" as const)
        : ("development" as const),
    capabilities,
  });
  factoryOwnedDescriptors.add(descriptor);
  return descriptor;
}

export function selectApprovalMutationWriter(
  handle: DashboardDataSourceHandle,
  readOnlyOverride = false,
): ApprovalMutationPermission {
  if (
    readOnlyOverride ||
    !isFactoryOwnedDashboardDataSourceDescriptor(handle.descriptor) ||
    handle.descriptor.dataSourceMode !== "live_api" ||
    !handle.descriptor.capabilities.approvalMutation ||
    !handle.descriptor.capabilities.runtimeSupervisionS1 ||
    !handle.approvalWriter
  ) {
    return { code: "mutation_not_permitted", permitted: false };
  }
  return { permitted: true, writer: handle.approvalWriter };
}
