import { dashboardEnv } from "../../config/dashboard-env";
import {
  createDashboardDataSourceDescriptor,
  type ApprovalMutationDataSource,
  type DashboardDataSourceHandle,
  type DashboardReadDataSource,
} from "./dashboard-data-source";

const IS_MOCK_PREVIEW_BUILD = !import.meta.env.PROD && import.meta.env.MODE === "mock";

function createLazyReader(
  loadSource: () => Promise<DashboardReadDataSource>,
): DashboardReadDataSource {
  const reader: DashboardReadDataSource = {
    getAdapterStatus: (adapterId, signal) =>
      loadSource().then((source) => source.getAdapterStatus(adapterId, signal)),
    getAuditIntegrity: (signal) => loadSource().then((source) => source.getAuditIntegrity(signal)),
    getAuditWindow: (filters, signal) =>
      loadSource().then((source) => source.getAuditWindow(filters, signal)),
    getConfigAuditFindings: (filters, signal) =>
      loadSource().then((source) => source.getConfigAuditFindings(filters, signal)),
    getCurrentPolicy: (signal) => loadSource().then((source) => source.getCurrentPolicy(signal)),
    getHealth: (signal) => loadSource().then((source) => source.getHealth(signal)),
    getLatestEvaluationRun: (signal) =>
      loadSource().then((source) => source.getLatestEvaluationRun(signal)),
    getPendingApprovals: (signal) =>
      loadSource().then((source) => source.getPendingApprovals(signal)),
    getPolicyHistory: (signal) => loadSource().then((source) => source.getPolicyHistory(signal)),
    getTraceDetail: (traceId, options) =>
      loadSource().then((source) => source.getTraceDetail(traceId, options)),
    getTraceProvenance: (traceId, options) =>
      loadSource().then((source) => source.getTraceProvenance(traceId, options)),
  };
  return Object.freeze(reader);
}

function createLazyApprovalWriter(
  loadSource: () => Promise<ApprovalMutationDataSource>,
): ApprovalMutationDataSource {
  const writer: ApprovalMutationDataSource = {
    resolveApproval: (approval, decision, csrfToken) =>
      loadSource().then((source) => source.resolveApproval(approval, decision, csrfToken)),
  };
  return Object.freeze(writer);
}

export function createDashboardDataSourceHandle(): DashboardDataSourceHandle {
  const descriptor = createDashboardDataSourceDescriptor({
    isProduction: import.meta.env.PROD,
    viteMode: import.meta.env.MODE,
  });
  let sourcePromise: Promise<DashboardReadDataSource> | null = null;

  if (IS_MOCK_PREVIEW_BUILD) {
    const loadPreviewSource = (): Promise<DashboardReadDataSource> => {
      sourcePromise ??= import("./mock-data-source").then(
        ({ MockDashboardDataSource }) => new MockDashboardDataSource(dashboardEnv.mockDelayMs),
      );
      return sourcePromise;
    };
    return Object.freeze({
      approvalWriter: null,
      descriptor,
      reader: createLazyReader(loadPreviewSource),
    });
  }

  const loadApiSource = (): Promise<DashboardReadDataSource & ApprovalMutationDataSource> => {
    sourcePromise ??= import("./api-data-source").then(
      ({ ApiDashboardDataSource }) => new ApiDashboardDataSource(),
    );
    return sourcePromise as Promise<DashboardReadDataSource & ApprovalMutationDataSource>;
  };
  return Object.freeze({
    approvalWriter: createLazyApprovalWriter(loadApiSource),
    descriptor,
    reader: createLazyReader(loadApiSource),
  });
}

export const dashboardDataSourceHandle = createDashboardDataSourceHandle();
