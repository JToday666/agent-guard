import { dashboardEnv } from "../../config/dashboard-env";
import type { DashboardDataSource } from "./dashboard-data-source";

export function createDashboardDataSource(): DashboardDataSource {
  let sourcePromise: Promise<DashboardDataSource> | null = null;
  const loadSource = (): Promise<DashboardDataSource> => {
    if (sourcePromise) return sourcePromise;
    sourcePromise =
      dashboardEnv.dataSource === "mock"
        ? import("./mock-data-source").then(
            ({ MockDashboardDataSource }) => new MockDashboardDataSource(dashboardEnv.mockDelayMs),
          )
        : import("./api-data-source").then(
            ({ ApiDashboardDataSource }) => new ApiDashboardDataSource(),
          );
    return sourcePromise;
  };

  return {
    getAdapterStatus: (...args) => loadSource().then((source) => source.getAdapterStatus(...args)),
    getAuditIntegrity: (...args) =>
      loadSource().then((source) => source.getAuditIntegrity(...args)),
    getAuditWindow: (...args) => loadSource().then((source) => source.getAuditWindow(...args)),
    getConfigAuditFindings: (...args) =>
      loadSource().then((source) => source.getConfigAuditFindings(...args)),
    getCurrentPolicy: (...args) => loadSource().then((source) => source.getCurrentPolicy(...args)),
    getHealth: (...args) => loadSource().then((source) => source.getHealth(...args)),
    getLatestEvaluationRun: (...args) =>
      loadSource().then((source) => source.getLatestEvaluationRun(...args)),
    getPendingApprovals: (...args) =>
      loadSource().then((source) => source.getPendingApprovals(...args)),
    getPolicyHistory: (...args) => loadSource().then((source) => source.getPolicyHistory(...args)),
    getTraceDetail: (...args) => loadSource().then((source) => source.getTraceDetail(...args)),
    getTraceProvenance: (...args) =>
      loadSource().then((source) => source.getTraceProvenance(...args)),
    resolveApproval: (...args) => loadSource().then((source) => source.resolveApproval(...args)),
  };
}

export const dashboardDataSource = createDashboardDataSource();
