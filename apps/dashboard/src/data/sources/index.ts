import { dashboardEnv } from "../../config/dashboard-env";
import { ApiDashboardDataSource } from "./api-data-source";
import type { DashboardDataSource } from "./dashboard-data-source";
import { MockDashboardDataSource } from "./mock-data-source";

export type { DashboardDataSource, EventFilters } from "./dashboard-data-source";
export { ApiDashboardDataSource } from "./api-data-source";
export { MockDashboardDataSource } from "./mock-data-source";

export const dashboardDataSource: DashboardDataSource =
  dashboardEnv.dataSource === "mock"
    ? new MockDashboardDataSource(dashboardEnv.mockDelayMs)
    : new ApiDashboardDataSource();
