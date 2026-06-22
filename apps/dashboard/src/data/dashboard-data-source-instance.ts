import { dashboardEnv } from "../config/dashboard-env";
import { ApiDashboardDataSource } from "./api-data-source";
import type { DashboardDataSource } from "./dashboard-data-source";
import { MockDashboardDataSource } from "./mock-data-source";

export const dashboardDataSource: DashboardDataSource =
  dashboardEnv.dataSource === "mock"
    ? new MockDashboardDataSource(dashboardEnv.mockDelayMs)
    : new ApiDashboardDataSource();
