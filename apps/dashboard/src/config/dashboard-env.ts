export interface DashboardEnv {
  apiBaseUrl: string;
  dataSource: "api" | "mock";
  mockDelayMs: number;
}

export const dashboardEnv: DashboardEnv = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || "/api/v1",
  dataSource: import.meta.env.MODE === "mock" ? "mock" : "api",
  mockDelayMs: Number(import.meta.env.VITE_API_MOCK_DELAY || "250"),
};
