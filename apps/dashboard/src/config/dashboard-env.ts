export interface DashboardEnv {
  apiBaseUrl: string;
  backendTarget: string;
  enableApiMock: boolean;
}

export const dashboardEnv: DashboardEnv = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || "/api/v1",
  backendTarget: import.meta.env.VITE_BACKEND_TARGET || "http://127.0.0.1:8000",
  enableApiMock: import.meta.env.VITE_ENABLE_API_MOCK === "true",
};
