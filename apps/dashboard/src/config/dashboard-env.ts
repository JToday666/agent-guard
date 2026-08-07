export interface DashboardEnv {
  apiBaseUrl: string;
  apiHealthUrl: string;
  mockDelayMs: number;
  requestTimeoutMs: number;
}

function positiveNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nonNegativeNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export const dashboardEnv: DashboardEnv = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || "/api/v1",
  apiHealthUrl: import.meta.env.VITE_API_HEALTH_URL || "/api/health",
  mockDelayMs: nonNegativeNumber(import.meta.env.VITE_API_MOCK_DELAY, 250),
  requestTimeoutMs: positiveNumber(import.meta.env.VITE_API_REQUEST_TIMEOUT_MS, 10_000),
};
