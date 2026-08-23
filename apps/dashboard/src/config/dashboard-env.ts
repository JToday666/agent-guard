export interface DashboardEnv {
  apiBaseUrl: string;
  apiHealthUrl: string;
  evidencePollIntervalMs: number;
  mockDelayMs: number;
  requestTimeoutMs: number;
  runtimeSupervisionS1Enabled: boolean;
}

export const DEFAULT_EVIDENCE_POLL_INTERVAL_MS = 10_000;
export const MIN_EVIDENCE_POLL_INTERVAL_MS = 2_000;

function positiveNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nonNegativeNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function resolveEvidencePollIntervalMs(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_EVIDENCE_POLL_INTERVAL_MS;
  return Math.max(MIN_EVIDENCE_POLL_INTERVAL_MS, Math.floor(parsed));
}

export function booleanFlag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === "") return fallback;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

const viteEnv = (
  import.meta as ImportMeta & {
    readonly env?: Partial<Record<keyof DashboardEnv | `VITE_${string}`, string>>;
  }
).env;

export const dashboardEnv: DashboardEnv = {
  apiBaseUrl: viteEnv?.VITE_API_BASE_URL || "/api/v1",
  apiHealthUrl: viteEnv?.VITE_API_HEALTH_URL || "/api/health",
  evidencePollIntervalMs: resolveEvidencePollIntervalMs(viteEnv?.VITE_EVIDENCE_POLL_INTERVAL_MS),
  mockDelayMs: nonNegativeNumber(viteEnv?.VITE_API_MOCK_DELAY, 250),
  requestTimeoutMs: positiveNumber(viteEnv?.VITE_API_REQUEST_TIMEOUT_MS, 10_000),
  runtimeSupervisionS1Enabled: booleanFlag(viteEnv?.VITE_RUNTIME_SUPERVISION_S1_ENABLED, true),
};
