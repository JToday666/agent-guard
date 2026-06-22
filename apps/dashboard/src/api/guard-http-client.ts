import { dashboardEnv } from "../config/dashboard-env";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export async function requestJson<T>(
  path: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`${dashboardEnv.apiBaseUrl}${path}`, {
    ...init,
    credentials: "include",
    signal,
    headers: {
      "Content-Type": "application/json",
      ...init.headers,
    },
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const code = payload?.error?.code ?? "REQUEST_FAILED";
    throw new ApiError(response.status, code, `请求失败 (${response.status})`);
  }

  return response.json() as Promise<T>;
}

export async function requestHealth(
  signal?: AbortSignal,
): Promise<{ status: string; database?: string }> {
  const response = await fetch("/api/health?check_db=true", {
    credentials: "include",
    signal,
  });
  if (!response.ok)
    throw new ApiError(response.status, "HEALTH_CHECK_FAILED", "健康检查失败");
  return response.json() as Promise<{ status: string; database?: string }>;
}
