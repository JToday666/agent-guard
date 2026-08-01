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

async function readErrorBody(response: Response): Promise<{ code: string; message: string }> {
  const fallback = {
    code: "REQUEST_FAILED",
    message: `请求失败 (${response.status})`,
  };
  const contentType = response.headers.get("content-type") ?? "";

  if (contentType.includes("application/json")) {
    const payload = await response.json().catch(() => null);
    const error = payload?.error;
    return {
      code: typeof error?.code === "string" && error.code ? error.code : fallback.code,
      message: typeof error?.message === "string" && error.message ? error.message : fallback.message,
    };
  }

  const text = (await response.text().catch(() => "")).trim();
  return {
    code: fallback.code,
    message: text ? `${text} (${response.status})` : fallback.message,
  };
}

export async function requestJson<T>(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
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
    const error = await readErrorBody(response);
    throw new ApiError(response.status, error.code, error.message);
  }

  return response.json() as Promise<T>;
}

export async function requestHealth(signal?: AbortSignal): Promise<{ status: string; database?: string }> {
  const response = await fetch("/api/health?check_db=true", {
    credentials: "include",
    signal,
  });
  if (!response.ok) throw new ApiError(response.status, "HEALTH_CHECK_FAILED", "健康检查失败");
  return response.json() as Promise<{ status: string; database?: string }>;
}
