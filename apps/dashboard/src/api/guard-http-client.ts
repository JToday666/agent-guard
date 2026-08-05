import { dashboardEnv } from "../config/dashboard-env";
import { getPublicApiErrorMessage } from "./public-api-error";

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

async function readErrorCode(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return "REQUEST_FAILED";
  const payload: unknown = await response.json().catch(() => null);
  if (!payload || typeof payload !== "object") return "REQUEST_FAILED";
  const error = "error" in payload ? payload.error : null;
  if (!error || typeof error !== "object" || !("code" in error)) return "REQUEST_FAILED";
  return typeof error.code === "string" && error.code ? error.code : "REQUEST_FAILED";
}

function createNetworkError(): ApiError {
  return new ApiError(0, "NETWORK_ERROR", getPublicApiErrorMessage(0, "NETWORK_ERROR"));
}

async function readJsonResponse<T>(response: Response): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(
      response.status,
      "INVALID_RESPONSE",
      getPublicApiErrorMessage(response.status, "INVALID_RESPONSE"),
    );
  }
}

export async function requestJson<T>(
  path: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${dashboardEnv.apiBaseUrl}${path}`, {
      ...init,
      credentials: "include",
      headers,
      signal: signal ?? init.signal,
    });
  } catch (reason) {
    if (reason instanceof Error && reason.name === "AbortError") throw reason;
    throw createNetworkError();
  }

  if (!response.ok) {
    const code = await readErrorCode(response);
    throw new ApiError(response.status, code, getPublicApiErrorMessage(response.status, code));
  }

  return readJsonResponse<T>(response);
}

export async function requestHealth(
  signal?: AbortSignal,
): Promise<{ status: string; database?: string }> {
  let response: Response;
  try {
    response = await fetch("/api/health?check_db=true", {
      credentials: "include",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (reason) {
    if (reason instanceof Error && reason.name === "AbortError") throw reason;
    throw createNetworkError();
  }
  if (!response.ok) throw new ApiError(response.status, "HEALTH_CHECK_FAILED", "健康检查失败");
  return readJsonResponse<{ status: string; database?: string }>(response);
}
