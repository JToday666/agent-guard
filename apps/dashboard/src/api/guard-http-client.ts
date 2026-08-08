import { dashboardEnv } from "../config/dashboard-env.ts";
import type { GuardHealthDto } from "./guard-api-types.ts";
import { getPublicApiErrorMessage } from "./public-api-error.ts";
import { createTimedRequestSignal } from "./request-lifecycle.ts";

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

export type ConditionalJsonResponse<T> =
  | { status: "modified"; value: T; etag: string | null }
  | { status: "not_modified"; etag: string | null };

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

function createTimeoutError(): ApiError {
  return new ApiError(0, "REQUEST_TIMEOUT", getPublicApiErrorMessage(0, "REQUEST_TIMEOUT"));
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

async function request(
  input: string,
  init: RequestInit,
  callerSignal?: AbortSignal | null,
): Promise<Response> {
  const lifecycle = createTimedRequestSignal(callerSignal, dashboardEnv.requestTimeoutMs);
  try {
    return await fetch(input, { ...init, signal: lifecycle.signal });
  } catch (reason) {
    if (lifecycle.didTimeout()) throw createTimeoutError();
    if (callerSignal?.aborted) throw lifecycle.signal.reason;
    if (reason instanceof Error && reason.name === "AbortError") throw reason;
    throw createNetworkError();
  } finally {
    lifecycle.dispose();
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

  const response = await request(
    `${dashboardEnv.apiBaseUrl}${path}`,
    {
      ...init,
      credentials: "include",
      headers,
    },
    signal ?? init.signal,
  );

  if (!response.ok) {
    const code = await readErrorCode(response);
    throw new ApiError(response.status, code, getPublicApiErrorMessage(response.status, code));
  }

  return readJsonResponse<T>(response);
}

export async function requestConditionalJson<T>(
  path: string,
  etag?: string,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<ConditionalJsonResponse<T>> {
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (etag) headers.set("If-None-Match", etag);
  const response = await request(
    `${dashboardEnv.apiBaseUrl}${path}`,
    {
      ...init,
      credentials: "include",
      headers,
    },
    signal ?? init.signal,
  );
  const responseEtag = response.headers.get("etag");
  if (response.status === 304) {
    return { status: "not_modified", etag: responseEtag ?? etag ?? null };
  }
  if (!response.ok) {
    const code = await readErrorCode(response);
    throw new ApiError(response.status, code, getPublicApiErrorMessage(response.status, code));
  }
  return {
    status: "modified",
    value: await readJsonResponse<T>(response),
    etag: responseEtag,
  };
}

export async function requestHealth(signal?: AbortSignal): Promise<GuardHealthDto> {
  const separator = dashboardEnv.apiHealthUrl.includes("?") ? "&" : "?";
  const response = await request(
    `${dashboardEnv.apiHealthUrl}${separator}check_db=true`,
    {
      credentials: "include",
      headers: { Accept: "application/json" },
    },
    signal,
  );
  if (response.ok) return readJsonResponse<GuardHealthDto>(response);
  if (response.status === 503) {
    const result = await readJsonResponse<GuardHealthDto>(response);
    if (result.status === "degraded") return result;
  }
  throw new ApiError(response.status, "HEALTH_CHECK_FAILED", "健康检查失败");
}
