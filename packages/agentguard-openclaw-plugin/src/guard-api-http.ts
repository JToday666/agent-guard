import { isIP } from "node:net";
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ENCODED_LINE_BREAK = /%0[ad]/iu;
const MAX_GUARD_API_RESPONSE_BYTES = 1024 * 1024;

export class GuardApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardApiError";
  }
}

export type GuardApiResponseFailure = "timed_out" | "too_large" | "malformed";

/** Stable, body-free classification for bounded response handling failures. */
export class GuardApiResponseError extends GuardApiError {
  readonly failure: GuardApiResponseFailure;

  constructor(failure: GuardApiResponseFailure) {
    super(`Guard API response failed: ${failure}`);
    this.name = "GuardApiResponseError";
    this.failure = failure;
  }
}

export function validateGuardApiBaseUrl(value: unknown): string {
  if (typeof value !== "string" || value === "" || value.trim() !== value) {
    throw new GuardApiError("Guard API URL must be a non-empty absolute URL");
  }
  if (
    CONTROL_CHARACTER.test(value) ||
    ENCODED_LINE_BREAK.test(value) ||
    value.includes("\\")
  ) {
    throw new GuardApiError("Guard API URL contains forbidden characters");
  }
  if (value.includes("?") || value.includes("#")) {
    throw new GuardApiError("Guard API URL cannot contain a query or fragment");
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new GuardApiError("Guard API URL is invalid");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new GuardApiError("Guard API URL must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw new GuardApiError("Guard API URL cannot contain user information");
  }

  const rawHost = rawHostname(value);
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (
    !rawHost ||
    hostname.includes("%") ||
    !hasCanonicalIpSpelling(rawHost, hostname)
  ) {
    throw new GuardApiError("Guard API URL must contain a valid host and port");
  }
  if (parsed.protocol === "http:" && !isExplicitLoopback(rawHost, hostname)) {
    throw new GuardApiError(
      "Guard API HTTP is allowed only for explicit loopback addresses",
    );
  }

  const normalizedPath = parsed.pathname.replace(/\/+$/u, "");
  return `${parsed.protocol}//${parsed.host}${normalizedPath}`;
}

function rawHostname(value: string): string {
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu.exec(value)?.[1];
  if (!authority || authority.includes("@")) {
    return "";
  }
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    return end >= 0 ? authority.slice(0, end + 1) : "";
  }
  return authority.split(":", 1)[0] ?? "";
}

function hasCanonicalIpSpelling(
  rawHost: string,
  parsedHostname: string,
): boolean {
  const unwrapped = rawHost.replace(/^\[|\]$/gu, "");
  const parsedKind = isIP(parsedHostname);
  if (parsedKind === 4) {
    return (
      isIP(unwrapped) === 4 &&
      unwrapped
        .split(".")
        .every((part) => String(Number.parseInt(part, 10)) === part)
    );
  }
  if (parsedKind === 6) {
    return rawHost.startsWith("[") && isIP(unwrapped) === 6;
  }
  return !/^(?:0x[0-9a-f]+|[0-9.]+)$/iu.test(unwrapped);
}

function isExplicitLoopback(rawHost: string, parsedHostname: string): boolean {
  if (parsedHostname === "localhost") {
    return rawHost.toLowerCase() === "localhost";
  }
  if (isIP(parsedHostname) === 4) {
    return (
      parsedHostname.startsWith("127.") &&
      hasCanonicalIpSpelling(rawHost, parsedHostname)
    );
  }
  return (
    parsedHostname === "::1" && hasCanonicalIpSpelling(rawHost, parsedHostname)
  );
}

export async function readBoundedJsonResponse(
  response: Response,
  signal: AbortSignal,
  abortPromise: Promise<never>,
  track: <T>(work: Promise<T>) => Promise<T> = (work) => work,
): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^\d+$/u.test(declaredLength) &&
    Number(declaredLength) > MAX_GUARD_API_RESPONSE_BYTES
  ) {
    throw new GuardApiResponseError("too_large");
  }
  if (!response.body) {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let completed = false;
  try {
    while (true) {
      const chunk = await Promise.race([track(reader.read()), abortPromise]);
      if (chunk.done) {
        completed = true;
        break;
      }
      totalBytes += chunk.value.byteLength;
      if (totalBytes > MAX_GUARD_API_RESPONSE_BYTES) {
        throw new GuardApiResponseError("too_large");
      }
      chunks.push(chunk.value);
    }
  } finally {
    if (!completed) {
      void track(reader.cancel()).catch(() => undefined);
    }
  }
  if (signal.aborted) {
    throw new GuardApiResponseError("timed_out");
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new GuardApiResponseError("malformed");
  }
  if (!text.trim()) {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }
}
