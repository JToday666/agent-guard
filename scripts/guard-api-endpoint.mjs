import { isIP } from "node:net";

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ENCODED_LINE_BREAK = /%0[ad]/iu;

export function validateGuardApiBaseUrl(value) {
  if (typeof value !== "string" || value === "" || value.trim() !== value) {
    throw new Error("Guard API URL must be a non-empty absolute URL");
  }
  if (
    CONTROL_CHARACTER.test(value) ||
    ENCODED_LINE_BREAK.test(value) ||
    value.includes("\\")
  ) {
    throw new Error("Guard API URL contains forbidden characters");
  }
  if (value.includes("?") || value.includes("#")) {
    throw new Error("Guard API URL cannot contain a query or fragment");
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Guard API URL is invalid");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Guard API URL must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Guard API URL cannot contain user information");
  }

  const rawHost = rawHostname(value);
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (
    !rawHost ||
    hostname.includes("%") ||
    !hasCanonicalIpSpelling(rawHost, hostname)
  ) {
    throw new Error("Guard API URL must contain a valid host and port");
  }
  if (parsed.protocol === "http:" && !isExplicitLoopback(rawHost, hostname)) {
    throw new Error(
      "Guard API HTTP is allowed only for explicit loopback addresses",
    );
  }

  const normalizedPath = parsed.pathname.replace(/\/+$/u, "");
  return `${parsed.protocol}//${parsed.host}${normalizedPath}`;
}

export function resolveGuardApiBaseUrl(env = process.env) {
  const explicit = env.AGENTGUARD_API_URL;
  if (typeof explicit === "string" && explicit !== "") {
    return validateGuardApiBaseUrl(explicit);
  }
  const host = env.AGENTGUARD_HOST || "127.0.0.1";
  const port = env.AGENTGUARD_PORT || "8088";
  const authorityHost =
    host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return validateGuardApiBaseUrl(`http://${authorityHost}:${port}`);
}

function rawHostname(value) {
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu.exec(value)?.[1];
  if (!authority || authority.includes("@")) {
    return "";
  }
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    return end >= 0 ? authority.slice(0, end + 1) : "";
  }
  return authority.split(":", 1)[0];
}

function hasCanonicalIpSpelling(rawHost, parsedHostname) {
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

function isExplicitLoopback(rawHost, parsedHostname) {
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
