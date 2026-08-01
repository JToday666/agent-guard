const SENSITIVE_KEY_PATTERN =
  /authorization|cookie|password|secret|token|csrf|nonce|api[_-]?key|email|phone|body|content/i;
const BEARER_PATTERN = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;
const API_KEY_PATTERN = /\b(?:sk|pk)-[A-Za-z0-9_-]{8,}\b/g;
const URL_SECRET_QUERY_PATTERN =
  /([?&](?:access_token|api[_-]?key|authorization|key|password|secret|token)=)[^&\s'")]+/gi;
const EMAIL_PATTERN =
  /\b([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
const HOME_PATH_PATTERN = /\/home\/[^/]+/g;

export function maskSensitiveText(value: string): string {
  return value
    .replace(URL_SECRET_QUERY_PATTERN, "$1[已脱敏]")
    .replace(EMAIL_PATTERN, "$1***@$2")
    .replace(HOME_PATH_PATTERN, "/home/***");
}

export function redactSensitiveData(value: unknown, fieldName = ""): unknown {
  if (SENSITIVE_KEY_PATTERN.test(fieldName)) return "[已脱敏]";

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveData(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, redactSensitiveData(item, key)]),
    );
  }

  if (typeof value === "string") {
    return maskSensitiveText(value)
      .replace(BEARER_PATTERN, "Bearer [已脱敏]")
      .replace(API_KEY_PATTERN, "[已脱敏]");
  }

  return value;
}
