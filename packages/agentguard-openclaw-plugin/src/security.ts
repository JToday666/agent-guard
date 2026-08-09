const SENSITIVE_NAME_PATTERN = String.raw`[A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*`;
const SENSITIVE_WORD_PATTERN = String.raw`(?:api[_-]?key|token|secret|password|credential)`;

const SENSITIVE_ENV_EXPANSION_PATTERN = new RegExp(String.raw`\$(?:\{)?(${SENSITIVE_NAME_PATTERN})(?:\})?`, "gi");
const SENSITIVE_ENV_READ_PATTERN = new RegExp(
  String.raw`(?:\b(?:printenv|env|set|export)\b.*${SENSITIVE_WORD_PATTERN})|` +
    String.raw`(?:${SENSITIVE_WORD_PATTERN}.*\b(?:printenv|env|set|export)\b)|` +
    String.raw`(?:/proc/self/environ)`,
  "i",
);
const CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
  "\\b(" +
    SENSITIVE_NAME_PATTERN +
    "|" +
    SENSITIVE_WORD_PATTERN +
    ")(\\s*[:=]\\s*)([\"']?)([^\\s\"'`]+)\\3",
  "gi",
);
const PROVIDER_KEY_PATTERN = /\bsk-[A-Za-z0-9][A-Za-z0-9._-]{8,}\b/g;
const AUTHORIZATION_VALUE_PATTERN = /(authorization\s*[:=]\s*)([^\s"'`,;]+(?:\s+[A-Za-z0-9._~+/=-]{8,})?)/gi;
const BEARER_TOKEN_PATTERN = /(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi;
const COOKIE_VALUE_PATTERN = /(cookie\s*[:=]\s*)([^\r\n"]+)/gi;
const PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const SENSITIVE_OBJECT_KEY_PATTERN = /(?:api[_-]?key|token|secret|password|credential|authorization|cookie|private[_-]?key)/i;
const REDACTION_MAX_DEPTH = 12;
const REDACTION_MAX_ITEMS = 1000;

const EXEC_LIKE_NAMES = new Set(["code_exec", "exec", "shell", "command", "bash", "sh", "powershell", "terminal"]);
const EXEC_LIKE_KINDS = new Set([
  "code_exec",
  "exec",
  "shell",
  "shell_exec",
  "command",
  "command_exec",
  "bash",
  "sh",
  "powershell",
  "terminal",
  "code_mode_exec",
]);

export function containsCredentialValueText(value: string): boolean {
  return (
    providerKeyPattern().test(value) ||
    credentialAssignmentPattern().test(value) ||
    bearerTokenPattern().test(value) ||
    privateKeyPattern().test(value)
  );
}

export function containsCredentialCommandText(value: string): boolean {
  return (
    sensitiveEnvExpansionPattern().test(value) ||
    SENSITIVE_ENV_READ_PATTERN.test(value) ||
    containsCredentialValueText(value)
  );
}

export function containsSensitiveCredentialText(value: unknown): boolean {
  return containsCredentialValueText(stringPreview(value));
}

export function redactSensitiveCredentials(value: string, limit = 240): string {
  const redacted = value
    .replace(privateKeyPattern(), "[redacted]")
    .replace(providerKeyPattern(), "sk-[redacted]")
    .replace(credentialAssignmentPattern(), (_match, key: string, sep: string) => `${key}${sep}[redacted]`)
    .replace(sensitiveEnvExpansionPattern(), "$[redacted]")
    .replace(authorizationValuePattern(), "$1[redacted]")
    .replace(bearerTokenPattern(), "$1[redacted]")
    .replace(cookieValuePattern(), "$1[redacted]");
  return redacted.length > limit ? `${redacted.slice(0, limit)}...` : redacted;
}

export function redactUnknownCredentials(value: unknown): { value: unknown; changed: boolean } {
  return redactUnknownCredentialsInternal(value, new WeakSet<object>(), {
    count: 0,
  });
}

function redactUnknownCredentialsInternal(
  value: unknown,
  seen: WeakSet<object>,
  budget: { count: number },
  depth = 0,
): { value: unknown; changed: boolean } {
  if (depth > REDACTION_MAX_DEPTH || budget.count >= REDACTION_MAX_ITEMS) {
    return { value: "[redacted:structure-limit]", changed: true };
  }
  budget.count += 1;
  if (typeof value === "string") {
    const redacted = redactSensitiveCredentials(value, 2000);
    return { value: redacted, changed: redacted !== value };
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return { value: "[redacted:circular]", changed: true };
    }
    seen.add(value);
    let changed = false;
    const mapped = value.map((item) => {
      const result = redactUnknownCredentialsInternal(
        item,
        seen,
        budget,
        depth + 1,
      );
      changed ||= result.changed;
      return result.value;
    });
    seen.delete(value);
    return { value: mapped, changed };
  }
  if (typeof value === "object" && value !== null) {
    if (seen.has(value)) {
      return { value: "[redacted:circular]", changed: true };
    }
    seen.add(value);
    let changed = false;
    const mapped: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      if (SENSITIVE_OBJECT_KEY_PATTERN.test(key)) {
        mapped[key] = "[redacted]";
        changed = true;
        continue;
      }
      const result = redactUnknownCredentialsInternal(
        nested,
        seen,
        budget,
        depth + 1,
      );
      changed ||= result.changed;
      mapped[key] = result.value;
    }
    seen.delete(value);
    return { value: mapped, changed };
  }
  return { value, changed: false };
}

export function sanitizePersistentInstructionPoisoning(value: unknown): { value: unknown; changed: boolean } {
  if (typeof value === "string") {
    if (!containsPersistentInstructionPoisoning(value)) {
      return { value, changed: false };
    }
    return {
      value: "[AgentGuard removed untrusted persistent instructions from this tool result.]",
      changed: true,
    };
  }
  if (Array.isArray(value)) {
    let changed = false;
    const mapped = value.map((item) => {
      const result = sanitizePersistentInstructionPoisoning(item);
      changed ||= result.changed;
      return result.value;
    });
    return { value: mapped, changed };
  }
  if (typeof value === "object" && value !== null) {
    let changed = false;
    const mapped: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      const result = sanitizePersistentInstructionPoisoning(nested);
      changed ||= result.changed;
      mapped[key] = result.value;
    }
    return { value: mapped, changed };
  }
  return { value, changed: false };
}

export function containsPersistentInstructionPoisoning(value: string): boolean {
  const normalized = value.toLowerCase();
  const persistenceIntent = [
    "persist this rule",
    "remember this rule",
    "store this rule",
    "save this rule",
    "remember this instruction",
    "store this instruction",
    "save this instruction",
    "future runs",
    "future requests",
    "future reports",
    "future sessions",
    "future tasks",
    "for all future",
    "always send",
    "from now on",
    "next time",
  ].some((marker) => normalized.includes(marker));
  const unsafeAction = [
    "attacker@",
    "send reports externally",
    "send future",
    "route future reports",
    "external",
    "webhook",
    "exfiltrate",
    "ignore previous",
    "ignore all prior",
    "override",
    "never mention",
    "never reveal",
    "never tell",
    "hide this rule",
  ].some((marker) => normalized.includes(marker));
  return persistenceIntent && unsafeAction;
}

export function isExecLikeToolIdentity(input: {
  toolName?: string | null;
  toolKind?: string | null;
  toolInputKind?: string | null;
}): boolean {
  const identifiers = [input.toolName, input.toolKind, input.toolInputKind]
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .map((value) => value.toLowerCase());
  return identifiers.some((value) => EXEC_LIKE_NAMES.has(value) || EXEC_LIKE_KINDS.has(value));
}

export function stringPreview(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value === null || value === undefined) {
    return "";
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function providerKeyPattern(): RegExp {
  return new RegExp(PROVIDER_KEY_PATTERN.source, "g");
}

function credentialAssignmentPattern(): RegExp {
  return new RegExp(CREDENTIAL_ASSIGNMENT_PATTERN.source, "gi");
}

function sensitiveEnvExpansionPattern(): RegExp {
  return new RegExp(SENSITIVE_ENV_EXPANSION_PATTERN.source, "gi");
}

function authorizationValuePattern(): RegExp {
  return new RegExp(AUTHORIZATION_VALUE_PATTERN.source, "gi");
}

function bearerTokenPattern(): RegExp {
  return new RegExp(BEARER_TOKEN_PATTERN.source, "gi");
}

function cookieValuePattern(): RegExp {
  return new RegExp(COOKIE_VALUE_PATTERN.source, "gi");
}

function privateKeyPattern(): RegExp {
  return new RegExp(PRIVATE_KEY_PATTERN.source, "g");
}
