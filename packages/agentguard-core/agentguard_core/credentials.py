"""Credential exposure matching and redaction helpers."""

from __future__ import annotations

import re

SENSITIVE_NAME_PATTERN = (
    r"[A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*"
)
SENSITIVE_WORD_PATTERN = r"(?:api[_-]?key|token|secret|password|credential)"

SENSITIVE_ENV_NAME_RE = re.compile(rf"\b{SENSITIVE_NAME_PATTERN}\b", re.IGNORECASE)
SENSITIVE_ENV_EXPANSION_RE = re.compile(
    rf"\$(?:\{{)?({SENSITIVE_NAME_PATTERN})(?:\}})?", re.IGNORECASE
)
SENSITIVE_ENV_READ_RE = re.compile(
    rf"(?:\b(?:printenv|env|set|export)\b.*{SENSITIVE_WORD_PATTERN})|"
    rf"(?:{SENSITIVE_WORD_PATTERN}.*\b(?:printenv|env|set|export)\b)|"
    r"(?:/proc/self/environ)",
    re.IGNORECASE,
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"\b(?P<key>{SENSITIVE_NAME_PATTERN}|{SENSITIVE_WORD_PATTERN})"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\s\"'`]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)
PROVIDER_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9._-]{8,}\b")


def has_credential_value_text(text: str) -> bool:
    """Return true when text appears to contain an actual credential value."""

    return bool(PROVIDER_KEY_RE.search(text) or CREDENTIAL_ASSIGNMENT_RE.search(text))


def has_credential_command_text(command: str) -> bool:
    """Return true when a shell command reads or prints credential material."""

    return bool(
        SENSITIVE_ENV_EXPANSION_RE.search(command)
        or SENSITIVE_ENV_READ_RE.search(command)
        or has_credential_value_text(command)
    )


def redact_credential_text(text: str, *, limit: int = 240) -> str:
    """Redact credential values while preserving useful operator context."""

    redacted = PROVIDER_KEY_RE.sub("sk-[redacted]", text)
    redacted = CREDENTIAL_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}[redacted]", redacted
    )
    redacted = SENSITIVE_ENV_EXPANSION_RE.sub("$[redacted]", redacted)
    if len(redacted) > limit:
        return f"{redacted[:limit]}..."
    return redacted
