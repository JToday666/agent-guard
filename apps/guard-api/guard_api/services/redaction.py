"""Unified server-side redaction and bounded projection for audit evidence.

Implements the frozen contract limits from 证据链与溯源 API 目标契约 §21.1/§21.2:
sensitive key coverage, credential content scrubbing, per-field character and
item caps, nesting depth, and the 64 KiB per-event evidence budget. Guard API
审批 payload 清洗与策略评估 evidence 投影必须共用本工具。
"""

from __future__ import annotations

import json
import re

from agentguard_core.credentials import (
    CREDENTIAL_ASSIGNMENT_RE,
    PROVIDER_KEY_RE,
    SENSITIVE_ENV_EXPANSION_RE,
)

REDACTED = "[redacted]"

# §21.1 服务端必做敏感 key 全集。
SENSITIVE_KEY_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "api_key",
    "cookie",
    "private_key",
    "access_key",
    "session",
    "nonce",
)

# §21.2 已冻结的默认限制；部署配置不得放宽。
CONTENT_PREVIEW_LIMIT = 2000
SUMMARY_TEXT_LIMIT = 500
CONTEXT_SOURCES_LIMIT = 20
NORMALIZED_RESOURCES_LIMIT = 50
RULE_HITS_LIMIT = 100
ARRAY_LIMIT = 20
MAX_NESTING_DEPTH = 6
MAX_EVIDENCE_BYTES = 64 * 1024

_AUTHORIZATION_VALUE_RE = re.compile(
    r"(authorization\s*[:=]\s*)([^\s\"'`,;]+(?:\s+[A-Za-z0-9._~+/=-]{8,})?)",
    re.IGNORECASE,
)
_BEARER_TOKEN_RE = re.compile(r"(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_COOKIE_VALUE_RE = re.compile(r"(cookie\s*[:=]\s*)([^\r\n\"]+)", re.IGNORECASE)
_PRIVATE_KEY_BODY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


def looks_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)


def scrub_text(value: str) -> str:
    """Scrub credential content inside a string per §21.1."""

    # 私钥块必须最先替换，避免被后续 key=value / Cookie 清洗吞掉首行。
    redacted = _PRIVATE_KEY_BODY_RE.sub(REDACTED, value)
    redacted = PROVIDER_KEY_RE.sub(f"sk-{REDACTED}", redacted)
    redacted = CREDENTIAL_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}{REDACTED}",
        redacted,
    )
    redacted = SENSITIVE_ENV_EXPANSION_RE.sub(f"$[{REDACTED}]", redacted)
    redacted = _AUTHORIZATION_VALUE_RE.sub(rf"\g<1>{REDACTED}", redacted)
    redacted = _BEARER_TOKEN_RE.sub(rf"\g<1>{REDACTED}", redacted)
    redacted = _COOKIE_VALUE_RE.sub(rf"\g<1>{REDACTED}", redacted)
    return redacted


def redact_structure(value: object) -> object:
    """Recursively replace sensitive-key values and scrub string content."""

    if hasattr(value, "model_dump"):
        return redact_structure(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED if looks_sensitive_key(str(key)) else redact_structure(nested)
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


def truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}..."


def bound_value(
    value: object,
    *,
    text_limit: int = SUMMARY_TEXT_LIMIT,
    array_limit: int = ARRAY_LIMIT,
    max_depth: int = MAX_NESTING_DEPTH,
    _depth: int = 1,
) -> object:
    """Project a JSON-compatible value onto the frozen §21.2 size limits."""

    if isinstance(value, str):
        return truncate_text(value, text_limit)
    if _depth >= max_depth:
        if isinstance(value, (dict, list)):
            return "..." if value else value
        return value
    if isinstance(value, dict):
        return {
            str(key): bound_value(
                nested,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [
            bound_value(
                item,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in value[:array_limit]
        ]
    return value


def bound_redacted_value(
    value: object,
    *,
    text_limit: int = SUMMARY_TEXT_LIMIT,
    array_limit: int = ARRAY_LIMIT,
    max_depth: int = MAX_NESTING_DEPTH,
) -> object:
    """Redact first, then project onto the frozen size limits."""

    return bound_value(
        redact_structure(value),
        text_limit=text_limit,
        array_limit=array_limit,
        max_depth=max_depth,
    )


def evidence_serialized_size(evidence: dict[str, object]) -> int:
    return len(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def enforce_evidence_budget(
    evidence: dict[str, object], *, max_bytes: int = MAX_EVIDENCE_BYTES
) -> dict[str, object]:
    """Shrink text projections until the serialized evidence fits the budget.

    超限截断投影，不拒绝写入（§21.2 / D-05）。
    """

    current = evidence
    for text_limit in (500, 200, 64, 16):
        if evidence_serialized_size(current) <= max_bytes:
            return current
        current = bound_value(
            current,
            text_limit=text_limit,
            array_limit=ARRAY_LIMIT,
            max_depth=MAX_NESTING_DEPTH,
        )
    return current
