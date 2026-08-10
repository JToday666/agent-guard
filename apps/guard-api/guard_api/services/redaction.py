"""Unified server-side redaction and bounded projection for audit evidence.

Implements the frozen contract limits from 证据链与溯源 API 目标契约 §21.1/§21.2:
sensitive key coverage, credential content scrubbing, per-field character and
item caps, nesting depth, and the 64 KiB per-event evidence budget. Guard API
审批 payload 清洗与策略评估 evidence 投影必须共用本工具。
"""

from __future__ import annotations

import json
import hashlib
import re

from agentguard_core import AuditEvent
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
OBJECT_KEYS_LIMIT = 100
OBJECT_KEY_TEXT_LIMIT = 128
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
        bounded: dict[str, object] = {}
        for key, nested in list(value.items())[:OBJECT_KEYS_LIMIT]:
            bounded_key = truncate_text(scrub_text(str(key)), OBJECT_KEY_TEXT_LIMIT)
            bounded[bounded_key] = bound_value(
                nested,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        return bounded
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


def sanitize_audit_event(event: AuditEvent) -> AuditEvent:
    """Return the canonical browser-safe event that is eligible for persistence.

    Redaction must happen before audit integrity metadata is attached. This makes
    the persisted hash chain authoritative for the safe representation and avoids
    relying on every producer—or a later browser response mapper—to remember the
    same security boundary.
    """

    raw_metadata = redact_structure(event.metadata)
    metadata: dict[str, object]
    if isinstance(raw_metadata, dict):
        raw_decision = raw_metadata.pop("guard_decision", None)
        bounded_metadata = bound_value(
            raw_metadata,
            text_limit=CONTENT_PREVIEW_LIMIT,
            array_limit=ARRAY_LIMIT,
        )
        metadata = bounded_metadata if isinstance(bounded_metadata, dict) else {}
        if raw_decision is not None:
            # Replay needs the complete GuardDecision shape. Keep the dedicated
            # rule/effect collection ceiling while preserving container types.
            metadata["guard_decision"] = _bound_typed_value(
                raw_decision,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=RULE_HITS_LIMIT,
            )
    else:
        metadata = {}

    evidence: dict[str, object] | None = None
    if event.evidence is not None:
        raw_evidence = redact_structure(event.evidence)
        replay_decision = (
            raw_evidence.pop("guard_decision", None)
            if isinstance(raw_evidence, dict)
            else None
        )
        bounded_evidence = bound_value(
            raw_evidence,
            text_limit=CONTENT_PREVIEW_LIMIT,
            array_limit=RULE_HITS_LIMIT,
        )
        if isinstance(bounded_evidence, dict) and replay_decision is not None:
            bounded_evidence["guard_decision"] = _bound_typed_value(
                replay_decision,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=RULE_HITS_LIMIT,
            )
        evidence = (
            enforce_evidence_budget(bounded_evidence)
            if isinstance(bounded_evidence, dict)
            else {}
        )

    return event.model_copy(
        update={
            "summary": truncate_text(scrub_text(event.summary), SUMMARY_TEXT_LIMIT),
            "resource_targets": [
                truncate_text(scrub_text(target), SUMMARY_TEXT_LIMIT)
                for target in event.resource_targets[:NORMALIZED_RESOURCES_LIMIT]
            ],
            "rule_hits": [
                truncate_text(scrub_text(rule_id), SUMMARY_TEXT_LIMIT)
                for rule_id in event.rule_hits[:RULE_HITS_LIMIT]
            ],
            "reason": truncate_text(scrub_text(event.reason), CONTENT_PREVIEW_LIMIT),
            "metadata": metadata,
            "evidence": evidence,
        }
    )


def _bound_typed_value(
    value: object,
    *,
    text_limit: int,
    array_limit: int,
    max_depth: int = MAX_NESTING_DEPTH,
    _depth: int = 1,
) -> object:
    """Bound replay data without replacing typed containers with strings."""

    if isinstance(value, str):
        return truncate_text(value, text_limit)
    if isinstance(value, dict):
        if _depth >= max_depth:
            return {}
        bounded: dict[str, object] = {}
        for key, nested in list(value.items())[:OBJECT_KEYS_LIMIT]:
            bounded_key = truncate_text(scrub_text(str(key)), OBJECT_KEY_TEXT_LIMIT)
            bounded[bounded_key] = _bound_typed_value(
                nested,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        return bounded
    if isinstance(value, list):
        if _depth >= max_depth:
            return []
        return [
            _bound_typed_value(
                item,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in value[:array_limit]
        ]
    return value


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
    original_size = evidence_serialized_size(evidence)
    for text_limit in (500, 200, 64, 16):
        if evidence_serialized_size(current) <= max_bytes:
            return current
        bounded = bound_value(
            current,
            text_limit=text_limit,
            array_limit=ARRAY_LIMIT,
            max_depth=MAX_NESTING_DEPTH,
        )
        current = bounded if isinstance(bounded, dict) else {}
    if evidence_serialized_size(current) <= max_bytes:
        return current

    # A large number of short keys can still exceed the byte budget after text
    # projection. Keep a deterministic commitment to the already-redacted input
    # instead of returning an oversized record or silently dropping all context.
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fallback: dict[str, object] = {
        "_truncated": True,
        "_original_size_bytes": original_size,
        "_redacted_sha256": digest,
    }
    if evidence_serialized_size(fallback) <= max_bytes:
        return fallback
    return {}
