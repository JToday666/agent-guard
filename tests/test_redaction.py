"""Tests for the unified redaction and bounded projection tool (§21.1/§21.2)."""

from __future__ import annotations

import json

from agentguard_core import AuditEvent

from guard_api.services.redaction import (
    ARRAY_LIMIT,
    CONTENT_PREVIEW_LIMIT,
    MAX_EVIDENCE_BYTES,
    MAX_NESTING_DEPTH,
    REDACTED,
    SUMMARY_TEXT_LIMIT,
    bound_redacted_value,
    bound_value,
    enforce_evidence_budget,
    evidence_serialized_size,
    looks_sensitive_key,
    redact_structure,
    sanitize_audit_event,
    scrub_text,
    truncate_text,
)


def test_sensitive_key_markers_cover_contract_list() -> None:
    for key in (
        "token",
        "auth_secret",
        "Password",
        "Authorization",
        "service_credential",
        "api_key",
        "session_cookie",
        "private_key_pem",
        "access_key",
        "session_id",
        "approval_nonce",
    ):
        assert looks_sensitive_key(key)
    assert not looks_sensitive_key("tool_name")
    assert not looks_sensitive_key("resource")


def test_redact_structure_replaces_sensitive_values() -> None:
    payload = {
        "api_token": "abc123",
        "nested": {"password": "hunter2", "visible": "ok"},
        "items": [{"secret": "s3cr3t"}, {"plain": "keep"}],
    }

    redacted = redact_structure(payload)

    assert redacted["api_token"] == REDACTED
    assert redacted["nested"]["password"] == REDACTED
    assert redacted["nested"]["visible"] == "ok"
    assert redacted["items"][0]["secret"] == REDACTED
    assert redacted["items"][1]["plain"] == "keep"


def test_scrub_text_cleans_credential_content() -> None:
    text = (
        "use sk-abcdefghijklmnop for openai; "
        "password: hunter2; "
        "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature; "
        "export DB_PASSWORD=${DB_PASSWORD}; "
        "Cookie: session=abcdef123456; "
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
    )

    scrubbed = scrub_text(text)

    assert "sk-abcdefghijklmnop" not in scrubbed
    assert "hunter2" not in scrubbed
    assert "eyJhbGciOiJSUzI1NiJ9" not in scrubbed
    assert "MIIE" not in scrubbed
    assert REDACTED in scrubbed


def test_truncate_text_boundary() -> None:
    exact = "x" * SUMMARY_TEXT_LIMIT
    assert truncate_text(exact, SUMMARY_TEXT_LIMIT) == exact
    assert truncate_text("x" * (SUMMARY_TEXT_LIMIT + 1), SUMMARY_TEXT_LIMIT) == (
        exact + "..."
    )
    assert len(
        truncate_text("y" * CONTENT_PREVIEW_LIMIT * 2, CONTENT_PREVIEW_LIMIT)
    ) == (CONTENT_PREVIEW_LIMIT + 3)


def test_bound_value_applies_array_and_depth_limits() -> None:
    items = list(range(ARRAY_LIMIT + 5))

    bounded = bound_value(items)

    assert bounded == list(range(ARRAY_LIMIT))

    deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "leaf"}}}}}}}

    bounded_deep = bound_value(deep)

    # 嵌套达到第 6 层时容器折叠为 "..."，不保留更深层内容。
    assert bounded_deep == {"a": {"b": {"c": {"d": {"e": "..."}}}}}
    assert MAX_NESTING_DEPTH == 6


def test_bound_redacted_value_combines_redaction_and_bounds() -> None:
    payload = {
        "api_token": "abc123",
        "notes": "z" * (SUMMARY_TEXT_LIMIT + 10),
        "items": [{"n": i} for i in range(ARRAY_LIMIT + 3)],
    }

    bounded = bound_redacted_value(payload)

    assert bounded["api_token"] == REDACTED
    assert len(bounded["notes"]) == SUMMARY_TEXT_LIMIT + 3
    assert len(bounded["items"]) == ARRAY_LIMIT


def test_enforce_evidence_budget_truncates_instead_of_rejecting() -> None:
    evidence: dict[str, object] = {
        "guard_event": {"user_task": "u" * 30_000},
        "guard_decision": {"reason": "r" * 40_000},
    }

    bounded = enforce_evidence_budget(evidence)

    assert evidence_serialized_size(bounded) <= MAX_EVIDENCE_BYTES
    assert bounded["guard_event"]["user_task"] != evidence["guard_event"]["user_task"]


def test_enforce_evidence_budget_keeps_small_evidence_untouched() -> None:
    evidence: dict[str, object] = {"guard_event": {"user_task": "small"}}

    assert enforce_evidence_budget(evidence) == evidence


def test_sanitize_audit_event_cleans_all_browser_readable_free_text() -> None:
    provider_key = "sk-abcdefghijklmnop"
    bearer = "Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"
    event = AuditEvent(
        audit_id="audit_redaction_boundary",
        schema_version="0.4",
        record_type="runtime_observation",
        trace_id="trace_redaction_boundary",
        summary=f"Observed {provider_key}",
        reason=bearer,
        resource_targets=[provider_key],
        rule_hits=[f"rule {bearer}"],
        links={"action_id": "call_redaction_boundary"},
        metadata={
            "ordinary_note": provider_key,
            "nested": {"content": bearer},
        },
        evidence={"guard_event": {"user_task": bearer, "note": provider_key}},
    )

    sanitized = sanitize_audit_event(event)
    serialized = json.dumps(sanitized.model_dump(mode="json"), ensure_ascii=False)

    assert provider_key not in serialized
    assert "eyJhbGciOiJSUzI1NiJ9" not in serialized
    assert REDACTED in serialized
    assert sanitized.audit_id == event.audit_id
    assert sanitized.trace_id == event.trace_id
    assert sanitized.links == event.links
