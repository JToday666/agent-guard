"""Signed audit-window cursor contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from guard_api.services.audit_window_cursor import (
    CURSOR_TTL,
    CursorExpiredError,
    decode_cursor,
    encode_cursor,
    normalize_window_filters,
)

_SIGNING_KEY = b"agentguard-test-cursor-signing-key-32-bytes"
_OTHER_KEY = b"agentguard-other-cursor-signing-key-32-bytes"
_NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)


def _cursor() -> str:
    return encode_cursor(
        upper_sequence=12,
        after_sequence=8,
        filters=normalize_window_filters(trace_id="trace-1", runtime="openclaw"),
        limit=4,
        snapshot_at="2026-08-09T11:59:00Z",
        signing_key=_SIGNING_KEY,
        issued_at=_NOW,
    )


def test_signed_cursor_round_trip_preserves_the_snapshot_scope() -> None:
    cursor = _cursor()

    state = decode_cursor(cursor, signing_key=_SIGNING_KEY, now=_NOW)

    assert cursor.startswith("awc3.")
    assert "=" not in cursor
    assert state["upper_sequence"] == 12
    assert state["after_sequence"] == 8
    assert state["filters"] == {
        "trace_id": "trace-1",
        "case_id": None,
        "runtime": "openclaw",
        "decision": None,
    }
    assert state["limit"] == 4


@pytest.mark.parametrize("segment", [1, 2])
def test_signed_cursor_rejects_payload_or_signature_tampering(segment: int) -> None:
    parts = _cursor().split(".")
    value = parts[segment]
    parts[segment] = f"{'A' if value[0] != 'A' else 'B'}{value[1:]}"

    with pytest.raises(CursorExpiredError):
        decode_cursor(".".join(parts), signing_key=_SIGNING_KEY, now=_NOW)


def test_signed_cursor_rejects_a_different_server_key() -> None:
    with pytest.raises(CursorExpiredError):
        decode_cursor(_cursor(), signing_key=_OTHER_KEY, now=_NOW)


def test_signed_cursor_expires_at_the_fixed_ttl_boundary() -> None:
    cursor = _cursor()
    decode_cursor(
        cursor,
        signing_key=_SIGNING_KEY,
        now=_NOW + CURSOR_TTL - timedelta(seconds=1),
    )

    with pytest.raises(CursorExpiredError):
        decode_cursor(
            cursor,
            signing_key=_SIGNING_KEY,
            now=_NOW + CURSOR_TTL,
        )


def test_signed_cursor_rejects_malformed_and_oversized_inputs() -> None:
    for cursor in ("not-a-cursor", "awc3...", "x" * 4097):
        with pytest.raises(CursorExpiredError):
            decode_cursor(cursor, signing_key=_SIGNING_KEY, now=_NOW)
