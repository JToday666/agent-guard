"""审计窗口 cursor 编解码（契约 §5.2）。

cursor 是带 HMAC-SHA256 签名的 base64url 不透明串，自包含快照上界、
规范化 filters、limit、当前位置和固定有效期；服务端不保存 cursor 状态。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

CURSOR_VERSION = 3
CURSOR_TTL = timedelta(minutes=15)
_CURSOR_PREFIX = "awc3"
_CURSOR_KIND = "audit_window"
_FILTER_KEYS = ("trace_id", "case_id", "runtime", "decision")
_PAYLOAD_KEYS = {
    "version",
    "kind",
    "upper_sequence",
    "after_sequence",
    "filters",
    "limit",
    "snapshot_at",
    "issued_at",
    "expires_at",
}
_MAX_CURSOR_LENGTH = 4096
_MAX_CLOCK_SKEW_SECONDS = 60
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CursorExpiredError(Exception):
    """cursor 已过期、被篡改或版本不受支持，对应 410 CURSOR_EXPIRED。"""


def normalize_window_filters(
    *,
    trace_id: str | None = None,
    case_id: str | None = None,
    runtime: str | None = None,
    decision: str | None = None,
) -> dict[str, str | None]:
    """规范化窗口过滤参数：空白串与空串统一为 None。"""

    normalized: dict[str, str | None] = {}
    for key, value in (
        ("trace_id", trace_id),
        ("case_id", case_id),
        ("runtime", runtime),
        ("decision", decision),
    ):
        if value is not None:
            value = value.strip()
        normalized[key] = value or None
    return normalized


def encode_cursor(
    *,
    upper_sequence: int,
    after_sequence: int,
    filters: dict[str, str | None],
    limit: int,
    snapshot_at: str,
    signing_key: bytes,
    issued_at: datetime,
) -> str:
    issued_at = _utc_datetime(issued_at)
    issued_at_seconds = int(issued_at.timestamp())
    payload = {
        "version": CURSOR_VERSION,
        "kind": _CURSOR_KIND,
        "upper_sequence": upper_sequence,
        "after_sequence": after_sequence,
        "filters": {key: filters.get(key) for key in _FILTER_KEYS},
        "limit": limit,
        "snapshot_at": snapshot_at,
        "issued_at": issued_at_seconds,
        "expires_at": issued_at_seconds + int(CURSOR_TTL.total_seconds()),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded_payload = _base64url_encode(raw)
    signing_input = f"{_CURSOR_PREFIX}.{encoded_payload}".encode("ascii")
    signature = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    return f"{_CURSOR_PREFIX}.{encoded_payload}.{_base64url_encode(signature)}"


def decode_cursor(
    cursor: str,
    *,
    signing_key: bytes,
    now: datetime,
) -> dict[str, Any]:
    """验证 cursor 签名、结构与有效期；任何失败均视为 cursor 失效。"""

    if not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
        raise CursorExpiredError(cursor)
    try:
        prefix, encoded_payload, encoded_signature = cursor.split(".")
    except ValueError:
        raise CursorExpiredError(cursor) from None
    if prefix != _CURSOR_PREFIX:
        raise CursorExpiredError(cursor)
    try:
        raw = _base64url_decode(encoded_payload)
        supplied_signature = _base64url_decode(encoded_signature)
    except (ValueError, binascii.Error):
        raise CursorExpiredError(cursor) from None
    signing_input = f"{prefix}.{encoded_payload}".encode("ascii")
    expected_signature = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise CursorExpiredError(cursor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CursorExpiredError(cursor) from None
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise CursorExpiredError(cursor)
    if payload.get("version") != CURSOR_VERSION or payload.get("kind") != _CURSOR_KIND:
        raise CursorExpiredError(cursor)

    upper_sequence = payload.get("upper_sequence")
    after_sequence = payload.get("after_sequence")
    filters = payload.get("filters")
    limit = payload.get("limit")
    snapshot_at = payload.get("snapshot_at")
    issued_at = payload.get("issued_at")
    expires_at = payload.get("expires_at")
    if (
        type(upper_sequence) is not int
        or type(after_sequence) is not int
        or not isinstance(filters, dict)
        or type(limit) is not int
        or not isinstance(snapshot_at, str)
        or type(issued_at) is not int
        or type(expires_at) is not int
        or upper_sequence < 1
        or after_sequence < 1
        or after_sequence > upper_sequence
        or not 1 <= limit <= 1000
        or expires_at - issued_at != int(CURSOR_TTL.total_seconds())
    ):
        raise CursorExpiredError(cursor)
    try:
        parsed_snapshot_at = datetime.fromisoformat(snapshot_at.replace("Z", "+00:00"))
    except ValueError:
        raise CursorExpiredError(cursor) from None
    if parsed_snapshot_at.tzinfo is None:
        raise CursorExpiredError(cursor)

    now_seconds = int(_utc_datetime(now).timestamp())
    if issued_at > now_seconds + _MAX_CLOCK_SKEW_SECONDS or now_seconds >= expires_at:
        raise CursorExpiredError(cursor)

    if set(filters) != set(_FILTER_KEYS):
        raise CursorExpiredError(cursor)
    normalized_filters: dict[str, str | None] = {}
    for key in _FILTER_KEYS:
        value = filters.get(key)
        if value is not None and (
            not isinstance(value, str) or not value or value != value.strip()
        ):
            raise CursorExpiredError(cursor)
        normalized_filters[key] = value
    return {
        "upper_sequence": upper_sequence,
        "after_sequence": after_sequence,
        "filters": normalized_filters,
        "limit": limit,
        "snapshot_at": snapshot_at,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not _BASE64URL_RE.fullmatch(value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(f"{value}{padding}", altchars=b"-_", validate=True)


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("cursor timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)
