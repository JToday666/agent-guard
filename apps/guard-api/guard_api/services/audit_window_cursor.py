"""审计窗口 cursor 编解码（契约 §5.2）。

cursor 是不可解释的 base64url 不透明串，绑定快照上界 upper_sequence、
规范化 filters 指纹、limit 与当前位置 after_sequence；服务端不保存
cursor 状态，快照由 upper_sequence 固化。指纹复用
storage/integrity.canonical_sha256 保证 Memory/PostgreSQL 一致。
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from guard_api.storage.integrity import canonical_sha256

CURSOR_VERSION = 1
_CURSOR_PREFIX = "awc"
_FILTER_KEYS = ("trace_id", "case_id", "runtime", "decision")


class CursorExpiredError(Exception):
    """cursor 无法解码或版本不受支持，对应 410 CURSOR_EXPIRED。"""


class CursorScopeMismatchError(Exception):
    """随 cursor 提交的 filters/limit 与 cursor 绑定的作用域不一致。"""


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


def filters_fingerprint(filters: dict[str, str | None]) -> str:
    payload = {key: filters.get(key) for key in _FILTER_KEYS}
    return canonical_sha256({"cursor_filters": payload})


def encode_cursor(
    *,
    upper_sequence: int,
    after_sequence: int,
    filters: dict[str, str | None],
    limit: int,
) -> str:
    payload = {
        "version": CURSOR_VERSION,
        "kind": _CURSOR_PREFIX,
        "upper_sequence": upper_sequence,
        "after_sequence": after_sequence,
        "fingerprint": filters_fingerprint(filters),
        "limit": limit,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str) -> dict[str, Any]:
    """解码并校验 cursor；任何失败或旧版本抛 CursorExpiredError。"""

    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise CursorExpiredError(cursor) from None
    if not isinstance(payload, dict):
        raise CursorExpiredError(cursor)
    if payload.get("version") != CURSOR_VERSION or payload.get("kind") != _CURSOR_PREFIX:
        raise CursorExpiredError(cursor)
    upper_sequence = payload.get("upper_sequence")
    after_sequence = payload.get("after_sequence")
    fingerprint = payload.get("fingerprint")
    limit = payload.get("limit")
    if (
        not isinstance(upper_sequence, int)
        or not isinstance(after_sequence, int)
        or not isinstance(fingerprint, str)
        or not isinstance(limit, int)
    ):
        raise CursorExpiredError(cursor)
    return {
        "upper_sequence": upper_sequence,
        "after_sequence": after_sequence,
        "fingerprint": fingerprint,
        "limit": limit,
    }
