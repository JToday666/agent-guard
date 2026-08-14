"""Argument canonicalization for V21-02 (01 §7.1, L236-252).

把原始 Tool payload arguments 递归展平为 ``json_pointer`` +
``CanonicalScalar`` 条目：

- 保类型，不做任何强制转换：``str "123"`` 与 ``int 123`` 是不同的规范
  参数，digest 也不同；
- 条目按 ``json_pointer`` 码点排序（集合语义，01 §29）；
- ``argument_digest`` 用 ``actions.canonical_json`` 的受限 canonical JSON
  计算（``sha256:`` 前缀）。

Bounded computation：参数条目数量与单值长度设上限；超限不抛异常，而是
确定性截断并标记 ``partial=True`` + reason_code，由调用方（builder）把
reason_code 写入 ActionIR.data_refs。float 值在受限 canonical JSON 类型域
之外：同样跳过并标记，绝不静默协变。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical_json import canonical_sha256
from .models import CANONICALIZATION_VERSION, CanonicalArgument, CanonicalArguments

__all__ = [
    "DEFAULT_SECURITY_ARGUMENT_KEYS",
    "MAX_ARGUMENT_DEPTH",
    "MAX_ARGUMENT_ITEMS",
    "MAX_VALUE_LENGTH",
    "NormalizedArguments",
    "normalize_arguments",
]

# 有界计算上限：防止恶意 payload 通过超大参数树耗尽计算资源。
MAX_ARGUMENT_ITEMS = 256
MAX_VALUE_LENGTH = 4096
# 递归展平深度上限：超限停止下钻并降级标记，避免 RecursionError。
MAX_ARGUMENT_DEPTH = 64

# security-relevant 参数名（按指针末段 casefold 匹配）。授权 matcher 只能
# 看到这些条目；其余条目仍进入 argument_digest 但不参与 capability 匹配。
DEFAULT_SECURITY_ARGUMENT_KEYS = frozenset(
    {
        "token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "auth",
        "authorization",
        "password",
        "credential",
        "user",
        "username",
        "account",
        "recipient",
        "to",
    }
)

REASON_DEPTH_LIMIT = "arguments.depth_limit_exceeded"
REASON_FLOAT_UNSUPPORTED = "arguments.float_value_unsupported"
REASON_ITEM_LIMIT = "arguments.item_limit_exceeded"
REASON_VALUE_TRUNCATED = "arguments.value_length_exceeded"
REASON_VALUE_TYPE_UNSUPPORTED = "arguments.value_type_unsupported"


@dataclass(frozen=True)
class NormalizedArguments:
    """规范化结果：canonical 模型 + 有界计算降级标记。"""

    canonical: CanonicalArguments
    partial: bool
    reason_codes: list[str] = field(default_factory=list)


def normalize_arguments(
    arguments: Mapping[str, Any],
    *,
    security_keys: frozenset[str] = DEFAULT_SECURITY_ARGUMENT_KEYS,
) -> NormalizedArguments:
    """递归展平 ``arguments`` 为排序后的规范参数集合。

    JSON pointer 转义遵循 RFC 6901：``~`` → ``~0``，``/`` → ``~1``。
    """
    items: list[CanonicalArgument] = []
    reason_codes: list[str] = []
    _flatten(arguments, "", items, reason_codes, security_keys, depth=0)

    partial = bool(reason_codes)
    # 先全局排序再截断，保证截断结果与展平顺序无关（确定性）。
    items.sort(key=lambda item: item.json_pointer)
    if len(items) > MAX_ARGUMENT_ITEMS:
        items = items[:MAX_ARGUMENT_ITEMS]
        partial = True
        if REASON_ITEM_LIMIT not in reason_codes:
            reason_codes.append(REASON_ITEM_LIMIT)
    digest_projection = [
        {
            "json_pointer": item.json_pointer,
            "security_relevant": item.security_relevant,
            "value": item.value,
        }
        for item in items
    ]
    canonical = CanonicalArguments(
        items=items,
        canonicalization_version=CANONICALIZATION_VERSION,
        argument_digest=canonical_sha256(digest_projection),
    )
    return NormalizedArguments(
        canonical=canonical, partial=partial, reason_codes=reason_codes
    )


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _is_security_relevant(pointer: str, security_keys: frozenset[str]) -> bool:
    last_segment = pointer.rsplit("/", 1)[-1]
    # 指针 token 已被转义；判定前还原转义再 casefold。
    unescaped = last_segment.replace("~1", "/").replace("~0", "~")
    return unescaped.casefold() in security_keys


def _flatten(
    value: Any,
    pointer: str,
    items: list[CanonicalArgument],
    reason_codes: list[str],
    security_keys: frozenset[str],
    depth: int,
) -> None:
    if isinstance(value, (dict, list)) and depth >= MAX_ARGUMENT_DEPTH:
        # 深度上限：停止下钻并显式降级，绝不 RecursionError。
        if REASON_DEPTH_LIMIT not in reason_codes:
            reason_codes.append(REASON_DEPTH_LIMIT)
        return
    if isinstance(value, dict):
        for key in sorted(value):
            _flatten(
                value[key],
                f"{pointer}/{_escape_pointer_token(str(key))}",
                items,
                reason_codes,
                security_keys,
                depth + 1,
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _flatten(
                item,
                f"{pointer}/{index}",
                items,
                reason_codes,
                security_keys,
                depth + 1,
            )
        return
    if isinstance(value, float):
        # 受限 canonical JSON 禁 float：跳过该值并显式降级，绝不协变。
        if REASON_FLOAT_UNSUPPORTED not in reason_codes:
            reason_codes.append(REASON_FLOAT_UNSUPPORTED)
        return
    if value is None or isinstance(value, (bool, int, str)):
        scalar: str | int | bool | None
        if isinstance(value, str):
            if len(value) > MAX_VALUE_LENGTH:
                scalar = value[:MAX_VALUE_LENGTH]
                if REASON_VALUE_TRUNCATED not in reason_codes:
                    reason_codes.append(REASON_VALUE_TRUNCATED)
            else:
                scalar = value
        else:
            scalar = value
        items.append(
            CanonicalArgument(
                json_pointer=pointer,
                value=scalar,
                security_relevant=_is_security_relevant(pointer, security_keys),
            )
        )
        return
    # 未知类型（对象、bytes 等）：不进入规范参数，显式降级。
    if REASON_VALUE_TYPE_UNSUPPORTED not in reason_codes:
        reason_codes.append(REASON_VALUE_TYPE_UNSUPPORTED)
