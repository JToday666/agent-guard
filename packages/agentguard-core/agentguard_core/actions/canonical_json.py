"""Deterministic canonical JSON for V21-02 (restricted RFC 8785 / JCS subset).

本模块实现项目统一的受限 canonical JSON 编码（01_F1 §29, L1162-1181）：

- object 键按 Unicode 码点排序（``sorted`` 对 ``str`` 的默认顺序）；
- 紧凑分隔符 ``(",", ":")``，无多余空白；
- ``ensure_ascii=False``，UTF-8 序列化；
- 类型域限制为 ``str / int / bool / None / list / dict``（dict 键必须为
  ``str``）；``float`` 与任何未知类型一律抛出 ``CanonicalizationError``。

与完整 RFC 8785 的差异边界（冻结声明）：

- 本实现是 RFC 8785 的「禁 float 子集」：RFC 8785 对 IEEE 754 double 定义了
  确定性序列化（ES6 Number 规则），而本实现直接拒绝 ``float``，避免任何
  浮点表示歧义进入安全摘要。
- 键排序使用 Unicode 码点顺序；RFC 8785 规定 UTF-16 code unit 顺序。两者
  仅在 BMP 之外（代理对）键名上可能产生顺序差异，本项目安全摘要输入禁止
  使用此类键名，差异面在本契约内为空。
- 不处理 ``-0``、``NaN``、``Infinity``（均随 float 一起被拒绝）。

该模块只依赖标准库，不引入 DB/HTTP，也不触碰判定路径。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
from typing import Any

__all__ = [
    "CanonicalizationError",
    "canonical_hmac_sha256",
    "canonical_json",
    "canonical_json_bytes",
    "canonical_sha256",
]


class CanonicalizationError(ValueError):
    """输入超出受限 canonical JSON 类型域（float / 未知类型 / 非 str 键）。"""


def canonical_json(value: Any) -> str:
    """返回受限类型域内 ``value`` 的确定性 canonical JSON 文本。"""
    return _serialize(value, path="$")


def canonical_json_bytes(value: Any) -> bytes:
    """返回 canonical JSON 的 UTF-8 字节（摘要输入口径）。"""
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """对 canonical JSON 字节计算 sha256，输出 ``sha256:`` 前缀 hex。"""
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def canonical_hmac_sha256(key: bytes, value: Any) -> str:
    """对 canonical JSON 字节计算 HMAC-SHA256，输出 ``hmac-sha256:`` 前缀 hex。

    ``key`` 必须由构造方以 ``bytes`` 注入；本函数不读取环境变量，也不把
    key 或输入写入日志。
    """
    if not isinstance(key, bytes) or not key:
        raise ValueError("HMAC key must be non-empty bytes")
    digest = hmac_module.new(key, canonical_json_bytes(value), hashlib.sha256)
    return f"hmac-sha256:{digest.hexdigest()}"


def _serialize(value: Any, *, path: str) -> str:
    # bool 是 int 子类，必须先于 int 判定；两者都直接交给 json.dumps。
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path}: float values are outside the restricted canonical JSON "
            "type domain (RFC 8785 float subset is forbidden)"
        )
    if isinstance(value, list):
        parts = [
            _serialize(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
        return f"[{','.join(parts)}]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"{path}: object keys must be str, got {type(key).__name__}"
                )
            rendered_key = json.dumps(
                key, ensure_ascii=False, separators=(",", ":")
            )
            rendered_value = _serialize(value[key], path=f"{path}.{key}")
            parts.append(f"{rendered_key}:{rendered_value}")
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(
        f"{path}: unsupported type {type(value).__name__} for canonical JSON"
    )
