"""ActionIR fingerprints for V21-02 (01 §9 指纹冻结, L414-447).

- ``authorization_fingerprint``：``HMAC(server_secret, JCS(白名单投影))``，
  带域分离标签 ``agentguard/v21/action-ir/v1``，输出 ``hmac-sha256:`` 前缀。
  参与项（白名单）：subject/principal、task_id/revision、action_type、
  final canonical resources/destinations、security-relevant arguments、
  effect、runtime binding、scope_digest、argument_digest。
  排除项：latency、random decision id、created_at、provider request id、
  display text、unordered debug metadata —— 靠「只投影白名单」天然排除，
  resource/destination 投影另显式剔除 ``display_summary``。
- ``audit_fingerprint``：非 keyed sha256，仅脱敏/摘要字段，``sha256:`` 前缀。
  可公开到 Audit/Dashboard，只用于关联和解释，不能承担授权安全语义。

Secret 纪律：``server_secret`` 仅由构造方以 ``bytes`` 注入；本模块不读取
环境变量、不写日志、不出现在任何 digest 输出的明文中。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
from typing import Any

from .canonical_json import canonical_json_bytes, canonical_sha256
from .models import ActionIR, CanonicalResource

__all__ = [
    "AUTHORIZATION_DOMAIN_TAG",
    "audit_fingerprint",
    "audit_projection",
    "authorization_fingerprint",
    "authorization_projection",
]

# 域分离标签：不同对象/版本的指纹输入空间互不碰撞。
AUTHORIZATION_DOMAIN_TAG = "agentguard/v21/action-ir/v1"


def _resource_projection(resource: CanonicalResource) -> dict[str, Any]:
    """final canonical identity 投影。

    剔除 ``display_summary``（展示文本无授权语义）与 ``resource_id``
    （由 builder 以 event_id 派生的簿记 id，属于事件级随机量）。
    """
    dumped = resource.model_dump(mode="json")
    dumped.pop("display_summary", None)
    dumped.pop("resource_id", None)
    return dumped


def authorization_projection(ir: ActionIR) -> dict[str, Any]:
    """authorization_fingerprint 的白名单投影（测试与审计可复用）。"""
    return {
        "schema_version": ir.schema_version,
        "principal_id": ir.principal_id,
        "task_id": ir.task_id,
        "task_revision": ir.task_revision,
        "action_type": ir.action_type,
        "resources": [_resource_projection(resource) for resource in ir.resources],
        "destinations": [
            _resource_projection(destination) for destination in ir.destinations
        ],
        "security_arguments": [
            item.model_dump(mode="json")
            for item in ir.canonical_arguments.items
            if item.security_relevant
        ],
        "effects": ir.effects.model_dump(mode="json"),
        "runtime_binding_id": ir.runtime_binding_id,
        "scope_digest": ir.scope_digest,
        "argument_digest": ir.argument_digest,
    }


def authorization_fingerprint(server_secret: bytes, ir: ActionIR) -> str:
    """HMAC-SHA256 授权指纹：域分离标签 + 白名单投影的受限 JCS 字节。

    用于 ``allow_once``、capability exact binding、内部 CAS（01 §9, L443）。
    """
    if not isinstance(server_secret, bytes) or not server_secret:
        raise ValueError("server_secret must be non-empty bytes")
    payload = AUTHORIZATION_DOMAIN_TAG.encode("utf-8") + b"\x00"
    payload += canonical_json_bytes(authorization_projection(ir))
    digest = hmac_module.new(server_secret, payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def audit_projection(ir: ActionIR) -> dict[str, Any]:
    """audit_fingerprint 的白名单投影（测试与审计可复用）。

    键名与 ``ActionIR.audit_fingerprint_fields`` 声明一一对应。
    """
    return {
        "schema_version": ir.schema_version,
        "event_id": ir.event_id,
        "action_id": ir.action_id,
        "trace_id": ir.trace_id,
        "tool_name": ir.tool_name,
        "action_type": ir.action_type,
        "impact": ir.impact,
        "resource_ids": [resource.canonical_id for resource in ir.resources],
        "destination_ids": [
            destination.canonical_id for destination in ir.destinations
        ],
        "argument_digest": ir.argument_digest,
        "normalizer_version": ir.normalizer_version,
    }


def audit_fingerprint(ir: ActionIR) -> str:
    """非 keyed sha256 审计指纹：仅脱敏/摘要字段，无授权安全语义。"""
    return canonical_sha256(audit_projection(ir))
