"""V21-06 AuthorityVerdict 判定与消费 intent 构造（Phase 1 纯新增）。

本模块是 V21-06（Authority / Capability）分支的判定纯函数：

- ``compute_authority_verdict``：把 ``OnlineSecurityState.active_grants``
  与 ``ActionIR`` 匹配（action_type / resource / destination 约束 +
  expiry / revoked / fingerprint 校验），产出 01 §23 冻结的
  ``AuthorityVerdict``；
- ``build_consumption_intent``：为执行前原子消费构造确定性
  ``ConsumptionIntent``（本文件新增 frozen 模型）。

C4 分层（04 §12）：Core 只做校验/构造确定性 intent/计算 digest，
**零原子操作**；remaining-use CAS、GrantConsumption 与 ExecutionLease
的原子写入在 Guard API 存储层单事务完成（``lease_service`` +
``storage.consume_grant``）。

匹配求值复用 ``actions/constraints.py`` 的表驱动 ``matches_*``
（未知 op → False，fail-closed）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ...actions.canonical_json import canonical_sha256
from ...actions.constraints import (
    matches_destination,
    matches_resource,
)
from ...actions.models import ActionIR
from ...signals.models import AuthorityVerdict
from ..facts import CapabilityGrant
from ..state import OnlineSecurityState

__all__ = [
    "AuthorityProjectionError",
    "ConsumptionIntent",
    "build_consumption_intent",
    "compute_authority_verdict",
]


class AuthorityProjectionError(ValueError):
    """V21-06 fail-closed 结构化异常：``reason_code`` 前缀 ``v21-06:``。"""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


# ---------------------------------------------------------------------------
# ConsumptionIntent（新增 frozen 模型；Core 侧零原子操作，C4）
# ---------------------------------------------------------------------------


class ConsumptionIntent(BaseModel):
    """grant 消费确定性 intent（Core 构造，Guard API 存储层执行）。

    ``intent_digest`` 仅由 ``grant_id`` / ``action_id`` /
    ``authorization_fingerprint`` 三者经受限 JCS sha256 派生：这是防双花
    幂等重试的稳定身份（同内容重试返回同一 token，01 §31），其余字段
    只作为存储层校验/绑定上下文，不进入 digest。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.1"] = "2.1"

    grant_id: str
    scope_digest: str
    action_id: str
    authorization_fingerprint: str
    approval_id: str
    runtime_binding_id: str

    intent_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """``intent_digest`` 白名单：防双花的三元稳定身份（01 §31）。"""
        return frozenset(
            {"grant_id", "action_id", "authorization_fingerprint"}
        )


def consumption_intent_digest(
    *, grant_id: str, action_id: str, authorization_fingerprint: str
) -> str:
    """``intent_digest``：三元身份的受限 JCS sha256（``sha256:`` 前缀）。"""
    return canonical_sha256(
        {
            "action_id": action_id,
            "authorization_fingerprint": authorization_fingerprint,
            "grant_id": grant_id,
        }
    )


# ---------------------------------------------------------------------------
# 时间比较（RFC 3339，带时区；无法解析 → fail-closed）
# ---------------------------------------------------------------------------


def _parse_rfc3339(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


# ---------------------------------------------------------------------------
# AuthorityVerdict（01 §23）
# ---------------------------------------------------------------------------


def compute_authority_verdict(
    state: OnlineSecurityState,
    action_ir: ActionIR,
    *,
    evaluated_at: str | None = None,
) -> AuthorityVerdict:
    """匹配 ``state.active_grants`` 与 ``ActionIR``，产出 AuthorityVerdict。

    逐 grant 校验（fail-closed，全部不匹配才 unauthorized）：

    1. revoked（grant 自身标记或 ``revoked_grant_ids``）→ 跳过；
    2. ``remaining_uses`` 已耗尽 → 跳过（用量权威在存储层 CAS，这里是
       投影层预检）；
    3. expiry：``expires_at`` 存在而 ``evaluated_at`` 缺失 → 无法证明
       有效，fail-closed 不匹配；两者可比且已过期 → 不匹配；
    4. fingerprint：human_approval grant 必须携带
       ``exact_authorization_fingerprint`` 且与
       ``action_ir.authorization_fingerprint`` 恒定时间语义一致；
    5. action_type / resource / destination 约束：复用
       ``matches_resource`` / ``matches_destination``（空约束列表视为
       无限制；约束非空而动作未命中 → explicit scope mismatch）。

    ``matched_grant_ids`` 非空 → ``authorized``；否则 ``unauthorized``
    并在 ``missing_capabilities`` / ``explicit_scope_mismatches`` 给出
    可审计原因。
    """
    matched: list[str] = []
    mismatches: list[str] = []
    revoked_ids = frozenset(state.revoked_grant_ids)

    evaluated_moment = (
        _parse_rfc3339(evaluated_at) if evaluated_at is not None else None
    )
    if evaluated_at is not None and evaluated_moment is None:
        raise AuthorityProjectionError(
            "v21-06:invalid_evaluated_at",
            "evaluated_at must be an RFC 3339 timestamp with timezone",
        )

    for grant in state.active_grants:
        if grant.grant_id in revoked_ids or grant.revoked:
            mismatches.append(f"{grant.grant_id}:revoked")
            continue
        if grant.remaining_uses is not None and grant.remaining_uses <= 0:
            mismatches.append(f"{grant.grant_id}:uses_exhausted")
            continue
        if grant.expires_at is not None:
            expires_moment = _parse_rfc3339(grant.expires_at)
            if evaluated_moment is None or expires_moment is None:
                mismatches.append(f"{grant.grant_id}:expiry_unverifiable")
                continue
            if evaluated_moment >= expires_moment:
                mismatches.append(f"{grant.grant_id}:expired")
                continue
        if grant.source_type == "human_approval":
            expected_fingerprint = grant.exact_authorization_fingerprint
            if expected_fingerprint is None:
                mismatches.append(f"{grant.grant_id}:invalid_approval_grant")
                continue
            if expected_fingerprint != action_ir.authorization_fingerprint:
                mismatches.append(f"{grant.grant_id}:fingerprint_mismatch")
                continue
        if grant.action_types and action_ir.action_type not in set(
            grant.action_types
        ):
            continue
        if grant.resource_constraints and not all(
            matches_resource(constraint, action_ir.resources)
            for constraint in grant.resource_constraints
        ):
            mismatches.append(f"{grant.grant_id}:resource_scope_mismatch")
            continue
        if grant.destination_constraints and not all(
            matches_destination(constraint, action_ir.destinations)
            for constraint in grant.destination_constraints
        ):
            mismatches.append(f"{grant.grant_id}:destination_scope_mismatch")
            continue
        matched.append(grant.grant_id)

    if matched:
        return AuthorityVerdict(
            status="authorized",
            matched_grant_ids=matched,
            missing_capabilities=[],
            explicit_scope_mismatches=mismatches,
            evidence_refs=[],
        )
    return AuthorityVerdict(
        status="unauthorized",
        matched_grant_ids=[],
        missing_capabilities=[action_ir.action_type],
        explicit_scope_mismatches=mismatches,
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# build_consumption_intent（Core 零原子操作，C4）
# ---------------------------------------------------------------------------


def build_consumption_intent(
    grant: CapabilityGrant, action_ir: ActionIR
) -> ConsumptionIntent:
    """为执行前原子消费构造确定性 ``ConsumptionIntent``。

    fail-closed 前置校验：

    - 只有 ``source_type == "human_approval"`` 的 allow_once grant 可消费
      （02 §12：V2 中 LLM Reviewer 不能产生可消费 grant）；
    - revoked grant 不可消费；
    - grant 必须携带 ``exact_authorization_fingerprint``，且与
      ``action_ir.authorization_fingerprint`` 一致；
    - grant 必须覆盖该 action 的 action_type / resource / destination
      约束（空约束列表视为无限制）。

    ``runtime_binding_id`` 取自已认证 ``ActionIR``（不接受 Adapter
    自报，01 §4 纪律）。本函数不读时钟、不触存储、不做任何扣减。
    """
    if grant.source_type != "human_approval":
        raise AuthorityProjectionError(
            "v21-06:consumption_requires_human_approval",
            f"only human_approval allow_once grants are consumable, "
            f"got source_type={grant.source_type!r}",
        )
    if grant.revoked:
        raise AuthorityProjectionError(
            "v21-06:grant_revoked",
            "revoked grant cannot be consumed",
        )
    fingerprint = grant.exact_authorization_fingerprint
    if fingerprint is None:
        raise AuthorityProjectionError(
            "v21-06:missing_fingerprint",
            "human_approval grant requires exact_authorization_fingerprint",
        )
    if fingerprint != action_ir.authorization_fingerprint:
        raise AuthorityProjectionError(
            "v21-06:fingerprint_mismatch",
            "action authorization_fingerprint does not match the grant",
        )
    if grant.scope_digest != action_ir.scope_digest:
        raise AuthorityProjectionError(
            "v21-06:scope_mismatch",
            "action scope_digest does not match the grant scope",
        )
    if grant.action_types and action_ir.action_type not in set(
        grant.action_types
    ):
        raise AuthorityProjectionError(
            "v21-06:action_type_not_granted",
            f"action_type {action_ir.action_type!r} is not covered by the "
            "grant",
        )
    if grant.resource_constraints and not all(
        matches_resource(constraint, action_ir.resources)
        for constraint in grant.resource_constraints
    ):
        raise AuthorityProjectionError(
            "v21-06:resource_scope_mismatch",
            "action resources do not satisfy the grant constraints",
        )
    if grant.destination_constraints and not all(
        matches_destination(constraint, action_ir.destinations)
        for constraint in grant.destination_constraints
    ):
        raise AuthorityProjectionError(
            "v21-06:destination_scope_mismatch",
            "action destinations do not satisfy the grant constraints",
        )
    if not grant.source_ref:
        raise AuthorityProjectionError(
            "v21-06:missing_approval_ref",
            "human_approval grant requires a stable source_ref (approval id)",
        )

    return ConsumptionIntent(
        grant_id=grant.grant_id,
        scope_digest=grant.scope_digest,
        action_id=action_ir.action_id,
        authorization_fingerprint=fingerprint,
        approval_id=grant.source_ref,
        runtime_binding_id=action_ir.runtime_binding_id,
        intent_digest=consumption_intent_digest(
            grant_id=grant.grant_id,
            action_id=action_ir.action_id,
            authorization_fingerprint=fingerprint,
        ),
    )
