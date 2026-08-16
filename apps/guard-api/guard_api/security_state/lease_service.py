"""V21-06 execution lease 事务编排（C4：Guard API 存储层单事务）。

C4 分层冻结（04 §12）：Core 只做校验/构造确定性 intent/计算 digest，
零原子操作；本服务把 ``ConsumptionIntent`` 翻译为存储层
``consume_grant(scope_digest, intent_payload)`` 的权威调用，原子性
（fingerprint/expiry/remaining 校验 → remaining-use CAS →
GrantConsumption → ExecutionLease）全部在存储层单事务内完成。

Lease token 纪律（01 §15 / §31）：

- 明文 lease token **不落库**：存储层只保存 ``token_digest``；
- token 由服务端确定性派生（HMAC(lease_key, 三元身份)），同一
  ``grant_id + action_id + authorization_fingerprint`` 在 lease 有效期
  内重试可返回原 token（``replayed=True``），不同指纹返回冲突；
- ``lease_key`` 从 ``GuardApiSettings.control_token`` 域隔离派生
  （与 ``audit_cursor_signing_key`` 同一模式），不暴露原始令牌。

本模块不注册任何 HTTP 路由（lease API 接线属后续阶段，01 §31）。
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from agentguard_core.actions.canonical_json import canonical_json_bytes
from agentguard_core.security_context import ExecutionLease
from agentguard_core.security_context.projection.authority_verdict import (
    ConsumptionIntent,
)

from guard_api.storage.base import (
    ApprovalExecutionLeaseUnavailableError,
    ApprovalLeaseAuthorizationError,
    ApprovalLeaseConsumeCommand,
    ApprovalLeaseConsumptionConflictError,
    ApprovalLeaseExpiredError,
    ApprovalLeaseNotConsumableError,
    ApprovalLeaseNotFoundError,
    ApprovalLeaseStoreError,
    ControlPlaneStore,
    GrantConsumptionResult,
)

if TYPE_CHECKING:
    from guard_api.auth import AuthContext
    from guard_api.services.approval import ApprovalService

__all__ = [
    "DEFAULT_LEASE_TTL_SECONDS",
    "REQUIRED_INTENT_PAYLOAD_KEYS",
    "ConsumptionIntentPayloadError",
    "GrantConsumptionConflictError",
    "GrantExpiredError",
    "GrantFingerprintMismatchError",
    "GrantNotRegisteredError",
    "GrantRevokedError",
    "GrantScopeMismatchError",
    "GrantUsesExhaustedError",
    "LeaseExpiredError",
    "LeaseRevokedError",
    "LeaseStoreError",
    "LeaseTokenMismatchError",
    "LeaseTransitionError",
    "LeaseService",
    "ApprovalExecutionLeaseService",
    "approval_execution_lease_service_from_settings",
    "derive_lease_token",
    "derive_lease_token_key",
    "lease_service_from_settings",
    "lease_token_digest",
    "validate_intent_payload",
]

#: lease 默认有效期（秒）：足够覆盖执行前消费 → runtime 执行的正常窗口。
DEFAULT_LEASE_TTL_SECONDS = 300

#: lease token 派生的域隔离标签（对齐 ``audit_cursor_signing_key`` 模式）。
_LEASE_TOKEN_KEY_DOMAIN = b"agentguard/execution-lease-token/v1"

#: ``consume_grant`` intent_payload 必备键（缺失/空值一律 fail-closed）。
REQUIRED_INTENT_PAYLOAD_KEYS: tuple[str, ...] = (
    "grant_id",
    "action_id",
    "authorization_fingerprint",
    "approval_id",
    "runtime_binding_id",
    "issued_at",
    "expires_at",
    "lease_token",
)


# ---------------------------------------------------------------------------
# 结构化异常（reason_code 前缀 ``v21-06:``；不吞错、不部分提交）
# ---------------------------------------------------------------------------


class LeaseStoreError(Exception):
    """V21-06 lease/consumption 存储层结构化异常基类。

    ``reason_code`` 前缀 ``v21-06:``；异常消息不得包含 lease token、
    server key 或其他敏感内容。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class GrantNotRegisteredError(LeaseStoreError):
    """grant 运行时行不存在（v21-06:grant_not_registered）。"""


class GrantScopeMismatchError(LeaseStoreError):
    """grant 行绑定的 scope_digest 与请求 scope 不一致。"""


class GrantFingerprintMismatchError(LeaseStoreError):
    """grant 绑定的 authorization_fingerprint 与请求不一致。"""


class GrantExpiredError(LeaseStoreError):
    """grant 已过期（status=expired 或 expires_at 已过）。"""


class GrantRevokedError(LeaseStoreError):
    """grant 已被撤销。"""


class GrantUsesExhaustedError(LeaseStoreError):
    """remaining_uses 已耗尽（allow_once double-spend 的拒绝路径）。"""


class GrantConsumptionConflictError(LeaseStoreError):
    """同一 (grant_id, action_id) 出现异 fingerprint 消费（双花告警语义）。"""


class LeaseExpiredError(LeaseStoreError):
    """lease 过期后的同键重试：明确拒绝，不静默签发新 lease（01 §31 410）。"""


class LeaseRevokedError(LeaseStoreError):
    """lease 已撤销后的同键重试：撤销语义不得被幂等重放绕过（F1）。"""


class LeaseTokenMismatchError(LeaseStoreError):
    """幂等重放分支调用方 token 与存储 token_digest 不符（伪造拒绝，F3）。"""


class LeaseTransitionError(LeaseStoreError):
    """不支持的 lease 终态转换 reason。"""


class ConsumptionIntentPayloadError(LeaseStoreError):
    """intent_payload 缺失必备键或含非字符串值。"""


def _error(
    cls: type[LeaseStoreError], reason_code: str, message: str
) -> LeaseStoreError:
    return cls(reason_code, message)


def validate_intent_payload(payload: dict[str, Any]) -> None:
    """存储层入口校验：必备键齐全且均为非空字符串（fail-closed）。"""
    if not isinstance(payload, dict):
        raise _error(
            ConsumptionIntentPayloadError,
            "v21-06:invalid_intent_payload",
            "intent_payload must be a dict",
        )
    for key in REQUIRED_INTENT_PAYLOAD_KEYS:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise _error(
                ConsumptionIntentPayloadError,
                "v21-06:invalid_intent_payload",
                f"intent_payload[{key!r}] must be a non-empty string",
            )


# ---------------------------------------------------------------------------
# lease token 确定性派生（明文不落库；重试可恢复同一 token）
# ---------------------------------------------------------------------------


def derive_lease_token_key(control_token: str) -> bytes:
    """从控制令牌域隔离派生 lease token HMAC 密钥，不暴露原始令牌。

    与 ``GuardApiSettings.audit_cursor_signing_key`` 同一派生模式：
    ``HMAC-SHA256(control_token, domain_tag)``。
    """
    if not control_token:
        raise ValueError("control_token must be non-empty")
    return hmac.new(
        control_token.encode("utf-8"),
        _LEASE_TOKEN_KEY_DOMAIN,
        hashlib.sha256,
    ).digest()


def derive_lease_token(
    key: bytes,
    *,
    grant_id: str,
    action_id: str,
    authorization_fingerprint: str,
) -> str:
    """确定性 lease token：``HMAC(key, JCS(三元身份))``。

    同一 ``grant_id + action_id + authorization_fingerprint`` 恒得同一
    token（01 §15 可恢复重试语义）；token 只经 ``GrantConsumptionResult``
    返回值交付，存储层永不落库明文。
    """
    if not isinstance(key, bytes) or not key:
        raise ValueError("lease token key must be non-empty bytes")
    payload = {
        "action_id": action_id,
        "authorization_fingerprint": authorization_fingerprint,
        "grant_id": grant_id,
        "purpose": "agentguard/execution-lease-token",
    }
    digest = hmac.new(key, canonical_json_bytes(payload), hashlib.sha256)
    return f"lease-v1:{digest.hexdigest()}"


def lease_token_digest(lease_token: str) -> str:
    """``token_digest``：明文 token 的 sha256（唯一落库形态，01 §15）。"""
    if not lease_token:
        raise ValueError("lease_token must be non-empty")
    return "sha256:" + hashlib.sha256(lease_token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# LeaseService（事务编排门面）
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LeaseService:
    """execution lease 编排服务：校验 intent → 交付存储层单事务消费。

    ``store`` 必须实现 V21-06 三方法（``consume_grant`` /
    ``get_execution_lease`` / ``expire_or_revoke_lease``）；原子性由
    存储层保证（postgres 单事务 + 行锁序 grant→consumption→lease；
    memory 单锁内同序读-校验-写）。
    """

    store: ControlPlaneStore
    lease_token_key: bytes
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS

    def consume_grant_atomic(
        self, intent: ConsumptionIntent, *, now: datetime | None = None
    ) -> GrantConsumptionResult:
        """执行前原子消费入口（01 §31 的服务侧编排）。

        服务侧只做确定性构造（issued_at/expires_at/token），随即委托
        存储层单事务完成全部权威校验与写入；失败路径抛结构化异常，
        不吞错、不部分提交。
        """
        if not isinstance(self.lease_token_key, bytes) or (not self.lease_token_key):
            raise ValueError("lease_token_key must be non-empty bytes")
        if self.lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be positive")

        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise ValueError("lease clock must include a timezone")
        issued_at = moment.isoformat()
        expires_at = (moment + timedelta(seconds=self.lease_ttl_seconds)).isoformat()
        lease_token = derive_lease_token(
            self.lease_token_key,
            grant_id=intent.grant_id,
            action_id=intent.action_id,
            authorization_fingerprint=intent.authorization_fingerprint,
        )
        payload: dict[str, Any] = {
            **intent.model_dump(mode="json"),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "lease_token": lease_token,
        }
        return self.store.consume_grant(intent.scope_digest, payload)

    def get_execution_lease(
        self, scope_digest: str, lease_ref: str
    ) -> ExecutionLease | None:
        """按 lease_id 或 token_digest 读取租约（scope 绑定校验在存储层）。"""
        return self.store.get_execution_lease(scope_digest, lease_ref)

    def expire_or_revoke_lease(
        self, scope_digest: str, lease_id: str, reason: str
    ) -> ExecutionLease:
        """把 lease 推进到 expired/revoked 终态（幂等；不存在抛 KeyError）。"""
        return self.store.expire_or_revoke_lease(scope_digest, lease_id, reason)


@dataclass(slots=True)
class ApprovalExecutionLeaseService:
    """RTE-05 approval-bound lease orchestration.

    Public callers supply only the ActionIR action ID and authorization
    fingerprint.  All remaining authority is recovered from the authenticated
    credential, approval, and private binding and is revalidated atomically by
    the store.
    """

    store: ControlPlaneStore
    approval_service: ApprovalService
    lease_token_key: bytes
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS

    def consume(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        auth_context: AuthContext,
        now: datetime | None = None,
    ) -> GrantConsumptionResult:
        try:
            return self._consume(
                approval_id,
                action_id=action_id,
                authorization_fingerprint=authorization_fingerprint,
                auth_context=auth_context,
                now=now,
            )
        except ApprovalLeaseStoreError:
            raise
        except Exception:
            # Never let driver/internal exception text escape the stable API
            # envelope.  Transient/unclassified failures are retryable and the
            # bound action remains fail-closed.
            raise ApprovalExecutionLeaseUnavailableError(
                "rte-05:lease_unavailable", "execution lease is unavailable"
            ) from None

    def _consume(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        auth_context: AuthContext,
        now: datetime | None = None,
    ) -> GrantConsumptionResult:
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise ValueError("lease clock must include a timezone")
        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise ApprovalLeaseNotFoundError(
                "rte-05:approval_not_found", "approval was not found"
            )
        credential_id = auth_context.credential_id
        credential_token_hash = auth_context.credential_token_hash
        runtime = auth_context.runtime
        agent_id = auth_context.agent_id
        if (
            credential_id is None
            or credential_token_hash is None
            or runtime is None
            or agent_id is None
            or auth_context.principal_id != approval.requesting_principal_id
            or runtime != approval.runtime
            or agent_id != approval.agent_id
        ):
            raise ApprovalLeaseAuthorizationError(
                "rte-05:identity_mismatch", "authenticated identity mismatch"
            )

        approval_expires_at = _parse_lease_datetime(approval.expires_at)
        if approval.status == "expired":
            raise ApprovalLeaseExpiredError(
                "rte-05:approval_expired", "approval has expired"
            )
        if (
            approval.status != "resolved"
            or approval.decision != "allow_once"
            or approval.resolution_source != "human"
        ):
            raise ApprovalLeaseNotConsumableError(
                "rte-05:approval_not_consumable", "approval is not consumable"
            )

        binding = self.store.get_enforcement_binding(approval_id)
        if binding is None or not binding.requires_execution_lease:
            if moment >= approval_expires_at:
                raise ApprovalLeaseExpiredError(
                    "rte-05:approval_expired", "approval has expired"
                )
            raise ApprovalExecutionLeaseUnavailableError(
                "rte-05:binding_unavailable", "execution binding is unavailable"
            )
        if binding.action_id != action_id or not hmac.compare_digest(
            binding.authorization_fingerprint,
            authorization_fingerprint,
        ):
            raise ApprovalLeaseConsumptionConflictError(
                "rte-05:binding_mismatch", "execution binding mismatch"
            )

        if binding.grant_id is None:
            # A consumption cannot exist before grant registration.  Once the
            # approval expires, recovery is terminal rather than retryable.
            if moment >= approval_expires_at:
                raise ApprovalLeaseExpiredError(
                    "rte-05:approval_expired", "approval has expired"
                )
            self.approval_service.ensure_strong_approval_grant_registered(approval_id)
            # Readiness is evaluated at request entry.  Even if the bounded
            # backfill succeeds synchronously, this attempt returns retryable
            # 503 and performs no consumption; the next identical request may
            # consume the now-registered grant.
            raise ApprovalExecutionLeaseUnavailableError(
                "rte-05:grant_unavailable", "execution lease is unavailable"
            )
        grant_id = binding.grant_id

        lease_token = derive_lease_token(
            self.lease_token_key,
            grant_id=grant_id,
            action_id=binding.action_id,
            authorization_fingerprint=binding.authorization_fingerprint,
        )
        expires_at = min(
            moment + timedelta(seconds=self.lease_ttl_seconds),
            approval_expires_at,
        ).isoformat()
        return self.store.consume_approval_execution_lease(
            ApprovalLeaseConsumeCommand(
                credential_id=credential_id,
                credential_token_hash=credential_token_hash,
                principal_id=auth_context.principal_id,
                runtime=runtime,
                agent_id=agent_id,
                approval_id=approval_id,
                action_id=action_id,
                authorization_fingerprint=authorization_fingerprint,
                lease_token=lease_token,
                expires_at=expires_at,
            )
        )


def lease_service_from_settings(
    store: ControlPlaneStore,
    settings: Any,
    *,
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
) -> LeaseService:
    """用 ``GuardApiSettings`` 构造 LeaseService（lease key 域隔离派生）。"""
    return LeaseService(
        store=store,
        lease_token_key=derive_lease_token_key(settings.control_token),
        lease_ttl_seconds=lease_ttl_seconds,
    )


def approval_execution_lease_service_from_settings(
    store: ControlPlaneStore,
    settings: Any,
    approval_service: ApprovalService,
    *,
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
) -> ApprovalExecutionLeaseService:
    return ApprovalExecutionLeaseService(
        store=store,
        approval_service=approval_service,
        lease_token_key=derive_lease_token_key(settings.control_token),
        lease_ttl_seconds=lease_ttl_seconds,
    )


def _parse_lease_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
