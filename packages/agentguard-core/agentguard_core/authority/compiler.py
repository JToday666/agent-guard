"""TaskAuthorizationCompiler 最小版 (V21-03, 01 §5 L207).

确定性纯函数编译器：读取 authoritative ``TaskFact``（而不是
``SecurityContext.user_task``）输出 ``CompiledTaskAuthority`` 授权摘要。

- **签名刻意不接收 SecurityContext**：从类型层面杜绝读取 Adapter 自报的
  ``user_task``（F0-11）；``user_task`` 永远只是 ``trusted_claim``。
- 任何结构/绑定校验失败一律 fail-closed 抛 ``TaskAuthorityError``，
  不静默降级、不放行。
- 约束求值如需执行，复用 ``actions/constraints.py`` 的 ``matches_*``
  表驱动求值器（未知 op → ``False``）。
- 不实现 CapabilityGrant/lease（属 V21-06）；不引入 DB/HTTP。
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import canonical_sha256
from ..actions.models import (
    ActionConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from .models import (
    SecurityStateScope,
    TaskFact,
    canonical_constraints_projection,
    scope_digest_projection,
    task_digest_projection,
)

__all__ = [
    "COMPILER_VERSION",
    "DERIVED_AUTHORITY_MARKER",
    "CompiledTaskAuthority",
    "TaskAuthorityError",
    "compile_task_authority",
    "compiled_task_authority_projection",
]

#: 编译器版本：任何编译语义变化必须升级版本，而不是静默改变 digest。
COMPILER_VERSION = "v21-03-task-compiler-2"

#: derived-authority 标记：授权派生自 authoritative TaskFact，
#: 与 Adapter 自报 claim（trusted_claim/untrusted_claim）严格区分。
DERIVED_AUTHORITY_MARKER = "derived_from_task_fact"


class TaskAuthorityError(ValueError):
    """fail-closed 结构化异常：``reason_code`` 前缀 ``v21-03:``。

    异常消息不得包含 task 正文、server key 或任何敏感内容。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class CompiledTaskAuthority(BaseModel):
    """TaskAuthorizationCompiler 最小版输出：授权摘要（非 grant）。

    透传 TaskFact 三类约束并标记 derived-authority 来源；``compiled_digest``
    为白名单投影的受限 JCS sha256，供下游做逐字段等价比对
    （恶意 Adapter 篡改 ``user_task`` 不得改变本输出的形式化表达）。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    task_id: str
    task_revision: int
    principal_id: str
    scope_digest: str
    status: Literal["active", "cancelled", "superseded"]

    action_constraints: list[ActionConstraint]
    resource_constraints: list[ResourceConstraint]
    destination_constraints: list[DestinationConstraint]

    derived_authority: Literal["derived_from_task_fact"] = DERIVED_AUTHORITY_MARKER
    compiler_version: str
    compiled_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``compiled_digest`` 的字段白名单（01 §29, L1162-1181）。

        键名与 ``compiled_task_authority_projection`` 的投影键一一对应
        （契约测试断言两者相等）。排除 ``compiled_digest``（digest 自身）。
        """
        return frozenset(
            {
                "schema_version",
                "task_id",
                "task_revision",
                "principal_id",
                "scope_digest",
                "status",
                "action_constraints",
                "resource_constraints",
                "destination_constraints",
                "derived_authority",
                "compiler_version",
            }
        )


def compiled_task_authority_projection(task_fact: TaskFact) -> dict[str, Any]:
    """``compiled_digest`` 的白名单投影（测试与审计可复用）。

    键名与 ``CompiledTaskAuthority.digest_fields()`` 声明一一对应；
    约束合取及成员按集合语义去重并稳定排序（01 §29）。
    """
    return {
        "schema_version": task_fact.schema_version,
        "task_id": task_fact.task_id,
        "task_revision": task_fact.revision,
        "principal_id": task_fact.principal_id,
        "scope_digest": task_fact.scope_digest,
        "status": task_fact.status,
        **canonical_constraints_projection(
            action_constraints=task_fact.action_constraints,
            resource_constraints=task_fact.resource_constraints,
            destination_constraints=task_fact.destination_constraints,
        ),
        "derived_authority": DERIVED_AUTHORITY_MARKER,
        "compiler_version": COMPILER_VERSION,
    }


def compile_task_authority(
    task_fact: TaskFact,
    scope: SecurityStateScope,
    *,
    server_key: bytes | None = None,
    server_keys: Mapping[str, bytes] | None = None,
) -> CompiledTaskAuthority:
    """把 authoritative ``TaskFact`` 编译为 ``CompiledTaskAuthority``。

    四步校验，全部 fail-closed：

    1. 结构校验：``producer == "guard_api_task_ingress"`` 且
       ``authority == "authoritative"``；
    2. 绑定校验：按持久化 ``scope_key_id`` 从 ``server_keys`` keyring
       取验证 key（兼容纯 core 单 key 调用），重算 ``scope_digest`` 并与
       ``task_fact.scope_digest`` 恒定时间比对（``hmac.compare_digest``），
       且 ``principal_id`` 与 scope 一致；
    3. 完整性纵深防御：重算 ``task_digest_projection`` 并与
       ``task_fact.task_digest`` 恒定时间比对，约束/正文被篡改即拒绝；
    4. 输出授权摘要：透传三类约束 + derived-authority 标记 +
       ``compiler_version``，``compiled_digest`` 为投影的受限 JCS sha256。
    """
    if task_fact.producer != "guard_api_task_ingress":
        raise TaskAuthorityError(
            "v21-03:invalid_producer",
            f"task_fact.producer must be 'guard_api_task_ingress', "
            f"got {task_fact.producer!r}",
        )
    if task_fact.authority != "authoritative":
        raise TaskAuthorityError(
            "v21-03:invalid_authority",
            f"task_fact.authority must be 'authoritative', "
            f"got {task_fact.authority!r}",
        )

    if server_keys is not None:
        verification_key = server_keys.get(task_fact.scope_key_id)
        if verification_key is None:
            raise TaskAuthorityError(
                "v21-03:unknown_scope_key_id",
                "task_fact.scope_key_id is not present in the verification keyring",
            )
    elif server_key is not None:
        # 单 key 参数保留给纯 core 调用与兼容测试；持久化调用应传 keyring。
        verification_key = server_key
    else:
        raise TaskAuthorityError(
            "v21-03:missing_scope_verification_key",
            "scope verification key material is required",
        )

    expected_digest = scope_digest_projection(scope, server_key=verification_key)
    if not hmac.compare_digest(
        expected_digest.encode("utf-8"),
        task_fact.scope_digest.encode("utf-8"),
    ):
        raise TaskAuthorityError(
            "v21-03:scope_digest_mismatch",
            "recomputed scope_digest does not match task_fact.scope_digest",
        )
    if scope.principal_id != task_fact.principal_id:
        raise TaskAuthorityError(
            "v21-03:principal_mismatch",
            "scope.principal_id does not match task_fact.principal_id",
        )

    # 纵深防御：TaskFact 白名单内容（约束/task_summary 等）被篡改后
    # task_digest 必然不匹配，编译即拒绝，不进入授权摘要输出。
    if not hmac.compare_digest(
        task_digest_projection(task_fact).encode("utf-8"),
        task_fact.task_digest.encode("utf-8"),
    ):
        raise TaskAuthorityError(
            "v21-03:task_digest_mismatch",
            "recomputed task_digest does not match task_fact.task_digest",
        )

    projection = compiled_task_authority_projection(task_fact)
    return CompiledTaskAuthority(
        schema_version=task_fact.schema_version,
        task_id=task_fact.task_id,
        task_revision=task_fact.revision,
        principal_id=task_fact.principal_id,
        scope_digest=task_fact.scope_digest,
        status=task_fact.status,
        action_constraints=list(task_fact.action_constraints),
        resource_constraints=list(task_fact.resource_constraints),
        destination_constraints=list(task_fact.destination_constraints),
        compiler_version=COMPILER_VERSION,
        compiled_digest=canonical_sha256(projection),
    )
