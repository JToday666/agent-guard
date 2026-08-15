"""V21-06 capability 投影 handler 与 Grant 编译（Phase 1 纯新增，零接线）。

本模块是 V21-06（Authority / Capability）分支的私有 handler 实现
（``handlers.CONTAINER_OWNERSHIP`` 的 capability 三容器）：

- ``apply_grant_upserts`` / ``apply_grant_revocations`` /
  ``apply_grant_consumptions``：三个 ``TypedUpsertHandler`` 纯函数，
  只消费 delta 容器 items 并返回新状态（不修改输入）；中央分发表
  ``handlers.TYPED_UPSERT_HANDLERS`` 的装配属 Phase 2 集成 PR，本模块
  不做任何运行时注册。
- ``compile_task_to_grants``：deterministic TaskFact→Grant 编译
  （02 §11）；``grant_id`` 由受限 JCS canonical sha256 派生，禁 uuid。
- ``compile_approval_to_grant``：Approval→allow_once Grant 投影
  （02 §12）；**仅 ``resolution_source == "human"``** 可投影为可消费
  grant，LLM reviewer 来源一律 fail-closed 拒绝（04 §12）。

C4 分层：本模块只做校验/确定性构造/digest 计算，零原子操作；
原子消费事务在 Guard API 存储层（``lease_service`` + storage）完成。

Digest 口径与 ``facts.py`` / ``authority/models.py`` 一致：统一使用
``actions/canonical_json.py`` 的受限 JCS（01 §29），只投影白名单字段。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from ...actions.canonical_json import canonical_sha256
from ...actions.models import (
    ActionConstraint,
    ArgumentConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from ...authority.models import TaskFact, canonical_constraints_projection
from ...signals.models import SequenceRef
from ..facts import CapabilityGrant, GrantConsumption, fact_digest_projection
from ..state import OnlineSecurityState

__all__ = [
    "CAPABILITY_COMPILER_VERSION",
    "ApprovalGrantProjection",
    "CapabilityProjectionError",
    "GrantPolicyContext",
    "apply_grant_consumptions",
    "apply_grant_revocations",
    "apply_grant_upserts",
    "compile_approval_to_grant",
    "compile_task_to_grants",
    "derive_grant_id",
    "grant_digest_projection",
]

#: capability 编译器版本：任何编译语义变化必须升级版本，而不是静默
#: 改变 grant digest（对齐 ``authority.compiler.COMPILER_VERSION`` 纪律）。
CAPABILITY_COMPILER_VERSION = "v21-06-capability-compiler-1"


class CapabilityProjectionError(ValueError):
    """V21-06 fail-closed 结构化异常：``reason_code`` 前缀 ``v21-06:``。

    异常消息不得包含授权正文、server key 或任何敏感内容。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


# ---------------------------------------------------------------------------
# 编译输入模型（core 侧冻结视图，不依赖 guard-api 模型）
# ---------------------------------------------------------------------------


class GrantPolicyContext(BaseModel):
    """Grant 编译的策略上下文（最小冻结视图）。

    ``scope_digest`` / ``principal_id`` 是编译期绑定校验锚点：TaskFact /
    Approval 投影必须与当前认证 scope 与 principal 一致，否则视为
    forged issuer 拒绝（fail-closed）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_revision: str
    scope_digest: str
    principal_id: str
    expires_at: str | None = None


class ApprovalGrantProjection(BaseModel):
    """Approval 权威记录的 grant 投影输入（02 §12 的 core 侧视图）。

    ``resolution_source`` 是 Approval 状态机的权威解析来源；V2 中只有
    ``"human"`` 的 ``allow_once`` 可投影为可消费 grant（01 §14 / 02 §12）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str
    scope_digest: str
    principal_id: str
    subject_agent_id: str | None = None
    task_id: str | None = None

    action_types: list[str]
    resource_constraints: list[ResourceConstraint]
    destination_constraints: list[DestinationConstraint]
    argument_constraints: list[ArgumentConstraint]

    resolution_source: str
    authorization_fingerprint: str

    resolved_sequence: SequenceRef | None = None
    expires_at: str | None = None
    policy_revision: str


# ---------------------------------------------------------------------------
# grant digest / grant_id 派生（01 §29 受限 JCS 口径，禁 uuid）
# ---------------------------------------------------------------------------


def grant_digest_projection(grant: CapabilityGrant) -> dict[str, Any]:
    """``grant_digest`` 的白名单投影：等价 ``fact_digest_projection``
    剔除 ``grant_digest`` 自身（digest 不进入自己的输入）。"""
    payload = fact_digest_projection(grant)
    payload.pop("grant_digest", None)
    return payload


def derive_grant_id(identity_payload: dict[str, Any]) -> str:
    """``grant_id`` 确定性派生：受限 JCS sha256（禁 uuid，04 §12）。"""
    suffix = canonical_sha256(identity_payload).removeprefix("sha256:")
    return f"grant:{suffix}"


def _finalize_grant(payload: dict[str, Any]) -> CapabilityGrant:
    """先用占位 digest 构造，再按白名单投影回填确定性 ``grant_digest``。"""
    pending = CapabilityGrant(**payload, grant_digest="sha256:pending")
    digest = canonical_sha256(grant_digest_projection(pending))
    return pending.model_copy(update={"grant_digest": digest})


def _check_binding(
    *,
    scope_digest: str,
    principal_id: str,
    policy_context: GrantPolicyContext,
) -> None:
    """scope/principal 绑定校验：不一致即 forged issuer（fail-closed）。"""
    if scope_digest != policy_context.scope_digest:
        raise CapabilityProjectionError(
            "v21-06:scope_mismatch",
            "grant source scope_digest does not match the authenticated "
            "policy context scope",
        )
    if principal_id != policy_context.principal_id:
        raise CapabilityProjectionError(
            "v21-06:principal_mismatch",
            "grant source principal does not match the authenticated "
            "policy context principal",
        )


# ---------------------------------------------------------------------------
# deterministic TaskFact → Grant（02 §11）
# ---------------------------------------------------------------------------


def compile_task_to_grants(
    task: TaskFact, policy_context: GrantPolicyContext
) -> list[CapabilityGrant]:
    """把 authoritative ``TaskFact`` 确定性编译为 ``CapabilityGrant`` 列表。

    冻结语义（02 §11）：

    - 默认最小权限：每个 ``ActionConstraint`` 编译为一个窄 scope grant；
      无 action 约束则不产生任何 grant（不因模糊词生成无限制 grant）；
    - ``producer``/``authority`` 非法、scope/principal 绑定不一致一律
      fail-closed 拒绝（forged issuer）；
    - ``cancelled``/``superseded`` 任务不产生 grant（授权已失效）；
    - ``grant_id`` / ``grant_digest`` 均由受限 JCS 确定性派生，同输入
      同输出（禁 uuid）。
    """
    if task.producer != "guard_api_task_ingress":
        raise CapabilityProjectionError(
            "v21-06:forged_issuer",
            f"task_fact.producer must be 'guard_api_task_ingress', "
            f"got {task.producer!r}",
        )
    if task.authority != "authoritative":
        raise CapabilityProjectionError(
            "v21-06:forged_issuer",
            f"task_fact.authority must be 'authoritative', "
            f"got {task.authority!r}",
        )
    _check_binding(
        scope_digest=task.scope_digest,
        principal_id=task.principal_id,
        policy_context=policy_context,
    )
    if task.status != "active":
        return []

    grants: list[CapabilityGrant] = []
    for constraint in task.action_constraints:
        if constraint.op != "in" or not constraint.action_types:
            raise CapabilityProjectionError(
                "v21-06:unsupported_action_constraint",
                "task action constraint must be a non-empty 'in' constraint",
            )
        action_types = sorted(set(constraint.action_types))
        source_ref = f"task_fact:{task.task_id}:rev:{task.revision}"
        normalized = canonical_constraints_projection(
            action_constraints=[ActionConstraint(action_types=action_types)],
            resource_constraints=task.resource_constraints,
            destination_constraints=task.destination_constraints,
        )
        grant_id = derive_grant_id(
            {
                "compiler_version": CAPABILITY_COMPILER_VERSION,
                "kind": "task_compiler",
                "policy_revision": policy_context.policy_revision,
                "scope_digest": task.scope_digest,
                "source_ref": source_ref,
                "task_id": task.task_id,
                **normalized,
            }
        )
        grants.append(
            _finalize_grant(
                {
                    "grant_id": grant_id,
                    "scope_digest": task.scope_digest,
                    "source_type": "task_compiler",
                    "source_ref": source_ref,
                    "subject_principal_id": task.principal_id,
                    "subject_agent_id": None,
                    "task_id": task.task_id,
                    "action_types": action_types,
                    "resource_constraints": list(task.resource_constraints),
                    "destination_constraints": list(
                        task.destination_constraints
                    ),
                    "argument_constraints": [],
                    "exact_authorization_fingerprint": None,
                    "usage_limit": None,
                    "remaining_uses": None,
                    "delegable": False,
                    "parent_grant_id": None,
                    "issued_sequence": None,
                    "expires_sequence": None,
                    "expires_at": policy_context.expires_at,
                    "revoked": False,
                    "revoked_sequence": None,
                    "policy_revision": policy_context.policy_revision,
                    "compiler_version": CAPABILITY_COMPILER_VERSION,
                    "evidence_refs": [],
                }
            )
        )
    return grants


# ---------------------------------------------------------------------------
# Approval → allow_once Grant（02 §12）
# ---------------------------------------------------------------------------


def compile_approval_to_grant(
    approval: ApprovalGrantProjection, policy_context: GrantPolicyContext
) -> CapabilityGrant:
    """把 authenticated human ``allow_once`` Approval 投影为单次 grant。

    冻结语义（02 §12 / 01 §14）：

    - **仅 ``resolution_source == "human"``** 可投影；LLM reviewer 来源
      一律 fail-closed 拒绝（V2 中 LLM Reviewer 不能产生可消费的
      allow_once grant，04 §12）；
    - Grant 绑定 ``authorization_fingerprint``、``usage_limit=1``、
      ``remaining_uses=1``、``delegable=false``（由
      ``CapabilityGrant._enforce_approval_single_use`` 强制）；
    - ``grant_id`` / ``grant_digest`` 确定性派生，同输入同输出。
    """
    if approval.resolution_source != "human":
        raise CapabilityProjectionError(
            "v21-06:llm_reviewer_grant_forbidden",
            f"only resolution_source='human' may project a consumable "
            f"allow_once grant, got {approval.resolution_source!r}",
        )
    if not approval.authorization_fingerprint:
        raise CapabilityProjectionError(
            "v21-06:missing_authorization_fingerprint",
            "human_approval grant projection requires an "
            "authorization_fingerprint",
        )
    if not approval.action_types:
        raise CapabilityProjectionError(
            "v21-06:empty_action_types",
            "approval grant projection requires at least one action type",
        )
    _check_binding(
        scope_digest=approval.scope_digest,
        principal_id=approval.principal_id,
        policy_context=policy_context,
    )

    action_types = sorted(set(approval.action_types))
    source_ref = f"approval:{approval.approval_id}"
    normalized = canonical_constraints_projection(
        action_constraints=[ActionConstraint(action_types=action_types)],
        resource_constraints=approval.resource_constraints,
        destination_constraints=approval.destination_constraints,
    )
    grant_id = derive_grant_id(
        {
            "approval_id": approval.approval_id,
            "authorization_fingerprint": approval.authorization_fingerprint,
            "compiler_version": CAPABILITY_COMPILER_VERSION,
            "kind": "human_approval",
            "policy_revision": approval.policy_revision,
            "scope_digest": approval.scope_digest,
            **normalized,
        }
    )
    return _finalize_grant(
        {
            "grant_id": grant_id,
            "scope_digest": approval.scope_digest,
            "source_type": "human_approval",
            "source_ref": source_ref,
            "subject_principal_id": approval.principal_id,
            "subject_agent_id": approval.subject_agent_id,
            "task_id": approval.task_id,
            "action_types": action_types,
            "resource_constraints": list(approval.resource_constraints),
            "destination_constraints": list(approval.destination_constraints),
            "argument_constraints": list(approval.argument_constraints),
            "exact_authorization_fingerprint": (
                approval.authorization_fingerprint
            ),
            "usage_limit": 1,
            "remaining_uses": 1,
            "delegable": False,
            "parent_grant_id": None,
            "issued_sequence": approval.resolved_sequence,
            "expires_sequence": None,
            "expires_at": approval.expires_at,
            "revoked": False,
            "revoked_sequence": None,
            "policy_revision": approval.policy_revision,
            "compiler_version": CAPABILITY_COMPILER_VERSION,
            "evidence_refs": [],
        }
    )


# ---------------------------------------------------------------------------
# Typed upsert handlers（capability 三容器；Phase 2 一次性注册）
# ---------------------------------------------------------------------------


def apply_grant_upserts(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """``grant_upserts`` handler：按 ``grant_id`` 去重合并入
    ``state.active_grants``（upsert 语义：同 id 后来者整体替换）。

    纯函数：不修改输入 state；保持既有顺序，新 id 追加到末尾。
    """
    merged: dict[str, CapabilityGrant] = {}
    order: list[str] = []
    for grant in state.active_grants:
        if grant.grant_id not in merged:
            order.append(grant.grant_id)
        merged[grant.grant_id] = grant
    for item in items:
        grant = item if isinstance(item, CapabilityGrant) else (
            CapabilityGrant.model_validate(item)
        )
        if grant.grant_id not in merged:
            order.append(grant.grant_id)
        merged[grant.grant_id] = grant
    return state.model_copy(
        update={"active_grants": [merged[grant_id] for grant_id in order]}
    )


def apply_grant_revocations(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """``grant_revocations`` handler：追加 ``revoked_grant_ids``（去重）
    并把 ``active_grants`` 中对应 grant 标记为 ``revoked=True``。"""
    revoked_ids = list(state.revoked_grant_ids)
    for item in items:
        grant_id = str(item)
        if grant_id not in revoked_ids:
            revoked_ids.append(grant_id)
    revoked_set = frozenset(revoked_ids)
    active_grants = [
        (
            grant.model_copy(update={"revoked": True})
            if grant.grant_id in revoked_set and not grant.revoked
            else grant
        )
        for grant in state.active_grants
    ]
    return state.model_copy(
        update={
            "revoked_grant_ids": revoked_ids,
            "active_grants": active_grants,
        }
    )


def apply_grant_consumptions(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """``grant_consumptions`` handler：按 ``consumption_id`` 幂等追加。

    同 ``consumption_id`` 同内容 → 幂等跳过；同 ``consumption_id`` 异
    内容 → 身份冲突 fail-closed（防伪造消费记录覆盖）。
    """
    existing_by_id = {
        consumption.consumption_id: consumption
        for consumption in state.grant_consumptions
    }
    appended = list(state.grant_consumptions)
    for item in items:
        consumption = item if isinstance(item, GrantConsumption) else (
            GrantConsumption.model_validate(item)
        )
        current = existing_by_id.get(consumption.consumption_id)
        if current is None:
            existing_by_id[consumption.consumption_id] = consumption
            appended.append(consumption)
            continue
        if current.model_dump(mode="json") != consumption.model_dump(
            mode="json"
        ):
            raise CapabilityProjectionError(
                "v21-06:consumption_identity_conflict",
                f"consumption_id {consumption.consumption_id!r} is already "
                "bound to different consumption content",
            )
    return state.model_copy(update={"grant_consumptions": appended})
