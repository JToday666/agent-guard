"""V2.1 frozen authority models (V21-03: Authenticated Task Ingress).

字段逐字冻结自
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``：

- SecurityStateScope §4, L133-155；
- EvaluationClock §5, L169-173；
- TaskFact §5, L178-199；
- digest 白名单规范 §29, L1162-1181。

本模块为纯新增 scaffold：不引入 DB/HTTP，不被判定路径
（``engine.py`` / ``decisions/policy.py``）引用。

Digest 口径声明（防三套 digest 口径混用）：

- 本模块所有 digest 统一使用 ``actions/canonical_json.py`` 的受限 JCS
  （RFC 8785 禁 float 子集，01 §29）作为规范化口径；
- ``task_digest`` = ``canonical_sha256(白名单投影)``，``sha256:`` 前缀；
- ``scope_digest`` = ``canonical_hmac_sha256(server_key, 白名单投影)``，
  ``hmac-sha256:`` 前缀；
- 禁止把 ``model_dump`` 全量结果直接作为 digest 输入：每种对象只投影
  ``digest_fields()`` 白名单字段（01 §29, L1181）。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import (
    canonical_hmac_sha256,
    canonical_json,
    canonical_sha256,
)
from ..actions.models import (
    ActionConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from ..signals.models import EvidenceRef, SequenceRef

__all__ = [
    "EvaluationClock",
    "SecurityStateScope",
    "TaskFact",
    "canonical_constraints_projection",
    "scope_digest_projection",
    "task_digest_projection",
]


def _canonical_value(value: Any) -> Any:
    """把模型/列表递归转为受限 canonical JSON 类型域内的纯数据。"""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def _canonical_constraint(constraint: BaseModel) -> dict[str, Any]:
    """规范化约束中的集合语义成员，不改变求值语义。"""
    payload = constraint.model_dump(mode="json")
    if "action_types" in payload:
        payload["action_types"] = sorted(set(payload["action_types"]))
    if "values" in payload:
        payload["values"] = sorted(set(payload["values"]))
    return payload


def _canonical_constraint_list(
    constraints: Sequence[BaseModel],
) -> list[dict[str, Any]]:
    """把约束合取集合规范为去重且按受限 JCS 稳定排序的列表。"""
    by_canonical_json = {
        canonical_json(payload): payload
        for payload in (_canonical_constraint(item) for item in constraints)
    }
    return [by_canonical_json[key] for key in sorted(by_canonical_json)]


def canonical_constraints_projection(
    *,
    action_constraints: list[ActionConstraint],
    resource_constraints: list[ResourceConstraint],
    destination_constraints: list[DestinationConstraint],
) -> dict[str, list[dict[str, Any]]]:
    """三类约束的集合语义规范化投影（01 §29）。"""
    return {
        "action_constraints": _canonical_constraint_list(action_constraints),
        "resource_constraints": _canonical_constraint_list(resource_constraints),
        "destination_constraints": _canonical_constraint_list(
            destination_constraints
        ),
    }


# ---------------------------------------------------------------------------
# SecurityStateScope (01 §4, L133-155)
# ---------------------------------------------------------------------------


class SecurityStateScope(BaseModel):
    """在线状态安全作用域（01 §4, L133-155 逐字冻结）。

    冻结语义：

    - ``trace_id`` 只是 scope 内关联维度，**不能单独作为安全状态 key**；
      它也不进入 scope digest 白名单（逐 trace 关联量不是稳定 scope 身份）。
    - ``runtime_binding_id`` **必须来自 Guard API 已认证 runtime binding，
      不接受 Adapter 自报**；Adapter 请求体中的自报值不得写入本字段。
    - ``agent_id`` / ``branch_id`` 是 scope 内维度，不默认拆成独立安全状态仓，
      避免跨 agent/branch flow 被割裂。
    - ``scope_digest = HMAC(server_key, JCS(stable scope fields))``：
      见 ``STABLE_SCOPE_FIELDS`` 与 ``scope_digest_projection``。
    - 多租户部署后可新增版本化 ``namespace_id``；Minimal 阶段不作为前置。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    principal_id: str
    runtime: str
    runtime_binding_id: str

    trace_id: str
    session_id: str | None = None

    scope_digest: str

    #: scope digest 稳定字段白名单（01 §29, L1162-1181）。
    #: ``trace_id``（逐 trace 关联量）与 ``scope_digest``（digest 自身）
    #: 不得进入白名单；禁止随模型增长让 ``model_dump`` 全量进入摘要。
    STABLE_SCOPE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "principal_id",
            "runtime",
            "runtime_binding_id",
            "session_id",
        }
    )

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``scope_digest`` 的字段白名单（等价 ``STABLE_SCOPE_FIELDS``）。"""
        return cls.STABLE_SCOPE_FIELDS


# ---------------------------------------------------------------------------
# EvaluationClock (01 §5, L169-173)
# ---------------------------------------------------------------------------


class EvaluationClock(BaseModel):
    """判定时钟（01 §5, L169-173 逐字冻结）。

    重放必须使用原始 ``EvaluationClock`` 判断 grant/task/lease 是否过期，
    不得改用 replay 时的 wall clock。
    """

    model_config = ConfigDict(extra="forbid")

    evaluated_at: str
    source: Literal["guard_api_authoritative_clock"] = (
        "guard_api_authoritative_clock"
    )
    clock_version: str


# ---------------------------------------------------------------------------
# TaskFact (01 §5, L178-199)
# ---------------------------------------------------------------------------


class TaskFact(BaseModel):
    """Authority Root（01 §5, L178-199 逐字冻结）。

    冻结语义：

    - ``task_digest`` 对规范化后的完整用户任务计算，不直接由 Adapter 提供；
    - TaskFact 必须与 ``principal_id + scope_digest`` 绑定；
    - Adapter 后续只能携带 ``task_id``/claim，不能覆盖 authoritative TaskFact；
      evaluate 中的 ``user_task`` 永远只是 ``trusted_claim``。
    - Task 更新产生新 revision；旧 revision 不静默覆盖。
    - ``created_sequence`` 本期默认为 ``None``：当前 ``SequenceDomain``
      （audit/runtime/memory/receipt/policy）尚无 task 域，留待后续阶段
      扩展 SequenceDomain 后接入。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    task_id: str
    scope_digest: str
    scope_key_id: str
    principal_id: str

    task_summary: str
    task_digest: str
    revision: int
    status: Literal["active", "cancelled", "superseded"]

    action_constraints: list[ActionConstraint]
    resource_constraints: list[ResourceConstraint]
    destination_constraints: list[DestinationConstraint]

    created_sequence: SequenceRef | None = None
    producer: Literal["guard_api_task_ingress"]
    authority: Literal["authoritative"] = "authoritative"

    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``task_digest`` 的字段白名单（01 §29, L1162-1181）。

        只覆盖规范化任务内容；任务身份、scope/principal 绑定、revision/status
        生命周期和签名 key id 均由独立字段承载，不进入内容摘要。禁止把
        random UUID 或其他非稳定字段纳入摘要。
        """
        return frozenset(
            {
                "schema_version",
                "task_summary",
                "action_constraints",
                "resource_constraints",
                "destination_constraints",
            }
        )


# ---------------------------------------------------------------------------
# Digest projections (01 §29 受限 JCS 口径)
# ---------------------------------------------------------------------------


def task_digest_projection(task_fact: TaskFact) -> str:
    """``task_digest``：``canonical_sha256(白名单投影)``，``sha256:`` 前缀。

    规范化口径为 ``actions/canonical_json.py`` 的受限 JCS（RFC 8785 禁 float
    子集），只投影 ``TaskFact.digest_fields()`` 白名单字段，禁止用
    ``model_dump`` 全量输出作为 digest 输入。服务端在 Task API 固定该值；
    Adapter 不得提供。
    """
    payload: dict[str, Any] = {
        "schema_version": task_fact.schema_version,
        "task_summary": task_fact.task_summary,
        **canonical_constraints_projection(
            action_constraints=task_fact.action_constraints,
            resource_constraints=task_fact.resource_constraints,
            destination_constraints=task_fact.destination_constraints,
        ),
    }
    return canonical_sha256(payload)


def scope_digest_projection(
    scope: SecurityStateScope, *, server_key: bytes
) -> str:
    """``scope_digest``：``canonical_hmac_sha256(server_key, 白名单投影)``。

    输出 ``hmac-sha256:`` 前缀；规范化口径同样是受限 JCS，只投影
    ``SecurityStateScope.STABLE_SCOPE_FIELDS`` 白名单字段。``server_key``
    由构造方以 ``bytes`` 注入；本函数不读取环境变量、不写日志。
    """
    payload: dict[str, Any] = {
        field: _canonical_value(getattr(scope, field))
        for field in sorted(SecurityStateScope.digest_fields())
    }
    return canonical_hmac_sha256(server_key, payload)
