"""RequiredCheckPlan 确定性生成（V21-04, 01 §18）。

``build_required_check_plan`` 是表驱动确定性映射（无 LLM）：由
``ActionIR``（或 impact 简写）+ ``PolicyProfile`` 决定 required /
optional domains（01 §18, L808：由 ActionIR + PolicySnapshot 确定，
不由 LLM 决定）。

- ``plan_id`` 用确定性 digest（禁 uuid）：``v21-04-plan:`` 前缀 +
  投影的受限 JCS sha256；
- ``reason_codes`` 前缀 ``v21-04:``；
- 映射规则任何变化必须提升 ``REQUIRED_CHECK_PLAN_VERSION``（02 §4.2
  projector_version 语义的 plan 侧对应纪律）。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..actions.canonical_json import canonical_sha256
from ..actions.models import ActionEffect, ActionIR
from ..decisions.evidence import RequiredCheckPlan
from ..signals.models import CoverageDomain, ImpactClass

__all__ = [
    "REQUIRED_CHECK_PLAN_VERSION",
    "PolicyProfile",
    "build_required_check_plan",
]

#: plan 映射规则版本：任何表驱动规则变化必须升级，不得静默改变 plan_id。
REQUIRED_CHECK_PLAN_VERSION = "v21-04-plan-4"

#: CoverageMap 固定域顺序（01 §17）；plan 列表按此序稳定排序。
_DOMAIN_ORDER: tuple[CoverageDomain, ...] = (
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
)


class PolicyProfile(BaseModel):
    """策略侧输入（PolicySnapshot 的确定性投影切片）。

    只承载 plan 映射所需的冻结维度；core 保持 stateless，不读取任何
    外部策略存储。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_revision: str
    policy_digest: str

    #: policy 是否要求 task authority；False 时 task 域 not_applicable
    #: （02 §6.1 not_applicable 行）。
    requires_task_authority: bool = True

    #: policy 明确无需 capability 检查的低影响动作集合（02 §6.3）。
    capability_not_required_actions: frozenset[str] = Field(default_factory=frozenset)

    #: policy 声明不需要 source/dataflow/memory 判定的动作类型
    #: （02 §6.2/§6.5/§6.6 的 not_applicable 行）。
    not_applicable_actions: frozenset[str] = Field(default_factory=frozenset)

    #: policy 仅声明不需要 source/dataflow 判定的观察类动作类型。
    #: 该开关不影响 memory；memory 仍须经过下方独立、带 lineage
    #: safeguard 的 ``memory_not_required_actions`` 判定。
    source_dataflow_not_required_actions: frozenset[str] = Field(
        default_factory=frozenset
    )

    #: Server-attested observation action types retain behavior inspection even
    #: when their ActionIR impact is low.  Explicit memory lineage remains a
    #: required domain for these observations.
    observation_actions: frozenset[str] = Field(default_factory=frozenset)

    #: policy 仅声明不需要 memory 判定的非持久动作类型。
    #: ``effects.persistence`` 或显式 memory resource/source 始终优先，
    #: 不允许被此集合豁免。
    memory_not_required_actions: frozenset[str] = Field(default_factory=frozenset)


def _impact_default_required(impact: ImpactClass) -> set[CoverageDomain]:
    """impact 基线必检域（表驱动，冻结于本版本）。"""
    if impact == "low":
        return {"task", "capability"}
    if impact == "moderate":
        return {"task", "source", "capability", "dataflow"}
    return {
        "task",
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
    }


def build_required_check_plan(
    action: ActionIR | ImpactClass,
    policy: PolicyProfile,
) -> RequiredCheckPlan:
    """表驱动确定性映射生成 ``RequiredCheckPlan``（无 LLM）。

    规则（本版本冻结）：

    - required 基线由 impact 决定（``_impact_default_required``）；
    - ``effects.external_communication / data_egress`` → 追加 source、
      dataflow（外发/数据流出必须可溯源）；
    - ``effects.persistence`` → 追加 memory；
    - policy 声明 not_applicable 的动作类型把 source/dataflow/memory
      移出 required；policy 声明无需 capability 的低影响动作同理；
    - policy 声明 ``source_dataflow_not_required_actions`` 时仅移出
      source/dataflow，不影响 memory；
    - policy 声明 ``observation_actions`` 时追加 behavior；若观察事件显式
      引用 memory resource/source，同时追加 memory；
    - policy 声明 ``memory_not_required_actions`` 时仅移出 memory，
      且只对非持久、未显式引用 memory resource/source 的动作生效；
    - ``policy.requires_task_authority=False`` → task 移入 optional；
    - ``runtime_outcome`` 本期恒为 optional（pre-execution 判定不依赖
      历史执行终态，02 §6.7 not_applicable 语义由判定侧承担）；
    - 未进 required 的域一律进 optional（fail-closed 可见性）。
    """
    if isinstance(action, ActionIR):
        action_ir: ActionIR | None = action
        impact: ImpactClass = action.impact
        effects = action.effects
        action_type = action.action_type
    else:
        action_ir = None
        impact = action
        effects = ActionEffect()
        action_type = ""

    required: set[CoverageDomain] = _impact_default_required(impact)
    reason_codes: list[str] = [f"v21-04:impact_{impact}"]

    egress_domains: set[CoverageDomain] = {"source", "dataflow"}
    policy_na_domains: set[CoverageDomain] = {"source", "dataflow", "memory"}

    if effects.external_communication or effects.data_egress:
        required |= egress_domains
        reason_codes.append("v21-04:effect_external_communication_or_egress")
    if effects.persistence:
        required.add("memory")
        reason_codes.append("v21-04:effect_persistence")

    if action_type in policy.not_applicable_actions:
        required -= policy_na_domains
        reason_codes.append("v21-04:policy_not_applicable_action")
    if action_type in policy.source_dataflow_not_required_actions:
        required -= {"source", "dataflow"}
        reason_codes.append("v21-04:policy_source_dataflow_not_required")
    if (
        action_type in policy.memory_not_required_actions
        and not effects.persistence
        and action_ir is not None
        and not any(resource.kind == "memory" for resource in action_ir.resources)
        and not any(
            ref.startswith(("memory:", "memory://", "source:memory:"))
            for ref in action_ir.data_refs
        )
    ):
        required.discard("memory")
        reason_codes.append("v21-04:policy_memory_not_required")
    if action_type in policy.observation_actions:
        required.add("behavior")
        reason_codes.append("v21-04:policy_observation_behavior_required")
        if action_ir is not None and (
            any(resource.kind == "memory" for resource in action_ir.resources)
            or any(
                ref.startswith(("memory:", "memory://", "source:memory:"))
                for ref in action_ir.data_refs
            )
        ):
            required.add("memory")
            reason_codes.append("v21-04:policy_observation_memory_lineage")
    if action_type in policy.capability_not_required_actions:
        required.discard("capability")
        reason_codes.append("v21-04:policy_capability_not_required")

    if not policy.requires_task_authority:
        required.discard("task")
        reason_codes.append("v21-04:policy_task_not_required")

    required.discard("runtime_outcome")

    required_domains: list[CoverageDomain] = [
        domain for domain in _DOMAIN_ORDER if domain in required
    ]
    optional_domains: list[CoverageDomain] = [
        domain for domain in _DOMAIN_ORDER if domain not in required
    ]

    semantic_dimensions: list[
        Literal["task_alignment", "instruction_semantics", "intent_ambiguity"]
    ] = (["task_alignment"] if "task" in required else [])

    projection: dict[str, Any] = {
        "plan_version": REQUIRED_CHECK_PLAN_VERSION,
        "impact": impact,
        "required_domains": required_domains,
        "optional_domains": optional_domains,
        "policy_revision": policy.policy_revision,
        "policy_digest": policy.policy_digest,
    }
    plan_id = f"v21-04-plan:{canonical_sha256(projection)}"

    return RequiredCheckPlan(
        plan_id=plan_id,
        impact=impact,
        required_domains=required_domains,
        optional_domains=optional_domains,
        required_capabilities=[],
        semantic_resolvable_dimensions=semantic_dimensions,
        reason_codes=reason_codes,
    )
