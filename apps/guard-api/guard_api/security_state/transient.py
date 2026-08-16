"""TransientSecurityFacts：current-event 事实与 Gate A assessment overlay。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/）：

- 01 章 §17 ``TransientSecurityFacts`` 字段逐字冻结（本模块 list→tuple
  偏差登记见模型 docstring）；
- 02 章 §9 Pre-decision 与 Post-commit 分离：本模型只承载
  ``GuardEvent → fact`` 映射产出的 Pre-decision transient bundle，
  **禁止直接写 OnlineState**；committed record 才经由确定性
  ``SecurityStateDeltaV21`` 投影（后续 PR，非本模块职责）；
- 02 章 §12 ``FACT_BUILDER_VERSION``：影响 fact 语义/
  digest 的变化必须 bump；
- 01 章 §29 digest 白名单规范：bundle digest 只投影语义白名单，
  排除注册 id、时间戳与 ``bundle_digest`` 自身。

本模块纪律（CT-PR-02a DoD，零接线）：

- 纯模型 + 纯函数 digest：无 state mutation、无 I/O、不产生
  ``GuardDecision``、不写 store；
- ``declassifications`` 恒空（净化只能由 ``trusted_declassifier``
  服务端记录表达，02 §5/CT-F0-02）；自 CT-PR-02b 起
  ``memory_facts`` / ``current_action`` 由 fact_builder 写侧
  handler 生产（占位语义历史登记见模型 docstring）。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context.facts import (
    DeclassificationFact,
    FlowFact,
    MemoryFact,
    RecentActionFact,
    SourceFact,
    fact_digest_projection,
)
from agentguard_core.signals.models import (
    EvaluationDegradation,
    EvidenceRef,
    SecuritySignal,
)

#: 02 章 §12 版本：影响 fact semantic/digest 的变化必须 bump，
#: 并评估 projector reprojection。
FACT_BUILDER_VERSION = "ct-fact-2"

#: Gate A 之前已持久化信封使用的 fact-builder 版本。旧审计记录没有
#: 显式版本字段，replay/backfill 必须按该版本重算历史 bundle digest，
#: 不能用当前全局版本静默改写摘要口径。
LEGACY_FACT_BUILDER_VERSION = "ct-fact-1"

#: Gate A 完整 assessment input 摘要版本。这与历史
#: ``bundle_digest`` 的投影定义分离，不改变 CT delta/projector 语义。
ASSESSMENT_OVERLAY_VERSION = "gate-a-overlay-1"


class TransientSecurityFacts(BaseModel):
    """01 章 §17 TARGET-FROZEN 字段逐字对齐（tuple 化偏差登记）。

    偏差登记：冻结文档写 ``list[...]``，本模块统一使用 ``tuple`` 以
    保证不可变与确定性顺序（与 CT-PR-01 ``VerifiedSourceDescriptor``
    惯例一致）；JSON 序列化仍为数组。

    字段生产口径：``declassifications`` 恒空（净化只能由
    ``trusted_declassifier`` 服务端记录表达，02 §5/CT-F0-02）；
    ``memory_facts`` / ``current_action`` 自 CT-PR-02b 起由
    fact_builder 写侧 handler 生产（02a 阶段恒空/None 的占位
    语义已由 02b 解除）；``bundle_digest`` 保留三类可投影事实
    的历史摘要，``overlay_digest`` 绑定完整 assessment input；
    两者由 builder 装配后回填。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    event_id: str
    scope_digest: str
    source_facts: tuple[SourceFact, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    memory_facts: tuple[MemoryFact, ...] = ()
    declassifications: tuple[DeclassificationFact, ...] = ()
    current_action: RecentActionFact | None = None
    signals: tuple[SecuritySignal, ...] = ()
    degradations: tuple[EvaluationDegradation, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    bundle_digest: str = ""
    overlay_digest: str = ""


def bundle_digest_projection(
    bundle: TransientSecurityFacts,
    *,
    fact_builder_version: str = FACT_BUILDER_VERSION,
) -> dict[str, Any]:
    """Bundle digest 白名单投影（01 §29 白名单冻结规则）。

    白名单：``fact_builder_version`` / ``event_id`` / ``scope_digest``，
    以及 source/flow/memory 三类事实逐条 ``fact_digest_projection``
    （各 fact 内部白名单已排除注册 id 与时间戳，facts.py §29）。

    排除项：``declassifications`` / ``current_action`` / ``signals`` /
    ``degradations`` / ``evidence_refs``（本 PR 恒空/None 或属派生
    记录，白名单扩展随后续 PR 冻结）与 ``bundle_digest`` 自身
    （防自引用）。
    """
    return {
        "fact_builder_version": fact_builder_version,
        "event_id": bundle.event_id,
        "scope_digest": bundle.scope_digest,
        "source_facts": [fact_digest_projection(fact) for fact in bundle.source_facts],
        "flow_facts": [fact_digest_projection(fact) for fact in bundle.flow_facts],
        "memory_facts": [fact_digest_projection(fact) for fact in bundle.memory_facts],
    }


def compute_bundle_digest(
    bundle: TransientSecurityFacts,
    *,
    fact_builder_version: str = FACT_BUILDER_VERSION,
) -> str:
    """单次 ``canonical_sha256(白名单投影)``，``sha256:`` 前缀（01 §29）。

    受限 JCS 子集（禁 float）保证 T-FactReplay：同内容 bundle 恒产
    同 digest。
    """
    return canonical_sha256(
        bundle_digest_projection(
            bundle,
            fact_builder_version=fact_builder_version,
        )
    )


def overlay_digest_projection(bundle: TransientSecurityFacts) -> dict[str, Any]:
    """Gate A assessment overlay 的完整、可重放摘要投影。

    ``bundle_digest`` 只绑定三类可投影事实；overlay 则必须
    绑定评估真正读取的所有字段。因此这里保留
    fact/action/signal/degradation 的完整 typed JSON（含稳定
    引用 ID），只排除两个派生 digest 字段以避免自引用。
    """

    return {
        "assessment_overlay_version": ASSESSMENT_OVERLAY_VERSION,
        "schema_version": bundle.schema_version,
        "event_id": bundle.event_id,
        "scope_digest": bundle.scope_digest,
        "source_facts": [fact.model_dump(mode="json") for fact in bundle.source_facts],
        "flow_facts": [fact.model_dump(mode="json") for fact in bundle.flow_facts],
        "memory_facts": [fact.model_dump(mode="json") for fact in bundle.memory_facts],
        "declassifications": [
            fact.model_dump(mode="json") for fact in bundle.declassifications
        ],
        "current_action": (
            bundle.current_action.model_dump(mode="json")
            if bundle.current_action is not None
            else None
        ),
        "signals": [signal.model_dump(mode="json") for signal in bundle.signals],
        "degradations": [
            degradation.model_dump(mode="json") for degradation in bundle.degradations
        ],
        "evidence_refs": [
            evidence.model_dump(mode="json") for evidence in bundle.evidence_refs
        ],
    }


def compute_overlay_digest(bundle: TransientSecurityFacts) -> str:
    """``canonical_sha256`` 绑定完整 current-event assessment input。"""

    return canonical_sha256(overlay_digest_projection(bundle))
