"""CoverageContext 与域 coverage 分发表（V21-05/06/07 Phase 2 集成装配）。

C3 冻结约束：coverage 判定必须接收完整上下文（RequiredCheckPlan、
required refs、watermarks、gaps、provider availability），不得只看
单一维度。本模块冻结**输入上下文模型**与**域分发表**：

- ``compute_coverage`` 接收/构建 ``CoverageContext``，对非 task 六域
  按 ``DOMAIN_COVERAGE_DISPATCH`` 分派（既有优先级 dirty→unknown、
  unprovable→partial、not_required→not_applicable 保留在总分派层，
  先于域函数）；task 域仍由总分派内既有逻辑逐字节处理；
- ``DOMAIN_COVERAGE_DISPATCH`` 装配六域判定纯函数（V21-05 三域 +
  V21-06 capability + V21-07 两域），Phase 2 集成 PR 一次性静态
  装配，禁止运行时注册；
- 字段类型全部复用现有冻结模型，不新造重复模型：``gaps`` 的元素用
  ``facts.GapRange``（即 ``StateWatermarks.gaps`` / ``localize_gaps``
  消费的同一 gap 类型；coverage.py 无独立 gap 结果模型）。
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..decisions.evidence import DomainCoverage, RequiredCheckPlan
from ..signals.models import CoverageDomain
from .coverage import GapContext
from .eviction import EvictionReport
from .facts import GapRange, StateWatermarks
from .state import OnlineSecurityState

__all__ = [
    "DOMAIN_COVERAGE_DISPATCH",
    "CoverageContext",
    "DomainCoverageFn",
]


class CoverageContext(BaseModel):
    """coverage 判定的完整输入上下文（C3；Phase 2 才被消费）。

    字段语义：

    - ``plan``：必检计划（required/optional domains）；
    - ``gap_context``：gap localized degradation 的四级定位输入
      （02 §7），无当前动作依赖信息时为 ``None``；
    - ``watermarks``：状态水位（含 gaps 全集）；
    - ``gaps``：当前判定相关的 gap 列表（元素类型 ``GapRange``，与
      ``StateWatermarks.gaps`` 同源）；
    - ``eviction_report``：安全保持型驱逐报告（02 §5.1 unprovable
      域降 partial 的输入）；
    - ``truncated``：bounded flow lookup / bounded rebuild 发生截断的
      域（C8：dataflow coverage 降 partial/unknown）；
    - ``provider_available``：projector / provider / lease store 等
      外部依赖可用性（键为 provider 标识）；
    - ``authoritative_head_revision``：权威 TaskFact head revision，
      task 域 stale 判定输入（02 §6.1）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: RequiredCheckPlan
    watermarks: StateWatermarks

    gap_context: GapContext | None = None
    gaps: tuple[GapRange, ...] = ()
    eviction_report: EvictionReport | None = None
    truncated: tuple[CoverageDomain, ...] = ()
    provider_available: Mapping[str, bool] = Field(default_factory=dict)
    authoritative_head_revision: int | None = None


#: 单域 coverage 判定纯函数签名：输入在线状态 + 完整上下文，输出
#: 现有冻结的 ``DomainCoverage`` 结果模型（V21-01，不新造类型）。
DomainCoverageFn = Callable[
    [OnlineSecurityState, CoverageContext], DomainCoverage
]

# 六域判定纯函数导入（置于 CoverageContext 定义之后：域函数模块以
# TYPE_CHECKING 方式反向引用 CoverageContext，该顺序打破导入环）。
from .projection.behavior_coverage import (  # noqa: E402
    behavior_coverage,
    runtime_outcome_coverage,
)
from .projection.capability_coverage import capability_coverage  # noqa: E402
from .projection.provenance_coverage import (  # noqa: E402
    dataflow_coverage,
    memory_coverage,
    source_coverage,
)

#: 域 → 判定函数分发表：六域（task 域由 ``compute_coverage`` 总分派
#: 内既有逻辑处理，不入本表）。Phase 2 集成 PR 一次性静态装配，
#: 禁止任何运行时追加/替换。
DOMAIN_COVERAGE_DISPATCH: Mapping[CoverageDomain, DomainCoverageFn] = (
    MappingProxyType(
        {
            "source": source_coverage,
            "capability": capability_coverage,
            "behavior": behavior_coverage,
            "dataflow": dataflow_coverage,
            "memory": memory_coverage,
            "runtime_outcome": runtime_outcome_coverage,
        }
    )
)
