"""安全保持型驱逐（V21-04, 02 §5.1）。

``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/02_状态投影_Provenance_Authority.md``
§5.1 (L170-206) 冻结：禁止普通 LRU 把安全关键事实「洗掉」。三类契约：

- **Sticky**：生命周期结束前不按普通 LRU 驱逐 —— active/revoked grant
  state、``CREDENTIAL`` / ``PERSISTENT_UNTRUSTED`` sticky summary、
  unresolved high-risk flow、Memory trust、gap/dirty marker；
- **Windowed**：可 bounded —— recent low-risk actions、recent benign
  source facts、普通 observation；
- **Aggregated**：原始事件可驱逐，但保留 high-impact count、external
  egress count、credential_seen_since_sequence、privilege/action budget、
  memory taint summary。

驱逐后无法证明 required domain 完整时，coverage 降 ``partial``
（由 ``EvictionReport.unprovable_domains`` + ``coverage.compute_coverage``
兑现）。State flooding 场景（02 §5.2）：credential read → N benign
actions 填满窗口 → external send，credential sticky 事实必须存活。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..signals.models import CoverageDomain
from .state import OnlineSecurityState

__all__ = [
    "CONTAINER_EVICTION_CLASS",
    "EvictionClass",
    "EvictionLimits",
    "EvictionReport",
    "apply_safe_eviction",
    "is_benign_source",
    "is_sticky_taint_summary",
]

EvictionClass = Literal["sticky", "windowed", "aggregated"]


@dataclass(frozen=True)
class EvictionLimits:
    """窗口容量常量（模块级集中配置，02 §5.1 bounded 要求）。

    ``observations`` 对应 windowed 类「普通 observation」的总量上限
    （以 recent_actions 容器承载）。aggregated/sticky 容器本期不做
    容量驱逐：计数型聚合在 V21-05+ 接线；sticky 类型上不可达。
    """

    recent_actions: int = 256
    benign_sources: int = 512
    observations: int = 1024


#: 子域容器 → 驱逐类别映射（02 §5.1 逐类对齐）。
CONTAINER_EVICTION_CLASS: dict[str, EvictionClass] = {
    "active_grants": "sticky",
    "revoked_grant_ids": "sticky",
    "grant_consumptions": "sticky",
    "execution_leases": "sticky",
    "sticky_taint_summaries": "sticky",
    "relevant_flows": "sticky",
    "memory_index": "sticky",
    "watermarks": "sticky",
    "dirty_domains": "sticky",
    "recent_actions": "windowed",
    "source_index": "windowed",
    "behavior_aggregates": "aggregated",
}


def is_sticky_taint_summary(taints: object) -> bool:
    """``CREDENTIAL`` / ``PERSISTENT_UNTRUSTED`` 摘要属于 sticky（02 §5.1）。"""
    labels = set(taints) if isinstance(taints, (list, tuple)) else set()
    return bool(labels & {"CREDENTIAL", "PERSISTENT_UNTRUSTED"})


def is_benign_source(source: object) -> bool:
    """windowed 可驱逐的 benign source：trusted 且无任何 taint。

    非 benign（untrusted/unknown 或带 taint）的 source 事实不参与
    windowed 收缩 —— 它们是来源判定依赖，按 sticky 语义保留。
    """
    trust = getattr(source, "trust", None)
    taints = getattr(source, "taints", None)
    return trust == "trusted" and not taints


class EvictionReport(BaseModel):
    """驱逐结果报告（纯数据，供 coverage 与测试断言）。"""

    model_config = ConfigDict(extra="forbid")

    removed_counts: dict[str, int] = Field(default_factory=dict)
    #: 驱逐后无法再证明完整的候选 coverage domain（与 plan.required_domains
    #: 求交集后由 ``compute_coverage`` 降 partial）。
    unprovable_domains: list[CoverageDomain] = Field(default_factory=list)


def apply_safe_eviction(
    state: OnlineSecurityState, limits: EvictionLimits
) -> tuple[OnlineSecurityState, EvictionReport]:
    """仅收缩 windowed 域的安全保持型驱逐（纯函数，返回新状态）。

    - ``recent_actions``：低风险动作从**头部**（最旧）驱逐至容量内；
      high/critical impact 动作按 02 §5.1 aggregated 语义保留
      （high-impact count 不得因驱逐丢失）；
    - ``source_index``：只驱逐 benign（trusted 且无 taint）source，
      其余按 sticky 语义保留；
    - sticky / aggregated 容器：本期不驱逐（sticky 类型上不可达；
      计数型聚合在 V21-05+ 接线）；
    - 任何 windowed 收缩发生后 ``evicted=True``：无法再证明被收缩域
      完整，coverage 按 02 §5.1 对相关 required domain 降 partial。
    """
    removed_counts: dict[str, int] = {}
    unprovable: set[CoverageDomain] = set()

    # recent_actions：保留 high/critical impact（aggregated 保留语义），
    # 其余 windowed 条目从最旧开始收缩。单次遍历 + 容量记账：驱逐后
    # 保留项维持原相对顺序（时序不被重排打破），sticky 项不被驱逐。
    windowed_count = sum(
        1
        for action in state.recent_actions
        if action.impact not in {"high", "critical"}
    )
    overflow = windowed_count - limits.recent_actions
    new_recent_actions = list(state.recent_actions)
    if overflow > 0:
        to_remove = overflow
        kept: list[Any] = []
        for action in new_recent_actions:
            if action.impact not in {"high", "critical"} and to_remove > 0:
                to_remove -= 1
                continue
            kept.append(action)
        new_recent_actions = kept
        removed_counts["recent_actions"] = overflow
        unprovable.add("behavior")

    # source_index：只收缩 benign source（从最旧开始），同样保持原相对顺序。
    benign_count = sum(
        1 for source in state.source_index if is_benign_source(source)
    )
    benign_overflow = benign_count - limits.benign_sources
    new_source_index = list(state.source_index)
    if benign_overflow > 0:
        to_remove_source = benign_overflow
        kept_sources: list[Any] = []
        for source in new_source_index:
            if is_benign_source(source) and to_remove_source > 0:
                to_remove_source -= 1
                continue
            kept_sources.append(source)
        new_source_index = kept_sources
        removed_counts["source_index"] = benign_overflow
        unprovable.add("source")

    new_state = state.model_copy(
        update={
            "recent_actions": new_recent_actions,
            "source_index": new_source_index,
            "evicted": bool(removed_counts),
        }
    )
    report = EvictionReport(
        removed_counts=removed_counts,
        unprovable_domains=sorted(unprovable),
    )
    return new_state, report
