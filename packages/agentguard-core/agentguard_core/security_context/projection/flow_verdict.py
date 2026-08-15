"""V21-08 FlowVerdict 纯函数生成器（纯新增，零接线）。

此前仓库只有 ``signals/models.py`` 的 ``FlowVerdict`` 冻结模型，无任何
生成器；本模块补齐投影侧生成入口。

契约口径：

- 02 §6.5（dataflow 判定表）：**"未发现危险 flow + dataflow=complete"**
  才可作为安全证据；``未发现危险 flow + dataflow=unknown`` 不能解释为
  安全。
- ``10_决策记录_V21-05-06-07前置.md`` D3：``FlowFact.strength`` 由
  producer 签发时给定，**投影不重算、不推断**；``strength == "possible"``
  在 dataflow 判定中降 ``partial``（无法证明强链路，fail-closed），
  不得升格为 exact 语义。
- 01 §23：FlowVerdict 冻结字段（status / strongest_strength / taints /
  external_sink / path_refs / evidence_refs）。

fail-closed 纪律：

- flow 数据截断（dataflow 域 dirty、sticky taint 存在 unresolved flow
  refs）→ 降级，``status`` 不得为 ``safe``；
- 任一 flow ``strength == "possible"`` → 无法证明强链路，不得 ``safe``；
- 缺 dataflow coverage 证据（partial/stale/unknown）→ 不得 ``safe``；
- 纯函数：不读时钟、不生成 uuid、不触 IO，同输入必同输出（T-Replay
  确定性）。
"""

from __future__ import annotations

from typing import Iterable

from ...actions.models import ActionIR
from ...signals.models import CoverageStatus, FlowStrength, FlowVerdict, TaintLabel
from ..facts import FlowFact, StickyTaintSummary
from ..snapshot import SecuritySnapshot

__all__ = [
    "DANGEROUS_TAINTS",
    "EXTERNAL_DESTINATION_KINDS",
    "compute_flow_verdict",
]

#: 构成"危险 flow"判定的 taint 集合（03 §7.1 数据外发矩阵覆盖
#: CREDENTIAL/SENSITIVE；PERSISTENT_UNTRUSTED 为 memory 持久不可信内容，
#: 外发同样是危险流，fail-closed 一并纳入）。
DANGEROUS_TAINTS: frozenset[TaintLabel] = frozenset(
    {"CREDENTIAL", "SENSITIVE", "PERSISTENT_UNTRUSTED"}
)

#: ActionIR destination 资源 kind 中属于外部 sink 的类别。
EXTERNAL_DESTINATION_KINDS: frozenset[str] = frozenset({"url", "api", "email"})

# strength 强弱排序（越小越强）。只用于"取最强"，绝不重算/升格 strength。
_STRENGTH_RANK: dict[str, int] = {"exact": 0, "strong": 1, "possible": 2}

# 截断/未决证据的降级集合：存在即 status 不得为 safe。
_DEGRADED_DATAFLOW_STATUSES = frozenset({"partial", "stale", "unknown"})


def _external_sink(action_ir: ActionIR) -> bool:
    """动作是否指向外部 sink（destination 资源类别或 effect 画像）。"""
    if action_ir.effects.external_communication or action_ir.effects.data_egress:
        return True
    return any(
        destination.kind in EXTERNAL_DESTINATION_KINDS
        for destination in action_ir.destinations
    )


def _is_dangerous(flow: FlowFact) -> bool:
    return bool(DANGEROUS_TAINTS.intersection(flow.taints))


def _strongest(strengths: Iterable[FlowStrength]) -> FlowStrength | None:
    best: FlowStrength | None = None
    for strength in strengths:
        if best is None or _STRENGTH_RANK[strength] < _STRENGTH_RANK[best]:
            best = strength
    return best


def _flow_data_truncated(snapshot: SecuritySnapshot) -> bool:
    """flow 数据截断/未决判定（02 §5.1 安全性驱逐与 bounded 状态口径）。

    - dataflow 域处于 dirty（投影被安全性驱逐/有界截断后未恢复）；
    - sticky taint summary 存在 unresolved flow refs（安全保持型摘要尚有
      未决链路）。

    任一成立即视为截断：``status`` 不得为 ``safe``。
    """
    if "dataflow" in snapshot.dirty_domains:
        return True
    return any(
        summary.unresolved_flow_refs for summary in snapshot.sticky_taint_summaries
    )


def _dangerous_sticky_taints(
    summaries: Iterable[StickyTaintSummary],
) -> list[TaintLabel]:
    """sticky taint 摘要中携带危险 taint 的标签（确定性排序）。"""
    labels: set[TaintLabel] = {
        taint
        for summary in summaries
        for taint in summary.taints
        if taint in DANGEROUS_TAINTS
    }
    return sorted(labels)


def compute_flow_verdict(
    snapshot: SecuritySnapshot,
    action_ir: ActionIR,
    *,
    dataflow_status: CoverageStatus | None = None,
) -> FlowVerdict:
    """由 ``SecuritySnapshot``（flows / sticky taint summaries）与
    ``ActionIR`` sink 信息生成 ``FlowVerdict``。

    ``dataflow_status`` 口径（02 §6.5）：优先消费**当前动作 plan 派生**
    的 dataflow coverage 状态（调用方显式传入）；缺省退回 snapshot 自带
    的 bootstrap coverage（兼容旧调用方/测试夹具）。bootstrap snapshot
    是全七域视图，无存储 flow 时把 dataflow 报为 ``unknown``；而低影响
    动作的当前 plan 通常不要求 dataflow（``not_applicable``）——若
    误用 bootstrap 口径，flow verdict 恒 ``uncertain``，fusion 永远无法
    CLEAR_ALLOW，shadow divergence 系统性偏向 DEFER。
    ``not_applicable`` 语义：当前动作无数据/影响流安全要求，未发现
    危险 flow 即可构成安全证据，不得要求 ``complete``。

    判定顺序（fail-closed）：

    1. **violation**：存在危险 flow（taint ∈ ``DANGEROUS_TAINTS``）。
       ``strongest_strength`` 透传 producer 签发的最强 strength（D3：
       不重算、不推断、不升格）；``path_refs`` 按 snapshot 内 flow 顺序
       收集危险 flow 的 ``flow_id``；``taints`` 为危险 flow taint 的
       确定性排序并集。
    2. **not_applicable**：dataflow coverage 为 ``not_applicable`` 且
       无危险 sticky taint（动作无数据/影响流安全要求；危险 flow 已在
       第 1 步拦截，非危险 flow 不构成阻碍）。
    3. **safe**：必须**同时**满足（02 §6.5 双前提）——
       - 未发现危险 flow（含 sticky taint 摘要无危险 taint）；
       - dataflow coverage ``complete``；
       - 无截断（dataflow 域非 dirty、sticky 摘要无 unresolved refs）；
       - 无任何 ``strength == "possible"`` 的 flow（D3：possible 降
         partial，不能作为安全证据）。
    4. **uncertain**：其余一切情形（dataflow partial/stale/unknown、
       possible 链路、截断降级等）——"未发现危险 flow + dataflow=unknown"
       不能解释为安全。

    ``evidence_refs`` 恒为空列表：生成器不伪造证据引用，由接线阶段按
    审计口径挂载。
    """
    external_sink = _external_sink(action_ir)
    dangerous_flows = [flow for flow in snapshot.flows if _is_dangerous(flow)]

    if dangerous_flows:
        return FlowVerdict(
            status="violation",
            strongest_strength=_strongest(
                flow.strength for flow in dangerous_flows
            ),
            taints=sorted(
                {
                    taint
                    for flow in dangerous_flows
                    for taint in flow.taints
                    if taint in DANGEROUS_TAINTS
                }
            ),
            external_sink=external_sink,
            path_refs=[flow.flow_id for flow in dangerous_flows],
            evidence_refs=[],
        )

    dataflow_status_resolved = (
        dataflow_status
        if dataflow_status is not None
        else snapshot.coverage.dataflow.status
    )
    sticky_dangerous = _dangerous_sticky_taints(snapshot.sticky_taint_summaries)

    if dataflow_status_resolved == "not_applicable" and not sticky_dangerous:
        return FlowVerdict(
            status="not_applicable",
            strongest_strength=None,
            taints=[],
            external_sink=external_sink,
            path_refs=[],
            evidence_refs=[],
        )

    possible_link_present = any(
        flow.strength == "possible" for flow in snapshot.flows
    )
    safe = (
        dataflow_status_resolved == "complete"
        and not _flow_data_truncated(snapshot)
        and not possible_link_present
        and not sticky_dangerous
    )
    if safe:
        return FlowVerdict(
            status="safe",
            strongest_strength=None,
            taints=[],
            external_sink=external_sink,
            path_refs=[],
            evidence_refs=[],
        )

    # uncertain：缺证据/possible 链路/截断，一律不作为安全证据。
    # strongest_strength 仅在确有 flow 证据时透传 producer 值，不推断。
    return FlowVerdict(
        status="uncertain",
        strongest_strength=_strongest(flow.strength for flow in snapshot.flows),
        taints=sticky_dangerous,
        external_sink=external_sink,
        path_refs=[flow.flow_id for flow in snapshot.flows],
        evidence_refs=[],
    )
