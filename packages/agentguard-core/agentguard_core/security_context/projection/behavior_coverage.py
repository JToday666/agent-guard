"""V21-07 behavior / runtime_outcome 两域 coverage 判定（Phase 1 纯新增）。

02_状态投影_Provenance_Authority.md §6.4（behavior）与 §6.7
（runtime_outcome）判定表的域函数实现，符合 ``DomainCoverageFn``
签名；Phase 2 集成 PR 已一次性装配进 ``DOMAIN_COVERAGE_DISPATCH``，
``compute_coverage`` 总分派按 dispatch 分派消费本模块。

C3 冻结约束：判定消费 ``CoverageContext`` 完整上下文 —— plan、
watermarks、gaps、eviction_report、provider_available，不只看单一维度。

State flooding 语义（02 §5.2 + C8）：``ctx.eviction_report`` 显示
windowed/aggregated 收缩（或 ``state.evicted``）时，evidence **不得**
判为 complete —— 驱逐后无法证明 required domain 完整，降 partial。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...decisions.evidence import DomainCoverage
from ...signals.models import SequenceDomain, SequenceRef
from ..coverage import RequiredHistoryWindow
from ..eviction import EvictionReport
from ..projector import PROJECTOR_VERSION
from ..state import OnlineSecurityState, compare_sequence_refs

if TYPE_CHECKING:
    # 仅类型注解消费：避免 coverage_context ↔ projection 导入环
    # （Phase 2 装配时 coverage_context 模块级导入本模块）。
    from ..coverage_context import CoverageContext

__all__ = [
    "BEHAVIOR_PROVIDER_KEY",
    "RUNTIME_OUTCOME_PROVIDER_KEY",
    "behavior_coverage",
    "runtime_outcome_coverage",
]

#: ``CoverageContext.provider_available`` 的 provider 标识键。
BEHAVIOR_PROVIDER_KEY = "behavior_projector"
RUNTIME_OUTCOME_PROVIDER_KEY = "runtime_outcome_projector"

#: behavior 域相关的序列域（与 coverage.py §7 兜底映射口径一致）。
_BEHAVIOR_GAP_SEQUENCE_DOMAINS: frozenset[SequenceDomain] = frozenset(
    {"audit", "runtime"}
)

_REASON_PREFIX = "v21-07"


def _eviction_degrades_behavior(
    report: EvictionReport | None,
) -> bool:
    """驱逐报告是否使 behavior 域不可证明完整（02 §5.1/§5.2）。"""
    if report is None:
        return False
    if "behavior" in report.unprovable_domains:
        return True
    return bool(
        report.removed_counts.get("recent_actions", 0)
        or report.removed_counts.get("behavior_aggregates", 0)
    )


def _behavior_window_covered(
    state: OnlineSecurityState, window: RequiredHistoryWindow
) -> bool:
    """required history window 是否已被 recent_actions/aggregate 覆盖。

    仅在同 ``sequence_domain + producer_binding_id`` 内比较
    （02 §5）；窗口的 end_sequence 不超过该分区最大已投影序列即覆盖。
    """
    end_ref = SequenceRef(
        domain=window.sequence_domain,
        producer_binding_id=window.producer_binding_id,
        value=window.end_sequence,
    )
    for action in state.recent_actions:
        sequence = action.runtime_sequence
        if sequence is None:
            continue
        if (
            sequence.domain != window.sequence_domain
            or sequence.producer_binding_id != window.producer_binding_id
        ):
            continue
        if compare_sequence_refs(sequence, end_ref) >= 0:
            return True
    for aggregate in state.behavior_aggregates:
        window_end = aggregate.window_end
        if (
            window_end.domain != window.sequence_domain
            or window_end.producer_binding_id != window.producer_binding_id
        ):
            continue
        if compare_sequence_refs(window_end, end_ref) >= 0:
            return True
    return False


def behavior_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """behavior 域五状态判定（02 §6.4 判定表）。

    - complete：RequiredCheckPlan 所需窗口与关键 predecessor 已覆盖，
      无关键 gap、无驱逐收缩影响；
    - partial：关键 predecessor/ref 缺失或窗口被安全性驱逐影响
      （state flooding 下 aggregated/windowed 收缩不得判 complete）；
    - stale：behavior aggregate/动作水位落后当前 required sequence；
    - unknown：behavior projector 不可用或域 dirty；
    - not_applicable：当前动作无需 sequence/behavior 判断。
    """
    domain = "behavior"
    as_of = ctx.watermarks.projected_sequence
    if domain not in ctx.plan.required_domains:
        return DomainCoverage(
            domain=domain,
            status="not_applicable",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:behavior_not_required"],
        )
    if domain in state.dirty_domains:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:dirty_projection"],
        )
    if ctx.provider_available.get(BEHAVIOR_PROVIDER_KEY) is False:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:behavior_projector_unavailable"],
        )

    # state flooding / 安全保持型驱逐：evidence 不得判 complete（C8）。
    if _eviction_degrades_behavior(ctx.eviction_report):
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:safety_preserving_eviction"],
        )
    if state.evicted:
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:eviction_window_unprovable"],
        )

    # ctx.gaps 为调用方 localized 后的当前判定相关 gap（02 §7）。
    behavior_gaps = [
        gap for gap in ctx.gaps if gap.domain in _BEHAVIOR_GAP_SEQUENCE_DOMAINS
    ]
    if behavior_gaps:
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:gap_affects_behavior_window"],
        )

    # stale：aggregate/动作水位落后 required history window。
    required_windows = (
        [
            window
            for window in ctx.gap_context.required_history_windows
            if window.domain == domain
        ]
        if ctx.gap_context is not None
        else []
    )
    for window in required_windows:
        if not _behavior_window_covered(state, window):
            return DomainCoverage(
                domain=domain,
                status="stale",
                as_of_sequence=as_of,
                projector_version=PROJECTOR_VERSION,
                reason_codes=[f"{_REASON_PREFIX}:behavior_watermark_behind"],
            )

    return DomainCoverage(
        domain=domain,
        status="complete",
        as_of_sequence=as_of,
        projector_version=PROJECTOR_VERSION,
        reason_codes=[f"{_REASON_PREFIX}:behavior_window_covered"],
    )


def runtime_outcome_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """runtime_outcome 域五状态判定（02 §6.7 判定表）。

    required 历史动作口径：high/critical impact 且
    ``final_decision == "allow"``（已放行待执行，期待 receipt）。

    - complete：required 历史动作 receipt 均已知；
    - partial：expected receipt 尚未到达但已知 pending（含跨域序列
      不可比的 fail-closed 降级）；
    - stale：receipt watermark 落后 required action 序列；
    - unknown：receipt channel/projector 不可用或域 dirty；
    - not_applicable：本次 pre-execution decision 不依赖历史执行终态。
    """
    domain = "runtime_outcome"
    as_of = ctx.watermarks.projected_sequence
    if domain not in ctx.plan.required_domains:
        return DomainCoverage(
            domain=domain,
            status="not_applicable",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:runtime_outcome_not_required"],
        )
    if domain in state.dirty_domains:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:dirty_projection"],
        )
    if ctx.provider_available.get(RUNTIME_OUTCOME_PROVIDER_KEY) is False:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:receipt_channel_unavailable"],
        )
    report = ctx.eviction_report
    if report is not None and domain in report.unprovable_domains:
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:safety_preserving_eviction"],
        )
    if any(gap.domain == "receipt" for gap in ctx.gaps):
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:gap_affects_receipt_window"],
        )

    expected = [
        action
        for action in state.recent_actions
        if action.impact in {"high", "critical"} and action.final_decision == "allow"
    ]
    outcome_ids = {outcome.action_id for outcome in state.runtime_outcomes}
    pending = [action for action in expected if action.action_id not in outcome_ids]
    if not pending:
        return DomainCoverage(
            domain=domain,
            status="complete",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"{_REASON_PREFIX}:receipt_window_covered"],
        )

    watermark = ctx.watermarks.runtime_receipt_sequence
    if watermark is not None:
        for action in pending:
            sequence = action.runtime_sequence
            if sequence is None:
                continue
            if (
                sequence.domain != watermark.domain
                or sequence.producer_binding_id != watermark.producer_binding_id
            ):
                # 跨域整数不可比（02 §5）：fail-closed 降 partial。
                return DomainCoverage(
                    domain=domain,
                    status="partial",
                    as_of_sequence=as_of,
                    projector_version=PROJECTOR_VERSION,
                    reason_codes=[f"{_REASON_PREFIX}:receipt_sequence_uncomparable"],
                )
            if compare_sequence_refs(sequence, watermark) > 0:
                return DomainCoverage(
                    domain=domain,
                    status="stale",
                    as_of_sequence=as_of,
                    projector_version=PROJECTOR_VERSION,
                    reason_codes=[f"{_REASON_PREFIX}:receipt_watermark_behind"],
                )
    return DomainCoverage(
        domain=domain,
        status="partial",
        as_of_sequence=as_of,
        projector_version=PROJECTOR_VERSION,
        reason_codes=[f"{_REASON_PREFIX}:receipt_pending"],
    )
