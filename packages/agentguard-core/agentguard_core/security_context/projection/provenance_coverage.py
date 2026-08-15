"""V21-05 三域 coverage 判定纯函数（02 §6.2/§6.5/§6.6）。

签名符合 ``coverage_context.DomainCoverageFn``：
``(state, ctx: CoverageContext) -> DomainCoverage``（复用 V21-01 冻结
的 ``DomainCoverage`` 结果模型，不新造类型）。

C3 冻结约束：判定消费 ``ctx`` 的完整上下文 —— ``plan``（required
判定）、``provider_available``（依赖可用性）、``dirty_domains`` /
``eviction_report``（fail-closed 降级）、``truncated``（C8 截断降
级）、``watermarks`` + ``gap_context.required_history_windows``
（stale 判定）、``gaps``（localized 降级）——**不是「有数据就
complete」**。

判定优先级（三域统一）：

1. 不在 ``plan.required_domains`` → ``not_applicable``；
2. 域 dirty → ``unknown``（02 §3：不得把投影失败解释为 complete）；
3. provider 显式不可用 → ``unknown``（``provider_available`` 键缺失
   视为未报告，不推断为不可用）；
4. ``eviction_report.unprovable_domains`` 命中 → ``partial``（02 §5.1）；
5. 域专属判定（截断降级 / gap 定位 / watermark stale / 数据完整性）。

**Phase 2 集成**：本模块三域函数已一次性静态装配进
``coverage_context.DOMAIN_COVERAGE_DISPATCH``（无运行时注册 API）。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..coverage import RequiredHistoryWindow
from ..facts import GapRange, StateWatermarks
from ..projector import PROJECTOR_VERSION
from ..state import OnlineSecurityState
from ...decisions.evidence import DomainCoverage
from ...signals.models import (
    CoverageDomain,
    CoverageStatus,
    SequenceDomain,
    SequenceRef,
)

if TYPE_CHECKING:
    # 仅类型注解消费：避免 coverage_context ↔ projection 导入环
    # （Phase 2 装配时 coverage_context 模块级导入本模块）。
    from ..coverage_context import CoverageContext

__all__ = [
    "DATAFLOW_PROVIDER_KEY",
    "MEMORY_PROVIDER_KEY",
    "SOURCE_PROVIDER_KEY",
    "dataflow_coverage",
    "memory_coverage",
    "source_coverage",
]

#: ``CoverageContext.provider_available`` 的 provider 标识约定。
SOURCE_PROVIDER_KEY = "source_projector"
DATAFLOW_PROVIDER_KEY = "flow_provider"
MEMORY_PROVIDER_KEY = "memory_state"

#: 序列域 → 兜底 coverage 域映射（与 coverage.py 优先级 4 口径一致）。
_SEQUENCE_DOMAIN_FALLBACK: dict[SequenceDomain, CoverageDomain] = {
    "memory": "memory",
}


# ---------------------------------------------------------------------------
# 公共降级前置（C3：完整上下文消费）
# ---------------------------------------------------------------------------


def _early_verdict(
    state: OnlineSecurityState,
    ctx: CoverageContext,
    domain: CoverageDomain,
    provider_key: str,
) -> DomainCoverage | None:
    """统一前置判定；返回 None 表示进入域专属判定。"""
    as_of = state.watermarks.projected_sequence
    if domain not in ctx.plan.required_domains:
        return DomainCoverage(
            domain=domain,
            status="not_applicable",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=["v21-05:policy_not_required"],
        )
    if domain in state.dirty_domains:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=["v21-05:dirty_projection"],
        )
    if ctx.provider_available.get(provider_key, True) is False:
        return DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=[f"v21-05:{provider_key}_unavailable"],
        )
    if (
        ctx.eviction_report is not None
        and domain in ctx.eviction_report.unprovable_domains
    ):
        return DomainCoverage(
            domain=domain,
            status="partial",
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=["v21-05:safety_preserving_eviction"],
        )
    return None


def _result(
    state: OnlineSecurityState,
    domain: CoverageDomain,
    status: CoverageStatus,
    reason_codes: list[str],
) -> DomainCoverage:
    return DomainCoverage(
        domain=domain,
        status=status,
        as_of_sequence=state.watermarks.projected_sequence,
        projector_version=PROJECTOR_VERSION,
        reason_codes=reason_codes,
    )


def _watermark_for(
    watermarks: StateWatermarks, sequence_domain: SequenceDomain
) -> SequenceRef | None:
    """序列域 → 对应状态水位（跨域比较禁止，02 §5）。"""
    if sequence_domain == "memory":
        return watermarks.memory_sequence
    if sequence_domain == "receipt":
        return watermarks.runtime_receipt_sequence
    if sequence_domain == "policy":
        return watermarks.committed_sequence
    return watermarks.projected_sequence


def _window_stale(ctx: CoverageContext, domain: CoverageDomain) -> bool:
    """required history window 落后水位 → stale（fail-closed 口径）。

    窗口指定 ``sequence_domain`` + ``producer_binding_id``，只与同域
    同 producer 的水位比较（02 §5 跨域比较禁止）；水位缺失或不可比
    均视为落后（无法证明新鲜度）。
    """
    if ctx.gap_context is None:
        return False
    stale = False
    for window in ctx.gap_context.required_history_windows:
        if window.domain != domain:
            continue
        watermark = _watermark_for(ctx.watermarks, window.sequence_domain)
        if watermark is None:
            stale = True
            continue
        if (
            watermark.domain != window.sequence_domain
            or watermark.producer_binding_id != window.producer_binding_id
        ):
            stale = True
            continue
        if watermark.value < window.end_sequence:
            stale = True
    return stale


def _gap_overlaps_window(
    gap: GapRange, window: RequiredHistoryWindow
) -> bool:
    """gap 与 required history window 的区间重叠（同域同 producer）。"""
    if gap.domain != window.sequence_domain:
        return False
    if gap.producer_binding_id != window.producer_binding_id:
        return False
    return gap.start_sequence <= window.end_sequence and (
        gap.end_sequence >= window.start_sequence
    )


def _gap_hits_domain(ctx: CoverageContext, domain: CoverageDomain) -> bool:
    """gap localized degradation：只有定位到本域的 gap 才降级（02 §7）。"""
    for gap in ctx.gaps:
        fallback = _SEQUENCE_DOMAIN_FALLBACK.get(gap.domain)
        if fallback == domain:
            return True
        if ctx.gap_context is not None:
            for window in ctx.gap_context.required_history_windows:
                if window.domain == domain and _gap_overlaps_window(
                    gap, window
                ):
                    return True
    return False


def _required_refs(ctx: CoverageContext) -> list[str]:
    """当前动作的 required stable refs（C3 判定输入，02 §7 优先级 2）。"""
    if ctx.gap_context is None:
        return []
    return sorted(ctx.gap_context.stable_refs)


# ---------------------------------------------------------------------------
# source 域（02 §6.2）
# ---------------------------------------------------------------------------


def source_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """source 域判定（02 §6.2 判定表）。

    - complete：required source refs 均有 producer/trust/taint 事实；
    - partial：部分 source 缺失 / 只有 claim（trust=unknown 视为缺
      trust mapping）/ gap 定位命中；
    - stale：source mapping/projector watermark 落后 required sequence；
    - unknown：source projector 不可用、域 dirty 或来源身份无法建立
      （required 但无 stable refs / 全部 refs 无对应事实）。
    """
    domain: CoverageDomain = "source"
    early = _early_verdict(state, ctx, domain, SOURCE_PROVIDER_KEY)
    if early is not None:
        return early

    refs = _required_refs(ctx)
    if not refs:
        return _result(
            state, domain, "unknown", ["v21-05:source_refs_unresolvable"]
        )

    if _gap_hits_domain(ctx, domain):
        return _result(
            state, domain, "partial", ["v21-05:sequence_gap_localized"]
        )
    if _window_stale(ctx, domain):
        return _result(
            state, domain, "stale", ["v21-05:source_watermark_behind"]
        )

    index = {source.source_id: source for source in state.source_index}
    missing = [ref for ref in refs if ref not in index]
    if len(missing) == len(refs):
        return _result(
            state,
            domain,
            "unknown",
            ["v21-05:source_identity_not_established"],
        )
    if missing:
        return _result(
            state, domain, "partial", ["v21-05:source_refs_missing"]
        )

    weak = [
        ref
        for ref in refs
        if index[ref].trust == "unknown" or not index[ref].producer
    ]
    if weak:
        return _result(
            state,
            domain,
            "partial",
            ["v21-05:source_trust_mapping_incomplete"],
        )
    return _result(state, domain, "complete", ["v21-05:source_complete"])


# ---------------------------------------------------------------------------
# dataflow 域（02 §6.5）
# ---------------------------------------------------------------------------


def dataflow_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """dataflow 域判定（02 §6.5 判定表 + C8 截断降级）。

    冻结口径：**「未发现危险 flow + dataflow=complete」才算安全证据**；
    「未发现危险 flow + dataflow=unknown」**不能**解释为安全 —— 因此
    本函数对证据不足一律 fail-closed（unknown/partial），不给出
    complete。

    - ``ctx.truncated`` 含 dataflow（bounded flow lookup 截断，C8）→
      partial，reason_code ``v21-05:flow_lookup_truncated``；
    - possible link / unresolved artifact / 无相关 flow → partial；
    - flow provider 不可用 / 域 dirty → unknown。
    """
    domain: CoverageDomain = "dataflow"
    early = _early_verdict(state, ctx, domain, DATAFLOW_PROVIDER_KEY)
    if early is not None:
        return early

    if domain in ctx.truncated:
        return _result(
            state, domain, "partial", ["v21-05:flow_lookup_truncated"]
        )
    if _gap_hits_domain(ctx, domain):
        return _result(
            state, domain, "partial", ["v21-05:sequence_gap_localized"]
        )
    if _window_stale(ctx, domain):
        return _result(
            state, domain, "stale", ["v21-05:flow_watermark_behind"]
        )

    flows = state.relevant_flows
    refs = _required_refs(ctx)
    if not flows:
        if refs:
            return _result(
                state, domain, "partial", ["v21-05:no_relevant_flows"]
            )
        return _result(
            state, domain, "unknown", ["v21-05:flow_refs_unresolvable"]
        )

    if any(flow.strength == "possible" for flow in flows):
        return _result(
            state, domain, "partial", ["v21-05:possible_flow_link"]
        )

    if refs:
        flow_refs = {
            ref
            for flow in flows
            for ref in (flow.source_ref, flow.target_ref)
        }
        if any(ref not in flow_refs for ref in refs):
            return _result(
                state, domain, "partial", ["v21-05:unresolved_artifact_ref"]
            )
    return _result(state, domain, "complete", ["v21-05:dataflow_complete"])


# ---------------------------------------------------------------------------
# memory 域（02 §6.6）
# ---------------------------------------------------------------------------


def memory_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """memory 域判定（02 §6.6 判定表）。

    - complete：required memory refs、change lifecycle、trust/taint、
      retrieval link 已知；
    - partial：retrieval origin / source link 缺失、lifecycle 未知、
      trust=unknown、gap 定位命中；
    - stale：memory lifecycle/taint watermark 落后；
    - unknown：memory state 不可用（provider 不可用 / 域 dirty /
      required 但 memory_index 为空）。
    """
    domain: CoverageDomain = "memory"
    early = _early_verdict(state, ctx, domain, MEMORY_PROVIDER_KEY)
    if early is not None:
        return early

    if _gap_hits_domain(ctx, domain):
        return _result(
            state, domain, "partial", ["v21-05:sequence_gap_localized"]
        )
    if _window_stale(ctx, domain):
        return _result(
            state, domain, "stale", ["v21-05:memory_watermark_behind"]
        )

    if not state.memory_index:
        return _result(
            state, domain, "unknown", ["v21-05:memory_state_unavailable"]
        )

    facts = {fact.memory_id: fact for fact in state.memory_index}
    refs = _required_refs(ctx)
    if refs:
        matched = [facts[ref] for ref in refs if ref in facts]
        if not matched:
            return _result(
                state, domain, "partial", ["v21-05:memory_refs_missing"]
            )
        considered = matched
    else:
        considered = list(facts.values())

    if any(
        fact.change_status is None or not fact.source_refs
        for fact in considered
    ):
        return _result(
            state,
            domain,
            "partial",
            ["v21-05:memory_lifecycle_or_source_link_missing"],
        )
    if any(fact.trust_state == "unknown" for fact in considered):
        return _result(
            state, domain, "partial", ["v21-05:memory_trust_unknown"]
        )
    return _result(state, domain, "complete", ["v21-05:memory_complete"])
