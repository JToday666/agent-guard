"""Coverage 计算与 gap localized degradation（V21-04 总分派 + V21-05/06/07 域接线，02 §6/§7）。

复用 ``decisions/evidence.py`` 已冻结的 ``DomainCoverage`` /
``CoverageMap`` 模型（V21-01，不得改动）。

- **task 域**按 02 §6.1 完整实现五状态（complete/partial/stale/unknown/
  not_applicable）；task 域不走 delta 投影 —— coverage 直接对照权威
  ``TaskFact`` head 判定，天然支持 stale 检测；
- **其余 6 域**按 ``coverage_context.DOMAIN_COVERAGE_DISPATCH`` 分派到
  各域判定纯函数（V21-05 三域 / V21-06 capability / V21-07 两域）；
  既有优先级保留在总分派层且先于域函数：not_required→not_applicable、
  dirty→unknown、unprovable→partial；
- **gap 不是全局 ASK**（02 §7）：``localize_gaps`` 按四级优先级
  （parent_event_ids → stable refs → RequiredCheckPlan window →
  sequence interval 兜底）把 gap 定位到相关域，仅相关域降级。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ..decisions.evidence import CoverageMap, DomainCoverage, RequiredCheckPlan
from ..signals.models import (
    CoverageDomain,
    EvaluationDegradation,
    SequenceDomain,
    SequenceRef,
)
from .facts import GapRange

if TYPE_CHECKING:
    from .coverage_context import CoverageContext
    from .eviction import EvictionReport
    from .state import OnlineSecurityState

__all__ = [
    "COVERAGE_DOMAINS",
    "GapContext",
    "RequiredHistoryWindow",
    "compute_coverage",
    "default_coverage_context",
    "localize_gaps",
]

#: CoverageMap 固定域顺序（01 §17）。
COVERAGE_DOMAINS: tuple[CoverageDomain, ...] = (
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
)

#: 序列域 → 最直接对应的 coverage 域（优先级 4 兜底映射）。
_SEQUENCE_DOMAIN_TO_COVERAGE: dict[SequenceDomain, CoverageDomain] = {
    "audit": "behavior",
    "runtime": "behavior",
    "memory": "memory",
    "receipt": "runtime_outcome",
    "policy": "capability",
}


class RequiredHistoryWindow(BaseModel):
    """RequiredCheckPlan 的 required history window 项（02 §7 优先级 3）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: CoverageDomain
    start_sequence: int
    end_sequence: int
    sequence_domain: SequenceDomain
    producer_binding_id: str


class GapContext(BaseModel):
    """gap 定位上下文：当前动作的依赖关系（02 §7 四级优先级输入）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    parent_event_ids: frozenset[str] = Field(default_factory=frozenset)
    stable_refs: frozenset[str] = Field(default_factory=frozenset)
    required_history_windows: tuple[RequiredHistoryWindow, ...] = ()


# ---------------------------------------------------------------------------
# compute_coverage (02 §6)
# ---------------------------------------------------------------------------


def _task_coverage(
    state: OnlineSecurityState,
    *,
    task_required: bool,
    authoritative_head_revision: int | None,
    projector_version: str,
    as_of_sequence: SequenceRef | None,
) -> DomainCoverage:
    """task 域五状态判定（02 §6.1 判定表逐行实现）。"""
    reasons: list[str] = []
    if not task_required:
        return DomainCoverage(
            domain="task",
            status="not_applicable",
            as_of_sequence=as_of_sequence,
            projector_version=projector_version,
            reason_codes=["v21-04:policy_task_not_required"],
        )

    task = state.task
    if task is None:
        return DomainCoverage(
            domain="task",
            status="unknown",
            as_of_sequence=as_of_sequence,
            projector_version=projector_version,
            reason_codes=["v21-04:no_authoritative_task"],
        )

    if (
        authoritative_head_revision is not None
        and task.revision < authoritative_head_revision
    ):
        return DomainCoverage(
            domain="task",
            status="stale",
            as_of_sequence=as_of_sequence,
            projector_version=projector_version,
            reason_codes=["v21-04:task_revision_behind_head"],
        )

    if not task.scope_digest:
        reasons.append("v21-04:task_scope_binding_incomplete")
    if not task.principal_id:
        reasons.append("v21-04:task_principal_binding_missing")
    if not _digest_well_formed(task.task_digest):
        reasons.append("v21-04:task_digest_invalid")
    if not (
        task.action_constraints
        or task.resource_constraints
        or task.destination_constraints
    ):
        reasons.append("v21-04:task_constraint_compilation_incomplete")

    if reasons:
        return DomainCoverage(
            domain="task",
            status="partial",
            as_of_sequence=as_of_sequence,
            projector_version=projector_version,
            reason_codes=reasons,
        )
    return DomainCoverage(
        domain="task",
        status="complete",
        as_of_sequence=as_of_sequence,
        projector_version=projector_version,
        reason_codes=["v21-04:task_authority_valid"],
    )


def _digest_well_formed(digest: str) -> bool:
    """最小 digest 形态校验（``sha256:`` / ``hmac-sha256:`` 前缀）。"""
    return digest.startswith(("sha256:", "hmac-sha256:")) and len(digest) > 10


def default_coverage_context(
    state: OnlineSecurityState,
    plan: RequiredCheckPlan,
    *,
    eviction_report: EvictionReport | None = None,
    authoritative_head_revision: int | None = None,
) -> "CoverageContext":
    """从 state + 现有入参构建默认 ``CoverageContext``（最小侵入工厂）。

    口径声明（调用方无法立即构造完整 ctx 时的默认口径）：

    - ``provider_available`` 缺省为空映射：域函数把键缺失视为
      **未报告**（不推断为不可用），等效默认 True；
    - ``truncated`` 缺省为空：未报告任何 bounded lookup 截断；
    - ``gaps`` 缺省为空：gap localized 降级由调用方经
      ``localize_gaps`` 独立消费，不在本工厂隐式注入；
    - ``gap_context`` 缺省 None：无当前动作依赖信息。

    该口径**不掩盖 fail-closed**：无证据时域函数仍各自降
    unknown/partial（source refs 不可解析、memory 状态不可用等）；
    需要精确降级的调用方应显式构造完整 ctx 传入 ``compute_coverage``。
    """
    # 函数级导入打破 coverage ↔ coverage_context 导入环（表本体在
    # coverage_context 静态装配，无运行时注册）。
    from .coverage_context import CoverageContext

    return CoverageContext(
        plan=plan,
        watermarks=state.watermarks,
        gap_context=None,
        gaps=(),
        eviction_report=eviction_report,
        truncated=(),
        provider_available={},
        authoritative_head_revision=authoritative_head_revision,
    )


def compute_coverage(
    state: OnlineSecurityState,
    plan: RequiredCheckPlan,
    *,
    projector_version: str,
    task_required: bool | None = None,
    authoritative_head_revision: int | None = None,
    eviction_report: EvictionReport | None = None,
    context: "CoverageContext | None" = None,
) -> CoverageMap:
    """7 域 coverage 判定（02 §6 判定表）。

    - task：02 §6.1 五状态完整实现（``task_required`` 缺省时按 plan
      推断：``"task" in plan.required_domains``）；
    - 其余 6 域：既有优先级保留在总分派层且先于域函数 ——
      不在 ``plan.required_domains`` → ``not_applicable``；dirty 域 →
      ``unknown``；``eviction_report.unprovable_domains`` 命中 →
      ``partial``；随后按 ``DOMAIN_COVERAGE_DISPATCH`` 分派到域判定
      纯函数（消费 ``context`` 完整上下文，C3）；
    - ``context`` 缺省时经 ``default_coverage_context`` 从 state +
      现有入参构造（口径见该工厂 docstring：provider_available 默认
      未报告、truncated 默认空，不掩盖 fail-closed）；
    - dirty 域覆盖判定：**task 域因权威直读豁免 dirty 降级**（本期
      冻结决策）：task 域不走 delta 投影，snapshot 直读权威 TaskFact
      head，投影存储脏态不影响 task 判定；其余 6 域 dirty 仍降
      ``unknown``；
    - 安全保持型驱逐：``eviction_report.unprovable_domains ∩
      plan.required_domains`` 降 ``partial``（02 §5.1）。
    """
    if context is None:
        context = default_coverage_context(
            state,
            plan,
            eviction_report=eviction_report,
            authoritative_head_revision=authoritative_head_revision,
        )
    # 函数级导入打破 coverage ↔ coverage_context 导入环。
    from .coverage_context import DOMAIN_COVERAGE_DISPATCH

    if task_required is None:
        task_required = "task" in plan.required_domains

    as_of = state.watermarks.projected_sequence
    required = set(plan.required_domains)
    dirty = set(state.dirty_domains)
    unprovable = (
        set(context.eviction_report.unprovable_domains)
        if context.eviction_report
        else set()
    )

    coverages: dict[CoverageDomain, DomainCoverage] = {}
    # F5：task 域 stale 检测的 head revision 双来源合并 —— 显式入参
    # 优先，缺省时消费 context 携带的 authoritative_head_revision
    # （C3：显式构造完整 ctx 的调用方不得被静默忽略）。
    head_revision = (
        authoritative_head_revision
        if authoritative_head_revision is not None
        else context.authoritative_head_revision
    )
    for domain in COVERAGE_DOMAINS:
        if domain == "task":
            coverage = _task_coverage(
                state,
                task_required=task_required,
                authoritative_head_revision=head_revision,
                projector_version=projector_version,
                as_of_sequence=as_of,
            )
        elif domain not in required:
            coverage = DomainCoverage(
                domain=domain,
                status="not_applicable",
                as_of_sequence=as_of,
                projector_version=projector_version,
                reason_codes=["v21-04:policy_not_required"],
            )
        elif domain in dirty:
            coverage = DomainCoverage(
                domain=domain,
                status="unknown",
                as_of_sequence=as_of,
                projector_version=projector_version,
                reason_codes=["v21-04:dirty_projection"],
            )
        elif domain in unprovable:
            coverage = DomainCoverage(
                domain=domain,
                status="partial",
                as_of_sequence=as_of,
                projector_version=projector_version,
                reason_codes=["v21-04:safety_preserving_eviction"],
            )
        else:
            coverage = DOMAIN_COVERAGE_DISPATCH[domain](state, context)
        coverages[domain] = coverage

    return CoverageMap(
        task=coverages["task"],
        source=coverages["source"],
        capability=coverages["capability"],
        behavior=coverages["behavior"],
        dataflow=coverages["dataflow"],
        memory=coverages["memory"],
        runtime_outcome=coverages["runtime_outcome"],
    )


# ---------------------------------------------------------------------------
# localize_gaps (02 §7)
# ---------------------------------------------------------------------------


def _gap_overlaps(
    gap: GapRange, window: RequiredHistoryWindow
) -> bool:
    """sequence interval 重叠（仅同 domain + producer 可比，02 §5）。"""
    if gap.domain != window.sequence_domain:
        return False
    if gap.producer_binding_id != window.producer_binding_id:
        return False
    return gap.start_sequence <= window.end_sequence and (
        gap.end_sequence >= window.start_sequence
    )


def _affected_domains(
    gap: GapRange, context: GapContext
) -> tuple[set[CoverageDomain], str]:
    """按 02 §7 四级优先级定位 gap 影响的 coverage 域。

    返回 (受影响域集合, 命中的优先级 reason_code)。优先级 1/2 需要
    gap 携带可解析的事件/引用 metadata，本期 ``GapRange`` 字段冻结不含
    这些维度，因此在上下文提供 parent_event_ids/stable_refs 且 gap
    reason 引用到它们时命中；否则进入优先级 3/4。
    """
    if context.parent_event_ids and any(
        ref in gap.reason for ref in context.parent_event_ids
    ):
        return set(COVERAGE_DOMAINS), "v21-04:gap_matched_parent_event_ids"
    if context.stable_refs and any(
        ref in gap.reason for ref in context.stable_refs
    ):
        return set(COVERAGE_DOMAINS), "v21-04:gap_matched_stable_refs"

    windowed: set[CoverageDomain] = {
        window.domain
        for window in context.required_history_windows
        if _gap_overlaps(gap, window)
    }
    if windowed:
        return windowed, "v21-04:gap_matched_required_window"

    fallback = _SEQUENCE_DOMAIN_TO_COVERAGE.get(gap.domain)
    if fallback is not None:
        return {fallback}, "v21-04:gap_sequence_interval_fallback"
    return set(), "v21-04:gap_unmapped"


def localize_gaps(
    plan: RequiredCheckPlan,
    gaps: list[GapRange],
    context: GapContext,
) -> list[EvaluationDegradation]:
    """把 gap 定位到相关域，产出 localized degradation（02 §7）。

    冻结语义：

    - **禁止** ``any gap → global ASK``：只有被定位命中的域降级；
    - 若 gap 与当前 required domain 无关，该域可以继续 complete；
    - 若无法确定 gap 是否包含必需 predecessor → 相关 domain =
      ``partial``（由消费方据 degradation 降级），而不是全局所有
      domain partial；
    - degradation_id 由 gap 身份确定性派生（禁 uuid）。
    """
    required = set(plan.required_domains)
    degradations: list[EvaluationDegradation] = []
    seen_ids: set[str] = set()

    for gap in gaps:
        affected, reason_code = _affected_domains(gap, context)
        relevant = sorted(affected & required)
        if not relevant:
            continue
        for domain in relevant:
            degradation_id = (
                "v21-04-gap:"
                f"{gap.domain}:{gap.producer_binding_id}:"
                f"{gap.start_sequence}-{gap.end_sequence}:{domain}"
            )
            if degradation_id in seen_ids:
                continue
            seen_ids.add(degradation_id)
            degradations.append(
                EvaluationDegradation(
                    degradation_id=degradation_id,
                    component_id="v21-04.state_projector",
                    domain=domain,
                    required_for_action=True,
                    failure_kind="sequence_gap",
                    reason_codes=[reason_code],
                    evidence_refs=[],
                )
            )
    return degradations
