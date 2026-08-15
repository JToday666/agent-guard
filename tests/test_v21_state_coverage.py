"""V21-04 Coverage 判定表与 gap localized degradation 测试（02 §6/§7）。

- task 域五状态完整实现（complete/partial/stale/unknown/not_applicable）；
- 其余 6 域经 ``DOMAIN_COVERAGE_DISPATCH`` 分派到域判定纯函数
  （V21-05/06/07 接线完成）：空状态 + 默认 ctx 下 source/dataflow/
  memory fail-closed 判 unknown，capability/behavior/runtime_outcome
  状态已知判 complete；dirty/not_required/eviction 优先级仍保留在
  总分派层（v21-04 reason codes）；
- gap localized degradation：按 02 §7 四级优先级把 gap 定位到相关域，
  仅相关域降级，禁止全局降级；
- 驱逐后无法证明完整 → partial（与 eviction 测试互补的 coverage 侧断言）。
"""

from __future__ import annotations

import pytest

from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PROJECTOR_VERSION,
    GapContext,
    GapRange,
    OnlineSecurityState,
    RequiredHistoryWindow,
    compute_coverage,
    localize_gaps,
)
from agentguard_core.security_context.coverage_context import CoverageContext

from tests.test_v21_security_state_models import make_watermarks
from tests.test_v21_state_replay import make_task_fact

NON_TASK_DOMAINS = [
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
]


def make_state(**overrides: object) -> OnlineSecurityState:
    payload: dict[str, object] = {"watermarks": make_watermarks()}
    payload.update(overrides)
    return OnlineSecurityState(**payload)  # pyright: ignore[reportArgumentType]


def plan(
    required: list[str],
) -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-04-plan:fixture",
        impact="high",
        required_domains=list(required),  # pyright: ignore[reportArgumentType]
        optional_domains=[d for d in COVERAGE_DOMAINS if d not in required],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-04:fixture"],
    )


def coverage_of(state: OnlineSecurityState, required: list[str], **kwargs):
    return compute_coverage(
        state,
        plan(required),
        projector_version=PROJECTOR_VERSION,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# task 域五状态（02 §6.1）
# ---------------------------------------------------------------------------


def test_task_complete_with_valid_authoritative_head() -> None:
    task = make_task_fact()
    state = make_state(task=task)
    coverage = coverage_of(state, ["task"], authoritative_head_revision=3)
    assert coverage.task.status == "complete"
    assert "v21-04:task_authority_valid" in coverage.task.reason_codes


def test_task_partial_when_constraint_compilation_incomplete() -> None:
    task = make_task_fact().model_copy(
        update={
            "action_constraints": [],
            "resource_constraints": [],
            "destination_constraints": [],
        }
    )
    state = make_state(task=task)
    coverage = coverage_of(state, ["task"], authoritative_head_revision=3)
    assert coverage.task.status == "partial"
    assert (
        "v21-04:task_constraint_compilation_incomplete"
        in coverage.task.reason_codes
    )


def test_task_partial_when_digest_malformed() -> None:
    task = make_task_fact().model_copy(update={"task_digest": "not-a-digest"})
    state = make_state(task=task)
    coverage = coverage_of(state, ["task"], authoritative_head_revision=3)
    assert coverage.task.status == "partial"
    assert "v21-04:task_digest_invalid" in coverage.task.reason_codes


def test_task_stale_when_revision_behind_head() -> None:
    state = make_state(task=make_task_fact())  # revision = 3
    coverage = coverage_of(state, ["task"], authoritative_head_revision=4)
    assert coverage.task.status == "stale"
    assert "v21-04:task_revision_behind_head" in coverage.task.reason_codes


def test_task_unknown_without_authoritative_task() -> None:
    state = make_state(task=None)
    coverage = coverage_of(state, ["task"])
    assert coverage.task.status == "unknown"
    assert "v21-04:no_authoritative_task" in coverage.task.reason_codes


def test_task_not_applicable_when_policy_does_not_require() -> None:
    state = make_state(task=None)
    coverage = coverage_of(state, ["behavior"], task_required=False)
    assert coverage.task.status == "not_applicable"
    assert "v21-04:policy_task_not_required" in coverage.task.reason_codes


def test_task_stale_detection_consumes_context_head_revision() -> None:
    # F5：显式构造的 context 携带 authoritative_head_revision 时，
    # task 域 stale 检测不得被静默忽略（C3）。
    state = make_state(task=make_task_fact())  # revision = 3
    ctx = CoverageContext(
        plan=plan(["task"]),
        watermarks=state.watermarks,
        authoritative_head_revision=4,
    )
    coverage = compute_coverage(
        state, plan(["task"]), projector_version=PROJECTOR_VERSION, context=ctx
    )
    assert coverage.task.status == "stale"
    assert "v21-04:task_revision_behind_head" in coverage.task.reason_codes

    # 合并口径：显式入参优先于 context 携带值。
    override = compute_coverage(
        state,
        plan(["task"]),
        projector_version=PROJECTOR_VERSION,
        authoritative_head_revision=3,
        context=ctx,
    )
    assert override.task.status == "complete"


# ---------------------------------------------------------------------------
# 其余 6 域接线后语义（DOMAIN_COVERAGE_DISPATCH 分派，02 §6.2-§6.7）
# ---------------------------------------------------------------------------

#: 空 state + 默认 ctx（无 gap_context / gaps / truncated）下六域的
#: 确定性判定（provenance 三域无 stable refs → fail-closed unknown；
#: capability 无 required capabilities / behavior 无窗口需求 /
#: runtime_outcome 无 pending receipt → 状态已知 complete）。
WIRED_EMPTY_STATE_EXPECTATION = {
    "source": ("unknown", "v21-05:source_refs_unresolvable"),
    "capability": ("complete", "v21-06:capability_state_known"),
    "behavior": ("complete", "v21-07:behavior_window_covered"),
    "dataflow": ("unknown", "v21-05:flow_refs_unresolvable"),
    "memory": ("unknown", "v21-05:memory_state_unavailable"),
    "runtime_outcome": ("complete", "v21-07:receipt_window_covered"),
}


def test_six_domains_dispatch_to_wired_verdicts() -> None:
    state = make_state(task=make_task_fact())
    coverage = coverage_of(state, ["task", *NON_TASK_DOMAINS])
    for domain in NON_TASK_DOMAINS:
        expected_status, expected_reason = WIRED_EMPTY_STATE_EXPECTATION[domain]
        domain_coverage = getattr(coverage, domain)
        assert domain_coverage.status == expected_status, domain
        assert expected_reason in domain_coverage.reason_codes, domain
        # 接线后 reason_code 用各域前缀（v21-04:projector_not_wired 退役）。
        assert "v21-04:projector_not_wired" not in (
            domain_coverage.reason_codes
        ), domain

    coverage_na = coverage_of(state, ["task"], task_required=True)
    for domain in NON_TASK_DOMAINS:
        domain_coverage = getattr(coverage_na, domain)
        assert domain_coverage.status == "not_applicable", domain
        assert (
            "v21-04:policy_not_required" in domain_coverage.reason_codes
        ), domain


def test_dirty_domain_is_fail_closed_unknown() -> None:
    state = make_state(dirty_domains=["behavior"])
    coverage = coverage_of(state, ["behavior"])
    assert coverage.behavior.status == "unknown"
    assert "v21-04:dirty_projection" in coverage.behavior.reason_codes


@pytest.mark.parametrize("domain", NON_TASK_DOMAINS)
def test_non_task_dirty_domains_degrade_unknown(domain: str) -> None:
    # F6 契约固化：其余 6 域 dirty 仍降 unknown（fail-closed）。
    state = make_state(dirty_domains=[domain])
    coverage = coverage_of(state, [domain])
    domain_coverage = getattr(coverage, domain)
    assert domain_coverage.status == "unknown"
    assert "v21-04:dirty_projection" in domain_coverage.reason_codes


def test_task_domain_is_exempt_from_dirty_degradation() -> None:
    # F6 契约固化（本期冻结决策）：task 域因权威直读豁免 dirty 降级 ——
    # task 在 dirty_domains 中时仍按权威 head 判定，不降 unknown。
    state = make_state(task=make_task_fact(), dirty_domains=["task"])
    coverage = coverage_of(state, ["task"], authoritative_head_revision=3)
    assert coverage.task.status == "complete"
    assert "v21-04:task_authority_valid" in coverage.task.reason_codes
    assert "v21-04:dirty_projection" not in coverage.task.reason_codes

    # 豁免不掩盖 stale 检测：head revision 领先时仍判 stale。
    stale = coverage_of(state, ["task"], authoritative_head_revision=4)
    assert stale.task.status == "stale"


# ---------------------------------------------------------------------------
# gap localized degradation（02 §7：禁止 any gap → global ASK）
# ---------------------------------------------------------------------------


def behavior_window() -> RequiredHistoryWindow:
    return RequiredHistoryWindow(
        domain="behavior",
        start_sequence=1,
        end_sequence=10,
        sequence_domain="audit",
        producer_binding_id="binding_a",
    )


def test_gap_in_behavior_window_only_degrades_behavior() -> None:
    required_plan = plan(["task", "behavior", "dataflow"])
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=4,
        end_sequence=6,
        reason="missing_audit_window",
    )
    context = GapContext(
        parent_event_ids=frozenset(),
        stable_refs=frozenset(),
        required_history_windows=(behavior_window(),),
    )
    degradations = localize_gaps(required_plan, [gap], context)

    assert degradations, "behavior 域 gap 必须产出 localized degradation"
    assert {degradation.domain for degradation in degradations} == {"behavior"}
    assert all(
        degradation.failure_kind == "sequence_gap"
        for degradation in degradations
    )
    assert all(
        degradation.required_for_action for degradation in degradations
    )
    assert all(
        code.startswith("v21-04:")
        for degradation in degradations
        for code in degradation.reason_codes
    )

    # task / dataflow 不受牵连：task 仍 complete，无全局降级。
    state = make_state(task=make_task_fact())
    coverage = coverage_of(
        state, ["task", "behavior", "dataflow"], authoritative_head_revision=3
    )
    assert coverage.task.status == "complete"
    degraded_domains = {degradation.domain for degradation in degradations}
    assert "task" not in degraded_domains
    assert "dataflow" not in degraded_domains


def test_gap_outside_required_domains_produces_no_degradation() -> None:
    required_plan = plan(["task", "behavior"])
    # receipt 序列域兜底映射 runtime_outcome，但不在 required → 不降级。
    gap = GapRange(
        domain="receipt",
        producer_binding_id="binding_a",
        start_sequence=1,
        end_sequence=2,
        reason="missing_receipts",
    )
    context = GapContext(required_history_windows=(behavior_window(),))
    assert localize_gaps(required_plan, [gap], context) == []


def test_gap_localization_priority_parent_event_ids_first() -> None:
    required_plan = plan(["task", "behavior", "memory"])
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=100,
        end_sequence=200,
        reason="missing window containing event_42",
    )
    context = GapContext(
        parent_event_ids=frozenset({"event_42"}),
        required_history_windows=(behavior_window(),),
    )
    degradations = localize_gaps(required_plan, [gap], context)
    # 优先级 1 命中：gap 明确覆盖当前动作的 parent 事件 → 所有 required
    # 域都必须按「无法确定 gap 是否包含必需 predecessor」处理。
    assert {d.domain for d in degradations} == {"task", "behavior", "memory"}
    assert all(
        "v21-04:gap_matched_parent_event_ids" in d.reason_codes
        for d in degradations
    )


def test_gap_sequence_interval_fallback_is_localized() -> None:
    required_plan = plan(["memory"])
    gap = GapRange(
        domain="memory",
        producer_binding_id="binding_a",
        start_sequence=1,
        end_sequence=2,
        reason="missing_memory_window",
    )
    degradations = localize_gaps(required_plan, [gap], GapContext())
    assert [d.domain for d in degradations] == ["memory"]
    assert degradations[0].reason_codes == [
        "v21-04:gap_sequence_interval_fallback"
    ]


def test_cross_domain_sequence_interval_never_compared() -> None:
    required_plan = plan(["behavior"])
    # memory 域 gap 与 audit 域 required window：不同序列域不做整数重叠
    # 判定（02 §5），因此 window 优先级不命中，走 memory 兜底映射；
    # memory 不在 required → 无降级。
    gap = GapRange(
        domain="memory",
        producer_binding_id="binding_a",
        start_sequence=1,
        end_sequence=10,
        reason="missing_memory_window",
    )
    context = GapContext(required_history_windows=(behavior_window(),))
    assert localize_gaps(required_plan, [gap], context) == []


def test_gap_localization_priority_stable_refs() -> None:
    # F10：优先级 2（stable refs）命中产出 localized degradation。
    required_plan = plan(["task", "behavior", "memory"])
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=100,
        end_sequence=200,
        reason="missing window covering flow_ref_7",
    )
    context = GapContext(
        stable_refs=frozenset({"flow_ref_7"}),
        required_history_windows=(behavior_window(),),
    )
    degradations = localize_gaps(required_plan, [gap], context)
    assert {d.domain for d in degradations} == {"task", "behavior", "memory"}
    assert all(
        "v21-04:gap_matched_stable_refs" in d.reason_codes for d in degradations
    )
    assert all(d.failure_kind == "sequence_gap" for d in degradations)


def test_gap_without_matching_refs_falls_back_not_priority_1_or_2() -> None:
    # F10 负例：reason 不含任何 parent event id / stable ref 且无窗口
    # 重叠时，不得误命中优先级 1/2，走序列区间兜底映射。
    required_plan = plan(["behavior"])
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=1,
        end_sequence=2,
        reason="missing_audit_window",
    )
    context = GapContext(
        parent_event_ids=frozenset({"event_999"}),
        stable_refs=frozenset({"ref_unrelated"}),
        required_history_windows=(),
    )
    degradations = localize_gaps(required_plan, [gap], context)
    assert [d.domain for d in degradations] == ["behavior"]
    assert degradations[0].reason_codes == [
        "v21-04:gap_sequence_interval_fallback"
    ]


@pytest.mark.parametrize("domain", NON_TASK_DOMAINS)
def test_wired_domains_report_real_verdicts_on_empty_state(domain: str) -> None:
    # 接线后六域给出真实判定（不再一律 unknown）：无证据的 provenance
    # 三域仍 fail-closed unknown，状态已知的三域判 complete。
    state = make_state(task=make_task_fact())
    coverage = coverage_of(state, ["task", *NON_TASK_DOMAINS])
    expected_status, _ = WIRED_EMPTY_STATE_EXPECTATION[domain]
    assert getattr(coverage, domain).status == expected_status
