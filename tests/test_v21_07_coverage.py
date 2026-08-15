"""V21-07 Behavior/Sequence — behavior / runtime_outcome 两域 coverage。

覆盖 02 §6.4（behavior）与 02 §6.7（runtime_outcome）判定表关键分支，
含 state flooding 场景（02 §5.2）：安全保持型驱逐收缩后 aggregated /
windowed evidence 不得判 complete（C8：不回退为 complete）。

夹具解耦（C6）：直接构造 ``OnlineSecurityState`` + ``CoverageContext``，
不依赖 V21-05/06 接线。B1-B5 端到端真实链验收属 Phase 2（集成 PR），
本期不做。
"""

from __future__ import annotations

from agentguard_core.actions.models import ActionEffect
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context.coverage import (
    GapContext,
    RequiredHistoryWindow,
)
from agentguard_core.security_context.coverage_context import CoverageContext
from agentguard_core.security_context.eviction import (
    EvictionLimits,
    EvictionReport,
    apply_safe_eviction,
)
from agentguard_core.security_context.facts import (
    GapRange,
    RecentActionFact,
    RuntimeOutcomeFact,
    StateWatermarks,
)
from agentguard_core.security_context.projection.behavior_coverage import (
    BEHAVIOR_PROVIDER_KEY,
    RUNTIME_OUTCOME_PROVIDER_KEY,
    behavior_coverage,
    runtime_outcome_coverage,
)
from agentguard_core.security_context.state import OnlineSecurityState
from agentguard_core.signals.models import SequenceRef


def make_watermarks(
    *,
    projected: SequenceRef | None = None,
    receipt: SequenceRef | None = None,
) -> StateWatermarks:
    return StateWatermarks(
        committed_sequence=None,
        projected_sequence=projected,
        runtime_receipt_sequence=receipt,
        memory_sequence=None,
        gaps=[],
    )


def seq(domain: str, producer: str, value: int) -> SequenceRef:
    return SequenceRef(
        domain=domain, producer_binding_id=producer, value=value  # type: ignore[arg-type]
    )


def make_action(
    action_id: str,
    *,
    impact: str = "low",
    runtime_sequence: SequenceRef | None = None,
    final_decision: str | None = "allow",
) -> RecentActionFact:
    return RecentActionFact(
        action_id=action_id,
        event_id=f"event_{action_id}",
        agent_id="agent_a",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=runtime_sequence,
        action_type=f"tool.{action_id}",
        impact=impact,  # type: ignore[arg-type]
        effects=ActionEffect(),
        resource_ids=[],
        destination_ids=[],
        data_refs=[],
        authority_status="authorized",
        final_decision=final_decision,  # type: ignore[arg-type]
        evidence_refs=[],
    )


def make_outcome(action_id: str, *, receipt_value: int = 1) -> RuntimeOutcomeFact:
    return RuntimeOutcomeFact(
        action_id=action_id,
        decision_id=f"decision_{action_id}",
        policy_audit_id=f"policy_audit_{action_id}",
        consumption_id=None,
        lease_id=None,
        execution_status="executed",
        receipt_sequence=seq("receipt", "binding_r", receipt_value),
        evidence_refs=[],
    )


def make_plan(required_domains: list[str]) -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-07-plan:fixture",
        impact="high",
        required_domains=required_domains,  # type: ignore[list-item]
        optional_domains=[],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-07:fixture"],
    )


def make_context(
    state: OnlineSecurityState,
    *,
    required: list[str],
    gaps: tuple[GapRange, ...] = (),
    gap_context: GapContext | None = None,
    eviction_report: EvictionReport | None = None,
    provider_available: dict[str, bool] | None = None,
) -> CoverageContext:
    return CoverageContext(
        plan=make_plan(required),
        watermarks=state.watermarks,
        gap_context=gap_context,
        gaps=gaps,
        eviction_report=eviction_report,
        provider_available=provider_available or {},
    )


def state_with_actions(
    actions: list[RecentActionFact],
    *,
    projected_value: int = 10,
) -> OnlineSecurityState:
    return OnlineSecurityState(
        recent_actions=actions,
        watermarks=make_watermarks(
            projected=seq("audit", "binding_a", projected_value)
        ),
    )


# ---------------------------------------------------------------------------
# 1. behavior 域（02 §6.4）
# ---------------------------------------------------------------------------


def test_behavior_not_applicable_when_not_required() -> None:
    state = state_with_actions([])
    ctx = make_context(state, required=["task"])
    result = behavior_coverage(state, ctx)
    assert result.status == "not_applicable"
    assert result.reason_codes == ["v21-07:behavior_not_required"]


def test_behavior_unknown_when_dirty() -> None:
    state = state_with_actions([])
    state = state.model_copy(update={"dirty_domains": ["behavior"]})
    ctx = make_context(state, required=["behavior"])
    result = behavior_coverage(state, ctx)
    assert result.status == "unknown"
    assert result.reason_codes == ["v21-07:dirty_projection"]


def test_behavior_unknown_when_projector_unavailable() -> None:
    state = state_with_actions([])
    ctx = make_context(
        state,
        required=["behavior"],
        provider_available={BEHAVIOR_PROVIDER_KEY: False},
    )
    result = behavior_coverage(state, ctx)
    assert result.status == "unknown"
    assert result.reason_codes == ["v21-07:behavior_projector_unavailable"]


def test_behavior_stale_when_watermark_behind_required_window() -> None:
    state = state_with_actions(
        [make_action("a1", runtime_sequence=seq("audit", "binding_a", 3))]
    )
    gap_context = GapContext(
        required_history_windows=(
            RequiredHistoryWindow(
                domain="behavior",
                start_sequence=1,
                end_sequence=9,
                sequence_domain="audit",
                producer_binding_id="binding_a",
            ),
        )
    )
    ctx = make_context(state, required=["behavior"], gap_context=gap_context)
    result = behavior_coverage(state, ctx)
    assert result.status == "stale"
    assert result.reason_codes == ["v21-07:behavior_watermark_behind"]


def test_behavior_partial_when_relevant_gap_present() -> None:
    state = state_with_actions([])
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=2,
        end_sequence=4,
        reason="missing audit interval",
    )
    ctx = make_context(state, required=["behavior"], gaps=(gap,))
    result = behavior_coverage(state, ctx)
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:gap_affects_behavior_window"]


def test_behavior_complete_happy_path() -> None:
    state = state_with_actions(
        [make_action("a1", runtime_sequence=seq("audit", "binding_a", 9))]
    )
    gap_context = GapContext(
        required_history_windows=(
            RequiredHistoryWindow(
                domain="behavior",
                start_sequence=1,
                end_sequence=9,
                sequence_domain="audit",
                producer_binding_id="binding_a",
            ),
        )
    )
    ctx = make_context(state, required=["behavior"], gap_context=gap_context)
    result = behavior_coverage(state, ctx)
    assert result.status == "complete"
    assert result.reason_codes == ["v21-07:behavior_window_covered"]


def test_behavior_eviction_shrink_must_not_be_complete() -> None:
    """state flooding 语义：windowed 收缩后不得判 complete（C8）。"""
    state = state_with_actions(
        [make_action("a1", runtime_sequence=seq("audit", "binding_a", 9))]
    )
    report = EvictionReport(
        removed_counts={"recent_actions": 12},
        unprovable_domains=["behavior"],
    )
    ctx = make_context(state, required=["behavior"], eviction_report=report)
    result = behavior_coverage(state, ctx)
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:safety_preserving_eviction"]


def test_behavior_flooding_scenario_small_window() -> None:
    """02 §5.2 小型构造场景：35 条 benign 动作填满窗口触发驱逐。"""
    actions = [
        make_action(
            f"benign_{index:02d}",
            impact="low",
            runtime_sequence=seq("audit", "binding_a", index),
        )
        for index in range(1, 36)
    ]
    state = state_with_actions(actions, projected_value=35)
    evicted_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=10)
    )
    assert report.removed_counts.get("recent_actions", 0) > 0
    assert "behavior" in report.unprovable_domains

    ctx = make_context(evicted_state, required=["behavior"], eviction_report=report)
    result = behavior_coverage(evicted_state, ctx)
    # aggregated 收缩语义不回退：不得 complete，降 partial。
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:safety_preserving_eviction"]


def test_behavior_evicted_flag_without_report_is_partial() -> None:
    state = state_with_actions([])
    state = state.model_copy(update={"evicted": True})
    ctx = make_context(state, required=["behavior"])
    result = behavior_coverage(state, ctx)
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:eviction_window_unprovable"]


# ---------------------------------------------------------------------------
# 2. runtime_outcome 域（02 §6.7）
# ---------------------------------------------------------------------------


def test_runtime_outcome_not_applicable_when_not_required() -> None:
    state = state_with_actions([])
    ctx = make_context(state, required=["task"])
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "not_applicable"
    assert result.reason_codes == ["v21-07:runtime_outcome_not_required"]


def test_runtime_outcome_unknown_when_channel_unavailable() -> None:
    state = state_with_actions([])
    ctx = make_context(
        state,
        required=["runtime_outcome"],
        provider_available={RUNTIME_OUTCOME_PROVIDER_KEY: False},
    )
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "unknown"
    assert result.reason_codes == ["v21-07:receipt_channel_unavailable"]


def test_runtime_outcome_unknown_when_dirty() -> None:
    state = state_with_actions([])
    state = state.model_copy(update={"dirty_domains": ["runtime_outcome"]})
    ctx = make_context(state, required=["runtime_outcome"])
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "unknown"
    assert result.reason_codes == ["v21-07:dirty_projection"]


def test_runtime_outcome_complete_when_receipts_known() -> None:
    state = state_with_actions(
        [
            make_action(
                "act_high",
                impact="high",
                runtime_sequence=seq("runtime", "binding_rt", 1),
            )
        ]
    )
    state = state.model_copy(update={"runtime_outcomes": [make_outcome("act_high")]})
    ctx = make_context(state, required=["runtime_outcome"])
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "complete"
    assert result.reason_codes == ["v21-07:receipt_window_covered"]


def test_runtime_outcome_partial_when_receipt_pending() -> None:
    state = state_with_actions(
        [
            make_action(
                "act_high",
                impact="critical",
                runtime_sequence=seq("runtime", "binding_rt", 1),
            )
        ]
    )
    ctx = make_context(state, required=["runtime_outcome"])
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:receipt_pending"]


def test_runtime_outcome_stale_when_watermark_behind() -> None:
    state = state_with_actions(
        [
            make_action(
                "act_high",
                impact="high",
                runtime_sequence=seq("receipt", "binding_r", 9),
            )
        ]
    )
    state = state.model_copy(
        update={
            "watermarks": make_watermarks(
                projected=seq("audit", "binding_a", 10),
                receipt=seq("receipt", "binding_r", 3),
            )
        }
    )
    ctx = make_context(state, required=["runtime_outcome"])
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "stale"
    assert result.reason_codes == ["v21-07:receipt_watermark_behind"]


def test_runtime_outcome_partial_cross_domain_sequence_uncomparable() -> None:
    state = state_with_actions(
        [
            make_action(
                "act_high",
                impact="high",
                runtime_sequence=seq("runtime", "binding_rt", 9),
            )
        ]
    )
    state = state.model_copy(
        update={
            "watermarks": make_watermarks(
                projected=seq("audit", "binding_a", 10),
                receipt=seq("receipt", "binding_r", 3),
            )
        }
    )
    ctx = make_context(state, required=["runtime_outcome"])
    result = runtime_outcome_coverage(state, ctx)
    # 跨域整数不可比（02 §5）：fail-closed 降 partial，不推断先后。
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:receipt_sequence_uncomparable"]


def test_runtime_outcome_partial_when_receipt_gap_present() -> None:
    state = state_with_actions([])
    gap = GapRange(
        domain="receipt",
        producer_binding_id="binding_r",
        start_sequence=5,
        end_sequence=7,
        reason="receipt channel interval missing",
    )
    ctx = make_context(state, required=["runtime_outcome"], gaps=(gap,))
    result = runtime_outcome_coverage(state, ctx)
    assert result.status == "partial"
    assert result.reason_codes == ["v21-07:gap_affects_receipt_window"]
