"""V21-04 安全保持型驱逐与 state flooding 测试（02 §5.1/§5.2）。

- 三类驱逐契约：sticky 不可驱逐、windowed 有界收缩、aggregated 保留
  计数语义（high-impact 动作不因窗口收缩丢失）；
- state flooding：credential sticky 事实 + N 个 benign 填满窗口 +
  external send，sticky 事实存活、capacity 有界；
- 驱逐后无法证明 required domain 完整 → coverage partial。
"""

from __future__ import annotations

from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    CONTAINER_EVICTION_CLASS,
    PROJECTOR_VERSION,
    EvictionLimits,
    OnlineSecurityState,
    StateWatermarks,
    StickyTaintSummary,
    apply_safe_eviction,
    compute_coverage,
    is_benign_source,
    is_sticky_taint_summary,
)
from agentguard_core.signals.models import SequenceRef

from tests.test_v21_security_state_models import (
    make_grant,
    make_recent_action,
    make_source_fact,
)


def make_state(**overrides: object) -> OnlineSecurityState:
    payload: dict[str, object] = {
        "watermarks": StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    }
    payload.update(overrides)
    return OnlineSecurityState(**payload)  # pyright: ignore[reportArgumentType]


def credential_summary() -> StickyTaintSummary:
    return StickyTaintSummary(
        summary_id="summary_credential",
        taints=["CREDENTIAL"],
        first_seen=SequenceRef(
            domain="audit", producer_binding_id="binding_a", value=1
        ),
        last_seen=SequenceRef(
            domain="audit", producer_binding_id="binding_a", value=1
        ),
        unresolved_flow_refs=[],
        memory_refs=[],
        evidence_refs=[],
    )


def test_eviction_class_mapping_follows_frozen_contract() -> None:
    sticky_containers = {
        "active_grants",
        "revoked_grant_ids",
        "grant_consumptions",
        "execution_leases",
        "sticky_taint_summaries",
        "relevant_flows",
        "memory_index",
        "watermarks",
        "dirty_domains",
    }
    for container in sticky_containers:
        assert CONTAINER_EVICTION_CLASS[container] == "sticky"
    assert CONTAINER_EVICTION_CLASS["recent_actions"] == "windowed"
    assert CONTAINER_EVICTION_CLASS["source_index"] == "windowed"
    assert CONTAINER_EVICTION_CLASS["behavior_aggregates"] == "aggregated"

    assert is_sticky_taint_summary(["CREDENTIAL"])
    assert is_sticky_taint_summary(["PERSISTENT_UNTRUSTED"])
    assert not is_sticky_taint_summary(["UNTRUSTED"])


def test_windowed_actions_are_bounded_from_oldest() -> None:
    actions = [make_recent_action(index) for index in range(5)]
    state = make_state(recent_actions=actions)
    new_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=2, benign_sources=512)
    )
    assert len(new_state.recent_actions) == 2
    # 从最旧开始驱逐，保留最近的 windowed 条目。
    assert [action.event_id for action in new_state.recent_actions] == [
        "event_3",
        "event_4",
    ]
    assert report.removed_counts == {"recent_actions": 3}
    assert report.unprovable_domains == ["behavior"]
    assert new_state.evicted is True


def test_high_impact_actions_survive_window_pressure() -> None:
    actions = [
        make_recent_action(0, impact="high", action_type="credential.read"),
        *[make_recent_action(index) for index in range(1, 6)],
    ]
    state = make_state(recent_actions=actions)
    new_state, _ = apply_safe_eviction(
        state, EvictionLimits(recent_actions=2, benign_sources=512)
    )
    event_ids = {action.event_id for action in new_state.recent_actions}
    # aggregated 保留语义：high-impact count 不因驱逐丢失。
    assert "event_0" in event_ids
    assert len(new_state.recent_actions) == 3


def test_only_benign_sources_are_evicted() -> None:
    sources = [
        make_source_fact(source_id="src_untrusted", trust="untrusted"),
        make_source_fact(source_id="src_tainted", taints=["SENSITIVE"]),
        *[
            make_source_fact(
                source_id=f"src_benign_{index}", trust="trusted", taints=[]
            )
            for index in range(3)
        ],
    ]
    assert not is_benign_source(sources[0])
    assert not is_benign_source(sources[1])

    state = make_state(source_index=sources)
    new_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=256, benign_sources=1)
    )
    retained_ids = {source.source_id for source in new_state.source_index}
    assert "src_untrusted" in retained_ids
    assert "src_tainted" in retained_ids
    assert len([sid for sid in retained_ids if sid.startswith("src_benign")]) == 1
    assert report.removed_counts == {"source_index": 2}


def test_sticky_containers_are_never_evicted() -> None:
    grant = make_grant()
    summary = credential_summary()
    state = make_state(
        active_grants=[grant],
        sticky_taint_summaries=[summary],
        dirty_domains=["behavior"],
        recent_actions=[make_recent_action(index) for index in range(10)],
    )
    new_state, _ = apply_safe_eviction(
        state, EvictionLimits(recent_actions=1, benign_sources=1)
    )
    assert new_state.active_grants == [grant]
    assert new_state.sticky_taint_summaries == [summary]
    assert new_state.dirty_domains == ["behavior"]


def test_state_flooding_keeps_credential_sticky_fact_bounded() -> None:
    # 02 §5.2：credential read → N benign actions 填满窗口 → external send。
    limits = EvictionLimits(recent_actions=8, benign_sources=8)
    flood_actions = [
        make_recent_action(0, impact="high", action_type="credential.read"),
        *[make_recent_action(index) for index in range(1, 30)],
        make_recent_action(
            30,
            impact="high",
            action_type="email.send",
            effects={"external_communication": True, "data_egress": True},
        ),
    ]
    state = make_state(
        active_grants=[make_grant()],
        sticky_taint_summaries=[credential_summary()],
        source_index=[
            make_source_fact(source_id="src_credential", taints=["CREDENTIAL"])
        ],
        recent_actions=flood_actions,
    )

    new_state, report = apply_safe_eviction(state, limits)

    # credential sticky 事实必须存活，不得被普通驱逐洗掉。
    assert new_state.sticky_taint_summaries == state.sticky_taint_summaries
    assert any(
        source.source_id == "src_credential" for source in new_state.source_index
    )
    # capacity 有界：windowed 条目不超出限额。
    windowed = [
        action
        for action in new_state.recent_actions
        if action.impact not in {"high", "critical"}
    ]
    assert len(windowed) <= limits.recent_actions
    # external send（high impact）与 credential read 均存活。
    event_ids = {action.event_id for action in new_state.recent_actions}
    assert "event_0" in event_ids
    assert "event_30" in event_ids
    assert report.unprovable_domains == ["behavior"]


def plan_with_required(required: list[str]) -> RequiredCheckPlan:
    all_domains = [
        "task",
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    ]
    return RequiredCheckPlan(
        plan_id="v21-04-plan:fixture",
        impact="high",
        required_domains=list(required),  # pyright: ignore[reportArgumentType]
        optional_domains=[d for d in all_domains if d not in required],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-04:fixture"],
    )


def test_eviction_makes_unprovable_required_domain_partial() -> None:
    actions = [make_recent_action(index) for index in range(10)]
    state = make_state(recent_actions=actions)
    new_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=2, benign_sources=512)
    )

    coverage = compute_coverage(
        new_state,
        plan_with_required(["behavior"]),
        projector_version=PROJECTOR_VERSION,
        task_required=False,
        eviction_report=report,
    )
    assert coverage.behavior.status == "partial"
    assert "v21-04:safety_preserving_eviction" in coverage.behavior.reason_codes

    # 未发生驱逐时同 plan 不降 partial（projector 未接线 → unknown）。
    coverage_clean = compute_coverage(
        state,
        plan_with_required(["behavior"]),
        projector_version=PROJECTOR_VERSION,
        task_required=False,
    )
    assert coverage_clean.behavior.status == "unknown"


def test_no_eviction_report_keeps_state_and_leaves_no_mark() -> None:
    state = make_state(recent_actions=[make_recent_action(1)])
    new_state, report = apply_safe_eviction(state, EvictionLimits())
    assert report.removed_counts == {}
    assert report.unprovable_domains == []
    assert new_state.evicted is False
    assert new_state.recent_actions == state.recent_actions


def test_eviction_preserves_original_relative_order_of_actions() -> None:
    # F8：驱逐后保留项必须维持原相对顺序（时序不被 sticky/windowed
    # 重排打破），sticky（high impact）项不被驱逐。
    actions = [
        make_recent_action(1),
        make_recent_action(2),
        make_recent_action(3, impact="high"),
    ]
    state = make_state(recent_actions=actions)
    new_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=1, benign_sources=512)
    )
    # windowed 超额 1 → 驱逐最旧的 event_1；event_2 与 high 的 event_3
    # 维持原相对顺序（修复前会重排为 [event_3, event_2]）。
    assert [action.event_id for action in new_state.recent_actions] == [
        "event_2",
        "event_3",
    ]
    assert report.removed_counts == {"recent_actions": 1}


def test_eviction_preserves_original_relative_order_of_sources() -> None:
    # F8：source_index 收缩 benign 后同样保持原相对顺序。
    sources = [
        make_source_fact(source_id="src_untrusted_0", trust="untrusted"),
        make_source_fact(source_id="src_benign_1", trust="trusted", taints=[]),
        make_source_fact(source_id="src_benign_2", trust="trusted", taints=[]),
        make_source_fact(source_id="src_untrusted_3", trust="untrusted"),
    ]
    state = make_state(source_index=sources)
    new_state, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=256, benign_sources=1)
    )
    # benign 超额 1 → 驱逐最旧的 src_benign_1；其余维持原序（修复前会
    # 重排为 [untrusted_0, untrusted_3, benign_2]）。
    assert [source.source_id for source in new_state.source_index] == [
        "src_untrusted_0",
        "src_benign_2",
        "src_untrusted_3",
    ]
    assert report.removed_counts == {"source_index": 1}
