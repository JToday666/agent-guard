"""V21-07 Behavior/Sequence — 分区排序与 branch/parent 优先级验收。

覆盖 02 §5（SequenceRef.domain + producer_binding_id 才可比较，跨域
整数比较 fail-closed）与 04 §13（branch/parent refs 优先于纯 sequence）。

B1-B5 端到端真实链验收属 Phase 2（集成 PR），本期用构造夹具解耦
（C6），本文件只验收排序/比较/前驱关联的纯函数语义。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.models import ActionEffect
from agentguard_core.security_context.facts import (
    RecentActionFact,
    StateWatermarks,
)
from agentguard_core.security_context.projection.behavior import (
    apply_action_additions,
    ordered_by_sequence_partition,
)
from agentguard_core.security_context.projection.behavior_matchers import (
    LINK_KIND_PRIORITY,
    predecessor_link_kind,
    select_predecessor,
)
from agentguard_core.security_context.state import (
    OnlineSecurityState,
    SequenceComparisonError,
    compare_sequence_refs,
)
from agentguard_core.signals.models import SequenceRef


def make_watermarks() -> StateWatermarks:
    return StateWatermarks(
        committed_sequence=None,
        projected_sequence=None,
        runtime_receipt_sequence=None,
        memory_sequence=None,
        gaps=[],
    )


def empty_state() -> OnlineSecurityState:
    return OnlineSecurityState(watermarks=make_watermarks())


def seq(domain: str, producer: str, value: int) -> SequenceRef:
    return SequenceRef(
        domain=domain, producer_binding_id=producer, value=value  # type: ignore[arg-type]
    )


def make_action(
    action_id: str,
    *,
    event_id: str | None = None,
    branch_id: str | None = None,
    parent_event_ids: list[str] | None = None,
    runtime_sequence: SequenceRef | None = None,
) -> RecentActionFact:
    return RecentActionFact(
        action_id=action_id,
        event_id=event_id or f"event_{action_id}",
        agent_id="agent_a",
        branch_id=branch_id,
        parent_event_ids=parent_event_ids or [],
        runtime_sequence=runtime_sequence,
        action_type=f"tool.{action_id}",
        impact="low",
        effects=ActionEffect(),
        resource_ids=[],
        destination_ids=[],
        data_refs=[],
        authority_status="authorized",
        final_decision="allow",
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# 1. 分区排序正例（02 §5）
# ---------------------------------------------------------------------------


def test_partition_sort_within_single_partition() -> None:
    actions = [
        make_action("a3", runtime_sequence=seq("audit", "binding_a", 30)),
        make_action("a1", runtime_sequence=seq("audit", "binding_a", 10)),
        make_action("a2", runtime_sequence=seq("audit", "binding_a", 20)),
    ]
    ordered = ordered_by_sequence_partition(actions)
    assert [a.action_id for a in ordered] == ["a1", "a2", "a3"]


def test_partition_sort_multi_domain_grouped_not_interleaved() -> None:
    actions = [
        make_action("r5", runtime_sequence=seq("runtime", "binding_b", 5)),
        make_action("a9", runtime_sequence=seq("audit", "binding_a", 9)),
        make_action("r1", runtime_sequence=seq("runtime", "binding_b", 1)),
        make_action("a2", runtime_sequence=seq("audit", "binding_a", 2)),
        make_action("p7", runtime_sequence=seq("policy", "binding_c", 7)),
    ]
    ordered = ordered_by_sequence_partition(actions)
    ids = [a.action_id for a in ordered]
    # 分区键字典序：audit < policy < runtime；分区内按序列值升序。
    assert ids == ["a2", "a9", "p7", "r1", "r5"]
    # 跨域整数（如 audit 9 与 runtime 1）永不直接比较：无异常且分区隔离。
    assert [partition_of(a) for a in ordered] == [
        ("audit", "binding_a"),
        ("audit", "binding_a"),
        ("policy", "binding_c"),
        ("runtime", "binding_b"),
        ("runtime", "binding_b"),
    ]


def partition_of(
    action: RecentActionFact,
) -> tuple[str, str] | None:
    sequence = action.runtime_sequence
    if sequence is None:
        return None
    return (sequence.domain, sequence.producer_binding_id)


def test_same_value_stable_and_cross_producer_partitions_distinct() -> None:
    actions = [
        make_action("x1", runtime_sequence=seq("audit", "binding_x", 5)),
        make_action("y1", runtime_sequence=seq("audit", "binding_y", 5)),
        make_action("x2", runtime_sequence=seq("audit", "binding_x", 5)),
    ]
    ordered = ordered_by_sequence_partition(actions)
    # 同分区同 value 稳定保持到达序；不同 producer 是不同分区不合并。
    assert [a.action_id for a in ordered] == ["x1", "x2", "y1"]


def test_apply_action_additions_mixed_domains_never_cross_compares() -> None:
    """handler 对跨域混合输入不抛错：先分桶，桶内才用比较器。"""
    state = empty_state()
    items = [
        make_action("m1", runtime_sequence=seq("memory", "binding_m", 100)),
        make_action("a1", runtime_sequence=seq("audit", "binding_a", 1)),
        make_action("r1", runtime_sequence=seq("receipt", "binding_r", 50)),
    ]
    result = apply_action_additions(state, items)
    ids = [a.action_id for a in result.recent_actions]
    assert ids == ["a1", "m1", "r1"]


# ---------------------------------------------------------------------------
# 2. 跨域整数比较必须 fail-closed 抛错（负例）
# ---------------------------------------------------------------------------


def test_cross_domain_sequence_comparison_raises_fail_closed() -> None:
    left = seq("audit", "binding_a", 1)
    right = seq("runtime", "binding_b", 999)
    with pytest.raises(SequenceComparisonError) as excinfo:
        compare_sequence_refs(left, right)
    assert excinfo.value.reason_code == "v21-04:cross_domain_sequence_comparison"


def test_cross_producer_sequence_comparison_raises_fail_closed() -> None:
    left = seq("audit", "binding_a", 1)
    right = seq("audit", "binding_b", 2)
    with pytest.raises(SequenceComparisonError) as excinfo:
        compare_sequence_refs(left, right)
    assert excinfo.value.reason_code == "v21-04:cross_producer_sequence_comparison"


def test_same_partition_comparison_returns_ordering() -> None:
    assert (
        compare_sequence_refs(
            seq("audit", "binding_a", 1), seq("audit", "binding_a", 2)
        )
        == -1
    )
    assert (
        compare_sequence_refs(
            seq("audit", "binding_a", 3), seq("audit", "binding_a", 3)
        )
        == 0
    )


def test_predecessor_link_cross_domain_sequence_is_not_linked() -> None:
    """仅凭跨域整数大小不得建立先后关联（fail-closed）。"""
    predecessor = make_action("pre", runtime_sequence=seq("audit", "binding_a", 1))
    successor = make_action("suc", runtime_sequence=seq("runtime", "binding_b", 1000))
    assert predecessor_link_kind(successor, predecessor) is None


# ---------------------------------------------------------------------------
# 3. branch/parent refs 优先于纯 sequence（04 §13）
# ---------------------------------------------------------------------------


def test_link_kind_parent_beats_branch_and_sequence() -> None:
    predecessor = make_action(
        "pre",
        event_id="evt_pre",
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    successor = make_action(
        "suc",
        parent_event_ids=["evt_pre"],
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    assert predecessor_link_kind(successor, predecessor) == "parent_event_ids"


def test_link_kind_branch_beats_pure_sequence() -> None:
    predecessor = make_action(
        "pre",
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    successor = make_action(
        "suc",
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    assert predecessor_link_kind(successor, predecessor) == "branch_id"


def test_link_kind_sequence_only_within_same_partition_and_ordered() -> None:
    predecessor = make_action("pre", runtime_sequence=seq("audit", "binding_a", 1))
    successor = make_action("suc", runtime_sequence=seq("audit", "binding_a", 2))
    assert predecessor_link_kind(successor, predecessor) == "runtime_sequence"
    # 后继早于前驱 → 不构成前驱关联。
    later = make_action("later", runtime_sequence=seq("audit", "binding_a", 0))
    assert predecessor_link_kind(later, predecessor) is None


def test_select_predecessor_prefers_parent_over_branch_and_sequence() -> None:
    assert (
        LINK_KIND_PRIORITY["parent_event_ids"]
        < (LINK_KIND_PRIORITY["branch_id"])
        < LINK_KIND_PRIORITY["runtime_sequence"]
    )

    by_sequence = make_action("pre_seq", runtime_sequence=seq("audit", "binding_a", 1))
    by_branch = make_action(
        "pre_branch",
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    by_parent = make_action(
        "pre_parent",
        event_id="evt_parent",
        runtime_sequence=seq("audit", "binding_a", 3),
    )
    successor = make_action(
        "suc",
        parent_event_ids=["evt_parent"],
        branch_id="branch_1",
        runtime_sequence=seq("audit", "binding_a", 4),
    )
    selected = select_predecessor(successor, [by_sequence, by_branch, by_parent])
    assert selected is not None
    chosen, kind = selected
    assert chosen.action_id == "pre_parent"
    assert kind == "parent_event_ids"


def test_select_predecessor_deterministic_tie_break() -> None:
    first = make_action(
        "pre_a",
        event_id="evt_a",
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    second = make_action(
        "pre_b",
        event_id="evt_b",
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    successor = make_action("suc", runtime_sequence=seq("audit", "binding_a", 9))
    forward = select_predecessor(successor, [second, first])
    reverse = select_predecessor(successor, [first, second])
    assert forward is not None and reverse is not None
    # 同级（runtime_sequence）按 event_id 确定性取胜，与候选顺序无关。
    assert forward[0].action_id == reverse[0].action_id == "pre_a"
    assert forward[1] == reverse[1] == "runtime_sequence"


def test_select_predecessor_excludes_self() -> None:
    action = make_action("solo", runtime_sequence=seq("audit", "binding_a", 1))
    assert select_predecessor(action, [action]) is None
