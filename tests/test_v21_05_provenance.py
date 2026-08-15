"""V21-05 provenance/taint handler 纯函数单测（Phase 1 纯新增）。

覆盖：

- 五个 typed upsert handler 的去重/幂等/确定性排序（同 key 异内容
  fail-closed，T-Replay 确定性）；
- taint 并集传播单调性（无 hop 衰减）；
- sticky taint 安全合并（union taints / min first / max last / refs
  有界并集）、容量超限只做安全合并、仍超限 fail-closed 抛错并声明
  dirty 域、CREDENTIAL/PERSISTENT_UNTRUSTED 保护摘要永不淘汰；
- declassification 承载于 sticky 摘要语义的效果与幂等；
- bounded relevant flow lookup 的有界遍历与截断标志（C8 不静默）；
- 本地构造的 provenance handler tuple 集成语义（**不触碰中央
  ``handlers.TYPED_UPSERT_HANDLERS``**，并断言其保持空 tuple）。

夹具直接构造 OnlineSecurityState / fact 对象，不依赖任何接线。
"""

from __future__ import annotations

import pytest

from agentguard_core.security_context import OnlineSecurityState, handlers
from agentguard_core.security_context.facts import (
    DeclassificationFact,
    FlowFact,
    MemoryFact,
    StickyTaintSummary,
)
from agentguard_core.security_context.projection.provenance import (
    MAX_STICKY_TAINT_SUMMARIES,
    PROVENANCE_TYPED_UPSERT_HANDLERS,
    TAINT_LABELS,
    ProvenanceProjectionError,
    apply_declassification_upserts,
    apply_flow_upserts,
    apply_memory_upserts,
    apply_source_upserts,
    apply_sticky_taint_upserts,
    propagate_taints,
    replay_declassification_effects,
)
from agentguard_core.security_context.projection.provenance_lookup import (
    bounded_relevant_flow_lookup,
)
from agentguard_core.security_context.state import state_digest
from agentguard_core.signals.models import SequenceRef

from tests.test_v21_security_state_models import (
    make_delta,
    make_source_fact,
    make_watermarks,
)

SCOPE = "hmac-sha256:scope_fixture"


# ---------------------------------------------------------------------------
# 夹具构造
# ---------------------------------------------------------------------------


def seq(value: int, *, domain: str = "audit", producer: str = "binding_a") -> SequenceRef:
    return SequenceRef(domain=domain, producer_binding_id=producer, value=value)  # type: ignore[arg-type]


def empty_state() -> OnlineSecurityState:
    return OnlineSecurityState(watermarks=make_watermarks())


def make_flow(
    flow_id: str,
    source_ref: str,
    target_ref: str,
    *,
    taints: list[str] | None = None,
    strength: str = "exact",
    relation: str = "derived_from",
) -> FlowFact:
    return FlowFact(
        flow_id=flow_id,
        scope_digest=SCOPE,
        source_ref=source_ref,
        target_ref=target_ref,
        relation=relation,  # type: ignore[arg-type]
        taints=taints if taints is not None else ["CREDENTIAL"],  # type: ignore[list-item]
        strength=strength,  # type: ignore[arg-type]
        origin="observed",
        sequence=None,
        producer="producer_a",
        evidence_refs=[],
    )


def make_memory(memory_id: str, **overrides: object) -> MemoryFact:
    payload: dict[str, object] = {
        "memory_id": memory_id,
        "change_id": None,
        "change_status": "committed",
        "trust_state": "tainted",
        "taints": ["PERSISTENT_UNTRUSTED"],
        "source_refs": ["src_1"],
        "last_write_sequence": None,
        "last_read_sequence": None,
        "evidence_refs": [],
    }
    payload.update(overrides)
    return MemoryFact(**payload)  # type: ignore[arg-type]


def make_summary(
    summary_id: str,
    taints: list[str],
    *,
    first: int = 1,
    last: int = 2,
    flow_refs: list[str] | None = None,
    memory_refs: list[str] | None = None,
) -> StickyTaintSummary:
    return StickyTaintSummary(
        summary_id=summary_id,
        taints=taints,  # type: ignore[list-item]
        first_seen=seq(first),
        last_seen=seq(last),
        unresolved_flow_refs=flow_refs or [],
        memory_refs=memory_refs or [],
        evidence_refs=[],
    )


def make_declass(
    declass_id: str,
    input_ref: str,
    output_ref: str,
    *,
    removed: list[str],
    retained: list[str] | None = None,
) -> DeclassificationFact:
    return DeclassificationFact(
        declass_id=declass_id,
        input_ref=input_ref,
        output_ref=output_ref,
        removed_taints=removed,  # type: ignore[list-item]
        retained_taints=retained or [],  # type: ignore[list-item]
        mechanism_id="dlp_v1",
        mechanism_version="1.0.0",
        policy_revision="rev_1",
        producer="trusted_declassifier",
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# 1. source / flow / memory handler：去重、幂等、确定性排序、不原地改；
#    同 key 异内容 fail-closed（T-Replay 确定性，F6）
# ---------------------------------------------------------------------------


def test_source_upserts_dedupe_idempotent_and_sorted() -> None:
    state = empty_state().model_copy(
        update={"source_index": [make_source_fact(source_id="src_b")]}
    )
    items = [
        make_source_fact(source_id="src_b"),  # 同 id 同内容 → 幂等 no-op
        make_source_fact(source_id="src_a"),
    ]
    result = apply_source_upserts(state, items)
    assert [s.source_id for s in result.source_index] == ["src_a", "src_b"]
    # 输入 state 不原地改
    assert [s.source_id for s in state.source_index] == ["src_b"]


def test_source_upserts_same_key_different_content_fail_closed() -> None:
    state = empty_state().model_copy(
        update={"source_index": [make_source_fact(source_id="src_b")]}
    )
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_source_upserts(
            state, [make_source_fact(source_id="src_b", trust="trusted")]
        )
    assert excinfo.value.reason_code == "v21-05:source_identity_conflict"
    assert excinfo.value.dirty_domains == ("source",)


def test_flow_upserts_dedupe_by_flow_id() -> None:
    state = empty_state()
    flows = [
        make_flow("flow_b", "a", "b"),
        make_flow("flow_a", "b", "c"),
        make_flow("flow_b", "a", "b"),  # 同内容重复 → 幂等 no-op
    ]
    result = apply_flow_upserts(state, flows)
    assert [f.flow_id for f in result.relevant_flows] == ["flow_a", "flow_b"]


def test_flow_upserts_same_key_different_content_fail_closed() -> None:
    state = empty_state()
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_flow_upserts(
            state,
            [
                make_flow("flow_b", "a", "b"),
                make_flow("flow_b", "a", "b", strength="strong"),
            ],
        )
    assert excinfo.value.reason_code == "v21-05:flow_identity_conflict"
    assert excinfo.value.dirty_domains == ("dataflow",)


def test_memory_upserts_dedupe_by_memory_id() -> None:
    state = empty_state()
    items = [
        make_memory("mem_b"),
        make_memory("mem_a"),
        make_memory("mem_b"),  # 同内容重复 → 幂等 no-op
    ]
    result = apply_memory_upserts(state, items)
    assert [m.memory_id for m in result.memory_index] == ["mem_a", "mem_b"]


def test_memory_upserts_same_key_different_content_fail_closed() -> None:
    state = empty_state()
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_memory_upserts(
            state,
            [
                make_memory("mem_b"),
                make_memory("mem_b", trust_state="clean", taints=[]),
            ],
        )
    assert excinfo.value.reason_code == "v21-05:memory_identity_conflict"
    assert excinfo.value.dirty_domains == ("memory",)


# ---------------------------------------------------------------------------
# 2. taint 传播单调性（02 §9.1）
# ---------------------------------------------------------------------------


def test_propagate_taints_union_without_hop_decay() -> None:
    merged = propagate_taints(
        ["CREDENTIAL"], ["UNTRUSTED", "SENSITIVE"], ["CREDENTIAL"]
    )
    # 并集传播：重复 label 不复制，顺序按冻结枚举序确定性排序
    assert merged == ["UNTRUSTED", "SENSITIVE", "CREDENTIAL"]
    assert set(TAINT_LABELS) == {
        "UNTRUSTED",
        "EXTERNAL_INSTRUCTION",
        "SENSITIVE",
        "CREDENTIAL",
        "PERSISTENT_UNTRUSTED",
    }


def test_propagate_taints_rejects_unknown_label() -> None:
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        propagate_taints(["NOT_A_LABEL"])  # type: ignore[list-item]
    assert excinfo.value.reason_code == "v21-05:unknown_taint_label"


def test_flow_handler_preserves_taints_no_decay() -> None:
    state = empty_state()
    chain = [
        make_flow("f1", "file:credential", "artifact:x", taints=["CREDENTIAL"]),
        make_flow("f2", "artifact:x", "message:y", taints=["CREDENTIAL"]),
        make_flow("f3", "message:y", "email:external", taints=["CREDENTIAL"]),
    ]
    result = apply_flow_upserts(state, chain)
    # 三跳后 taint 不衰减
    assert all(f.taints == ["CREDENTIAL"] for f in result.relevant_flows)


# ---------------------------------------------------------------------------
# 3. sticky taint handler：合并、容量、保护、fail-closed
# ---------------------------------------------------------------------------


def test_sticky_merge_same_id_union_taints_min_first_max_last() -> None:
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [
                make_summary(
                    "s1", ["CREDENTIAL"], first=5, last=9, flow_refs=["f1"]
                )
            ]
        }
    )
    incoming = make_summary(
        "s1", ["UNTRUSTED"], first=3, last=12, flow_refs=["f2"], memory_refs=["m1"]
    )
    result = apply_sticky_taint_upserts(state, [incoming])
    assert len(result.sticky_taint_summaries) == 1
    merged = result.sticky_taint_summaries[0]
    assert merged.taints == ["UNTRUSTED", "CREDENTIAL"]
    assert merged.first_seen.value == 3
    assert merged.last_seen.value == 12
    assert merged.unresolved_flow_refs == ["f1", "f2"]
    assert merged.memory_refs == ["m1"]


def test_sticky_merge_cross_domain_sequence_fail_closed() -> None:
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [
                make_summary("s1", ["CREDENTIAL"], first=5, last=9)
            ]
        }
    )
    incoming = StickyTaintSummary(
        summary_id="s1",
        taints=["CREDENTIAL"],
        first_seen=SequenceRef(
            domain="memory", producer_binding_id="binding_a", value=1
        ),
        last_seen=SequenceRef(
            domain="memory", producer_binding_id="binding_a", value=2
        ),
        unresolved_flow_refs=[],
        memory_refs=[],
        evidence_refs=[],
    )
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_sticky_taint_upserts(state, [incoming])
    assert excinfo.value.reason_code == "v21-05:sticky_sequence_cross_domain"
    assert excinfo.value.dirty_domains == ("dataflow",)


def test_sticky_overflow_safe_merge_same_taint_set() -> None:
    # 超过容量但同 taint 集合可安全合并 → 不抛错
    summaries = [
        make_summary(f"s{i}", ["UNTRUSTED"], flow_refs=[f"f{i}"])
        for i in range(MAX_STICKY_TAINT_SUMMARIES + 3)
    ]
    result = apply_sticky_taint_upserts(empty_state(), summaries)
    assert len(result.sticky_taint_summaries) == 1
    merged = result.sticky_taint_summaries[0]
    assert merged.taints == ["UNTRUSTED"]
    assert merged.summary_id.startswith("sticky-merged:")
    # refs 并集保留（有界并集，容量内无损）
    assert len(merged.unresolved_flow_refs) == MAX_STICKY_TAINT_SUMMARIES + 3


def test_sticky_overflow_after_safe_merge_fail_closed() -> None:
    # 17 种不同 taint 集合 > MAX(16)，安全合并不足以压回容量 → 抛错
    distinct_sets: list[list[str]] = [[]]
    for label in TAINT_LABELS:
        distinct_sets.append([label])
    for i, left in enumerate(TAINT_LABELS):
        for right in TAINT_LABELS[i + 1 :]:
            distinct_sets.append([left, right])
    for i, left in enumerate(TAINT_LABELS):
        for j, middle in enumerate(TAINT_LABELS[i + 1 :]):
            for right in TAINT_LABELS[i + 1 + j + 1 :]:
                distinct_sets.append([left, middle, right])
    assert len(distinct_sets) >= MAX_STICKY_TAINT_SUMMARIES + 1
    summaries = [
        make_summary(f"s{i}", taints)
        for i, taints in enumerate(
            distinct_sets[: MAX_STICKY_TAINT_SUMMARIES + 1]
        )
    ]
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_sticky_taint_upserts(empty_state(), summaries)
    assert excinfo.value.reason_code == "v21-05:sticky_taint_summary_overflow"
    assert excinfo.value.dirty_domains == ("dataflow",)


def test_sticky_protected_summary_never_evicted() -> None:
    # CREDENTIAL 摘要：宁可 fail-closed 抛错也不被普通淘汰
    protected = make_summary("protected", ["CREDENTIAL"])
    fillers = [
        make_summary(f"s{i}", [TAINT_LABELS[i % len(TAINT_LABELS)]])
        for i in range(MAX_STICKY_TAINT_SUMMARIES + 2)
    ]
    summaries = [protected, *fillers]
    try:
        result = apply_sticky_taint_upserts(empty_state(), summaries)
        # 若安全合并成功，protected 摘要必须仍在且标签不丢失
        ids = {s.summary_id for s in result.sticky_taint_summaries}
        assert "protected" in ids or any(
            "protected" in s.summary_id for s in result.sticky_taint_summaries
        )
        kept = [
            s
            for s in result.sticky_taint_summaries
            if "protected" in s.summary_id
        ]
        assert kept and "CREDENTIAL" in kept[0].taints
    except ProvenanceProjectionError as error:
        # fail-closed 路径同样合法：绝不静默淘汰 protected 摘要
        assert error.reason_code == "v21-05:sticky_taint_summary_overflow"


# ---------------------------------------------------------------------------
# 4. declassification handler：承载决策、效果、幂等
# ---------------------------------------------------------------------------


def test_declassification_hosted_on_sticky_summaries() -> None:
    # OnlineSecurityState 无 declassification 专属容器（02 §5 冻结），
    # 效果承载于 sticky_taint_summaries
    assert "declassifications" not in OnlineSecurityState.model_fields
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [
                make_summary(
                    "s1",
                    ["CREDENTIAL", "SENSITIVE"],
                    flow_refs=["artifact:x"],
                    memory_refs=["mem_1"],
                ),
                make_summary("s2", ["UNTRUSTED"], flow_refs=["other"]),
            ]
        }
    )
    declass = make_declass(
        "d1",
        "artifact:x",
        "artifact:y",
        removed=["CREDENTIAL"],
        retained=["SENSITIVE"],
    )
    result = apply_declassification_upserts(state, [declass])
    s1 = next(s for s in result.sticky_taint_summaries if s.summary_id == "s1")
    s2 = next(s for s in result.sticky_taint_summaries if s.summary_id == "s2")
    assert s1.taints == ["SENSITIVE"]  # CREDENTIAL 被 trusted 净化移除
    assert s2.taints == ["UNTRUSTED"]  # 未命中的摘要不受影响


def test_declassification_matched_via_memory_refs() -> None:
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [
                make_summary("s1", ["SENSITIVE"], memory_refs=["mem_1"])
            ]
        }
    )
    declass = make_declass(
        "d1", "mem_1", "mem_2", removed=["SENSITIVE"]
    )
    result = apply_declassification_upserts(state, [declass])
    assert result.sticky_taint_summaries[0].taints == []


def test_declassification_is_idempotent() -> None:
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [
                make_summary("s1", ["CREDENTIAL"], flow_refs=["artifact:x"])
            ]
        }
    )
    declass = make_declass("d1", "artifact:x", "artifact:y", removed=["CREDENTIAL"])
    once = apply_declassification_upserts(state, [declass])
    twice = apply_declassification_upserts(once, [declass])
    assert state_digest(twice) == state_digest(once)


def test_declassification_conflict_fail_closed() -> None:
    state = empty_state()
    conflicting = make_declass(
        "d1", "a", "b", removed=["CREDENTIAL"], retained=["CREDENTIAL"]
    )
    with pytest.raises(ProvenanceProjectionError) as excinfo:
        apply_declassification_upserts(state, [conflicting])
    assert excinfo.value.reason_code == "v21-05:declassification_conflict"


# ---------------------------------------------------------------------------
# 4b. Codex P1-4：同 delta declassification + sticky_taint 并存的顺序兼容
# ---------------------------------------------------------------------------


def _declass_and_sticky_items() -> tuple[
    list[DeclassificationFact], list[StickyTaintSummary]
]:
    declass = make_declass(
        "d1",
        "artifact:x",
        "artifact:y",
        removed=["CREDENTIAL"],
        retained=["SENSITIVE"],
    )
    incoming = make_summary(
        "s_new",
        ["CREDENTIAL", "SENSITIVE"],
        flow_refs=["artifact:x"],
    )
    return [declass], [incoming]


def test_same_delta_declass_and_sticky_new_summary_is_cleaned() -> None:
    # 中央分发表按 01 §27 声明序：declassification_upserts 先于
    # sticky_taint_upserts；同 delta 并存时，新增摘要必须经后处理
    # 重放后移除被 trusted declassifier 移除的 label。
    declasses, stickies = _declass_and_sticky_items()
    delta = make_delta().model_copy(
        update={
            "declassification_upserts": declasses,
            "sticky_taint_upserts": stickies,
        }
    )
    result = handlers.apply_typed_updates(empty_state(), delta)
    summary = next(
        s for s in result.sticky_taint_summaries if s.summary_id == "s_new"
    )
    assert summary.taints == ["SENSITIVE"]  # CREDENTIAL 已被净化


def test_declass_sticky_order_independence_deterministic() -> None:
    # 确定性断言：同一 delta 两类容器以两种顺序施加（模拟增量路径与
    # rebuild 重排序路径）结果一致 —— state digest 相同且 label 已净化。
    declasses, stickies = _declass_and_sticky_items()

    # 顺序 A（01 §27 声明序 + 后处理）：declass → sticky → replay。
    order_a = apply_declassification_upserts(empty_state(), declasses)
    order_a = apply_sticky_taint_upserts(order_a, stickies)
    order_a = replay_declassification_effects(order_a, declasses)

    # 顺序 B（逆序）：sticky → declass（对新摘要直接生效）→ replay（幂等）。
    order_b = apply_sticky_taint_upserts(empty_state(), stickies)
    order_b = apply_declassification_upserts(order_b, declasses)
    order_b = replay_declassification_effects(order_b, declasses)

    assert state_digest(order_a) == state_digest(order_b)
    for state in (order_a, order_b):
        summary = next(
            s for s in state.sticky_taint_summaries if s.summary_id == "s_new"
        )
        assert summary.taints == ["SENSITIVE"]


def test_replay_declassification_effects_idempotent_and_empty_noop() -> None:
    declasses, stickies = _declass_and_sticky_items()
    base = apply_sticky_taint_upserts(empty_state(), stickies)
    once = replay_declassification_effects(base, declasses)
    twice = replay_declassification_effects(once, declasses)
    assert state_digest(twice) == state_digest(once)
    # 空 items 原样返回（不复制、不修改）。
    assert replay_declassification_effects(base, []) is base


# ---------------------------------------------------------------------------
# 5. bounded relevant flow lookup（02 §8 + C8）
# ---------------------------------------------------------------------------


def chain_state(length: int) -> OnlineSecurityState:
    """a0 → a1 → ... → a_length 的线性 flow 链。"""
    flows = [
        make_flow(f"flow_{i:02d}", f"node_{i}", f"node_{i + 1}")
        for i in range(length)
    ]
    return empty_state().model_copy(update={"relevant_flows": flows})


def test_lookup_traverses_full_chain_within_budget() -> None:
    state = chain_state(3)
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="node_0"
    )
    assert [f.flow_id for f in flows] == ["flow_00", "flow_01", "flow_02"]
    assert truncated is False


def test_lookup_depth_budget_truncates() -> None:
    state = chain_state(6)
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="node_0", max_depth=2
    )
    assert truncated is True
    reachable = {f.flow_id for f in flows}
    # 深度预算外的远端 flow 不得被静默纳入完整子图
    assert "flow_04" not in reachable
    assert "flow_05" not in reachable


def test_lookup_breadth_budget_truncates() -> None:
    # 单节点 3 条邻接 flow，breadth=2 → 截断
    flows = [
        make_flow(f"edge_{i}", "hub", f"leaf_{i}") for i in range(3)
    ]
    state = empty_state().model_copy(update={"relevant_flows": flows})
    found, truncated = bounded_relevant_flow_lookup(
        state, target_ref="hub", max_breadth=2
    )
    assert truncated is True
    assert len(found) == 2


def test_lookup_node_budget_truncates() -> None:
    state = chain_state(6)
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="node_0", node_budget=2
    )
    assert truncated is True


def test_lookup_disconnected_target_returns_empty_not_truncated() -> None:
    state = chain_state(3)
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="unknown_node"
    )
    assert flows == []
    assert truncated is False


def test_lookup_is_deterministic_and_does_not_touch_state() -> None:
    state = chain_state(4)
    digest_before = state_digest(state)
    first, _ = bounded_relevant_flow_lookup(state, target_ref="node_2")
    second, _ = bounded_relevant_flow_lookup(state, target_ref="node_2")
    assert [f.flow_id for f in first] == [f.flow_id for f in second]
    # 双向可达：node_2 同时向前溯源与向后追 sink
    assert [f.flow_id for f in first] == [
        "flow_00",
        "flow_01",
        "flow_02",
        "flow_03",
    ]
    # 临时邻接索引不入 state：digest 零影响
    assert state_digest(state) == digest_before


# ---------------------------------------------------------------------------
# 6. 本地 handler tuple 与中央分发表一致性（Phase 2 接线后）
# ---------------------------------------------------------------------------


def test_provenance_handler_tuple_matches_ownership_and_central_wired() -> None:
    containers = {name for name, _ in PROVENANCE_TYPED_UPSERT_HANDLERS}
    expected = {
        name
        for name, owner in handlers.CONTAINER_OWNERSHIP.items()
        if owner == "provenance"
    }
    assert containers == expected
    # Phase 2 集成：中央分发表一次性装配全部 11 容器，其中 provenance
    # 五容器的 handler 与本地装配蓝本一致（同函数对象）。
    central = dict(handlers.TYPED_UPSERT_HANDLERS)
    assert len(central) == 11
    local = dict(PROVENANCE_TYPED_UPSERT_HANDLERS)
    for name, handler in local.items():
        assert central[name] is handler, name


def test_local_handler_tuple_integration_semantics() -> None:
    # 模拟 Phase 2 装配后的确定性应用顺序（容器序 = tuple 序）
    containers: dict[str, list[object]] = {
        "source_upserts": [make_source_fact(source_id="src_1")],
        "flow_upserts": [make_flow("f1", "src_1", "sink_1")],
        "declassification_upserts": [],
        "memory_upserts": [make_memory("mem_1")],
        "sticky_taint_upserts": [
            make_summary("s1", ["CREDENTIAL"], flow_refs=["f1"])
        ],
    }
    state = empty_state()
    for name, handler_fn in PROVENANCE_TYPED_UPSERT_HANDLERS:
        items = containers[name]
        if items:
            state = handler_fn(state, items)  # type: ignore[arg-type]
    assert [s.source_id for s in state.source_index] == ["src_1"]
    assert [f.flow_id for f in state.relevant_flows] == ["f1"]
    assert [m.memory_id for m in state.memory_index] == ["mem_1"]
    assert [s.summary_id for s in state.sticky_taint_summaries] == ["s1"]
    # lookup 与 handler 结果联动：bounded subgraph 可达
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="sink_1"
    )
    assert [f.flow_id for f in flows] == ["f1"]
    assert truncated is False
