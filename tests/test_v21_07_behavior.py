"""V21-07 Behavior/Sequence — handler 与 B1-B6 matcher 验收（Phase 1）。

夹具解耦（C6）：全部测试直接构造 ``OnlineSecurityState`` 与 typed
fact，不依赖 V21-05（provenance）/ V21-06（capability）接线；
B1-B5 的端到端真实链验收属 Phase 2（集成 PR），本期不做。

覆盖：

- 三个 typed upsert handler：分区保序、action_id 去重/幂等、
  runtime outcome 同内容幂等/异内容 fail-closed（T-Replay 确定性）、
  aggregate 增量计数合并；
- B1-B6 matcher 合成事实夹具验收（B6 完整独立验收）；
- behavior signal 纪律：signal 不单独决定 deny（02 §14 末句）。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.models import ActionEffect
from agentguard_core.security_context.facts import (
    BehaviorAggregate,
    CapabilityGrant,
    FlowFact,
    MemoryFact,
    RecentActionFact,
    RuntimeOutcomeFact,
    SourceFact,
    StateWatermarks,
    StickyTaintSummary,
)
from agentguard_core.security_context.projection.behavior import (
    BehaviorProjectionError,
    apply_action_additions,
    apply_behavior_aggregate_upserts,
    apply_runtime_outcome_upserts,
)
from agentguard_core.security_context.projection.behavior_matchers import (
    B6_ANOMALY_COUNT_THRESHOLD,
    generate_behavior_signals,
    match_b1,
    match_b2,
    match_b3,
    match_b4,
    match_b5,
    match_b6,
)
from agentguard_core.security_context.state import OnlineSecurityState
from agentguard_core.signals.models import SequenceRef

SCOPE = "sha256:" + "0" * 16


# ---------------------------------------------------------------------------
# 夹具构造器（C6：直接构造状态对象，不依赖 V21-05/06 接线）
# ---------------------------------------------------------------------------


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
    impact: str = "low",
    effects: ActionEffect | None = None,
    destination_ids: list[str] | None = None,
    data_refs: list[str] | None = None,
    final_decision: str | None = "allow",
) -> RecentActionFact:
    return RecentActionFact(
        action_id=action_id,
        event_id=event_id or f"event_{action_id}",
        agent_id="agent_a",
        branch_id=branch_id,
        parent_event_ids=parent_event_ids or [],
        runtime_sequence=runtime_sequence,
        action_type=f"tool.{action_id}",
        impact=impact,  # type: ignore[arg-type]
        effects=effects or ActionEffect(),
        resource_ids=[],
        destination_ids=destination_ids or [],
        data_refs=data_refs or [],
        authority_status="authorized",
        final_decision=final_decision,  # type: ignore[arg-type]
        evidence_refs=[],
    )


def make_flow(
    flow_id: str,
    *,
    source_ref: str,
    target_ref: str,
    relation: str,
    taints: list[str] | None = None,
) -> FlowFact:
    return FlowFact(
        flow_id=flow_id,
        scope_digest=SCOPE,
        source_ref=source_ref,
        target_ref=target_ref,
        relation=relation,  # type: ignore[arg-type]
        taints=taints or [],  # type: ignore[list-item]
        strength="strong",
        origin="observed",
        sequence=None,
        producer="projector",
        evidence_refs=[],
    )


def make_source(
    source_id: str,
    *,
    source_type: str = "tool_result",
    trust: str = "untrusted",
    taints: list[str] | None = None,
) -> SourceFact:
    return SourceFact(
        source_id=source_id,
        scope_digest=SCOPE,
        source_type=source_type,  # type: ignore[arg-type]
        trust=trust,  # type: ignore[arg-type]
        verification_state="unverified",
        origin="observed",
        authority="trusted_claim",
        producer="projector",
        taints=taints or [],  # type: ignore[list-item]
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )


def make_memory(
    memory_id: str,
    *,
    trust_state: str = "tainted",
    taints: list[str] | None = None,
) -> MemoryFact:
    return MemoryFact(
        memory_id=memory_id,
        change_id=None,
        change_status="committed",
        trust_state=trust_state,  # type: ignore[arg-type]
        taints=["PERSISTENT_UNTRUSTED"] if taints is None else taints,
        source_refs=[],
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[],
    )


def make_grant(
    grant_id: str,
    *,
    action_types: list[str],
    issued_value: int | None,
    principal: str = "principal_a",
    task_id: str | None = "task_1",
    issued_domain: str = "policy",
    revoked: bool = False,
) -> CapabilityGrant:
    return CapabilityGrant(
        grant_id=grant_id,
        scope_digest=SCOPE,
        source_type="system_policy",
        source_ref="policy:system",
        subject_principal_id=principal,
        subject_agent_id=None,
        task_id=task_id,
        action_types=action_types,
        resource_constraints=[],
        destination_constraints=[],
        argument_constraints=[],
        exact_authorization_fingerprint=None,
        usage_limit=None,
        remaining_uses=None,
        delegable=False,
        parent_grant_id=None,
        issued_sequence=(
            seq(issued_domain, "binding_p", issued_value)
            if issued_value is not None
            else None
        ),
        expires_sequence=None,
        expires_at=None,
        revoked=revoked,
        revoked_sequence=None,
        policy_revision="rev-1",
        compiler_version=None,
        grant_digest="sha256:" + "1" * 16,
        evidence_refs=[],
    )


def make_outcome(
    action_id: str, *, status: str = "executed", receipt_value: int = 1
) -> RuntimeOutcomeFact:
    return RuntimeOutcomeFact(
        action_id=action_id,
        decision_id=f"decision_{action_id}",
        policy_audit_id=f"policy_audit_{action_id}",
        consumption_id=None,
        lease_id=None,
        execution_status=status,  # type: ignore[arg-type]
        receipt_sequence=seq("receipt", "binding_r", receipt_value),
        evidence_refs=[],
    )


def make_aggregate(
    aggregate_id: str,
    *,
    pattern_id: str = "B6",
    count: int = 1,
    start_value: int = 1,
    end_value: int = 2,
    domain: str = "audit",
    producer: str = "binding_a",
    confidence: str = "low",
    predecessor_refs: list[str] | None = None,
) -> BehaviorAggregate:
    return BehaviorAggregate(
        aggregate_id=aggregate_id,
        pattern_id=pattern_id,  # type: ignore[arg-type]
        window_start=seq(domain, producer, start_value),
        window_end=seq(domain, producer, end_value),
        count=count,
        confidence=confidence,  # type: ignore[arg-type]
        predecessor_refs=predecessor_refs or [],
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# 1. apply_action_additions — 分区保序 + 幂等
# ---------------------------------------------------------------------------


def test_action_additions_partition_ordering() -> None:
    state = empty_state()
    items = [
        make_action("a3", runtime_sequence=seq("audit", "binding_a", 3)),
        make_action("r1", runtime_sequence=seq("runtime", "binding_b", 1)),
        make_action("a1", runtime_sequence=seq("audit", "binding_a", 1)),
        make_action("a2", runtime_sequence=seq("audit", "binding_a", 2)),
        make_action("r2", runtime_sequence=seq("runtime", "binding_b", 2)),
    ]
    result = apply_action_additions(state, items)
    ids = [action.action_id for action in result.recent_actions]
    # audit 分区按序列值升序，runtime 分区紧随其后（分区键字典序）。
    assert ids == ["a1", "a2", "a3", "r1", "r2"]
    # 输入状态不被修改（纯函数）。
    assert state.recent_actions == []


def test_action_additions_stable_tie_and_unsequenced_tail() -> None:
    state = empty_state()
    items = [
        make_action("first", runtime_sequence=seq("audit", "binding_a", 5)),
        make_action("second", runtime_sequence=seq("audit", "binding_a", 5)),
        make_action("noseq_a"),
        make_action("noseq_b"),
    ]
    result = apply_action_additions(state, items)
    ids = [action.action_id for action in result.recent_actions]
    # 同 sequence value 稳定保持到达序；无序列条目置尾保持到达序。
    assert ids == ["first", "second", "noseq_a", "noseq_b"]


def test_action_additions_idempotent_replay() -> None:
    state = empty_state()
    item = make_action("a1", runtime_sequence=seq("audit", "binding_a", 1))
    once = apply_action_additions(state, [item])
    twice = apply_action_additions(once, [item])
    assert [a.action_id for a in twice.recent_actions] == ["a1"]


def test_action_additions_rejects_wrong_item_type() -> None:
    with pytest.raises(BehaviorProjectionError) as excinfo:
        apply_action_additions(empty_state(), [{"not": "a fact"}])
    assert excinfo.value.reason_code == "v21-07:invalid_action_additions_item"


def test_action_additions_empty_items_returns_state() -> None:
    state = empty_state()
    assert apply_action_additions(state, []) is state


# ---------------------------------------------------------------------------
# 2. apply_runtime_outcome_upserts — action_id 去重：同内容幂等，
#    异内容 fail-closed（T-Replay 确定性，F6）
# ---------------------------------------------------------------------------


def test_runtime_outcome_upserts_dedup_by_action_id() -> None:
    state = empty_state()
    first = make_outcome("act_1", status="executed", receipt_value=1)
    inserted = apply_runtime_outcome_upserts(state, [first])
    assert len(inserted.runtime_outcomes) == 1

    # 同 action_id 同内容重复到达 → 幂等 no-op。
    same = make_outcome("act_1", status="executed", receipt_value=1)
    unchanged = apply_runtime_outcome_upserts(inserted, [same])
    assert len(unchanged.runtime_outcomes) == 1
    assert unchanged.runtime_outcomes[0].execution_status == "executed"

    appended = apply_runtime_outcome_upserts(unchanged, [make_outcome("act_2")])
    assert [o.action_id for o in appended.runtime_outcomes] == [
        "act_1",
        "act_2",
    ]


def test_runtime_outcome_upserts_same_key_different_content_fail_closed() -> None:
    state = empty_state()
    first = make_outcome("act_1", status="executed", receipt_value=1)
    inserted = apply_runtime_outcome_upserts(state, [first])
    revised = make_outcome("act_1", status="failed", receipt_value=2)
    with pytest.raises(BehaviorProjectionError) as excinfo:
        apply_runtime_outcome_upserts(inserted, [revised])
    assert (
        excinfo.value.reason_code
        == "v21-07:runtime_outcome_identity_conflict"
    )


# ---------------------------------------------------------------------------
# 3. apply_behavior_aggregate_upserts — 增量计数器合并
# ---------------------------------------------------------------------------


def test_aggregate_upserts_incremental_counter_merge() -> None:
    state = empty_state()
    existing = make_aggregate(
        "agg_1",
        count=3,
        start_value=2,
        end_value=5,
        confidence="low",
        predecessor_refs=["p1"],
    )
    base = state.model_copy(update={"behavior_aggregates": [existing]})

    incoming = make_aggregate(
        "agg_2",
        count=4,
        start_value=4,
        end_value=9,
        confidence="high",
        predecessor_refs=["p1", "p2"],
    )
    result = apply_behavior_aggregate_upserts(base, [incoming])

    assert len(result.behavior_aggregates) == 1
    merged = result.behavior_aggregates[0]
    assert merged.count == 7  # 递增，不重扫窗口
    assert merged.window_start.value == 2  # 取较早
    assert merged.window_end.value == 9  # 推进
    assert merged.confidence == "high"  # 取较高
    assert merged.predecessor_refs == ["p1", "p2"]  # 确定合并去重


def test_aggregate_upserts_new_pattern_appended_from_delta() -> None:
    state = empty_state()
    base = state.model_copy(
        update={"behavior_aggregates": [make_aggregate("agg_b6", pattern_id="B6")]}
    )
    incoming = make_aggregate("agg_b1", pattern_id="B1", count=2, end_value=3)
    result = apply_behavior_aggregate_upserts(base, [incoming])
    assert len(result.behavior_aggregates) == 2
    new_entry = result.behavior_aggregates[1]
    # 不匹配现有 aggregate → 按 delta 携带内容原样并入，不凭空合成。
    assert new_entry == incoming


def test_aggregate_upserts_distinct_partitions_not_merged() -> None:
    state = empty_state()
    base = state.model_copy(
        update={
            "behavior_aggregates": [
                make_aggregate("agg_a", producer="binding_a", count=5)
            ]
        }
    )
    incoming = make_aggregate("agg_b", producer="binding_b", count=5)
    result = apply_behavior_aggregate_upserts(base, [incoming])
    assert len(result.behavior_aggregates) == 2
    assert {a.count for a in result.behavior_aggregates} == {5}


# ---------------------------------------------------------------------------
# 4. B1 — sensitive read → external egress
# ---------------------------------------------------------------------------


def test_match_b1_direct_sensitive_egress_and_chain() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow(
                    "flow_direct",
                    source_ref="artifact:s",
                    target_ref="email:external",
                    relation="sent_to",
                    taints=["SENSITIVE"],
                ),
                make_flow(
                    "flow_read",
                    source_ref="file:report",
                    target_ref="artifact:x",
                    relation="read_from",
                    taints=["SENSITIVE"],
                ),
                make_flow(
                    "flow_egress",
                    source_ref="artifact:x",
                    target_ref="https:external",
                    relation="sent_to",
                ),
            ]
        }
    )
    matches = match_b1(state)
    reasons = {reason for m in matches for reason in m.reason_codes}
    assert "v21-07:b1_sensitive_direct_egress" in reasons
    assert "v21-07:b1_sensitive_read_to_egress" in reasons
    chain = next(m for m in matches if "flow_egress" in m.fact_refs)
    assert "flow_read" in chain.fact_refs


def test_match_b1_no_sensitive_no_match() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow(
                    "flow_ok",
                    source_ref="artifact:x",
                    target_ref="https:external",
                    relation="sent_to",
                ),
            ]
        }
    )
    assert match_b1(state) == []


# ---------------------------------------------------------------------------
# 5. B2 — untrusted tool_result → high-impact action
# ---------------------------------------------------------------------------


def test_match_b2_untrusted_tool_result_to_high_impact() -> None:
    producer = make_action(
        "act_producer",
        event_id="evt_producer",
        data_refs=["src_tool"],
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    high = make_action(
        "act_high",
        impact="high",
        parent_event_ids=["evt_producer"],
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    state = empty_state().model_copy(
        update={
            "source_index": [make_source("src_tool")],
            "relevant_flows": [
                make_flow(
                    "flow_influence",
                    source_ref="src_tool",
                    target_ref="action:act_high",
                    relation="influenced_by",
                )
            ],
            "recent_actions": [producer, high],
        }
    )
    matches = match_b2(state)
    assert len(matches) == 1
    match = matches[0]
    assert match.subject_refs == ("act_high",)
    assert "src_tool" in match.fact_refs
    # branch/parent refs 优先：parent_event_ids 命中（04 §13）。
    assert match.link_kind == "parent_event_ids"


def test_match_b2_trusted_source_no_match() -> None:
    high = make_action("act_high", impact="critical")
    state = empty_state().model_copy(
        update={
            "source_index": [make_source("src_tool", trust="trusted")],
            "relevant_flows": [
                make_flow(
                    "flow_influence",
                    source_ref="src_tool",
                    target_ref="action:act_high",
                    relation="influenced_by",
                )
            ],
            "recent_actions": [high],
        }
    )
    assert match_b2(state) == []


# ---------------------------------------------------------------------------
# 6. B3 — credential read → network/API/email
# ---------------------------------------------------------------------------


def test_match_b3_direct_credential_egress() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow(
                    "flow_cred_out",
                    source_ref="secret:api_key",
                    target_ref="api:external",
                    relation="sent_to",
                    taints=["CREDENTIAL"],
                )
            ]
        }
    )
    matches = match_b3(state)
    assert any("v21-07:b3_credential_direct_egress" in m.reason_codes for m in matches)


def test_match_b3_credential_context_with_email_destination() -> None:
    read_action = make_action(
        "act_read",
        event_id="evt_read",
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    send_action = make_action(
        "act_send",
        parent_event_ids=["evt_read"],
        destination_ids=["email:external-relay"],
        runtime_sequence=seq("audit", "binding_a", 2),
    )
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow(
                    "flow_cred_read",
                    source_ref="file:creds",
                    target_ref="action:act_read",
                    relation="read_from",
                    taints=["CREDENTIAL"],
                )
            ],
            "recent_actions": [read_action, send_action],
        }
    )
    matches = match_b3(state)
    sink_matches = [
        m
        for m in matches
        if "v21-07:b3_credential_read_to_external_sink" in m.reason_codes
    ]
    assert len(sink_matches) == 1
    assert sink_matches[0].subject_refs == ("act_send",)
    assert sink_matches[0].link_kind == "parent_event_ids"


def test_match_b3_no_credential_no_sink_match() -> None:
    action = make_action("act_send", destination_ids=["email:external"])
    state = empty_state().model_copy(update={"recent_actions": [action]})
    assert match_b3(state) == []


# ---------------------------------------------------------------------------
# 7. B4 — memory write/retrieve → future action
# ---------------------------------------------------------------------------


def test_match_b4_tainted_memory_to_future_action() -> None:
    write_action = make_action(
        "act_mem_write",
        event_id="evt_mem_write",
        effects=ActionEffect(persistence=True),
        data_refs=["mem_poisoned"],
        runtime_sequence=seq("audit", "binding_a", 1),
    )
    future_action = make_action(
        "act_future",
        parent_event_ids=["evt_mem_write"],
        data_refs=["mem_poisoned"],
        runtime_sequence=seq("audit", "binding_a", 3),
    )
    state = empty_state().model_copy(
        update={
            "memory_index": [make_memory("mem_poisoned")],
            "relevant_flows": [
                make_flow(
                    "flow_mem_load",
                    source_ref="mem_poisoned",
                    target_ref="action:act_future",
                    relation="loaded_from_memory",
                )
            ],
            "recent_actions": [write_action, future_action],
        }
    )
    matches = match_b4(state)
    assert len(matches) == 1
    assert matches[0].subject_refs == ("act_future",)
    assert matches[0].link_kind == "parent_event_ids"
    assert "mem_poisoned" in matches[0].fact_refs


def test_match_b4_clean_memory_no_match() -> None:
    action = make_action("act_future", data_refs=["mem_clean"])
    state = empty_state().model_copy(
        update={
            "memory_index": [make_memory("mem_clean", trust_state="clean", taints=[])],
            "recent_actions": [action],
        }
    )
    assert match_b4(state) == []


# ---------------------------------------------------------------------------
# 8. B5 — privilege escalation / scope expansion
# ---------------------------------------------------------------------------


def test_match_b5_scope_expansion_detected() -> None:
    base_grant = make_grant("grant_1", action_types=["read"], issued_value=1)
    escalated = make_grant("grant_2", action_types=["read", "delete"], issued_value=2)
    state = empty_state().model_copy(update={"active_grants": [base_grant, escalated]})
    matches = match_b5(state)
    assert len(matches) == 1
    assert matches[0].subject_refs == ("grant_2",)
    assert matches[0].reason_codes == ("v21-07:b5_scope_expansion:delete",)


def test_match_b5_no_expansion_no_match() -> None:
    grants = [
        make_grant("grant_1", action_types=["read", "write"], issued_value=1),
        make_grant("grant_2", action_types=["read"], issued_value=2),
    ]
    state = empty_state().model_copy(update={"active_grants": grants})
    assert match_b5(state) == []


def test_match_b5_revoked_grant_ignored() -> None:
    grants = [
        make_grant("grant_1", action_types=["read"], issued_value=1),
        make_grant(
            "grant_2",
            action_types=["read", "admin"],
            issued_value=2,
            revoked=True,
        ),
    ]
    state = empty_state().model_copy(update={"active_grants": grants})
    assert match_b5(state) == []


def test_match_b5_cross_domain_issue_sequence_not_compared() -> None:
    # issued_sequence 跨域不可比：fail-closed，不推断先后 → 无命中。
    grants = [
        make_grant(
            "grant_1",
            action_types=["read"],
            issued_value=1,
            issued_domain="policy",
        ),
        make_grant(
            "grant_2",
            action_types=["read", "admin"],
            issued_value=2,
            issued_domain="audit",
        ),
    ]
    state = empty_state().model_copy(update={"active_grants": grants})
    assert match_b5(state) == []


# ---------------------------------------------------------------------------
# 9. B6 — budget/frequency anomaly（完整独立验收）
# ---------------------------------------------------------------------------


def test_match_b6_threshold_boundary() -> None:
    below = make_aggregate("agg_below", count=B6_ANOMALY_COUNT_THRESHOLD - 1)
    at = make_aggregate("agg_at", count=B6_ANOMALY_COUNT_THRESHOLD, end_value=3)
    state = empty_state().model_copy(update={"behavior_aggregates": [below, at]})
    matches = match_b6(state)
    assert [m.subject_refs for m in matches] == [("agg_at",)]


def test_match_b6_incremental_build_then_anomaly() -> None:
    """小型构造场景：增量计数器合并达到阈值后 B6 命中（不跑批）。"""
    state = empty_state()
    for index in range(1, 8):
        state = apply_behavior_aggregate_upserts(
            state,
            [
                make_aggregate(
                    f"agg_{index}",
                    count=3,
                    end_value=index + 1,
                )
            ],
        )
    # 7 次增量 × count 3 = 21 ≥ 阈值 20，且窗口被推进而非重扫。
    assert len(state.behavior_aggregates) == 1
    aggregate = state.behavior_aggregates[0]
    assert aggregate.count == 21
    assert aggregate.window_end.value == 8
    matches = match_b6(state)
    assert len(matches) == 1
    assert "v21-07:b6_frequency_anomaly" in matches[0].reason_codes[0]


# ---------------------------------------------------------------------------
# 10. behavior signal 纪律：signal 不单独决定 deny（02 §14 末句）
# ---------------------------------------------------------------------------


def test_generate_behavior_signals_signal_only_discipline() -> None:
    state = empty_state().model_copy(
        update={
            "behavior_aggregates": [
                make_aggregate("agg_hot", count=B6_ANOMALY_COUNT_THRESHOLD)
            ]
        }
    )
    signals = generate_behavior_signals(state)
    assert len(signals) == 1
    signal = signals[0]
    assert signal.category == "behavior:B6"
    assert signal.detector_id == "v21-07.behavior_matchers"
    # signal 模型结构上不携带 decision（final 判定属 Fusion 阶段）。
    assert "decision" not in type(signal).model_fields
    # 显式纪律标签：behavior signal 不单独决定 deny。
    assert "v21-07:signal-only-no-standalone-deny" in signal.tags


def test_generate_behavior_signals_empty_state_no_signals() -> None:
    assert generate_behavior_signals(empty_state()) == []


def test_generate_behavior_signals_deterministic() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow(
                    "flow_direct",
                    source_ref="artifact:s",
                    target_ref="email:external",
                    relation="sent_to",
                    taints=["SENSITIVE"],
                )
            ]
        }
    )
    first = generate_behavior_signals(state)
    second = generate_behavior_signals(state)
    assert [s.signal_id for s in first] == [s.signal_id for s in second]
    assert first[0].category == "behavior:B1"


def test_sticky_summary_credential_enables_b3() -> None:
    summary = StickyTaintSummary(
        summary_id="sticky_1",
        taints=["CREDENTIAL"],
        first_seen=seq("audit", "binding_a", 1),
        last_seen=seq("audit", "binding_a", 2),
        unresolved_flow_refs=[],
        memory_refs=[],
        evidence_refs=[],
    )
    action = make_action("act_send", destination_ids=["network:egress"])
    state = empty_state().model_copy(
        update={
            "sticky_taint_summaries": [summary],
            "recent_actions": [action],
        }
    )
    matches = match_b3(state)
    assert any(m.subject_refs == ("act_send",) for m in matches)
