"""V21-05/06/07 Phase 2 集成接线后的跨域链端到端验收（02 §13）。

规模纪律：每场景小构造（≤50 条事实），不做大规模跑批；全部经
真实投影路径（``apply_delta`` 中央分发表）产出 state，再消费
coverage / verdict / matcher —— 不使用合成旁路夹具。

场景清单（命名按实际链路语义；02 §13 三链说明见下方注释）：

1. authority 链（V21-06）：approval → compile → grant_upserts 投影 →
   coverage(capability) → authority verdict → revocation/consumption；
2. provenance coverage 链（V21-05）：source/flow/memory 投影 →
   六域 coverage 真实判定；
3. behavior 链（V21-07）：action_additions + runtime_outcome
   投影 → coverage 判定（含 receipt watermark stale 降级）；
4. B1-B6 matcher 消费真实投影产物（B6 独立聚合阈值）；
5. 02 §5.2 state flooding 小型场景：credential read → N benign →
   external send，驱逐后 sticky/aggregated 语义不回退；
6. flow lookup 截断 → dataflow coverage 降级契约（C8）；
7. Shadow 纪律：watermark-only delta 接线前后语义等价；
8. reprojection 契约（D2）：legacy envelope 经懒 decoder 重组后
   rebuild 的 state_digest 确定性 + decoder fail-closed。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PROJECTOR_VERSION,
    EvictionLimits,
    GapContext,
    OnlineSecurityState,
    apply_delta,
    apply_safe_eviction,
    default_coverage_context,
    delta_digest_projection,
    state_digest,
)
from agentguard_core.security_context.coverage_context import CoverageContext
from agentguard_core.security_context.facts import (
    BehaviorAggregate,
    GrantConsumption,
    RuntimeOutcomeFact,
)
from agentguard_core.security_context.projection import (
    CapabilityProjectionError,
    build_consumption_intent,
    compile_approval_to_grant,
    compute_authority_verdict,
)
from agentguard_core.security_context.projection.behavior_matchers import (
    B6_ANOMALY_COUNT_THRESHOLD,
    match_b1,
    match_b2,
    match_b3,
    match_b4,
    match_b5,
    match_b6,
)
from agentguard_core.security_context.projection.behavior_coverage import (
    behavior_coverage,
    runtime_outcome_coverage,
)
from agentguard_core.security_context.projection.provenance_coverage import (
    dataflow_coverage,
    memory_coverage,
    source_coverage,
)
from agentguard_core.security_context.projection.provenance_lookup import (
    bounded_relevant_flow_lookup,
)
from agentguard_core.security_context.state import state_digest as _state_digest_ref
from agentguard_core.signals.models import SequenceRef

from guard_api.security_state.rebuild import (
    LEGACY_PROJECTOR_VERSION,
    PREVIOUS_PROJECTOR_VERSION,
    _decode_legacy_delta,
    rebuild_locked,
)
from guard_api.storage.base import ProjectionIdentityRecord
from guard_api.storage.memory import MemoryControlPlaneStore

from tests.test_v21_05_provenance import (
    chain_state,
    empty_state,
    make_flow,
    make_memory,
    make_summary,
)
from tests.test_v21_06_capability import (
    make_action_ir,
    make_approval_projection,
    make_policy_context,
)
from tests.test_v21_security_state_models import (
    SCOPE,
    make_delta,
    make_grant,
    make_recent_action,
    make_source_fact,
    make_watermarks,
)

#: verdict 评估时刻（落在 make_grant expires_at 2026-08-14T01:00:00Z 内）。
EVALUATED_AT = "2026-08-14T00:30:00Z"


def apply_applied(delta) -> OnlineSecurityState:
    """经中央闸门 apply_delta 并断言 applied（接线后的真实投影路径）。"""
    result = apply_delta(empty_state(), delta)
    assert result.outcome == "applied"
    return result.state


def make_plan(
    required: list[str],
    *,
    required_capabilities: list[str] | None = None,
) -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-07-plan:integration",
        impact="high",
        required_domains=required,  # pyright: ignore[reportArgumentType]
        optional_domains=[d for d in COVERAGE_DOMAINS if d not in required],
        required_capabilities=required_capabilities or [],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-07:integration_fixture"],
    )


def seq_ref(value: int, *, domain: str = "audit") -> SequenceRef:
    return SequenceRef(domain=domain, producer_binding_id="binding_a", value=value)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. authority 链（V21-06 九项验收接线后复验）
#
# 命名口径：02 §13 的三链（P1 untrusted influence→high-impact、
# P2 credential→external sink、P3 poisoned memory）是**判定矩阵**
# 维度的端到端攻击链，其投影侧要素（source/flow/memory/sticky 投影、
# B1-B6 matcher 的命中夹具、grant/revocation/consumption 状态）已由
# 本文件各链测试覆盖；判定矩阵本身的融合验收属 V21-08 Fusion 范围，
# 本阶段不实现，故测试名按实际投影链路语义命名，不再复用 P1/P2/P3。
# ---------------------------------------------------------------------------


def test_authority_chain_approval_grant_projection_to_verdict_and_revoke() -> None:
    approval = make_approval_projection()
    grant = compile_approval_to_grant(approval, make_policy_context())
    action_ir = make_action_ir(action_type="file.write")

    # grant_upserts 经中央分发表投影入 state。
    state = apply_applied(make_delta().model_copy(update={"grant_upserts": [grant]}))
    assert [g.grant_id for g in state.active_grants] == [grant.grant_id]

    # coverage：required capability 被活跃 grant 覆盖 → complete。
    plan = make_plan(["capability"], required_capabilities=["file.write"])
    context = default_coverage_context(state, plan)
    assert capability_status(state, context) == "complete"

    # verdict：fingerprint/action_type 匹配 → authorized。
    verdict = compute_authority_verdict(state, action_ir, evaluated_at=EVALUATED_AT)
    assert verdict.status == "authorized"
    assert grant.grant_id in verdict.matched_grant_ids

    # 消费 intent（防双花身份确定性）：同内容重试同 digest。
    intent = build_consumption_intent(grant, action_ir)
    retry = build_consumption_intent(grant, action_ir)
    assert intent.intent_digest == retry.intent_digest

    # grant_revocations 经中央分发表投影 → verdict 翻 unauthorized。
    revoked = apply_delta(
        state,
        make_delta(
            source_record_id="record_revoke",
            base_state_version=1,
            projected_value=2,
        ).model_copy(update={"grant_revocations": [grant.grant_id]}),
    )
    assert revoked.outcome == "applied"
    assert grant.grant_id in revoked.state.revoked_grant_ids
    verdict_after = compute_authority_verdict(
        revoked.state, action_ir, evaluated_at=EVALUATED_AT
    )
    assert verdict_after.status == "unauthorized"

    # coverage：revoked 后无活跃 grant 覆盖 required capability → unknown。
    context_after = default_coverage_context(revoked.state, plan)
    assert capability_status(revoked.state, context_after) == "unknown"


def capability_status(state: OnlineSecurityState, context: CoverageContext) -> str:
    from agentguard_core.security_context.coverage_context import (
        DOMAIN_COVERAGE_DISPATCH,
    )

    return DOMAIN_COVERAGE_DISPATCH["capability"](state, context).status


def test_authority_chain_consumption_projection_idempotent_and_conflict_fail_closed() -> None:
    grant = make_grant()
    state = apply_applied(make_delta().model_copy(update={"grant_upserts": [grant]}))
    consumption = GrantConsumption(
        consumption_id="consumption_1",
        grant_id="grant_1",
        action_id="action_1",
        authorization_fingerprint="hmac-sha256:fp",
        sequence=seq_ref(5, domain="receipt"),
        evidence_refs=[],
    )

    applied = apply_delta(
        state,
        make_delta(
            source_record_id="record_consume",
            base_state_version=1,
            projected_value=2,
        ).model_copy(update={"grant_consumptions": [consumption]}),
    )
    assert applied.outcome == "applied"
    assert [c.consumption_id for c in applied.state.grant_consumptions] == [
        "consumption_1"
    ]

    # 同 consumption_id 异内容 → 身份冲突 fail-closed（分支异常经
    # 中央闸门 apply_delta 直接冒泡，不得静默覆盖）。
    forged = consumption.model_copy(update={"action_id": "action_forged"})
    with pytest.raises(CapabilityProjectionError) as excinfo:
        apply_delta(
            applied.state,
            make_delta(
                source_record_id="record_conflict",
                base_state_version=2,
                projected_value=3,
            ).model_copy(update={"grant_consumptions": [forged]}),
        )
    assert excinfo.value.reason_code == "v21-06:consumption_identity_conflict"


# ---------------------------------------------------------------------------
# 2. provenance coverage 链：source/flow/memory 投影 → coverage 真实判定
# ---------------------------------------------------------------------------


def test_provenance_coverage_chain_projection_to_coverage_verdicts() -> None:
    delta = make_delta().model_copy(
        update={
            "source_upserts": [make_source_fact(trust="trusted")],
            "flow_upserts": [
                make_flow("f1", "src_1", "mem_1", taints=["UNTRUSTED"])
            ],
            "memory_upserts": [make_memory("mem_1", source_refs=["src_1"])],
        }
    )
    state = apply_applied(delta)
    assert [s.source_id for s in state.source_index] == ["src_1"]
    assert [f.flow_id for f in state.relevant_flows] == ["f1"]
    assert [m.memory_id for m in state.memory_index] == ["mem_1"]

    plan = make_plan(["source", "dataflow", "memory"])
    # 逐域消费各自相关的 stable refs（C3：判定消费完整上下文）。
    source_ctx = CoverageContext(
        plan=plan,
        watermarks=state.watermarks,
        gap_context=GapContext(stable_refs=frozenset({"src_1"})),
    )
    source = source_coverage(state, source_ctx)
    assert source.status == "complete"
    assert "v21-05:source_complete" in source.reason_codes

    dataflow_ctx = CoverageContext(
        plan=plan,
        watermarks=state.watermarks,
        gap_context=GapContext(stable_refs=frozenset({"src_1", "mem_1"})),
    )
    dataflow = dataflow_coverage(state, dataflow_ctx)
    assert dataflow.status == "complete"
    assert "v21-05:dataflow_complete" in dataflow.reason_codes

    memory_ctx = CoverageContext(
        plan=plan,
        watermarks=state.watermarks,
        gap_context=GapContext(stable_refs=frozenset({"mem_1"})),
    )
    memory = memory_coverage(state, memory_ctx)
    assert memory.status == "complete"
    assert "v21-05:memory_complete" in memory.reason_codes

    # 同一 state 换无 refs 上下文：source 无 stable refs 无法建立来源
    # 身份 → fail-closed unknown；dataflow 的 flow 子图已知非空且无
    # 待解析 refs → 「未发现危险 flow + complete」安全证据成立。
    bare = CoverageContext(plan=plan, watermarks=state.watermarks)
    assert source_coverage(state, bare).status == "unknown"
    assert dataflow_coverage(state, bare).status == "complete"


# ---------------------------------------------------------------------------
# 3. behavior 链：action/receipt 投影 → behavior/runtime_outcome coverage
# ---------------------------------------------------------------------------


def test_behavior_chain_action_projection_to_runtime_outcome_coverage() -> None:
    allowed_action = make_recent_action(
        1,
        impact="high",
        final_decision="allow",
        action_type="email.send",
        runtime_sequence=seq_ref(9, domain="receipt"),
    )
    delta = make_delta().model_copy(update={"action_additions": [allowed_action]})
    state = apply_applied(delta)

    plan = make_plan(["behavior", "runtime_outcome"])
    context = default_coverage_context(state, plan)
    # high+allow 动作期待 receipt 而未到达 → partial（receipt_pending）。
    outcome = runtime_outcome_coverage(state, context)
    assert outcome.status == "partial"
    assert "v21-07:receipt_pending" in outcome.reason_codes
    assert behavior_coverage(state, context).status == "complete"

    # runtime_outcome_upserts 投影 receipt → pending 消解 → complete。
    receipt = RuntimeOutcomeFact(
        action_id="action_1",
        decision_id="decision_1",
        policy_audit_id="audit_1",
        consumption_id=None,
        lease_id=None,
        execution_status="executed",
        receipt_sequence=seq_ref(9, domain="receipt"),
        evidence_refs=[],
    )
    with_receipt = apply_delta(
        state,
        make_delta(
            source_record_id="record_receipt",
            base_state_version=1,
            projected_value=2,
        ).model_copy(update={"runtime_outcome_upserts": [receipt]}),
    )
    assert with_receipt.outcome == "applied"
    context_after = default_coverage_context(with_receipt.state, plan)
    outcome_after = runtime_outcome_coverage(with_receipt.state, context_after)
    assert outcome_after.status == "complete"
    assert "v21-07:receipt_window_covered" in outcome_after.reason_codes

    # receipt watermark 落后 pending 动作序列 → stale（跨域比较禁止）。
    stale_ctx = CoverageContext(
        plan=plan,
        watermarks=state.watermarks.model_copy(
            update={"runtime_receipt_sequence": seq_ref(0, domain="receipt")}
        ),
    )
    assert runtime_outcome_coverage(state, stale_ctx).status == "stale"
    assert (
        "v21-07:receipt_watermark_behind"
        in runtime_outcome_coverage(state, stale_ctx).reason_codes
    )


# ---------------------------------------------------------------------------
# 4. B1-B6 matcher 消费真实投影产物（非合成夹具）
# ---------------------------------------------------------------------------


def projected_matcher_state() -> OnlineSecurityState:
    """经中央分发表一次性投影出的 B1-B5 命中场景（小型构造）。"""
    delta = make_delta().model_copy(
        update={
            # B1/B3：SENSITIVE+CREDENTIAL 读取 flow → 外发 sent_to flow。
            "flow_upserts": [
                make_flow(
                    "f_read",
                    "cred_store",
                    "action:action_1",
                    taints=["CREDENTIAL", "SENSITIVE"],
                    relation="read_from",
                ),
                make_flow(
                    "f_send",
                    "cred_store",
                    "https://sink.example",
                    taints=["CREDENTIAL", "SENSITIVE"],
                    relation="sent_to",
                ),
                # B2：untrusted tool_result → high-impact 动作影响边。
                make_flow(
                    "f_influence",
                    "src_tool",
                    "action:action_2",
                    taints=["UNTRUSTED"],
                    relation="influenced_by",
                ),
                # B4：tainted memory → 后续动作 loaded_from_memory 边。
                make_flow(
                    "f_loaded",
                    "mem_1",
                    "action:action_3",
                    taints=["PERSISTENT_UNTRUSTED"],
                    relation="loaded_from_memory",
                ),
            ],
            "source_upserts": [
                make_source_fact(
                    source_id="src_tool", source_type="tool_result", trust="untrusted"
                )
            ],
            "memory_upserts": [make_memory("mem_1")],
            "action_additions": [
                make_recent_action(
                    1, impact="high", action_type="credential.read"
                ),
                make_recent_action(2, impact="high", action_type="shell.exec"),
                make_recent_action(3, impact="moderate", action_type="email.send"),
            ],
            # B5：同 principal+task 的后发 grant action_types 扩展。
            "grant_upserts": [
                make_grant(
                    grant_id="grant_early",
                    action_types=["file.read"],
                    issued_sequence=seq_ref(1, domain="policy"),
                ),
                make_grant(
                    grant_id="grant_late",
                    action_types=["file.read", "email.send"],
                    issued_sequence=seq_ref(2, domain="policy"),
                ),
            ],
        }
    )
    # B3 外部出口动作：destination 为 email: 前缀（02 §10 外部判定口径）。
    state = apply_applied(delta)
    actions = [
        (
            action.model_copy(update={"destination_ids": ["email:ops@example.com"]})
            if action.action_id == "action_3"
            else action
        )
        for action in state.recent_actions
    ]
    return state.model_copy(update={"recent_actions": actions})


def test_b1_to_b5_matchers_hit_on_projected_state() -> None:
    state = projected_matcher_state()

    b1 = match_b1(state)
    assert b1 and all(m.pattern_id == "B1" for m in b1)
    assert any(
        "v21-07:b1_sensitive_direct_egress" in m.reason_codes for m in b1
    )

    b2 = match_b2(state)
    assert [m.subject_refs for m in b2] == [("action_2",)]

    b3 = match_b3(state)
    assert any(
        "v21-07:b3_credential_direct_egress" in m.reason_codes for m in b3
    )
    assert any(
        "v21-07:b3_credential_read_to_external_sink" in m.reason_codes
        for m in b3
    )

    b4 = match_b4(state)
    assert [m.subject_refs for m in b4] == [("action_3",)]

    b5 = match_b5(state)
    assert [m.subject_refs for m in b5] == [("grant_late",)]
    assert any("email.send" in code for m in b5 for code in m.reason_codes)


def test_b6_aggregate_threshold_hit_via_projection() -> None:
    # B6 独立：聚合由 behavior_aggregate_upserts 增量维护，matcher 只读。
    aggregate = BehaviorAggregate(
        aggregate_id="agg_b6_1",
        pattern_id="B6",
        window_start=seq_ref(1),
        window_end=seq_ref(50),
        count=B6_ANOMALY_COUNT_THRESHOLD,
        confidence="high",
        predecessor_refs=[],
        evidence_refs=[],
    )
    state = apply_applied(
        make_delta().model_copy(update={"behavior_aggregate_upserts": [aggregate]})
    )
    matches = match_b6(state)
    assert [m.pattern_id for m in matches] == ["B6"]

    below = state.model_copy(
        update={
            "behavior_aggregates": [
                aggregate.model_copy(
                    update={"count": B6_ANOMALY_COUNT_THRESHOLD - 1}
                )
            ]
        }
    )
    assert match_b6(below) == []


# ---------------------------------------------------------------------------
# 5. 02 §5.2 state flooding：sticky/aggregated 语义不回退
# ---------------------------------------------------------------------------


def test_state_flooding_sticky_and_aggregate_semantics_hold() -> None:
    benign = [make_recent_action(index) for index in range(2, 7)]
    delta = make_delta().model_copy(
        update={
            "action_additions": [
                make_recent_action(
                    1, impact="high", action_type="credential.read"
                ),
                *benign,
                make_recent_action(
                    7,
                    impact="high",
                    action_type="email.send",
                    parent_event_ids=["event_1"],
                    destination_ids=["email:ext@example.com"],
                ),
            ],
            "sticky_taint_upserts": [
                make_summary("sticky_1", ["CREDENTIAL"], flow_refs=["f1"])
            ],
            "behavior_aggregate_upserts": [
                BehaviorAggregate(
                    aggregate_id="agg_b3_1",
                    pattern_id="B3",
                    window_start=seq_ref(1),
                    window_end=seq_ref(7),
                    count=3,
                    confidence="medium",
                    predecessor_refs=["event_1"],
                    evidence_refs=[],
                )
            ],
        }
    )
    state = apply_applied(delta)

    # windowed 限额 2 < benign 5：benign 被驱逐，high 项全保留。
    evicted, report = apply_safe_eviction(
        state, EvictionLimits(recent_actions=2, benign_sources=512)
    )
    assert evicted.evicted is True
    assert report.removed_counts.get("recent_actions", 0) >= 1
    event_ids = {action.event_id for action in evicted.recent_actions}
    assert "event_1" in event_ids and "event_7" in event_ids

    # sticky / aggregated 不因 flooding 驱逐丢失（语义不回退）。
    assert [s.summary_id for s in evicted.sticky_taint_summaries] == ["sticky_1"]
    assert [a.aggregate_id for a in evicted.behavior_aggregates] == ["agg_b3_1"]

    # 驱逐后 B3 matcher 仍命中外发动作（parent 因果链保留）。
    b3 = match_b3(evicted)
    assert any(m.subject_refs == ("action_7",) for m in b3)

    # coverage：驱逐后 behavior 不得判 complete（C8 fail-closed partial）。
    plan = make_plan(["behavior"])
    context = default_coverage_context(evicted, plan, eviction_report=report)
    assert behavior_coverage(evicted, context).status == "partial"


# ---------------------------------------------------------------------------
# 6. flow lookup 截断 → dataflow coverage 降级（C8）
# ---------------------------------------------------------------------------


def test_flow_lookup_truncation_degrades_dataflow_coverage() -> None:
    state = chain_state(6)  # 线性 flow 链超出深度预算
    flows, truncated = bounded_relevant_flow_lookup(
        state, target_ref="node_0", max_depth=2
    )
    assert truncated is True
    assert len(flows) < 6

    plan = make_plan(["dataflow"])
    context = CoverageContext(
        plan=plan,
        watermarks=state.watermarks,
        truncated=("dataflow",),
    )
    verdict = dataflow_coverage(state, context)
    assert verdict.status == "partial"
    assert "v21-05:flow_lookup_truncated" in verdict.reason_codes


# ---------------------------------------------------------------------------
# 7. Shadow 纪律：watermark-only delta 接线前后语义等价
# ---------------------------------------------------------------------------


def test_watermark_only_delta_semantics_unchanged_after_wiring() -> None:
    # legacy decision 路径（只推进 watermark）不受 typed 接线影响：
    # applied、typed 容器全空不注入内容、版本推进与幂等登记语义不变。
    state = empty_state()
    delta = make_delta()
    result = apply_delta(state, delta)
    assert result.outcome == "applied"
    new_state = result.state
    assert new_state.state_version == 1
    assert new_state.source_index == []
    assert new_state.relevant_flows == []
    assert new_state.memory_index == []
    assert new_state.active_grants == []
    assert new_state.recent_actions == []
    assert new_state.runtime_outcomes == []
    assert new_state.behavior_aggregates == []
    assert new_state.sticky_taint_summaries == []
    assert new_state.execution_leases == []  # C5：恒空
    assert len(new_state.applied_projections) == 1

    # 同幂等键重放 → noop（CAS/幂等语义不变）。
    replay = apply_delta(new_state, delta)
    assert replay.outcome == "noop"


# ---------------------------------------------------------------------------
# 8. reprojection 契约（D2）：懒 legacy decoder + rebuild 确定性
# ---------------------------------------------------------------------------


def make_legacy_delta(
    *, source_record_id: str, projected_sequence: int, base: int
):
    """构造历史 ``v21-04.projector.1`` envelope（只含 watermark 推进）。"""
    delta = make_delta(
        source_record_id=source_record_id,
        base_state_version=base,
        projected_value=base + 1,
    ).model_copy(
        update={
            "projector_version": LEGACY_PROJECTOR_VERSION,
            "watermarks": make_watermarks().model_copy(
                update={"projected_sequence": seq_ref(projected_sequence)}
            ),
        }
    )
    return delta.model_copy(
        update={
            "delta_digest": canonical_sha256(delta_digest_projection(delta))
        }
    )


def legacy_projection_row(delta, *, applied_state_version: int):
    return ProjectionIdentityRecord(
        scope_digest=SCOPE,
        source_record_type="policy_evaluation",
        source_record_id=delta.source.source_record_id,
        source_revision=delta.source.source_revision,
        projector_version=LEGACY_PROJECTOR_VERSION,
        delta_digest=delta.delta_digest,
        delta_payload=delta.model_dump(mode="json"),
        applied_state_version=applied_state_version,
        created_at="2026-08-14T00:00:00+00:00",
    )


def test_legacy_decoder_rejects_non_empty_typed_containers() -> None:
    bad = make_legacy_delta(
        source_record_id="rec_bad", projected_sequence=1, base=0
    ).model_copy(update={"source_upserts": [make_source_fact()]})
    with pytest.raises(Exception) as excinfo:
        _decode_legacy_delta(bad)
    assert excinfo.value.reason_code == "v21-04:legacy_delta_typed_content"


def test_legacy_decoder_rejects_version_inconsistency() -> None:
    delta = make_legacy_delta(
        source_record_id="rec_inconsistent", projected_sequence=1, base=0
    ).model_copy(update={"projector_version": PROJECTOR_VERSION})
    with pytest.raises(Exception) as excinfo:
        _decode_legacy_delta(delta)
    assert (
        excinfo.value.reason_code
        == "v21-04:legacy_envelope_version_inconsistent"
    )


def test_previous_projector_decoder_preserves_typed_content() -> None:
    delta = make_delta().model_copy(
        update={
            "projector_version": PREVIOUS_PROJECTOR_VERSION,
            "source_upserts": [make_source_fact()],
        }
    )
    delta = delta.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(delta))}
    )
    decoded = _decode_legacy_delta(delta, require_empty_typed=False)
    assert decoded.projector_version == PROJECTOR_VERSION
    assert decoded.source_upserts == delta.source_upserts


def test_reprojection_of_legacy_envelopes_is_deterministic() -> None:
    # D2：旧版本 envelope（只含 watermark）经 decoder 重组后 rebuild 的
    # state_digest 确定性 —— 两次 rebuild 同 digest，且与同内容直接以
    # 新版本登记的行 rebuild 结果一致。
    store = MemoryControlPlaneStore()
    delta_a = make_legacy_delta(
        source_record_id="rec_legacy_a", projected_sequence=3, base=0
    )
    delta_b = make_legacy_delta(
        source_record_id="rec_legacy_b", projected_sequence=7, base=1
    )
    store.record_projection(legacy_projection_row(delta_a, applied_state_version=1))
    store.record_projection(legacy_projection_row(delta_b, applied_state_version=2))

    first, alert_first = rebuild_locked(store, SCOPE)
    assert alert_first is None
    assert first.state_version == 2
    assert first.dirty_domains == []
    second, alert_second = rebuild_locked(store, SCOPE)
    assert alert_second is None
    assert state_digest(first) == state_digest(second)

    # 等价对照：同内容 delta 以当前版本直接登记 → rebuild 同 digest。
    reference = MemoryControlPlaneStore()
    for index, legacy in enumerate((delta_a, delta_b), start=1):
        fresh = legacy.model_copy(update={"projector_version": PROJECTOR_VERSION})
        fresh = fresh.model_copy(
            update={
                "delta_digest": canonical_sha256(
                    delta_digest_projection(fresh)
                )
            }
        )
        reference.record_projection(
            ProjectionIdentityRecord(
                scope_digest=SCOPE,
                source_record_type="policy_evaluation",
                source_record_id=fresh.source.source_record_id,
                source_revision=fresh.source.source_revision,
                projector_version=PROJECTOR_VERSION,
                delta_digest=fresh.delta_digest,
                delta_payload=fresh.model_dump(mode="json"),
                applied_state_version=index,
                created_at="2026-08-14T00:00:00+00:00",
            )
        )
    reference_state, reference_alert = rebuild_locked(reference, SCOPE)
    assert reference_alert is None
    assert state_digest(reference_state) == state_digest(first)
    # 哨兵：state_digest 导入唯一性（防未来重名函数漂移）。
    assert state_digest is _state_digest_ref
