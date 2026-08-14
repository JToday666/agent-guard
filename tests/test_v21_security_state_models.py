"""V21-04 security-context fact/state 模型契约测试。

覆盖：模型 roundtrip、extra=forbid、digest 白名单（随机 id/时间戳变更
不影响 digest）、01 §27 source_record_type 枚举逐字核对、五元组
幂等键（event_id-only 反例）、state_digest T-Replay 锚点语义、
SequenceRef 跨域比较 fail-closed。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import SecurityStateScope
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    SOURCE_RECORD_TYPES,
    AppliedProjection,
    BehaviorAggregate,
    CapabilityGrant,
    DeclassificationFact,
    ExecutionLease,
    FlowFact,
    GapRange,
    GrantConsumption,
    MemoryFact,
    OnlineSecurityState,
    ProjectionRecordIdentity,
    RecentActionFact,
    RuntimeOutcomeFact,
    SecuritySnapshot,
    SecurityStateDeltaV21,
    SequenceComparisonError,
    SourceFact,
    StateWatermarks,
    StickyTaintSummary,
    WatermarkDelta,
    compare_sequence_refs,
    delta_digest_projection,
    fact_digest,
    projection_identity_key,
    state_digest,
)
from agentguard_core.signals.models import SequenceRef

SCOPE = "hmac-sha256:scope_fixture"


def make_scope(**overrides: object) -> SecurityStateScope:
    """SecurityStateScope 测试夹具（scope_digest 绑定本文件 SCOPE）。"""
    payload: dict[str, object] = {
        "principal_id": "principal_a",
        "runtime": "openclaw",
        "runtime_binding_id": "binding_a",
        "trace_id": "trace_fixture",
        "session_id": None,
        "scope_digest": SCOPE,
    }
    payload.update(overrides)
    return SecurityStateScope(**payload)  # pyright: ignore[reportArgumentType]


def make_source_fact(**overrides: object) -> SourceFact:
    payload: dict[str, object] = {
        "source_id": "src_1",
        "scope_digest": SCOPE,
        "source_type": "web",
        "trust": "untrusted",
        "verification_state": "unverified",
        "origin": "observed",
        "authority": "trusted_claim",
        "producer": "producer_a",
        "taints": ["UNTRUSTED"],
        "first_sequence": None,
        "last_sequence": None,
        "evidence_refs": [],
    }
    payload.update(overrides)
    return SourceFact(**payload)  # pyright: ignore[reportArgumentType]


def make_lease(**overrides: object) -> ExecutionLease:
    payload: dict[str, object] = {
        "lease_id": "lease_1",
        "consumption_id": "consumption_1",
        "approval_id": "approval_1",
        "grant_id": "grant_1",
        "action_id": "action_1",
        "authorization_fingerprint": "hmac-sha256:fp",
        "runtime_binding_id": "binding_a",
        "issued_at": "2026-08-14T00:00:00Z",
        "expires_at": "2026-08-14T01:00:00Z",
        "token_digest": "sha256:token",
        "status": "consumed",
        "evidence_refs": [],
    }
    payload.update(overrides)
    return ExecutionLease(**payload)  # pyright: ignore[reportArgumentType]


def make_grant(**overrides: object) -> CapabilityGrant:
    payload: dict[str, object] = {
        "grant_id": "grant_1",
        "scope_digest": SCOPE,
        "source_type": "human_approval",
        "source_ref": "approval_1",
        "subject_principal_id": "principal_a",
        "subject_agent_id": None,
        "task_id": "task_1",
        "action_types": ["email.send"],
        "resource_constraints": [],
        "destination_constraints": [],
        "argument_constraints": [],
        "exact_authorization_fingerprint": "hmac-sha256:fp",
        "usage_limit": 1,
        "remaining_uses": 1,
        "delegable": False,
        "parent_grant_id": None,
        "issued_sequence": None,
        "expires_sequence": None,
        "expires_at": "2026-08-14T01:00:00Z",
        "revoked": False,
        "revoked_sequence": None,
        "policy_revision": "rev_1",
        "compiler_version": None,
        "grant_digest": "sha256:grant_content",
        "evidence_refs": [],
    }
    payload.update(overrides)
    return CapabilityGrant(**payload)  # pyright: ignore[reportArgumentType]


def make_recent_action(index: int, **overrides: object) -> RecentActionFact:
    payload: dict[str, object] = {
        "action_id": f"action_{index}",
        "event_id": f"event_{index}",
        "agent_id": "agent_a",
        "branch_id": None,
        "parent_event_ids": [],
        "runtime_sequence": None,
        "action_type": "file.read",
        "impact": "low",
        "effects": {},
        "resource_ids": [f"file:doc_{index}"],
        "destination_ids": [],
        "data_refs": [],
        "authority_status": "authorized",
        "final_decision": None,
        "evidence_refs": [],
    }
    payload.update(overrides)
    return RecentActionFact(**payload)  # pyright: ignore[reportArgumentType]


def make_watermarks() -> StateWatermarks:
    return StateWatermarks(
        committed_sequence=None,
        projected_sequence=None,
        runtime_receipt_sequence=None,
        memory_sequence=None,
        gaps=[],
    )


def make_delta(
    *,
    source_record_id: str = "record_1",
    source_revision: int = 1,
    base_state_version: int = 0,
    projected_value: int = 1,
    projection_id: str | None = None,
) -> SecurityStateDeltaV21:
    identity = ProjectionRecordIdentity(
        source_record_type="policy_evaluation",
        source_record_id=source_record_id,
        source_revision=source_revision,
        source_sequence=None,
    )
    delta = SecurityStateDeltaV21(
        projection_id=projection_id
        or f"projection_{source_record_id}_{source_revision}",
        scope_digest=SCOPE,
        source=identity,
        base_state_version=base_state_version,
        new_state_version=base_state_version + 1,
        projector_version=PROJECTOR_VERSION,
        task_upsert=None,
        source_upserts=[],
        flow_upserts=[],
        declassification_upserts=[],
        memory_upserts=[],
        grant_upserts=[],
        grant_revocations=[],
        grant_consumptions=[],
        action_additions=[],
        runtime_outcome_upserts=[],
        behavior_aggregate_upserts=[],
        sticky_taint_upserts=[],
        watermark_delta=WatermarkDelta(
            projected_sequence=SequenceRef(
                domain="audit",
                producer_binding_id="binding_a",
                value=projected_value,
            )
        ),
        coverage_invalidations=[],
        dirty_domain_updates=[],
        delta_digest="",
    )
    return delta.model_copy(
        update={
            "delta_digest": canonical_sha256(delta_digest_projection(delta))
        }
    )


def test_fact_models_roundtrip_json() -> None:
    facts = [
        make_source_fact(),
        DeclassificationFact(
            declass_id="declass_1",
            input_ref="src_1",
            output_ref="src_2",
            removed_taints=["UNTRUSTED"],
            retained_taints=[],
            mechanism_id="mechanism_a",
            mechanism_version="1",
            policy_revision="rev_1",
            producer="trusted_declassifier",
            evidence_refs=[],
        ),
        FlowFact(
            flow_id="flow_1",
            scope_digest=SCOPE,
            source_ref="src_1",
            target_ref="artifact_1",
            relation="derived_from",
            taints=["UNTRUSTED"],
            strength="possible",
            origin="semantic_inferred",
            sequence=None,
            producer="projector",
            evidence_refs=[],
        ),
        MemoryFact(
            memory_id="memory_1",
            change_id="change_1",
            change_status="committed",
            trust_state="tainted",
            taints=["PERSISTENT_UNTRUSTED"],
            source_refs=["src_1"],
            last_write_sequence=None,
            last_read_sequence=None,
            evidence_refs=[],
        ),
        make_grant(),
        GrantConsumption(
            consumption_id="consumption_1",
            grant_id="grant_1",
            action_id="action_1",
            authorization_fingerprint="hmac-sha256:fp",
            sequence=None,
            evidence_refs=[],
        ),
        make_lease(),
        make_recent_action(1),
        RuntimeOutcomeFact(
            action_id="action_1",
            decision_id="decision_1",
            policy_audit_id="policy_audit_1",
            consumption_id=None,
            lease_id=None,
            execution_status="executed",
            receipt_sequence=SequenceRef(
                domain="receipt", producer_binding_id="binding_a", value=1
            ),
            evidence_refs=[],
        ),
        BehaviorAggregate(
            aggregate_id="aggregate_1",
            pattern_id="B3",
            window_start=SequenceRef(
                domain="audit", producer_binding_id="binding_a", value=1
            ),
            window_end=SequenceRef(
                domain="audit", producer_binding_id="binding_a", value=10
            ),
            count=3,
            confidence="medium",
            predecessor_refs=["event_1"],
            evidence_refs=[],
        ),
        StickyTaintSummary(
            summary_id="summary_1",
            taints=["CREDENTIAL"],
            first_seen=SequenceRef(
                domain="audit", producer_binding_id="binding_a", value=1
            ),
            last_seen=SequenceRef(
                domain="audit", producer_binding_id="binding_a", value=2
            ),
            unresolved_flow_refs=["flow_1"],
            memory_refs=[],
            evidence_refs=[],
        ),
        GapRange(
            domain="audit",
            producer_binding_id="binding_a",
            start_sequence=5,
            end_sequence=7,
            reason="missing_audit_window",
        ),
        make_watermarks(),
    ]
    for fact in facts:
        dump = fact.model_dump(mode="json")
        assert type(fact).model_validate(dump) == fact


def test_fact_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        make_source_fact(unknown_field="x")  # pyright: ignore[reportCallIssue]
    with pytest.raises(ValidationError):
        make_lease(unknown_field="x")  # pyright: ignore[reportCallIssue]


def test_digest_whitelist_excludes_random_ids_and_timestamps() -> None:
    base = make_source_fact()
    assert fact_digest(base) == fact_digest(
        make_source_fact(source_id="src_totally_different")
    )
    assert fact_digest(base) != fact_digest(make_source_fact(trust="trusted"))

    lease = make_lease()
    assert fact_digest(lease) == fact_digest(
        make_lease(
            lease_id="lease_other",
            issued_at="2030-01-01T00:00:00Z",
            expires_at="2030-01-02T00:00:00Z",
        )
    )
    assert fact_digest(lease) != fact_digest(make_lease(status="expired"))

    grant = make_grant()
    assert fact_digest(grant) == fact_digest(make_grant(grant_id="grant_other"))
    assert fact_digest(grant) != fact_digest(make_grant(revoked=True))


def test_source_record_type_literal_is_frozen_verbatim() -> None:
    # 01 §27 (L1049-1056) 逐字核对：**不含 task 记录类型**。
    assert SOURCE_RECORD_TYPES == (
        "policy_evaluation",
        "runtime_outcome",
        "approval",
        "memory_transition",
        "policy_revision",
        "runtime_observation",
    )
    with pytest.raises(ValidationError):
        ProjectionRecordIdentity(
            source_record_type="task",  # pyright: ignore[reportArgumentType]
            source_record_id="record_1",
            source_revision=1,
            source_sequence=None,
        )


def test_snapshot_field_set_matches_frozen_01_section_19() -> None:
    # 字段集合契约（F3）：SecuritySnapshot.model_fields 键集合与
    # 01_F1字段与契约冻结.md §19 (L815-845) 逐字一致。注意 §19 冻结的
    # 是 ``scope: SecurityStateScope``，不是 scope_digest: str。
    assert set(SecuritySnapshot.model_fields) == {
        "schema_version",
        "snapshot_id",
        "state_version",
        "scope",  # 01 §19 L820: scope: SecurityStateScope
        "evaluation_clock",
        "as_of_sequence",
        "projector_version",
        "policy_revision",
        "policy_digest",
        "coverage",
        "watermarks",
        "task",
        "sources",
        "grants",
        "recent_actions",
        "flows",
        "memory_facts",
        "runtime_outcomes",
        "behavior_aggregates",
        "sticky_taint_summaries",
        "declassifications",
        "dirty_domains",
        "snapshot_digest",
    }


def test_delta_and_identity_field_sets_match_frozen_01_section_27() -> None:
    # 字段集合契约（F3）：与 01_F1字段与契约冻结.md §27 (L1048-1098)
    # 逐字一致。
    assert set(ProjectionRecordIdentity.model_fields) == {
        "source_record_type",
        "source_record_id",
        "source_revision",
        "source_sequence",
    }
    assert set(SecurityStateDeltaV21.model_fields) == {
        "schema_version",
        "projection_id",
        "scope_digest",
        "source",
        "base_state_version",
        "new_state_version",
        "projector_version",
        "task_upsert",
        "source_upserts",
        "flow_upserts",
        "declassification_upserts",
        "memory_upserts",
        "grant_upserts",
        "grant_revocations",
        "grant_consumptions",
        "action_additions",
        "runtime_outcome_upserts",
        "behavior_aggregate_upserts",
        "sticky_taint_upserts",
        "watermark_delta",
        "coverage_invalidations",
        "dirty_domain_updates",
        "delta_digest",
    }


def test_projection_identity_key_is_five_tuple_not_event_id() -> None:
    key_a = projection_identity_key(
        SCOPE, "policy_evaluation", "record_1", 1, PROJECTOR_VERSION
    )
    key_same = projection_identity_key(
        SCOPE, "policy_evaluation", "record_1", 1, PROJECTOR_VERSION
    )
    key_new_revision = projection_identity_key(
        SCOPE, "policy_evaluation", "record_1", 2, PROJECTOR_VERSION
    )
    key_new_projector = projection_identity_key(
        SCOPE, "policy_evaluation", "record_1", 1, "v21-04.projector.999"
    )
    assert key_a == key_same
    # 同 source_record_id（event 身份）不同 source_revision 必须是不同
    # 幂等身份：event_id-only 幂等键被 02 §4 禁止。
    assert key_a != key_new_revision
    assert key_a != key_new_projector
    assert key_a.startswith("sha256:")


def test_delta_digest_excludes_projection_id() -> None:
    delta = make_delta()
    same_content_other_id = make_delta(projection_id="projection_random_other")
    assert delta_digest_projection(delta) == delta_digest_projection(
        same_content_other_id
    )
    assert delta.delta_digest == same_content_other_id.delta_digest

    different_content = make_delta(projected_value=99)
    assert delta.delta_digest != different_content.delta_digest


def test_state_digest_is_t_replay_anchor() -> None:
    state = OnlineSecurityState(watermarks=make_watermarks())
    # state_version / applied_projections（随机 source_record_id 派生键）/
    # evicted 运维标记不进入 state digest。
    drifted = state.model_copy(
        update={
            "state_version": 7,
            "applied_projections": [
                AppliedProjection(
                    projection_key="sha256:random_derived_key",
                    delta_digest="sha256:whatever",
                )
            ],
            "evicted": True,
        }
    )
    assert state_digest(state) == state_digest(drifted)

    # 安全内容变化必须改变 digest。
    changed = state.model_copy(update={"dirty_domains": ["behavior"]})
    assert state_digest(state) != state_digest(changed)


def test_sequence_ref_cross_domain_comparison_is_fail_closed() -> None:
    left = SequenceRef(domain="audit", producer_binding_id="b", value=1)
    right = SequenceRef(domain="runtime", producer_binding_id="b", value=2)
    with pytest.raises(SequenceComparisonError) as excinfo:
        compare_sequence_refs(left, right)
    assert excinfo.value.reason_code == "v21-04:cross_domain_sequence_comparison"

    cross_producer_left = SequenceRef(
        domain="audit", producer_binding_id="b1", value=1
    )
    cross_producer_right = SequenceRef(
        domain="audit", producer_binding_id="b2", value=1
    )
    with pytest.raises(SequenceComparisonError) as excinfo:
        compare_sequence_refs(cross_producer_left, cross_producer_right)
    assert (
        excinfo.value.reason_code
        == "v21-04:cross_producer_sequence_comparison"
    )

    assert compare_sequence_refs(left, left) == 0
    bigger = SequenceRef(domain="audit", producer_binding_id="b", value=2)
    assert compare_sequence_refs(left, bigger) == -1
    assert compare_sequence_refs(bigger, left) == 1
