"""V21-04 Idempotent Projector 契约测试。

覆盖 7 类验收场景中的 projector 相关场景：

- commit failure（未提交记录拒绝投影，F0-8 / 02 §3）；
- projector failure（apply 异常 → dirty 标记，不得 complete）；
- duplicate projection（同 identity 同 digest 重放 no-op）；
- digest conflict（同 identity 异 digest → conflict + dirty，不静默覆盖）；
- CAS 三分支（applied / needs_rebuild / noop）；
- event_id-only 幂等键反例（同 event 身份不同 source_revision 必须是
  不同投影身份）。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
    OnlineSecurityState,
    ProjectionError,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    StateWatermarks,
    WatermarkDelta,
    apply_delta,
    compute_coverage,
    delta_digest_projection,
    mark_state_dirty,
    project_committed_record,
    state_digest,
)
from agentguard_core.signals.models import SequenceRef

from tests.test_v21_security_state_models import (
    SCOPE,
    make_delta,
    make_grant,
    make_recent_action,
    make_source_fact,
    make_watermarks,
)


def make_record(
    delta: SecurityStateDeltaV21, *, committed: bool = True
) -> CommittedRecord:
    return CommittedRecord(
        record_id=f"audit_{delta.source.source_record_id}",
        committed=committed,
        source_record_type=delta.source.source_record_type,
        source_record_id=delta.source.source_record_id,
        source_revision=delta.source.source_revision,
        scope_digest=delta.scope_digest,
        projector_version=PROJECTOR_VERSION,
        delta=delta,
        task_upsert=None,
    )


def empty_state() -> OnlineSecurityState:
    return OnlineSecurityState(watermarks=make_watermarks())


def plan_required_behavior() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-04-plan:fixture",
        impact="high",
        required_domains=["task", "behavior"],
        optional_domains=[
            "source",
            "capability",
            "dataflow",
            "memory",
            "runtime_outcome",
        ],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-04:fixture"],
    )


# ---------------------------------------------------------------------------
# commit failure（F0-8：未 committed 不得成为后续历史状态）
# ---------------------------------------------------------------------------


def test_commit_failure_rejects_uncommitted_record() -> None:
    delta = make_delta()
    record = make_record(delta, committed=False)
    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(record, base_state_version=0, scope_digest=SCOPE)
    assert excinfo.value.reason_code == "v21-04:record_not_committed"


def test_commit_failure_scope_and_version_validation() -> None:
    delta = make_delta()
    record = make_record(delta)
    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(
            record, base_state_version=0, scope_digest="hmac-sha256:other_scope"
        )
    assert excinfo.value.reason_code == "v21-04:scope_digest_mismatch"

    stale_projector = record.model_copy(
        update={"projector_version": "v21-04.projector.0"}
    )
    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(
            stale_projector, base_state_version=0, scope_digest=SCOPE
        )
    assert excinfo.value.reason_code == "v21-04:projector_version_mismatch"

    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(
            record, base_state_version=3, scope_digest=SCOPE
        )
    assert excinfo.value.reason_code == "v21-04:base_state_version_mismatch"


def test_project_rejects_tampered_delta_digest() -> None:
    delta = make_delta()
    tampered = delta.model_copy(update={"delta_digest": "sha256:forged"})
    record = make_record(tampered)
    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(record, base_state_version=0, scope_digest=SCOPE)
    assert excinfo.value.reason_code == "v21-04:delta_digest_mismatch"


def test_project_rejects_task_upsert_payload() -> None:
    delta = make_delta()
    record = make_record(delta)
    with_task = record.model_copy(update={"task_upsert": {"task_id": "task_x"}})
    with pytest.raises(ProjectionError) as excinfo:
        project_committed_record(with_task, base_state_version=0, scope_digest=SCOPE)
    assert excinfo.value.reason_code == "v21-04:task_delta_projection_forbidden"


# ---------------------------------------------------------------------------
# projector failure（02 §3：失败不得解释为 complete）
# ---------------------------------------------------------------------------


def test_projector_failure_marks_state_dirty_not_complete() -> None:
    state = empty_state()
    delta = make_delta()
    record = make_record(delta.model_copy(update={"delta_digest": "sha256:bad"}))

    # 编排语义：project/apply 抛错 → dirty marker，不产生 applied 状态。
    with pytest.raises(ProjectionError):
        projected = project_committed_record(
            record, base_state_version=state.state_version, scope_digest=SCOPE
        )
        apply_delta(state, projected)
    failed = mark_state_dirty(
        state, ["behavior"], reason_code="v21-04:projector_apply_failed"
    )
    assert failed.dirty_domains == ["behavior"]
    assert failed.state_version == 0

    coverage = compute_coverage(
        failed,
        plan_required_behavior(),
        projector_version=PROJECTOR_VERSION,
        task_required=False,
    )
    assert coverage.behavior.status == "unknown"
    assert coverage.behavior.status != "complete"
    assert "v21-04:dirty_projection" in coverage.behavior.reason_codes


def test_mark_state_dirty_requires_v21_04_reason_prefix() -> None:
    state = empty_state()
    with pytest.raises(ProjectionError) as excinfo:
        mark_state_dirty(state, ["behavior"], reason_code="other:prefix")
    assert excinfo.value.reason_code == "v21-04:invalid_reason_code"


# ---------------------------------------------------------------------------
# CAS 三分支 + duplicate projection + digest conflict（02 §4.1）
# ---------------------------------------------------------------------------


def test_apply_delta_cas_applies_and_advances_version() -> None:
    state = empty_state()
    delta = make_delta(base_state_version=0)
    result = apply_delta(state, delta)
    assert result.outcome == "applied"
    assert result.state.state_version == 1
    assert result.state.watermarks.projected_sequence is not None
    assert result.state.watermarks.projected_sequence.value == 1
    # 输入状态不被修改（纯函数）。
    assert state.state_version == 0


def test_apply_delta_duplicate_projection_is_noop() -> None:
    state = empty_state()
    delta = make_delta(base_state_version=0)
    first = apply_delta(state, delta)
    assert first.outcome == "applied"

    # 同 identity 同 digest 重放：no-op，版本与 digest 不变。
    replay = apply_delta(first.state, delta)
    assert replay.outcome == "noop"
    assert replay.state.state_version == 1
    assert state_digest(replay.state) == state_digest(first.state)


def test_apply_delta_digest_conflict_marks_dirty_without_overwrite() -> None:
    state = empty_state()
    delta_v1 = make_delta(base_state_version=0)
    applied = apply_delta(state, delta_v1)

    # 同五元组 identity、不同内容 → digest 冲突。
    conflicting_identity = ProjectionRecordIdentity(
        source_record_type=delta_v1.source.source_record_type,
        source_record_id=delta_v1.source.source_record_id,
        source_revision=delta_v1.source.source_revision,
        source_sequence=None,
    )
    forged = SecurityStateDeltaV21(
        projection_id="projection_forged",
        scope_digest=SCOPE,
        source=conflicting_identity,
        base_state_version=0,
        new_state_version=1,
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
                domain="audit", producer_binding_id="binding_a", value=999
            )
        ),
        coverage_invalidations=[],
        dirty_domain_updates=["behavior"],
        delta_digest="",
    )
    forged = forged.model_copy(
        update={
            "delta_digest": canonical_sha256(delta_digest_projection(forged))
        }
    )

    result = apply_delta(applied.state, forged)
    assert result.outcome == "conflict"
    assert "behavior" in result.state.dirty_domains
    # 不静默覆盖：版本与水位保持冲突前状态。
    assert result.state.state_version == 1
    assert result.state.watermarks.projected_sequence is not None
    assert result.state.watermarks.projected_sequence.value == 1


def test_apply_delta_version_mismatch_unknown_identity_needs_rebuild() -> None:
    state = empty_state()
    delta = make_delta(source_record_id="record_unknown", base_state_version=5)
    result = apply_delta(state, delta)
    assert result.outcome == "needs_rebuild"
    assert result.state.state_version == 0
    assert result.state is state


def test_event_id_only_idempotency_counterexample() -> None:
    # 同 source_record_id（事件身份）不同 source_revision 是两个投影身份，
    # 必须依次应用而不是被当作重复投影吞掉。
    state = empty_state()
    delta_rev1 = make_delta(source_record_id="record_x", source_revision=1)
    delta_rev2 = make_delta(
        source_record_id="record_x",
        source_revision=2,
        base_state_version=1,
        projected_value=2,
    )
    first = apply_delta(state, delta_rev1)
    assert first.outcome == "applied"
    second = apply_delta(first.state, delta_rev2)
    assert second.outcome == "applied"
    assert second.state.state_version == 2
    assert len(second.state.applied_projections) == 2
    keys = {
        applied.projection_key for applied in second.state.applied_projections
    }
    assert len(keys) == 2


def test_apply_delta_merges_gaps_and_dirty_domains() -> None:
    state = empty_state()
    delta = make_delta(base_state_version=0)
    delta = delta.model_copy(
        update={
            "watermark_delta": WatermarkDelta(
                new_gaps=[
                    {
                        "domain": "audit",
                        "producer_binding_id": "binding_a",
                        "start_sequence": 2,
                        "end_sequence": 4,
                        "reason": "missing_window",
                    }
                ]
            ),
            "dirty_domain_updates": ["memory"],
            "coverage_invalidations": ["source"],
        }
    )
    delta = delta.model_copy(
        update={
            "delta_digest": canonical_sha256(delta_digest_projection(delta))
        }
    )
    result = apply_delta(state, delta)
    assert result.outcome == "applied"
    assert [gap.reason for gap in result.state.watermarks.gaps] == [
        "missing_window"
    ]
    assert result.state.dirty_domains == ["memory", "source"]


def test_watermarks_fixture_is_complete_shape() -> None:
    watermarks = make_watermarks()
    assert isinstance(watermarks, StateWatermarks)
    assert watermarks.gaps == []


# ---------------------------------------------------------------------------
# V21-05/06/07 接线后：非空 typed upsert 列表经中央分发表应用
# ---------------------------------------------------------------------------


def test_apply_delta_applies_non_empty_typed_upsert_lists() -> None:
    state = empty_state()
    delta = make_delta(base_state_version=0)

    wired_grants = delta.model_copy(update={"grant_upserts": [make_grant()]})
    result = apply_delta(state, wired_grants)
    assert result.outcome == "applied"
    assert result.state.state_version == 1
    assert [grant.grant_id for grant in result.state.active_grants] == [
        "grant_1"
    ]
    # state_version 推进且输入状态不被修改（纯函数）。
    assert state.state_version == 0
    assert state.active_grants == []

    wired_multi = delta.model_copy(
        update={
            "source_upserts": [make_source_fact()],
            "action_additions": [make_recent_action(1)],
            "sticky_taint_upserts": [],
        }
    )
    result_multi = apply_delta(state, wired_multi)
    assert result_multi.outcome == "applied"
    assert [s.source_id for s in result_multi.state.source_index] == ["src_1"]
    assert [
        action.action_id for action in result_multi.state.recent_actions
    ] == ["action_1"]
    assert result_multi.state.sticky_taint_summaries == []
    assert state.state_version == 0


def test_apply_delta_accepts_empty_typed_upsert_lists() -> None:
    # 空列表（本期冻结形态）不受 F4 拦截，照常 applied。
    state = empty_state()
    result = apply_delta(state, make_delta(base_state_version=0))
    assert result.outcome == "applied"
    assert result.state.state_version == 1
