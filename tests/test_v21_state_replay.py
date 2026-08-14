"""V21-04 crash/replay、rebuild determinism 与 T-Replay 测试（05 §12）。

- crash/replay：中途崩溃后 bounded rebuild 恢复；
- rebuild determinism：增量 apply 与 rebuild 的 state_digest 相同，且与
  输入记录顺序无关（规范化按 identity 五元组排序）；
- T-Replay：同 authoritative records + same projector_version，不同随机
  ID → 相同 OnlineSecurityState digest 与 Snapshot digest。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.models import ActionConstraint
from agentguard_core.authority.models import (
    EvaluationClock,
    TaskFact,
)
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
    OnlineSecurityState,
    ProjectionError,
    SecuritySnapshot,
    apply_delta,
    build_snapshot,
    project_committed_record,
    rebuild_state,
    snapshot_digest_projection,
    state_digest,
)

from tests.test_v21_security_state_models import (
    SCOPE,
    make_delta,
    make_scope,
    make_watermarks,
)


def make_record(delta, *, committed: bool = True) -> CommittedRecord:
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


def three_records(
    *, suffix: str = "", random_prefix: str = "projection"
):
    """三条 committed 记录（watermark 依次推进），随机 id 可参数化。"""
    records = []
    for index in range(1, 4):
        delta = make_delta(
            source_record_id=f"record_{index}{suffix}",
            source_revision=1,
            base_state_version=index - 1,
            projected_value=index,
            projection_id=f"{random_prefix}_{index}{suffix}",
        )
        records.append(make_record(delta))
    return records


def apply_all(records: list[CommittedRecord]) -> OnlineSecurityState:
    state = OnlineSecurityState(watermarks=make_watermarks())
    for record in records:
        delta = project_committed_record(
            record,
            base_state_version=state.state_version,
            scope_digest=SCOPE,
        )
        result = apply_delta(state, delta)
        assert result.outcome == "applied"
        state = result.state
    return state


# ---------------------------------------------------------------------------
# crash/replay + rebuild determinism
# ---------------------------------------------------------------------------


def test_crash_replay_rebuild_recovers_full_state() -> None:
    records = three_records()

    # 增量应用到第 2 条后「崩溃」（丢弃内存态）。
    state = OnlineSecurityState(watermarks=make_watermarks())
    for record in records[:2]:
        delta = project_committed_record(
            record,
            base_state_version=state.state_version,
            scope_digest=SCOPE,
        )
        state = apply_delta(state, delta).state

    # bounded rebuild 从 committed 权威记录恢复。
    rebuilt = rebuild_state(records, PROJECTOR_VERSION)
    assert rebuilt.state_version == 3
    assert rebuilt.watermarks.projected_sequence is not None
    assert rebuilt.watermarks.projected_sequence.value == 3

    full = apply_all(records)
    assert state_digest(rebuilt) == state_digest(full)


def test_rebuild_determinism_is_order_independent() -> None:
    records = three_records()
    incremental = apply_all(records)

    rebuilt_forward = rebuild_state(records, PROJECTOR_VERSION)
    rebuilt_reversed = rebuild_state(list(reversed(records)), PROJECTOR_VERSION)
    rebuilt_rotated = rebuild_state(
        [records[1], records[2], records[0]], PROJECTOR_VERSION
    )

    assert state_digest(rebuilt_forward) == state_digest(incremental)
    assert state_digest(rebuilt_reversed) == state_digest(incremental)
    assert state_digest(rebuilt_rotated) == state_digest(incremental)
    assert rebuilt_reversed.state_version == incremental.state_version == 3


def test_rebuild_skips_duplicate_records_idempotently() -> None:
    records = three_records()
    duplicated = [*records, records[0], records[2]]
    rebuilt = rebuild_state(duplicated, PROJECTOR_VERSION)
    assert rebuilt.state_version == 3
    assert state_digest(rebuilt) == state_digest(rebuild_state(records, PROJECTOR_VERSION))


def test_rebuild_rejects_wrong_projector_version() -> None:
    records = three_records()
    with pytest.raises(ProjectionError) as excinfo:
        rebuild_state(records, "v21-04.projector.0")
    assert excinfo.value.reason_code == "v21-04:rebuild_projector_version_mismatch"


def test_rebuild_rejects_mixed_scopes() -> None:
    records = three_records()
    other_scope = records[0].model_copy(
        update={"scope_digest": "hmac-sha256:other_scope"}
    )
    with pytest.raises(ProjectionError) as excinfo:
        rebuild_state([*records, other_scope], PROJECTOR_VERSION)
    assert excinfo.value.reason_code == "v21-04:rebuild_scope_mix"


def test_rebuild_rejects_uncommitted_record() -> None:
    records = three_records()
    uncommitted = records[1].model_copy(update={"committed": False})
    with pytest.raises(ProjectionError) as excinfo:
        rebuild_state([records[0], uncommitted, records[2]], PROJECTOR_VERSION)
    assert excinfo.value.reason_code == "v21-04:record_not_committed"


# ---------------------------------------------------------------------------
# T-Replay（05 §12：允许随机 ID 不同，安全内容 digest 必须一致）
# ---------------------------------------------------------------------------


def make_task_fact() -> TaskFact:
    return TaskFact(
        task_id="task_1",
        scope_digest=SCOPE,
        scope_key_id="key_1",
        principal_id="principal_a",
        task_summary="整理本周会议纪要",
        task_digest="sha256:task_content_digest",
        revision=3,
        status="active",
        action_constraints=[
            ActionConstraint(op="in", action_types=["file.read", "notes.write"])
        ],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        evidence_refs=[],
    )


def make_plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-04-plan:fixture",
        impact="moderate",
        required_domains=["task", "source", "capability", "dataflow"],
        optional_domains=["behavior", "memory", "runtime_outcome"],
        required_capabilities=[],
        semantic_resolvable_dimensions=["task_alignment"],
        reason_codes=["v21-04:fixture"],
    )


def make_clock() -> EvaluationClock:
    return EvaluationClock(
        evaluated_at="2026-08-14T08:00:00Z",
        clock_version="clock_v1",
    )


def snapshot_for(records: list[CommittedRecord], *, snapshot_id: str) -> SecuritySnapshot:
    state = rebuild_state(records, PROJECTOR_VERSION)
    return build_snapshot(
        state,
        snapshot_id=snapshot_id,
        scope=make_scope(),
        evaluation_clock=make_clock(),
        policy_revision="rev_7",
        policy_digest="sha256:policy_content",
        plan=make_plan(),
        task_fact_head=make_task_fact(),
    )


def test_t_replay_random_ids_do_not_change_state_or_snapshot_digest() -> None:
    run_a = three_records(suffix="_run_a", random_prefix="projection_alpha")
    run_b = three_records(suffix="_run_b", random_prefix="projection_beta")

    state_a = rebuild_state(run_a, PROJECTOR_VERSION)
    state_b = rebuild_state(run_b, PROJECTOR_VERSION)
    # 随机 source_record_id / projection_id 不同，安全内容 digest 相同。
    assert state_digest(state_a) == state_digest(state_b)

    snapshot_a = snapshot_for(run_a, snapshot_id="snapshot_random_1")
    snapshot_b = snapshot_for(run_b, snapshot_id="snapshot_random_2")
    assert snapshot_a.snapshot_id != snapshot_b.snapshot_id
    assert snapshot_a.snapshot_digest == snapshot_b.snapshot_digest
    assert snapshot_digest_projection(snapshot_a) == snapshot_digest_projection(
        snapshot_b
    )


def test_t_replay_security_content_change_breaks_digest() -> None:
    run_a = three_records(suffix="_run_a")
    snapshot_a = snapshot_for(run_a, snapshot_id="snapshot_1")

    # 权威内容变化（task head revision 前进）必须改变 snapshot digest。
    state_b = rebuild_state(run_a, PROJECTOR_VERSION)
    newer_task = make_task_fact().model_copy(update={"revision": 4})
    snapshot_b = build_snapshot(
        state_b,
        snapshot_id="snapshot_1",
        scope=make_scope(),
        evaluation_clock=make_clock(),
        policy_revision="rev_7",
        policy_digest="sha256:policy_content",
        plan=make_plan(),
        task_fact_head=newer_task,
    )
    assert snapshot_a.snapshot_digest != snapshot_b.snapshot_digest
