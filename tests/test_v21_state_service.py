"""V21-04 SecurityStateService 编排测试（memory 后端）。

覆盖 7 类验收场景中 guard-api 编排侧语义：

- commit failure：未提交记录拒绝投影（F0-8），含存储侧验证钩子；
- projector failure：apply 失败 → dirty + 结构化 alert，不吞错；
- duplicate projection：服务层重放 no-op，state_version 不变；
- digest conflict：同身份异 digest → dirty + alert，不静默覆盖；
- dirty 后 snapshot 前自动 bounded rebuild（crash/replay 确定性）；
- task 域直读权威 TaskFact head 的 stale 检测（02 §6.1）。
"""

from __future__ import annotations

import sys

import pytest

from agentguard_core.authority.models import EvaluationClock, TaskFact
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    OnlineSecurityState,
    state_digest,
)
from guard_api.security_state import SecurityStateProjectError, SecurityStateService
from guard_api.security_state.rebuild import rebuild_locked
from guard_api.storage.base import StateVersionConflictError
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_v21_security_state_models import SCOPE, make_delta, make_scope
from tests.test_v21_state_projector import make_record


def _service() -> SecurityStateService:
    return SecurityStateService(MemoryControlPlaneStore())


def _clock() -> EvaluationClock:
    return EvaluationClock(
        evaluated_at="2026-08-14T00:00:00Z", clock_version="test-clock-1"
    )


def _task_fact(revision: int = 3) -> TaskFact:
    return TaskFact(
        task_id="task_state_service",
        scope_digest=SCOPE,
        scope_key_id="scope_key_test",
        principal_id="principal_a",
        task_summary="fixture task",
        task_digest="sha256:" + "ab" * 32,
        revision=revision,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )


def _plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-04-plan:service_fixture",
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


def _snapshot_kwargs(**overrides):
    kwargs = {
        "scope": make_scope(),
        "task_fact_head": _task_fact(),
        "evaluation_clock": _clock(),
        "policy_revision": "rev-1",
        "policy_digest": "sha256:policy_fixture",
        "plan": _plan(),
    }
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# commit failure（F0-8）
# ---------------------------------------------------------------------------


def test_commit_failure_rejects_uncommitted_record() -> None:
    service = _service()
    record = make_record(make_delta(), committed=False)
    with pytest.raises(SecurityStateProjectError) as excinfo:
        service.project_committed(record, scope_digest=SCOPE)
    assert excinfo.value.reason_code == "v21-04:record_not_committed"
    assert excinfo.value.alert.scope_digest == SCOPE
    # 未提交记录从未投影：不置 dirty、不产生状态。
    assert service.store_access.get_security_state(SCOPE) is None


def test_commit_failure_via_store_lookup_hook() -> None:
    service = _service()
    record = make_record(make_delta())
    # 存储侧验证钩子查不到源记录（返回 False）→ fail-closed 拒绝。
    with pytest.raises(SecurityStateProjectError) as excinfo:
        service.project_committed(
            record,
            scope_digest=SCOPE,
            verify_source_committed=lambda _record: False,
        )
    assert excinfo.value.reason_code == "v21-04:record_not_committed"

    # 钩子确认已提交 → 正常投影。
    result = service.project_committed(
        record,
        scope_digest=SCOPE,
        verify_source_committed=lambda _record: True,
    )
    assert result.outcome == "applied"
    assert result.state_version == 1


# ---------------------------------------------------------------------------
# projector failure（apply 失败 → dirty + alert，不吞错）
# ---------------------------------------------------------------------------


def test_projector_failure_marks_dirty_and_returns_alert() -> None:
    service = _service()
    tampered = make_delta().model_copy(update={"delta_digest": "sha256:bad"})
    record = make_record(tampered)
    with pytest.raises(SecurityStateProjectError) as excinfo:
        service.project_committed(record, scope_digest=SCOPE)
    alert = excinfo.value.alert
    assert alert.reason_code == "v21-04:delta_digest_mismatch"
    assert alert.domains  # fail-closed 受影响域非空

    # state 置 dirty（失败不得解释为 complete），state_version 不推进。
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True
    assert stored.state_version == 0
    assert set(stored.dirty_domains) == set(alert.domains)


# ---------------------------------------------------------------------------
# duplicate projection（幂等重放 no-op，state_version 不变）
# ---------------------------------------------------------------------------


def test_duplicate_projection_is_noop_and_version_unchanged() -> None:
    service = _service()
    record = make_record(make_delta())
    first = service.project_committed(record, scope_digest=SCOPE)
    assert first.outcome == "applied"
    assert first.state_version == 1

    replayed = service.project_committed(record, scope_digest=SCOPE)
    assert replayed.outcome == "replayed_noop"
    assert replayed.state_version == 1
    assert "v21-04:idempotent_replay_noop" in replayed.reason_codes

    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 1
    # 幂等登记只有一条。
    assert len(service.store_access.list_rebuild_inputs(SCOPE, limit=10)) == 1


# ---------------------------------------------------------------------------
# digest conflict（dirty + alert，不静默覆盖）
# ---------------------------------------------------------------------------


def test_digest_conflict_marks_dirty_without_silent_overwrite() -> None:
    service = _service()
    original = make_record(make_delta(source_record_id="rec_conflict"))
    assert (
        service.project_committed(original, scope_digest=SCOPE).state_version == 1
    )

    # 同幂等身份、异内容（不同 projected_sequence）→ 异 delta_digest。
    forged = make_record(
        make_delta(source_record_id="rec_conflict", projected_value=99)
    )
    with pytest.raises(SecurityStateProjectError) as excinfo:
        service.project_committed(forged, scope_digest=SCOPE)
    assert excinfo.value.reason_code == "v21-04:projection_digest_conflict"

    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True
    assert stored.state_version == 1  # 旧版本永不静默覆盖


# ---------------------------------------------------------------------------
# 多 delta 推进 + dirty 后 snapshot 前自动 bounded rebuild
# ---------------------------------------------------------------------------


def test_apply_advances_version_chain_and_watermarks() -> None:
    service = _service()
    first = service.project_committed(
        make_record(make_delta(source_record_id="rec_a")), scope_digest=SCOPE
    )
    second = service.project_committed(
        make_record(
            make_delta(source_record_id="rec_b", base_state_version=1, projected_value=2)
        ),
        scope_digest=SCOPE,
    )
    assert first.state_version == 1
    assert second.state_version == 2

    snapshot = service.read_snapshot(SCOPE, **_snapshot_kwargs())
    assert snapshot.state_version == 2
    assert snapshot.watermarks.projected_sequence is not None
    assert snapshot.watermarks.projected_sequence.value == 2


def test_dirty_state_triggers_bounded_rebuild_before_snapshot() -> None:
    service = _service()
    service.project_committed(
        make_record(make_delta(source_record_id="rec_rebuild")), scope_digest=SCOPE
    )
    before = _stored_state(service)

    # 模拟 projector failure / crash 后的 dirty 标记。
    service.store_access.mark_security_state_dirty(SCOPE, ["behavior"])
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True

    # snapshot 前自动 bounded rebuild：版本链重整，水位恢复。
    snapshot = service.read_snapshot(SCOPE, **_snapshot_kwargs())
    assert snapshot.state_version == 1
    rebuilt = _stored_state(service)
    # F5：rebuild 成功路径并入既有列级 dirty 域，失败事实不被静默消解。
    assert "behavior" in rebuilt.dirty_domains
    assert state_digest(rebuilt) == state_digest(
        before.model_copy(update={"dirty_domains": ["behavior"]})
    )  # T-Replay 确定性（除保留的 dirty 域外内容不变）
    stored_after = service.store_access.get_security_state(SCOPE)
    assert stored_after is not None
    assert stored_after.dirty is True


def test_ensure_ready_rebuilds_dirty_state() -> None:
    service = _service()
    service.project_committed(
        make_record(make_delta(source_record_id="rec_ready")), scope_digest=SCOPE
    )
    service.store_access.mark_security_state_dirty(SCOPE, ["memory"])
    state = service.ensure_ready(SCOPE)
    assert state.state_version == 1
    # F5：rebuild 不丢弃既有列级 dirty 域（fail-closed 保持）。
    assert "memory" in state.dirty_domains
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True


def test_ensure_ready_initializes_missing_state() -> None:
    service = _service()
    state = service.ensure_ready(SCOPE)
    assert state.state_version == 0
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is False
    assert stored.state_version == 0


# ---------------------------------------------------------------------------
# F1：dirty 双口径同步（失败事实不被后续成功投影静默清除）
# ---------------------------------------------------------------------------


def test_dirty_survives_subsequent_successful_projection() -> None:
    service = _service()
    service.project_committed(
        make_record(make_delta(source_record_id="rec_dirty_a")),
        scope_digest=SCOPE,
    )
    # 投影失败 → dirty 标记（列 + payload 双口径，F1）。
    service.store_access.mark_security_state_dirty(SCOPE, ["behavior"])

    # 下一条记录成功投影：dirty 域必须保留，不得被 CAS 回写清除。
    result = service.project_committed(
        make_record(
            make_delta(
                source_record_id="rec_dirty_b",
                base_state_version=1,
                projected_value=2,
            )
        ),
        scope_digest=SCOPE,
    )
    assert result.outcome == "applied"
    assert result.state_version == 2

    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True
    assert "behavior" in stored.dirty_domains
    # payload 口径同样保留（双口径一致）。
    payload_state = OnlineSecurityState.model_validate(stored.canonical_payload)
    assert "behavior" in payload_state.dirty_domains

    # snapshot 前因 dirty 触发 bounded rebuild；rebuild 后 dirty 域仍在
    # （F5 并入语义），coverage 对该域 fail-closed 降 unknown。
    snapshot = service.read_snapshot(SCOPE, **_snapshot_kwargs())
    assert "behavior" in snapshot.dirty_domains
    assert "behavior" in _plan().required_domains
    assert snapshot.coverage.behavior.status == "unknown"
    assert "v21-04:dirty_projection" in snapshot.coverage.behavior.reason_codes


def test_mark_dirty_syncs_payload_for_subsequent_projection() -> None:
    # 仅存储列 dirty 而 payload 未同步的旧口径下，projector 从 payload
    # 重建状态会丢失 dirty；mark_dirty 后 payload 必须可 model_validate
    # 读回且携带 dirty 域（双后端在 store 契约测试覆盖，此处验证服务层
    # 投影消费链路）。
    service = _service()
    service.store_access.mark_security_state_dirty(SCOPE, ["dataflow", "memory"])
    result = service.project_committed(
        make_record(make_delta(source_record_id="rec_after_dirty")),
        scope_digest=SCOPE,
    )
    assert result.outcome == "applied"
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert set(stored.dirty_domains) >= {"dataflow", "memory"}


# ---------------------------------------------------------------------------
# F2/F5：rebuild 截断 fail-closed + 版本不回退 + 列级 dirty 并入
# ---------------------------------------------------------------------------


def _project_three_records(service: SecurityStateService) -> None:
    service.project_committed(
        make_record(make_delta(source_record_id="rec_trunc_1")),
        scope_digest=SCOPE,
    )
    service.project_committed(
        make_record(
            make_delta(
                source_record_id="rec_trunc_2",
                base_state_version=1,
                projected_value=2,
            )
        ),
        scope_digest=SCOPE,
    )
    service.project_committed(
        make_record(
            make_delta(
                source_record_id="rec_trunc_3",
                base_state_version=2,
                projected_value=3,
            )
        ),
        scope_digest=SCOPE,
    )


def test_rebuild_truncation_fail_closed_and_version_not_regressed() -> None:
    service = _service()
    _project_three_records(service)

    # 登记数（3）> limit（2）：输入被截断 → 不得静默成功。
    state, alert = rebuild_locked(service.store_access, SCOPE, limit=2)
    assert alert is not None
    assert alert.reason_code == "v21-04:rebuild_input_truncated"
    # dirty 覆盖全部 7 域。
    assert set(state.dirty_domains) == set(COVERAGE_DOMAINS)
    # state_version 不回退（既有 3，截断重建链短于既有链时取 max）。
    assert state.state_version >= 3
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version >= 3
    assert stored.dirty is True
    assert set(stored.dirty_domains) == set(COVERAGE_DOMAINS)


def test_rebuild_truncation_uses_clamped_effective_limit(monkeypatch) -> None:
    # 复现评审 F2：调用方 limit 大于存储钳制值时，截断判定必须基于
    # 钳制后的有效值，否则实际读取被钳制而误判未截断（静默丢投影 +
    # state_version 回退）。
    # 包 __init__ 以同名函数覆盖模块属性，字符串路径会解析到函数，
    # 故直接取 sys.modules 中的模块对象打补丁。
    rebuild_module = sys.modules["guard_api.security_state.rebuild"]
    monkeypatch.setattr(rebuild_module, "MAX_REBUILD_INPUT_LIMIT", 2)
    monkeypatch.setattr(
        "guard_api.storage.memory._bounded_limit",
        lambda limit: max(1, min(limit, 2)),
    )
    service = _service()
    _project_three_records(service)

    state, alert = rebuild_locked(service.store_access, SCOPE, limit=100)
    # 修复前：len(inputs)=2 >= 100 为 False → 静默成功；修复后必须
    # 按有效钳制值 2 判定截断。
    assert alert is not None
    assert alert.reason_code == "v21-04:rebuild_input_truncated"
    assert set(state.dirty_domains) == set(COVERAGE_DOMAINS)
    assert state.state_version >= 3


def test_rebuild_success_merges_existing_column_dirty() -> None:
    # F5：rebuild 非截断成功分支不得丢弃既有列级 dirty 域。
    service = _service()
    service.project_committed(
        make_record(make_delta(source_record_id="rec_merge_dirty")),
        scope_digest=SCOPE,
    )
    service.store_access.mark_security_state_dirty(SCOPE, ["behavior"])

    state, alert = rebuild_locked(service.store_access, SCOPE)
    assert alert is None
    assert state.state_version == 1
    assert "behavior" in state.dirty_domains
    stored = service.store_access.get_security_state(SCOPE)
    assert stored is not None
    assert stored.dirty is True
    payload_state = OnlineSecurityState.model_validate(stored.canonical_payload)
    assert "behavior" in payload_state.dirty_domains


# ---------------------------------------------------------------------------
# F9：ensure_ready 首次初始化的 CAS 良性竞争
# ---------------------------------------------------------------------------


def test_ensure_ready_initialization_conflict_rereads_existing(monkeypatch) -> None:
    service = _service()
    access = service.store_access
    real_cas = access.cas_security_state

    def racing_cas(scope_digest, expected_state_version, record):
        # 模拟另一编排抢先完成首次初始化写入，本方 CAS 被判冲突。
        real_cas(scope_digest, expected_state_version, record)
        raise StateVersionConflictError(
            expected_state_version=expected_state_version,
            current_state_version=record.state_version,
        )

    monkeypatch.setattr(access, "cas_security_state", racing_cas)
    # 良性竞争：不上抛，重读既有记录返回。
    state = service.ensure_ready(SCOPE)
    assert state.state_version == 0
    stored = access.get_security_state(SCOPE)
    assert stored is not None


# ---------------------------------------------------------------------------
# task 域直读权威 TaskFact head（stale 检测，02 §6.1）
# ---------------------------------------------------------------------------


def test_snapshot_reads_authoritative_task_head_directly() -> None:
    service = _service()
    head = _task_fact(revision=3)
    snapshot = service.read_snapshot(SCOPE, **_snapshot_kwargs(task_fact_head=head))
    assert snapshot.task is not None
    assert snapshot.task.revision == 3
    # head 与权威 revision 一致 → 非 stale。
    assert snapshot.coverage.task.status != "stale"


def test_snapshot_task_coverage_detects_stale_head() -> None:
    service = _service()
    stale_head = _task_fact(revision=3)
    snapshot = service.read_snapshot(
        SCOPE,
        **_snapshot_kwargs(
            task_fact_head=stale_head, authoritative_head_revision=5
        ),
    )
    assert snapshot.coverage.task.status == "stale"
    assert "v21-04:task_revision_behind_head" in snapshot.coverage.task.reason_codes


def test_snapshot_without_task_head_is_unknown() -> None:
    service = _service()
    snapshot = service.read_snapshot(
        SCOPE, **_snapshot_kwargs(task_fact_head=None)
    )
    assert snapshot.task is None
    assert snapshot.coverage.task.status == "unknown"
    assert "v21-04:no_authoritative_task" in snapshot.coverage.task.reason_codes


def _stored_state(service: SecurityStateService) -> OnlineSecurityState:
    record = service.store_access.get_security_state(SCOPE)
    assert record is not None
    return OnlineSecurityState.model_validate(record.canonical_payload)
