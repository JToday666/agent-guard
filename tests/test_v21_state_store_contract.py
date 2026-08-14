"""V21-04 存储契约测试：security_states / projection_records 双实现。

memory 与 postgres store 必须运行相同的 V21-04 存储契约（镜像
``test_store_contract.py`` 的参数化 fixture 模式）：

- CAS 成功 / 冲突（StateVersionConflictError，旧版本永不覆盖）；
- record_projection 三分支（新写入 / 同 digest no-op / 异 digest 冲突）；
- dirty 读写（缺态创建 version=0 脏记录；dirty 不改 state_version）；
- list_rebuild_inputs 有界与按 applied_state_version 升序；
- get_security_state / get_projection 缺省 None。
"""

from __future__ import annotations

import pytest

from agentguard_core.security_context import OnlineSecurityState, StateWatermarks
from guard_api.storage.base import (
    ProjectionDigestConflictError,
    ProjectionIdentityRecord,
    SecurityStateRecord,
    StateVersionConflictError,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

SCOPE = "hmac-sha256:state_contract_scope"
OTHER_SCOPE = "hmac-sha256:state_contract_other"
PROJECTOR_VERSION = "v21-04.projector.1"


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        return MemoryControlPlaneStore()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres_store = PostgresControlPlaneStore(database_url)
    postgres_store.initialize()
    return postgres_store


def _empty_state_payload() -> dict:
    state = OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )
    return state.model_dump(mode="json")


def _state_record(
    scope_digest: str,
    state_version: int,
    *,
    dirty: bool = False,
    dirty_domains: list[str] | None = None,
) -> SecurityStateRecord:
    return SecurityStateRecord(
        scope_digest=scope_digest,
        state_version=state_version,
        canonical_payload=_empty_state_payload(),
        dirty=dirty,
        dirty_domains=list(dirty_domains or []),
        projector_version=PROJECTOR_VERSION,
        updated_at=f"2026-08-14T00:00:{state_version:02d}+00:00",
    )


def _projection_record(
    scope_digest: str,
    *,
    source_record_id: str = "rec_1",
    source_revision: int = 1,
    delta_digest: str = "sha256:delta_a",
    applied_state_version: int = 1,
) -> ProjectionIdentityRecord:
    return ProjectionIdentityRecord(
        scope_digest=scope_digest,
        source_record_type="policy_evaluation",
        source_record_id=source_record_id,
        source_revision=source_revision,
        projector_version=PROJECTOR_VERSION,
        delta_digest=delta_digest,
        delta_payload={"opaque": source_record_id},
        applied_state_version=applied_state_version,
        created_at="2026-08-14T00:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# security_states：读取缺省 / CAS 成功 / CAS 冲突
# ---------------------------------------------------------------------------


def test_get_security_state_missing_returns_none(store) -> None:
    assert store.get_security_state(SCOPE) is None


def test_cas_creates_state_and_roundtrips_payload(store) -> None:
    assert store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 1)) is True
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 1
    assert stored.dirty is False
    # canonical_payload 读回口径：model_validate 重建 OnlineSecurityState。
    state = OnlineSecurityState.model_validate(stored.canonical_payload)
    assert state.state_version == 0  # payload 是空白状态快照
    assert stored.projector_version == PROJECTOR_VERSION


def test_cas_advances_version_chain(store) -> None:
    store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 1))
    assert store.cas_security_state(SCOPE, 1, _state_record(SCOPE, 2)) is True
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 2


def test_cas_version_conflict_raises_and_keeps_record(store) -> None:
    store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 1))
    with pytest.raises(StateVersionConflictError) as excinfo:
        store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 9))
    assert excinfo.value.expected_state_version == 0
    assert excinfo.value.current_state_version == 1
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 1  # 旧版本永不静默覆盖


def test_cas_without_existing_record_requires_expected_zero(store) -> None:
    with pytest.raises(StateVersionConflictError) as excinfo:
        store.cas_security_state(SCOPE, 3, _state_record(SCOPE, 4))
    assert excinfo.value.current_state_version == 0


# ---------------------------------------------------------------------------
# dirty 读写
# ---------------------------------------------------------------------------


def test_mark_dirty_creates_version_zero_record_when_missing(store) -> None:
    store.mark_security_state_dirty(SCOPE, ["behavior"])
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 0
    assert stored.dirty is True
    assert stored.dirty_domains == ["behavior"]


def test_mark_dirty_merges_domains_and_preserves_version(store) -> None:
    store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 2))
    store.mark_security_state_dirty(SCOPE, ["behavior"])
    store.mark_security_state_dirty(SCOPE, ["memory", "behavior"])
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    assert stored.state_version == 2  # dirty 不影响 CAS 锚点
    assert stored.dirty is True
    assert stored.dirty_domains == ["behavior", "memory"]


def test_mark_dirty_is_scoped(store) -> None:
    store.mark_security_state_dirty(SCOPE, ["behavior"])
    assert store.get_security_state(OTHER_SCOPE) is None


def test_mark_dirty_syncs_payload_dirty_domains(store) -> None:
    # F1 双口径同步：列级 dirty 域必须同时并入 canonical_payload 内的
    # dirty_domains，且 payload 仍可 model_validate 读回（否则 projector
    # 从 payload 重建状态后回写会静默清除失败事实）。
    store.cas_security_state(SCOPE, 0, _state_record(SCOPE, 2))
    store.mark_security_state_dirty(SCOPE, ["behavior"])
    store.mark_security_state_dirty(SCOPE, ["memory", "behavior"])
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    payload_state = OnlineSecurityState.model_validate(stored.canonical_payload)
    assert payload_state.dirty_domains == ["behavior", "memory"]
    assert payload_state.state_version == 0  # payload 其余内容不被改动


def test_mark_dirty_missing_state_payload_carries_dirty(store) -> None:
    # 缺态创建的 version=0 脏记录：payload 与列同时携带 dirty 域。
    store.mark_security_state_dirty(SCOPE, ["dataflow"])
    stored = store.get_security_state(SCOPE)
    assert stored is not None
    payload_state = OnlineSecurityState.model_validate(stored.canonical_payload)
    assert payload_state.dirty_domains == ["dataflow"]
    assert stored.dirty_domains == ["dataflow"]


# ---------------------------------------------------------------------------
# projection_records：幂等三分支 + 读取
# ---------------------------------------------------------------------------


def test_record_projection_new_write_returns_true(store) -> None:
    record = _projection_record(SCOPE)
    stored, created = store.record_projection(record)
    assert created is True
    assert stored.delta_digest == record.delta_digest


def test_record_projection_same_digest_is_noop(store) -> None:
    record = _projection_record(SCOPE)
    store.record_projection(record)
    replayed = _projection_record(SCOPE, applied_state_version=99)
    stored, created = store.record_projection(replayed)
    assert created is False
    # no-op 返回既有记录（含既有 applied_state_version），不覆盖。
    assert stored.applied_state_version == 1
    rows = store.list_rebuild_inputs(SCOPE, limit=10)
    assert len(rows) == 1


def test_record_projection_digest_conflict_raises(store) -> None:
    store.record_projection(_projection_record(SCOPE))
    conflicting = _projection_record(SCOPE, delta_digest="sha256:forged")
    with pytest.raises(ProjectionDigestConflictError) as excinfo:
        store.record_projection(conflicting)
    assert excinfo.value.existing_digest == "sha256:delta_a"
    assert excinfo.value.incoming_digest == "sha256:forged"
    # 既有记录不被静默覆盖。
    stored = store.get_projection(
        SCOPE, "policy_evaluation", "rec_1", 1, PROJECTOR_VERSION
    )
    assert stored is not None
    assert stored.delta_digest == "sha256:delta_a"


def test_get_projection_missing_returns_none(store) -> None:
    assert (
        store.get_projection(SCOPE, "policy_evaluation", "rec_x", 1, PROJECTOR_VERSION)
        is None
    )


def test_get_projection_roundtrip(store) -> None:
    store.record_projection(_projection_record(SCOPE, source_revision=7))
    stored = store.get_projection(
        SCOPE, "policy_evaluation", "rec_1", 7, PROJECTOR_VERSION
    )
    assert stored is not None
    assert stored.source_revision == 7
    assert stored.delta_payload == {"opaque": "rec_1"}


# ---------------------------------------------------------------------------
# list_rebuild_inputs：有界与排序
# ---------------------------------------------------------------------------


def test_list_rebuild_inputs_ordered_and_bounded(store) -> None:
    # 乱序写入 applied_state_version，读取必须升序返回。
    store.record_projection(
        _projection_record(SCOPE, source_record_id="rec_c", applied_state_version=3)
    )
    store.record_projection(
        _projection_record(SCOPE, source_record_id="rec_a", applied_state_version=1)
    )
    store.record_projection(
        _projection_record(SCOPE, source_record_id="rec_b", applied_state_version=2)
    )
    # 其他 scope 的记录不进入本 scope 的 rebuild 输入。
    store.record_projection(_projection_record(OTHER_SCOPE))

    rows = store.list_rebuild_inputs(SCOPE, limit=10)
    assert [row.applied_state_version for row in rows] == [1, 2, 3]
    assert [row.source_record_id for row in rows] == ["rec_a", "rec_b", "rec_c"]

    bounded = store.list_rebuild_inputs(SCOPE, limit=2)
    assert [row.applied_state_version for row in bounded] == [1, 2]


def test_list_rebuild_inputs_empty_scope(store) -> None:
    assert store.list_rebuild_inputs(SCOPE, limit=10) == []
