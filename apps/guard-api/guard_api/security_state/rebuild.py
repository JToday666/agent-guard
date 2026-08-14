"""bounded rebuild：crash/replay 恢复（02 §3.1）与有界截断 fail-closed。

- rebuild 输入为 ``list_rebuild_inputs`` 的有界读取（按
  ``applied_state_version`` 升序），core ``rebuild_state`` 按规范序
  （幂等五元组受限 JCS 序）重放并重整版本链 —— T-Replay 确定性：同
  authoritative records + same projector_version → 相同 state digest；
- 截断判定基于存储钳制后的**有效 limit**（F2：存储层把 limit 钳制到
  ``[1, MAX_REBUILD_INPUT_LIMIT]``，用调用方原始 limit 判定会在
  limit > 钳制值时静默丢投影）：返回条数达到有效 limit → 输入可能
  被截断：fail-closed 把全部 coverage 域并入 dirty + 结构化 alert，
  不得静默“成功”；
- state_version 单调不回退（F2）：rebuild 结果的 state_version 不得
  低于既有 state_version（必要时取 max）——截断时重建版本链可能短于
  既有链，CAS 锚点不得回退；内容不完整已由全域 dirty fail-closed 承担；
- rebuild 成功路径并入既有列级 dirty 域（F5）：不得静默丢弃既有失败
  事实标记，直到显式消解机制接线前保持 fail-closed；
- rebuild 失败（digest 冲突等）→ 全域 dirty + 结构化 alert，保留既有
  状态不静默覆盖；
- 回写走 ``cas_security_state``（预期版本 = 当前存储版本），冲突即
  dirty + 上抛。
"""

from __future__ import annotations

from typing import Any, Literal, cast

from agentguard_core import utc_now_iso
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PROJECTOR_VERSION,
    SOURCE_RECORD_TYPES,
    CommittedRecord,
    OnlineSecurityState,
    ProjectionError,
    SecurityStateDeltaV21,
    rebuild_state,
)

from guard_api.storage.base import (
    MAX_REBUILD_INPUT_LIMIT,
    ProjectionIdentityRecord,
    SecurityStateRecord,
    StateVersionConflictError,
)

from .models import SecurityAlert, SecurityStateProjectError
from .store import SecurityStateStoreAccess, empty_online_state

#: rebuild 有界读取默认上限（= 存储层钳制上限 MAX_REBUILD_INPUT_LIMIT）。
DEFAULT_REBUILD_LIMIT = 1000

_SourceRecordType = Literal[
    "policy_evaluation",
    "runtime_outcome",
    "approval",
    "memory_transition",
    "policy_revision",
    "runtime_observation",
]


def rebuild(
    store: SecurityStateStoreAccess,
    scope_digest: str,
    *,
    limit: int = DEFAULT_REBUILD_LIMIT,
) -> tuple[OnlineSecurityState, SecurityAlert | None]:
    """bounded rebuild（公开入口，持 per-scope 编排锁）。"""

    with store.scope_lock(scope_digest):
        return rebuild_locked(store, scope_digest, limit=limit)


def rebuild_locked(
    store: SecurityStateStoreAccess,
    scope_digest: str,
    *,
    limit: int = DEFAULT_REBUILD_LIMIT,
) -> tuple[OnlineSecurityState, SecurityAlert | None]:
    """rebuild 内核：调用方必须已持有该 scope 的编排锁。

    返回 ``(重建后的状态, alert)``；alert 非空表示 rebuild 失败或输入被
    截断，状态已 fail-closed 置 dirty。
    """

    # F2：截断判定必须基于存储钳制后的有效 limit，否则 limit > 钳制值
    # 时实际读取被钳制而判定误判为未截断（静默丢投影 + 版本回退）。
    effective_limit = max(1, min(limit, MAX_REBUILD_INPUT_LIMIT))
    inputs = store.list_rebuild_inputs(scope_digest, limit=effective_limit)
    truncated = len(inputs) >= effective_limit
    committed = [_committed_from_projection(row) for row in inputs]

    try:
        rebuilt = rebuild_state(committed, PROJECTOR_VERSION)
    except ProjectionError as exc:
        alert = SecurityAlert(
            reason_code=exc.reason_code,
            message=str(exc),
            scope_digest=scope_digest,
            domains=tuple(COVERAGE_DOMAINS),
        )
        store.mark_security_state_dirty(scope_digest, list(COVERAGE_DOMAINS))
        current = store.get_security_state(scope_digest)
        state = (
            OnlineSecurityState.model_validate(current.canonical_payload)
            if current is not None
            else empty_online_state()
        )
        return state, alert

    truncation_alert: SecurityAlert | None = None
    if truncated:
        # 有界截断：无法证明输入完整 → 全域 fail-closed 降 dirty
        # （coverage 把 dirty 域判 unknown，等效 partial 且更保守），
        # 并产出结构化 alert，不得静默“成功”。
        rebuilt = rebuilt.model_copy(
            update={
                "dirty_domains": sorted(
                    set(rebuilt.dirty_domains) | set(COVERAGE_DOMAINS)
                )
            }
        )
        truncation_alert = SecurityAlert(
            reason_code="v21-04:rebuild_input_truncated",
            message="rebuild inputs were truncated by the bounded read "
            "limit; state is fail-closed dirty",
            scope_digest=scope_digest,
            domains=tuple(COVERAGE_DOMAINS),
        )

    current = store.get_security_state(scope_digest)
    expected_version = current.state_version if current is not None else 0

    # F2：state_version 单调不回退。截断时重建的版本链可能短于既有链，
    # CAS 锚点取 max 保持不回退；内容不完整的风险已由全域 dirty
    # fail-closed 承担（不得解释为 complete）。
    if rebuilt.state_version < expected_version:
        rebuilt = rebuilt.model_copy(
            update={"state_version": expected_version}
        )

    # F5：成功路径不得丢弃既有列级 dirty 域：回写前并入
    # （rebuilt.dirty_domains ∩ 既有列级 dirty_domains 的并集）。
    if current is not None and current.dirty_domains:
        rebuilt = rebuilt.model_copy(
            update={
                "dirty_domains": sorted(
                    set(rebuilt.dirty_domains) | set(current.dirty_domains)
                )
            }
        )

    try:
        store.cas_security_state(
            scope_digest, expected_version, _state_record(scope_digest, rebuilt)
        )
    except StateVersionConflictError as exc:
        alert = SecurityAlert(
            reason_code="v21-04:state_version_conflict",
            message=str(exc),
            scope_digest=scope_digest,
            domains=tuple(COVERAGE_DOMAINS),
        )
        store.mark_security_state_dirty(scope_digest, list(COVERAGE_DOMAINS))
        raise SecurityStateProjectError(alert) from exc
    return rebuilt, truncation_alert


def _committed_from_projection(row: ProjectionIdentityRecord) -> CommittedRecord:
    """由投影登记行重组 rebuild 输入（delta_payload 是存储的权威快照）。"""

    if row.source_record_type not in SOURCE_RECORD_TYPES:
        raise ProjectionError(
            "v21-04:invalid_source_record_type",
            f"projection record type {row.source_record_type!r} is outside "
            "the frozen SOURCE_RECORD_TYPES enumeration",
        )
    delta = SecurityStateDeltaV21.model_validate(row.delta_payload)
    return CommittedRecord(
        record_id=(
            "projection:"
            f"{row.source_record_type}:{row.source_record_id}:"
            f"{row.source_revision}"
        ),
        committed=True,
        source_record_type=cast(_SourceRecordType, row.source_record_type),
        source_record_id=row.source_record_id,
        source_revision=row.source_revision,
        scope_digest=row.scope_digest,
        projector_version=row.projector_version,
        delta=delta,
        task_upsert=None,
    )


def _state_record(scope_digest: str, state: OnlineSecurityState) -> SecurityStateRecord:
    return SecurityStateRecord(
        scope_digest=scope_digest,
        state_version=state.state_version,
        canonical_payload=state.model_dump(mode="json"),
        dirty=bool(state.dirty_domains),
        dirty_domains=list(state.dirty_domains),
        projector_version=PROJECTOR_VERSION,
        updated_at=utc_now_iso(),
    )


def state_from_record(record: SecurityStateRecord | None) -> OnlineSecurityState:
    """存储记录 → OnlineSecurityState（缺省返回空白状态）。"""

    if record is None:
        return empty_online_state()
    payload: Any = record.canonical_payload
    return OnlineSecurityState.model_validate(payload)
