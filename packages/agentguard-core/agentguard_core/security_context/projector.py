"""Idempotent Projector（V21-04, 02 §3/§4）。

冻结语义来源：

- Commit/Projector 顺序（02 §3, L48-95）：先 commit 权威记录 +
  projection envelope，再 apply delta，CAS V→V+1。不变量：
  **没有 committed authoritative record，就不能让该事实成为后续历史状态**
  （F0-8）。``project_committed_record`` 在入口 fail-closed 拒绝未
  committed 输入；
- 幂等键五元组与 CAS 三分支（02 §4, L99-131）：
  1. 幂等重放：projection identity 已见且 digest 相同 → no-op；
  2. 版本领先/缺失 → reconcile/rebuild（``needs_rebuild`` 结果）；
  3. digest 冲突 → state dirty + security alert，**不静默覆盖**；
- T-Replay 确定性（05 §12, L460-470）：同 authoritative records +
  same projector_version → 相同 state digest / snapshot digest，
  允许随机 ID 不同。

错误类型 ``ProjectionError`` 的 ``reason_code`` 前缀 ``v21-04:``。
core 保持 stateless：全部为纯函数，无全局可变单例、无 IO。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import canonical_sha256
from ..signals.models import CoverageDomain
from .delta import (
    SecurityStateDeltaV21,
    delta_digest_projection,
    projection_identity_key,
)
from .facts import StateWatermarks
from .state import AppliedProjection, OnlineSecurityState

__all__ = [
    "PROJECTOR_VERSION",
    "ApplyOutcome",
    "ApplyResult",
    "CommittedRecord",
    "ProjectionError",
    "apply_delta",
    "mark_state_dirty",
    "project_committed_record",
    "rebuild_state",
]

#: Projector 版本（02 §4.2）：resource normalization / taint propagation /
#: flow construction / behavior aggregation / capability projection /
#: coverage computation 任一逻辑变化必须提升版本。CT05 增加可比较的
#: Memory lifecycle merge 后提升至 projector.3；guard-api 对
#: ``v21-07.projector.2`` 与 ``v21-04.projector.1`` 提供懒 decoder。
PROJECTOR_VERSION = "ct-05.projector.3"

ApplyOutcome = Literal["applied", "noop", "conflict", "needs_rebuild"]

# 置于 PROJECTOR_VERSION 之后导入：handlers 装配链（projection 子包 →
# behavior_coverage → 本模块 PROJECTOR_VERSION）依赖该常量先定义，
# 该顺序打破导入环。
from .handlers import apply_typed_updates  # noqa: E402


class ProjectionError(ValueError):
    """fail-closed 投影异常：``reason_code`` 前缀 ``v21-04:``。

    异常消息不得包含 task 正文、server key 或任何敏感内容。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class CommittedRecord(BaseModel):
    """已 commit 的权威记录投影输入（02 §2.1 Authoritative Record Plane）。

    ``committed=False`` 的记录在 ``project_committed_record`` 入口被
    fail-closed 拒绝（F0-8）：commit failure 时不得让该事实成为后续
    历史状态。``delta`` 是权威记录携带的 typed update payload；
    ``task_upsert`` 本期恒为 ``None``（task 域不走 delta 投影，
    01 §27 的 source_record_type 枚举不含 task 类型）。
    """

    model_config = ConfigDict(extra="forbid")

    record_id: str
    committed: bool

    source_record_type: Literal[
        "policy_evaluation",
        "runtime_outcome",
        "approval",
        "memory_transition",
        "policy_revision",
        "runtime_observation",
    ]
    source_record_id: str
    source_revision: int
    scope_digest: str
    projector_version: str

    delta: Any
    task_upsert: Any = None


class ApplyResult(BaseModel):
    """``apply_delta`` 的纯函数结果（不修改输入状态）。"""

    model_config = ConfigDict(extra="forbid")

    outcome: ApplyOutcome
    state: OnlineSecurityState
    reason_codes: list[str]


def _delta_digest(delta: SecurityStateDeltaV21) -> str:
    return canonical_sha256(delta_digest_projection(delta))


def _content_digest(delta: SecurityStateDeltaV21) -> str:
    """位置无关的内容摘要：排除 base/new_state_version 位置字段。

    rebuild 按规范序重整版本链，位置字段随重放位置变化；内容摘要用于
    检测同 identity 异内容的 digest 冲突（02 §4.1 第 3 分支）。
    """
    projection = {
        key: value
        for key, value in delta_digest_projection(delta).items()
        if key not in {"base_state_version", "new_state_version"}
    }
    return canonical_sha256(projection)


def _validate_record_payload(
    record: CommittedRecord, *, scope_digest: str
) -> SecurityStateDeltaV21:
    """入口与结构校验（不含版本链），返回 delta payload。"""
    if not record.committed:
        raise ProjectionError(
            "v21-04:record_not_committed",
            "cannot project an uncommitted authoritative record (F0-8)",
        )
    if record.task_upsert is not None:
        raise ProjectionError(
            "v21-04:task_delta_projection_forbidden",
            "task domain is never projected via delta; snapshot reads the "
            "authoritative TaskFact head directly (01 §27 / 02 §2)",
        )
    if record.scope_digest != scope_digest:
        raise ProjectionError(
            "v21-04:scope_digest_mismatch",
            "record scope_digest does not match the projection scope",
        )
    if record.projector_version != PROJECTOR_VERSION:
        raise ProjectionError(
            "v21-04:projector_version_mismatch",
            f"record projector_version {record.projector_version!r} does "
            f"not match {PROJECTOR_VERSION!r}",
        )

    payload = record.delta
    if not isinstance(payload, SecurityStateDeltaV21):
        raise ProjectionError(
            "v21-04:invalid_delta_payload",
            "record.delta must be a SecurityStateDeltaV21",
        )

    if payload.scope_digest != scope_digest:
        raise ProjectionError(
            "v21-04:delta_scope_mismatch",
            "delta scope_digest does not match the projection scope",
        )
    if payload.task_upsert is not None:
        raise ProjectionError(
            "v21-04:task_delta_projection_forbidden",
            "delta.task_upsert must be None: task domain is read from the "
            "authoritative TaskFact head at snapshot build time",
        )
    if payload.projector_version != PROJECTOR_VERSION:
        raise ProjectionError(
            "v21-04:delta_projector_version_mismatch",
            "delta.projector_version does not match PROJECTOR_VERSION",
        )
    if payload.source.source_record_type != record.source_record_type:
        raise ProjectionError(
            "v21-04:identity_type_mismatch",
            "delta.source.source_record_type does not match the record",
        )
    if payload.source.source_record_id != record.source_record_id:
        raise ProjectionError(
            "v21-04:identity_id_mismatch",
            "delta.source.source_record_id does not match the record",
        )
    if payload.source.source_revision != record.source_revision:
        raise ProjectionError(
            "v21-04:identity_revision_mismatch",
            "delta.source.source_revision does not match the record",
        )
    return payload


def project_committed_record(
    record: CommittedRecord,
    *,
    base_state_version: int,
    scope_digest: str,
) -> SecurityStateDeltaV21:
    """把已 commit 的权威记录投影为 ``SecurityStateDeltaV21``。

    入口 fail-closed 校验（任一失败抛 ``ProjectionError``）：

    1. ``record.committed`` 必须为真（F0-8 / commit failure 场景）；
    2. ``record.task_upsert`` 必须为 ``None``：task 域不走 delta 投影
       （01 §27 的 ``source_record_type`` 枚举不含 task 记录类型）；
    3. ``record.scope_digest`` 与调用方 scope 一致；
    4. ``record.projector_version`` 与本模块 ``PROJECTOR_VERSION`` 一致
       （版本不一致必须走 rebuild，不得混版本投影）；
    5. delta 结构校验、scope 一致、身份三元组一致、``projector_version``
       一致；
    6. 纵深防御：重算 ``delta_digest`` 白名单投影并恒定比对，
       payload 被篡改即拒绝；
    7. 版本链校验：``base/new_state_version`` 与 CAS 前提一致
       （增量路径；rebuild 路径见 ``rebuild_state`` 的位置重整）。

    确定性要求：同 ``ProjectionRecordIdentity + projector_version`` 在
    同一 base 下重放必须得到相同 ``delta_digest``（01 §27）；
    ``projection_id`` 由幂等键确定性派生（禁 uuid），不进 digest。
    """
    payload = _validate_record_payload(record, scope_digest=scope_digest)

    expected_digest = _delta_digest(payload)
    if payload.delta_digest != expected_digest:
        raise ProjectionError(
            "v21-04:delta_digest_mismatch",
            "recomputed delta digest does not match delta.delta_digest",
        )
    if payload.base_state_version != base_state_version:
        raise ProjectionError(
            "v21-04:base_state_version_mismatch",
            f"delta.base_state_version {payload.base_state_version} does "
            f"not match projection base {base_state_version}",
        )
    if payload.new_state_version != base_state_version + 1:
        raise ProjectionError(
            "v21-04:new_state_version_invalid",
            "delta.new_state_version must equal base_state_version + 1",
        )
    return payload


def apply_delta(
    state: OnlineSecurityState, delta: SecurityStateDeltaV21
) -> ApplyResult:
    """应用 committed delta（纯函数，返回新状态；02 §4.1 CAS 三分支）。

    1. 幂等重放：``state.state_version != delta.base_state_version`` 且
       projection identity 已见且 digest 相同 → ``noop``（原状态返回）；
    2. digest 冲突：identity 已见但 digest 不同 → ``conflict`` +
       ``dirty_domains`` 标记（不静默覆盖，02 §4.1 第 3 分支）；
    3. CAS 通过：``base == current`` → 应用 typed update，
       ``state_version + 1``，登记 applied projection → ``applied``；
    4. 版本领先/缺失 → ``needs_rebuild``（原状态返回，不修改）。

    typed update 实现（V21-05/06/07 接线）：watermarks 推进、
    dirty_domains 合并、coverage_invalidations 并入 dirty、幂等登记，
    以及经 ``handlers.apply_typed_updates`` 按中央分发表 tuple 序
    （01 §27 字段声明序）确定性应用全部非空 typed 容器（容器为空
    自然跳过）。handler 失败抛各自分支的 fail-closed 异常
    （``v21-05:`` / ``v21-06:`` / ``v21-07:`` 前缀）并向上传播，
    由编排方置脏相关域，version 不推进。
    """
    projection_key = projection_identity_key(
        delta.scope_digest,
        delta.source.source_record_type,
        delta.source.source_record_id,
        delta.source.source_revision,
        delta.projector_version,
    )
    incoming_digest = _delta_digest(delta)
    existing = next(
        (
            applied
            for applied in state.applied_projections
            if applied.projection_key == projection_key
        ),
        None,
    )

    if state.state_version != delta.base_state_version:
        if existing is not None and existing.delta_digest == incoming_digest:
            return ApplyResult(
                outcome="noop",
                state=state,
                reason_codes=["v21-04:idempotent_replay_noop"],
            )
        if existing is not None:
            dirty = sorted(set(state.dirty_domains) | set(delta.dirty_domain_updates))
            return ApplyResult(
                outcome="conflict",
                state=state.model_copy(update={"dirty_domains": dirty}),
                reason_codes=[
                    "v21-04:projection_digest_conflict",
                    "v21-04:state_dirty_marker",
                ],
            )
        return ApplyResult(
            outcome="needs_rebuild",
            state=state,
            reason_codes=["v21-04:state_version_mismatch"],
        )

    if existing is not None:
        if existing.delta_digest == incoming_digest:
            return ApplyResult(
                outcome="noop",
                state=state,
                reason_codes=["v21-04:idempotent_replay_noop"],
            )
        dirty = sorted(set(state.dirty_domains) | set(delta.dirty_domain_updates))
        return ApplyResult(
            outcome="conflict",
            state=state.model_copy(update={"dirty_domains": dirty}),
            reason_codes=[
                "v21-04:projection_digest_conflict",
                "v21-04:state_dirty_marker",
            ],
        )

    watermarks = state.watermarks
    delta_watermark = delta.watermark_delta
    new_watermarks = StateWatermarks(
        committed_sequence=_max_sequence(
            watermarks.committed_sequence, delta_watermark.committed_sequence
        ),
        projected_sequence=_max_sequence(
            watermarks.projected_sequence, delta_watermark.projected_sequence
        ),
        runtime_receipt_sequence=_max_sequence(
            watermarks.runtime_receipt_sequence,
            delta_watermark.runtime_receipt_sequence,
        ),
        memory_sequence=_max_sequence(
            watermarks.memory_sequence, delta_watermark.memory_sequence
        ),
        gaps=_merge_gaps(watermarks.gaps, delta_watermark),
    )

    dirty = sorted(
        set(state.dirty_domains)
        | set(delta.dirty_domain_updates)
        | set(delta.coverage_invalidations)
    )

    # typed update 按中央分发表 tuple 序应用（容器为空自然跳过）；
    # handler 失败即抛分支 fail-closed 异常，version 不推进。
    typed_state = apply_typed_updates(state, delta)

    new_state = typed_state.model_copy(
        update={
            "watermarks": new_watermarks,
            "state_version": delta.new_state_version,
            "dirty_domains": dirty,
            "applied_projections": [
                *state.applied_projections,
                AppliedProjection(
                    projection_key=projection_key,
                    delta_digest=incoming_digest,
                ),
            ],
        }
    )
    return ApplyResult(
        outcome="applied",
        state=new_state,
        reason_codes=["v21-04:delta_applied"],
    )


def _max_sequence(existing: Any, incoming: Any) -> Any:
    """水位合并：同 domain + producer 时取较大者（02 §5 可比性约束）。"""
    if incoming is None:
        return existing
    if existing is None:
        return incoming
    if (
        existing.domain == incoming.domain
        and existing.producer_binding_id == incoming.producer_binding_id
    ):
        return existing if existing.value >= incoming.value else incoming
    # 不可比时按规范重放序取新值（重放序确定，结果仍确定）。
    return incoming


def _merge_gaps(current_gaps: list[Any], delta_watermark: Any) -> list[Any]:
    """合并缺口：移除 resolved_gaps，追加 new_gaps（按身份去重）。"""
    resolved = {
        (gap.domain, gap.producer_binding_id, gap.start_sequence, gap.end_sequence)
        for gap in delta_watermark.resolved_gaps
    }
    merged = [
        gap
        for gap in current_gaps
        if (gap.domain, gap.producer_binding_id, gap.start_sequence, gap.end_sequence)
        not in resolved
    ]
    seen = {
        (gap.domain, gap.producer_binding_id, gap.start_sequence, gap.end_sequence)
        for gap in merged
    }
    for gap in delta_watermark.new_gaps:
        identity = (
            gap.domain,
            gap.producer_binding_id,
            gap.start_sequence,
            gap.end_sequence,
        )
        if identity not in seen:
            seen.add(identity)
            merged.append(gap)
    merged.sort(
        key=lambda item: (
            item.domain,
            item.producer_binding_id,
            item.start_sequence,
            item.end_sequence,
        )
    )
    return merged


def mark_state_dirty(
    state: OnlineSecurityState,
    domains: list[CoverageDomain],
    *,
    reason_code: str,
) -> OnlineSecurityState:
    """projector failure 的 dirty 标记（02 §3：失败不得解释为 complete）。

    apply 失败时由编排方调用：把受影响域并入 ``dirty_domains``；
    coverage 计算会把 dirty 域 fail-closed 降 unknown。``reason_code``
    必须以 ``v21-04:`` 前缀给出（仅做形态校验，不落状态字段）。
    """
    if not reason_code.startswith("v21-04:"):
        raise ProjectionError(
            "v21-04:invalid_reason_code",
            f"reason_code must use the 'v21-04:' prefix, got {reason_code!r}",
        )
    return state.model_copy(
        update={"dirty_domains": sorted(set(state.dirty_domains) | set(domains))}
    )


def rebuild_state(
    committed_records: list[CommittedRecord],
    projector_version: str,
) -> OnlineSecurityState:
    """从 committed 权威记录重建 OnlineSecurityState（rebuild determinism）。

    - 只接受 ``projector_version == PROJECTOR_VERSION``（跨版本重建必须
      显式迁移，不静默混版本）；
    - 规范化排序：按幂等身份五元组
      ``(scope_digest, source_record_type, source_record_id,
      source_revision, projector_version)`` 的受限 JCS 序稳定排序，
      与输入顺序无关；
    - 版本链位置重整：存储 delta 的 ``base/new_state_version`` 反映原始
      commit 位置，rebuild 按规范序从 ``state_version = 0`` 重放时在
      当前重放位置重整版本链并重算 ``delta_digest``（typed update 内容
      不变；位置字段不是安全内容，且 ``state_version`` 不在 state
      digest 白名单内，不破坏 T-Replay 锚点）；
    - 同 identity 同 digest 的重复记录幂等跳过（no-op）；digest 冲突
      fail-closed 抛错；
    - crash/replay：中途崩溃后以本函数 bounded rebuild 恢复（02 §3.1）。
    """
    if projector_version != PROJECTOR_VERSION:
        raise ProjectionError(
            "v21-04:rebuild_projector_version_mismatch",
            f"rebuild requires projector_version {PROJECTOR_VERSION!r}, "
            f"got {projector_version!r}",
        )

    def identity_sort_key(record: CommittedRecord) -> tuple[str, str, int, str]:
        # CT05 makes source_revision an authoritative lifecycle sequence for
        # memory_transition. Sorting the explicit identity fields (rather than
        # their hash) guarantees revision 1 → 2 → 3 regardless of input order.
        # The final digest remains a deterministic tie-breaker for all records.
        digest = canonical_sha256(
            {
                "scope_digest": record.scope_digest,
                "source_record_type": record.source_record_type,
                "source_record_id": record.source_record_id,
                "source_revision": record.source_revision,
                "projector_version": record.projector_version,
            }
        )
        return (
            record.source_record_type,
            record.source_record_id,
            record.source_revision,
            digest,
        )

    ordered = sorted(committed_records, key=identity_sort_key)
    scope_digests = {record.scope_digest for record in ordered}
    if len(scope_digests) > 1:
        raise ProjectionError(
            "v21-04:rebuild_scope_mix",
            "rebuild_state accepts committed records of a single scope",
        )
    scope_digest = next(iter(scope_digests), "")

    # 幂等去重 + digest 冲突检测：同 identity 同内容跳过；同 identity
    # 异内容 → conflict（不静默覆盖）。内容比较用位置无关摘要。
    seen_content: dict[str, str] = {}
    unique_payloads: list[SecurityStateDeltaV21] = []
    for record in ordered:
        payload = _validate_record_payload(record, scope_digest=scope_digest)
        key = projection_identity_key(
            record.scope_digest,
            record.source_record_type,
            record.source_record_id,
            record.source_revision,
            record.projector_version,
        )
        content = _content_digest(payload)
        if key in seen_content:
            if seen_content[key] != content:
                raise ProjectionError(
                    "v21-04:rebuild_digest_conflict",
                    "same projection identity with different content: "
                    "state dirty, no silent overwrite",
                )
            continue
        seen_content[key] = content
        unique_payloads.append(payload)

    state = OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )
    for payload in unique_payloads:
        delta = payload.model_copy(
            update={
                "base_state_version": state.state_version,
                "new_state_version": state.state_version + 1,
            }
        )
        delta = delta.model_copy(update={"delta_digest": _delta_digest(delta)})
        result = apply_delta(state, delta)
        if result.outcome == "conflict":
            raise ProjectionError(
                "v21-04:rebuild_digest_conflict",
                "digest conflict during rebuild: state dirty, no silent " "overwrite",
            )
        if result.outcome == "needs_rebuild":
            raise ProjectionError(
                "v21-04:rebuild_version_chain_broken",
                "unexpected version chain break during rebuild",
            )
        state = result.state
    return state
