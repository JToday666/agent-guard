"""SecurityStateProjector：commit → project → 幂等写入 → CAS 编排（02 §3/§4）。

编排顺序（02 §3 Commit/Projector 顺序）：

1. 确认源记录已 committed：编排入口 fail-closed 校验（F0-8），默认以
   ``CommittedRecord.committed`` 为准，调用方可注入权威存储侧的验证钩子
   ``verify_source_committed``（查不到/未提交即拒绝）；
2. 幂等重放短路：同五元组身份同 ``delta_digest`` 已登记且状态已反映 →
   no-op，``state_version`` 不变；
3. core ``project_committed_record``（delta_digest 重算恒定比对 + 版本链
   校验）→ core ``apply_delta``（三分支纯函数）；
4. applied → ``record_projection`` 幂等登记（projection envelope）→
   ``cas_security_state`` V→V+1；
5. 任一失败 → ``mark_security_state_dirty`` + 结构化 security alert，
   经 ``SecurityStateProjectError`` 上抛（不吞错、不改任何判定）。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentguard_core import utc_now_iso
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PROJECTOR_VERSION,
    CommittedRecord,
    OnlineSecurityState,
    ProjectionError,
    SecurityStateDeltaV21,
    apply_delta,
    delta_digest_projection,
    project_committed_record,
)

from guard_api.storage.base import (
    ProjectionDigestConflictError,
    ProjectionIdentityRecord,
    SecurityStateRecord,
    StateVersionConflictError,
)

from .models import ProjectApplyResult, SecurityAlert, SecurityStateProjectError
from .store import SecurityStateStoreAccess, empty_online_state

#: 源记录 committed 状态验证钩子：返回 False 即 fail-closed 拒绝（F0-8）。
CommittedVerifier = Callable[[CommittedRecord], bool]


def _default_committed_check(record: CommittedRecord) -> bool:
    return record.committed


def _failure_domains(delta: Any) -> list[str]:
    """fail-closed 受影响域：delta 可解析时取其声明域，否则全域降级。"""

    if isinstance(delta, SecurityStateDeltaV21):
        domains = sorted(
            set(delta.dirty_domain_updates) | set(delta.coverage_invalidations)
        )
        if domains:
            return [str(domain) for domain in domains]
    return [str(domain) for domain in COVERAGE_DOMAINS]


class SecurityStateProjector:
    """已 commit 权威记录 → OnlineSecurityState 的投影编排器。"""

    def __init__(self, store: SecurityStateStoreAccess) -> None:
        self._store = store

    def project_and_apply(
        self,
        committed_record: CommittedRecord,
        *,
        scope_digest: str,
        verify_source_committed: CommittedVerifier | None = None,
    ) -> ProjectApplyResult:
        """编排单条已 commit 权威记录的投影与应用。

        成功返回 ``ProjectApplyResult``（applied / replayed_noop /
        needs_rebuild）；失败抛 ``SecurityStateProjectError``（携带结构化
        alert）且 state 已置 dirty —— 调用方不得把失败解释为 complete。
        """

        with self._store.scope_lock(scope_digest):
            verify = (
                verify_source_committed
                if verify_source_committed is not None
                else _default_committed_check
            )
            if not verify(committed_record):
                # commit failure（F0-8）：未提交记录不得成为后续历史状态。
                # 该记录从未投影，不置 dirty，仅拒绝并返回 alert。
                alert = SecurityAlert(
                    reason_code="v21-04:record_not_committed",
                    message="cannot project an uncommitted authoritative "
                    "record (F0-8)",
                    scope_digest=scope_digest,
                )
                raise SecurityStateProjectError(alert)

            # 幂等重放短路：同身份同 digest 已登记且状态已反映 → no-op。
            existing = self._store.get_projection(
                scope_digest,
                committed_record.source_record_type,
                committed_record.source_record_id,
                committed_record.source_revision,
                committed_record.projector_version,
            )
            current_record = self._store.get_security_state(scope_digest)
            current_version = (
                current_record.state_version if current_record is not None else 0
            )
            incoming_digest = _incoming_delta_digest(committed_record.delta)
            if existing is not None:
                if existing.delta_digest != incoming_digest:
                    domains = _failure_domains(committed_record.delta)
                    alert = SecurityAlert(
                        reason_code="v21-04:projection_digest_conflict",
                        message="same projection identity with different "
                        "delta digest: state dirty, no silent overwrite",
                        scope_digest=scope_digest,
                        domains=tuple(domains),
                    )
                    self._store.mark_security_state_dirty(scope_digest, domains)
                    raise SecurityStateProjectError(alert)
                if current_record is not None and (
                    existing.applied_state_version <= current_version
                ):
                    return ProjectApplyResult(
                        outcome="replayed_noop",
                        state_version=current_version,
                        reason_codes=("v21-04:idempotent_replay_noop",),
                    )
                # 登记存在但状态未反映（crash 窗口 / rebuild 后版本重整）：
                # 继续走 core 幂等判定，由其三分支给出确定性结果。

            current_state = (
                OnlineSecurityState.model_validate(current_record.canonical_payload)
                if current_record is not None
                else empty_online_state()
            )
            if current_record is not None and current_record.dirty_domains:
                # F1：存储列级 dirty 域必须并入在线状态 dirty_domains
                # （集合并集）。否则后续成功投影的 CAS 回写会用 payload
                # 口径覆盖列，把 mark_security_state_dirty 登记的失败
                # 事实静默清除（fail-closed 恢复信号丢失）。dirty 状态
                # 下投影本身可继续，回写保留合并后的 dirty 域。
                current_state = current_state.model_copy(
                    update={
                        "dirty_domains": sorted(
                            set(current_state.dirty_domains)
                            | set(current_record.dirty_domains)
                        )
                    }
                )

            try:
                delta = project_committed_record(
                    committed_record,
                    base_state_version=current_state.state_version,
                    scope_digest=scope_digest,
                )
                result = apply_delta(current_state, delta)
            except ProjectionError as exc:
                domains = _failure_domains(committed_record.delta)
                alert = SecurityAlert(
                    reason_code=exc.reason_code,
                    message=str(exc),
                    scope_digest=scope_digest,
                    domains=tuple(domains),
                )
                self._store.mark_security_state_dirty(scope_digest, domains)
                raise SecurityStateProjectError(alert) from exc

            if result.outcome == "noop":
                return ProjectApplyResult(
                    outcome="replayed_noop",
                    state_version=result.state.state_version,
                    reason_codes=tuple(result.reason_codes),
                )
            if result.outcome == "conflict":
                domains = _failure_domains(delta)
                alert = SecurityAlert(
                    reason_code="v21-04:projection_digest_conflict",
                    message="digest conflict during apply: state dirty, no "
                    "silent overwrite",
                    scope_digest=scope_digest,
                    domains=tuple(domains),
                )
                self._store.mark_security_state_dirty(scope_digest, domains)
                raise SecurityStateProjectError(alert)
            if result.outcome == "needs_rebuild":
                # 版本领先/缺失 → reconcile/rebuild（ensure_ready 钩子承接）。
                return ProjectApplyResult(
                    outcome="needs_rebuild",
                    state_version=current_state.state_version,
                    reason_codes=tuple(result.reason_codes),
                )

            # applied：先幂等登记 projection envelope，再 CAS V→V+1。
            identity_record = ProjectionIdentityRecord(
                scope_digest=scope_digest,
                source_record_type=committed_record.source_record_type,
                source_record_id=committed_record.source_record_id,
                source_revision=committed_record.source_revision,
                projector_version=committed_record.projector_version,
                delta_digest=delta.delta_digest,
                delta_payload=delta.model_dump(mode="json"),
                applied_state_version=result.state.state_version,
                created_at=utc_now_iso(),
            )
            try:
                self._store.record_projection(identity_record)
                state_record = SecurityStateRecord(
                    scope_digest=scope_digest,
                    state_version=result.state.state_version,
                    canonical_payload=result.state.model_dump(mode="json"),
                    dirty=bool(result.state.dirty_domains),
                    dirty_domains=list(result.state.dirty_domains),
                    projector_version=PROJECTOR_VERSION,
                    updated_at=utc_now_iso(),
                )
                self._store.cas_security_state(
                    scope_digest, current_state.state_version, state_record
                )
            except (
                ProjectionDigestConflictError,
                StateVersionConflictError,
            ) as exc:
                domains = _failure_domains(delta)
                alert = SecurityAlert(
                    reason_code=(
                        "v21-04:projection_digest_conflict"
                        if isinstance(exc, ProjectionDigestConflictError)
                        else "v21-04:state_version_conflict"
                    ),
                    message=str(exc),
                    scope_digest=scope_digest,
                    domains=tuple(domains),
                )
                self._store.mark_security_state_dirty(scope_digest, domains)
                raise SecurityStateProjectError(alert) from exc

            return ProjectApplyResult(
                outcome="applied",
                state_version=result.state.state_version,
                reason_codes=tuple(result.reason_codes),
            )


def _incoming_delta_digest(delta: Any) -> str:
    """入参 delta 的受限 JCS 摘要（非 SecurityStateDeltaV21 时返回空串）。"""

    if not isinstance(delta, SecurityStateDeltaV21):
        return ""
    return canonical_sha256(delta_digest_projection(delta))
