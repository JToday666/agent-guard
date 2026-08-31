"""SecuritySnapshot 构建入口：dirty/缺态先 bounded rebuild 再出快照。

冻结语义（01 §19 / 02 §2）：

- task 域不走 delta 投影：``build_snapshot`` 直读调用方注入的权威
  ``task_fact_head``，天然支持 stale 检测（coverage 对照 head revision）；
- dirty / 缺态状态不得直接出快照：先 ``rebuild_locked`` bounded rebuild
  （rebuild 失败时状态保持 dirty，coverage fail-closed 降 unknown）；
- ``snapshot_id`` 由内容确定性派生（禁 uuid）：T-Replay 同权威输入得到
  相同 snapshot digest（05 §12）。
"""

from __future__ import annotations

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import (
    EvaluationClock,
    SecurityStateScope,
    TaskFact,
)
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    OnlineSecurityState,
    PROJECTOR_VERSION,
    SecurityStateDeltaV21,
    SecuritySnapshot,
    build_snapshot,
    delta_digest_projection,
    projection_identity_key,
    rebuild_state,
    state_digest,
)
from agentguard_core.security_context.projection import (
    GrantPolicyContext,
    compile_task_to_grants,
)
from guard_api.storage.base import MAX_REBUILD_INPUT_LIMIT
from guard_api.storage.base import ProjectionIdentityRecord

from .models import SecurityStateNotReadyError
from .rebuild import _committed_from_projection, rebuild_locked, state_from_record
from .store import SecurityStateStoreAccess


def security_state_authority_digest(
    *,
    scope_digest: str,
    state_version: int,
    canonical_payload: dict[str, object],
    dirty: bool,
    dirty_domains: list[str],
    projector_version: str,
    projection_history: (
        list[ProjectionIdentityRecord] | tuple[ProjectionIdentityRecord, ...]
    ) = (),
) -> str:
    """Digest every security-state authority field consumed by a decision.

    ``updated_at`` is deliberately excluded: it is operational metadata and
    does not change the authority represented by the row.  The full canonical
    payload and both dirty representations are included so a same-version
    dirty/payload drift cannot be hidden behind the monotonic version scalar.
    The complete bounded projection history is included as canonical bytes as
    well.  This prevents a semantically equivalent alias/rewrite, an unapplied
    envelope, or a history replacement from retaining the Phase-A anchor.
    """

    return canonical_sha256(
        {
            "scope_digest": scope_digest,
            "state_version": state_version,
            "canonical_payload": canonical_payload,
            "dirty": dirty,
            "dirty_domains": dirty_domains,
            "projector_version": projector_version,
            "projection_history": [
                {
                    "scope_digest": row.scope_digest,
                    "source_record_type": row.source_record_type,
                    "source_record_id": row.source_record_id,
                    "source_revision": row.source_revision,
                    "projector_version": row.projector_version,
                    "delta_digest": row.delta_digest,
                    "delta_payload": row.delta_payload,
                    "applied_state_version": row.applied_state_version,
                }
                for row in sorted(
                    projection_history,
                    key=lambda item: (
                        item.scope_digest,
                        item.source_record_type,
                        item.source_record_id,
                        item.source_revision,
                        item.projector_version,
                        item.applied_state_version,
                    ),
                )
            ],
        }
    )


def _validate_scope_inputs(
    scope_digest: str,
    *,
    scope: SecurityStateScope,
    task_fact_head: TaskFact | None,
) -> None:
    """Reject any cross-scope snapshot input before touching state storage."""

    if scope.scope_digest != scope_digest:
        raise ValueError(
            f"cross-scope snapshot: scope_digest parameter {scope_digest!r} "
            f"!= scope.scope_digest {scope.scope_digest!r}"
        )
    if task_fact_head is not None and task_fact_head.scope_digest != scope_digest:
        raise ValueError(
            f"cross-scope snapshot: scope_digest parameter {scope_digest!r} "
            f"!= task_fact_head.scope_digest {task_fact_head.scope_digest!r}"
        )


def _build_snapshot_from_state(
    state: OnlineSecurityState,
    *,
    scope_digest: str,
    scope: SecurityStateScope,
    task_fact_head: TaskFact | None,
    evaluation_clock: EvaluationClock,
    policy_revision: str,
    policy_digest: str,
    plan: RequiredCheckPlan,
    authoritative_head_revision: int | None,
) -> tuple[SecuritySnapshot, list[str]]:
    """Build snapshot and revoked IDs from one already-selected state object."""

    revoked_grant_ids = list(state.revoked_grant_ids)

    # task 域不走 delta 投影：把权威 TaskFact head 注入快照输入态，
    # 使 coverage 能对照 head revision 完成 stale 检测（02 §6.1）。
    if task_fact_head is not None and state.task is not task_fact_head:
        state = state.model_copy(update={"task": task_fact_head})
    if task_fact_head is not None:
        state = _with_compiled_task_grants(
            state,
            task_fact_head=task_fact_head,
            policy_revision=policy_revision,
        )

    snapshot_id = "v21-04-snapshot:" + canonical_sha256(
        {
            "scope_digest": scope_digest,
            "state_version": state.state_version,
            "projector_version": PROJECTOR_VERSION,
            "policy_revision": policy_revision,
            "policy_digest": policy_digest,
        }
    )
    snapshot = build_snapshot(
        state,
        snapshot_id=snapshot_id,
        scope=scope,
        evaluation_clock=evaluation_clock,
        policy_revision=policy_revision,
        policy_digest=policy_digest,
        plan=plan,
        task_fact_head=task_fact_head,
        authoritative_head_revision=authoritative_head_revision,
    )
    return snapshot, revoked_grant_ids


def _require_projection_reflection(
    store: SecurityStateStoreAccess,
    *,
    scope_digest: str,
    state: OnlineSecurityState,
) -> tuple[ProjectionIdentityRecord, ...]:
    """Prove every bounded projection envelope is reflected in this state.

    ``record_projection`` intentionally precedes the state CAS.  A hard crash
    between those writes can therefore leave a clean-looking state row that is
    missing authority already present in ``projection_records``.  Strict reads
    reject that crash window instead of silently treating the stale cache as
    ready.  The same pure decoder/rebuild path used by recovery validates
    legacy aliases and semantic conflicts before an alias counts as reflected.
    """

    rows = store.list_rebuild_inputs(
        scope_digest,
        limit=MAX_REBUILD_INPUT_LIMIT,
    )
    if len(rows) >= MAX_REBUILD_INPUT_LIMIT:
        raise SecurityStateNotReadyError("projection_history_unbounded")

    applied_by_key: dict[str, str] = {}
    for applied in state.applied_projections:
        if applied.projection_key in applied_by_key:
            raise SecurityStateNotReadyError("projection_reflection_duplicate")
        applied_by_key[applied.projection_key] = applied.delta_digest

    try:
        committed = []
        direct_current_digests: dict[str, set[str]] = {}
        for row in rows:
            if (
                row.scope_digest != scope_digest
                or type(row.applied_state_version) is not int
                or row.applied_state_version <= 0
                or row.applied_state_version > state.state_version
            ):
                raise SecurityStateNotReadyError("projection_unapplied")
            raw_delta = SecurityStateDeltaV21.model_validate(row.delta_payload)
            raw_digest = canonical_sha256(delta_digest_projection(raw_delta))
            if (
                type(row.source_record_type) is not str
                or type(row.source_record_id) is not str
                or type(row.source_revision) is not int
                or type(row.projector_version) is not str
                or raw_delta.scope_digest != row.scope_digest
                or raw_delta.source.source_record_type != row.source_record_type
                or raw_delta.source.source_record_id != row.source_record_id
                or raw_delta.source.source_revision != row.source_revision
                or raw_delta.projector_version != row.projector_version
                or canonical_sha256(raw_delta.model_dump(mode="json"))
                != canonical_sha256(row.delta_payload)
                or type(raw_delta.base_state_version) is not int
                or type(raw_delta.new_state_version) is not int
                or raw_delta.delta_digest != raw_digest
                or row.delta_digest != raw_digest
                or raw_delta.new_state_version != row.applied_state_version
                or raw_delta.new_state_version != raw_delta.base_state_version + 1
            ):
                raise SecurityStateNotReadyError("projection_envelope_invalid")

            normalized = _committed_from_projection(row)
            normalized_key = projection_identity_key(
                normalized.scope_digest,
                normalized.source_record_type,
                normalized.source_record_id,
                normalized.source_revision,
                normalized.projector_version,
            )
            committed.append(normalized)
            if row.projector_version == PROJECTOR_VERSION:
                direct_current_digests.setdefault(normalized_key, set()).add(raw_digest)

        # Pure reconstruction only: no state initialization, repair, or dirty
        # write.  It also rejects unsupported versions and semantic alias
        # conflicts using exactly the recovery decoder's rules.
        rebuilt = rebuild_state(committed, PROJECTOR_VERSION)
    except SecurityStateNotReadyError:
        raise
    except (TypeError, ValueError) as exc:
        raise SecurityStateNotReadyError("projection_history_invalid") from exc

    rebuilt_by_key = {
        applied.projection_key: applied.delta_digest
        for applied in rebuilt.applied_projections
    }
    if len(rebuilt_by_key) != len(rebuilt.applied_projections):
        raise SecurityStateNotReadyError("projection_reflection_duplicate")
    if set(rebuilt_by_key) != set(applied_by_key):
        raise SecurityStateNotReadyError("projection_record_missing")
    if state.evicted:
        # Eviction is a valid compatibility transformation, but Product strict
        # authority has no persisted eviction input to replay yet.  Therefore
        # it cannot prove equivalence from projection history and must stop.
        raise SecurityStateNotReadyError("projection_eviction_unverifiable")
    if state.state_version != rebuilt.state_version:
        raise SecurityStateNotReadyError("projection_state_version_mismatch")
    if state_digest(state) != state_digest(rebuilt):
        raise SecurityStateNotReadyError("projection_state_digest_mismatch")

    for projection_key, applied_digest in applied_by_key.items():
        acceptable_digests = {
            rebuilt_by_key[projection_key],
            *direct_current_digests.get(projection_key, set()),
        }
        if applied_digest not in acceptable_digests:
            raise SecurityStateNotReadyError("projection_digest_mismatch")
    return tuple(rows)


def get_snapshot_with_revoked(
    store: SecurityStateStoreAccess,
    scope_digest: str,
    *,
    scope: SecurityStateScope,
    task_fact_head: TaskFact | None,
    evaluation_clock: EvaluationClock,
    policy_revision: str,
    policy_digest: str,
    plan: RequiredCheckPlan,
    authoritative_head_revision: int | None = None,
) -> tuple[SecuritySnapshot, list[str]]:
    """构建快照并同源返回 ``revoked_grant_ids``（D3 只读入口）。

    ``12_决策记录_V21-09前置.md`` D3：revoked 集与 snapshot 构建**同源
    同锁**——两者取自同一 ``scope_lock`` 窗口内读取的同一份 online
    state record（rebuild 后的重建态亦同源），保证 revoked 集与
    snapshot 的 ``state_version`` 一致，不出现半新半旧组合。
    ``SecuritySnapshot`` 冻结字段不含 revoked（01 §19 逐字不动），
    撤销集以元组第二项透出，维持入参注入形态。
    """

    _validate_scope_inputs(
        scope_digest,
        scope=scope,
        task_fact_head=task_fact_head,
    )

    with store.scope_lock(scope_digest):
        record = store.get_security_state(scope_digest)
        if (
            record is None
            or record.dirty
            or record.projector_version != PROJECTOR_VERSION
        ):
            state, _alert = rebuild_locked(store, scope_digest)
        else:
            state = state_from_record(record)

        snapshot, revoked_grant_ids = _build_snapshot_from_state(
            state,
            scope_digest=scope_digest,
            scope=scope,
            task_fact_head=task_fact_head,
            evaluation_clock=evaluation_clock,
            policy_revision=policy_revision,
            policy_digest=policy_digest,
            plan=plan,
            authoritative_head_revision=authoritative_head_revision,
        )
    return snapshot, revoked_grant_ids


def get_ready_snapshot_with_revoked(
    store: SecurityStateStoreAccess,
    scope_digest: str,
    *,
    scope: SecurityStateScope,
    task_fact_head: TaskFact | None,
    evaluation_clock: EvaluationClock,
    policy_revision: str,
    policy_digest: str,
    plan: RequiredCheckPlan,
    authoritative_head_revision: int | None = None,
) -> tuple[SecuritySnapshot, list[str], str]:
    """Strictly read one ready state without any repair or persistence.

    Product Active uses this boundary before a formal decision.  Missing,
    dirty, stale-projector, malformed, non-canonical, or row/payload-inconsistent
    states are unavailable authority, not an invitation to initialize or
    rebuild on the decision path.
    """

    _validate_scope_inputs(
        scope_digest,
        scope=scope,
        task_fact_head=task_fact_head,
    )
    with store.scope_lock(scope_digest):
        record = store.get_security_state(scope_digest)
        if record is None:
            raise SecurityStateNotReadyError("missing")
        if record.scope_digest != scope_digest:
            raise SecurityStateNotReadyError("scope_mismatch")
        if record.projector_version != PROJECTOR_VERSION:
            raise SecurityStateNotReadyError("projector_mismatch")
        if record.dirty is not False or not isinstance(record.dirty_domains, list):
            raise SecurityStateNotReadyError("dirty")
        if record.dirty_domains:
            raise SecurityStateNotReadyError("dirty")
        if type(record.state_version) is not int or record.state_version < 0:
            raise SecurityStateNotReadyError("state_version_invalid")
        if not isinstance(record.canonical_payload, dict):
            raise SecurityStateNotReadyError("payload_invalid")
        try:
            state = OnlineSecurityState.model_validate(record.canonical_payload)
        except (TypeError, ValueError) as exc:
            raise SecurityStateNotReadyError("payload_invalid") from exc
        canonical_payload = state.model_dump(mode="json")
        try:
            payload_is_canonical = canonical_sha256(
                canonical_payload
            ) == canonical_sha256(record.canonical_payload)
        except (TypeError, ValueError) as exc:
            raise SecurityStateNotReadyError("payload_invalid") from exc
        if not payload_is_canonical:
            raise SecurityStateNotReadyError("payload_not_canonical")
        if state.state_version != record.state_version:
            raise SecurityStateNotReadyError("state_version_mismatch")
        if state.dirty_domains:
            raise SecurityStateNotReadyError("payload_dirty")
        projection_history = _require_projection_reflection(
            store,
            scope_digest=scope_digest,
            state=state,
        )

        snapshot, revoked = _build_snapshot_from_state(
            state,
            scope_digest=scope_digest,
            scope=scope,
            task_fact_head=task_fact_head,
            evaluation_clock=evaluation_clock,
            policy_revision=policy_revision,
            policy_digest=policy_digest,
            plan=plan,
            authoritative_head_revision=authoritative_head_revision,
        )
        authority_digest = security_state_authority_digest(
            scope_digest=record.scope_digest,
            state_version=record.state_version,
            canonical_payload=record.canonical_payload,
            dirty=record.dirty,
            dirty_domains=list(record.dirty_domains),
            projector_version=record.projector_version,
            projection_history=projection_history,
        )
    return snapshot, revoked, authority_digest


def _with_compiled_task_grants(
    state: OnlineSecurityState,
    *,
    task_fact_head: TaskFact,
    policy_revision: str,
) -> OnlineSecurityState:
    """Inject rebuildable TaskFact grants into the snapshot-only state.

    Task authority is authoritative input, while capability grants are a
    deterministic projection. Recompile the current head inside the same scope
    lock as snapshot construction, replace only older projections for that
    task, and never write the derived grants back to storage.
    """

    compiled = compile_task_to_grants(
        task_fact_head,
        GrantPolicyContext(
            policy_revision=policy_revision,
            scope_digest=task_fact_head.scope_digest,
            principal_id=task_fact_head.principal_id,
        ),
    )
    retained = [
        grant
        for grant in state.active_grants
        if not (
            grant.source_type == "task_compiler"
            and grant.task_id == task_fact_head.task_id
        )
    ]
    merged = {grant.grant_id: grant for grant in (*retained, *compiled)}
    return state.model_copy(
        update={"active_grants": [merged[grant_id] for grant_id in sorted(merged)]}
    )


def get_snapshot(
    store: SecurityStateStoreAccess,
    scope_digest: str,
    *,
    scope: SecurityStateScope,
    task_fact_head: TaskFact | None,
    evaluation_clock: EvaluationClock,
    policy_revision: str,
    policy_digest: str,
    plan: RequiredCheckPlan,
    authoritative_head_revision: int | None = None,
) -> SecuritySnapshot:
    """构建不可变 ``SecuritySnapshot``（判定输入快照）。

    ``scope`` 与 ``task_fact_head`` 同为注入式权威输入（01 §19）；
    ``authoritative_head_revision`` 缺省时 core 取
    ``task_fact_head.revision``；传入更小的 head revision 会触发 task 域
    stale 判定（02 §6.1）。行为与 V21-08 逐字一致（委托
    ``get_snapshot_with_revoked``，仅不透出同源 revoked 集）。
    """

    snapshot, _revoked = get_snapshot_with_revoked(
        store,
        scope_digest,
        scope=scope,
        task_fact_head=task_fact_head,
        evaluation_clock=evaluation_clock,
        policy_revision=policy_revision,
        policy_digest=policy_digest,
        plan=plan,
        authoritative_head_revision=authoritative_head_revision,
    )
    return snapshot
