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
    SecuritySnapshot,
    build_snapshot,
)
from agentguard_core.security_context.projection import (
    GrantPolicyContext,
    compile_task_to_grants,
)

from .rebuild import rebuild_locked, state_from_record
from .store import SecurityStateStoreAccess


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

    # Fail-closed: reject cross-scope snapshot inputs. When scope_digest,
    # scope.scope_digest, or task_fact_head.scope_digest disagree, a valid
    # authoritative task from another principal/scope could be reported as
    # complete and influence a decision for the wrong state.
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

        # D3 同源读取：revoked 集取自构建 snapshot 的同一 state 对象
        # （task_fact_head 注入仅替换 task 域，不影响撤销集）。
        revoked_grant_ids = list(state.revoked_grant_ids)

        # task 域不走 delta 投影：把权威 TaskFact head 注入快照输入态，
        # 使 coverage 能对照 head revision 完成 stale 检测（02 §6.1）。
        # 该注入仅存在于快照构建的临时态，不回写存储（task 域不参与
        # 投影状态版本链）。
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
        update={
            "active_grants": [merged[grant_id] for grant_id in sorted(merged)]
        }
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
