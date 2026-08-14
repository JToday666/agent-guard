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
    PROJECTOR_VERSION,
    SecuritySnapshot,
    build_snapshot,
)

from .rebuild import rebuild_locked, state_from_record
from .store import SecurityStateStoreAccess


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
    stale 判定（02 §6.1）。
    """

    with store.scope_lock(scope_digest):
        record = store.get_security_state(scope_digest)
        if record is None or record.dirty:
            state, _alert = rebuild_locked(store, scope_digest)
        else:
            state = state_from_record(record)

        # task 域不走 delta 投影：把权威 TaskFact head 注入快照输入态，
        # 使 coverage 能对照 head revision 完成 stale 检测（02 §6.1）。
        # 该注入仅存在于快照构建的临时态，不回写存储（task 域不参与
        # 投影状态版本链）。
        if task_fact_head is not None and state.task is not task_fact_head:
            state = state.model_copy(update={"task": task_fact_head})

        snapshot_id = "v21-04-snapshot:" + canonical_sha256(
            {
                "scope_digest": scope_digest,
                "state_version": state.state_version,
                "projector_version": PROJECTOR_VERSION,
                "policy_revision": policy_revision,
                "policy_digest": policy_digest,
            }
        )
        return build_snapshot(
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
