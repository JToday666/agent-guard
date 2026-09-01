"""SecurityStateService：V21-04 安全状态对外 API 门面。

V21-08 T4 起由 ``main.py`` 注册进 ApiContext/EvaluationService 可达
位置，供 shadow 旁路编排（``services/v21_shadow.py``）只读消费；
不新增 HTTP 路由。对外入口：

- ``project_committed``：已 commit 权威记录的投影 + 应用编排；
- ``read_snapshot``：判定输入快照（dirty/缺态自动 bounded rebuild，
  task 域直读权威 TaskFact head）；
- ``read_snapshot_with_revoked``：snapshot + 同源 revoked 集（D3，
  V21-09 编排注入 assess 的权威撤销集读取入口）；
- ``read_ready_snapshot_with_revoked``：Product 决策专用严格只读入口，
  不初始化、不 rebuild、不修复、不置脏；
- ``ensure_ready``：下一次 state-dependent 决策前的 rebuild 钩子。
"""

from __future__ import annotations

from agentguard_core import utc_now_iso
from agentguard_core.authority.models import (
    EvaluationClock,
    SecurityStateScope,
    TaskFact,
)
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
    OnlineSecurityState,
    SecuritySnapshot,
)

from guard_api.storage.base import (
    ControlPlaneStore,
    SecurityStateRecord,
    StateVersionConflictError,
)

from .models import ProjectApplyResult, SecurityStateProjectError
from .projector import CommittedVerifier, SecurityStateProjector
from .rebuild import DEFAULT_REBUILD_LIMIT, rebuild_locked, state_from_record
from .snapshot_builder import (
    get_ready_snapshot_with_revoked,
    get_snapshot,
    get_snapshot_with_revoked,
)
from .store import SecurityStateStoreAccess, empty_online_state


class SecurityStateService:
    """V21-04 安全状态服务门面（storage 编排 + core 纯函数消费）。"""

    def __init__(self, store: ControlPlaneStore) -> None:
        self._access = SecurityStateStoreAccess(store)
        self._projector = SecurityStateProjector(self._access)

    @property
    def store_access(self) -> SecurityStateStoreAccess:
        """底层 store 薄封装（供消费方读取投影登记等诊断信息）。"""

        return self._access

    def project_committed(
        self,
        committed_record: CommittedRecord,
        *,
        scope_digest: str,
        verify_source_committed: CommittedVerifier | None = None,
    ) -> ProjectApplyResult:
        """投影并应用一条已 commit 权威记录（失败抛带 alert 的异常）。"""

        return self._projector.project_and_apply(
            committed_record,
            scope_digest=scope_digest,
            verify_source_committed=verify_source_committed,
        )

    def read_snapshot(
        self,
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
        """读取判定输入快照；dirty/缺态先 bounded rebuild。

        ``scope`` 与 ``task_fact_head`` 同为注入式权威输入（01 §19）。
        """

        return get_snapshot(
            self._access,
            scope_digest,
            scope=scope,
            task_fact_head=task_fact_head,
            evaluation_clock=evaluation_clock,
            policy_revision=policy_revision,
            policy_digest=policy_digest,
            plan=plan,
            authoritative_head_revision=authoritative_head_revision,
        )

    def read_snapshot_with_revoked(
        self,
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
        """读取 snapshot 并同源返回 ``revoked_grant_ids``（D3 只读入口）。

        与 ``read_snapshot`` 同一调用链：revoked 集与 snapshot 取自同一
        ``scope_lock`` 窗口内的同一份 online state record，保证两者
        ``state_version`` 一致（``12_决策记录_V21-09前置.md`` D3）；
        不新增存储方法、不新增写面。dirty/缺态先 bounded rebuild，
        语义与 ``read_snapshot`` 逐字一致。
        """

        return get_snapshot_with_revoked(
            self._access,
            scope_digest,
            scope=scope,
            task_fact_head=task_fact_head,
            evaluation_clock=evaluation_clock,
            policy_revision=policy_revision,
            policy_digest=policy_digest,
            plan=plan,
            authoritative_head_revision=authoritative_head_revision,
        )

    def read_ready_snapshot_with_revoked(
        self,
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
        """Read one internally consistent ready state with zero writes.

        Unlike the compatibility snapshot APIs, this method never initializes,
        rebuilds, repairs, or dirties state.  The third result is the complete
        state authority digest for later Phase-B revalidation.
        """

        return get_ready_snapshot_with_revoked(
            self._access,
            scope_digest,
            scope=scope,
            task_fact_head=task_fact_head,
            evaluation_clock=evaluation_clock,
            policy_revision=policy_revision,
            policy_digest=policy_digest,
            plan=plan,
            authoritative_head_revision=authoritative_head_revision,
        )

    def ensure_ready(
        self,
        scope_digest: str,
        *,
        rebuild_limit: int = DEFAULT_REBUILD_LIMIT,
    ) -> OnlineSecurityState:
        """下一次 state-dependent 决策前的 rebuild 钩子。

        缺态 → 写入 version=0 的初始空态（不置 dirty；首次初始化的
        CAS 良性竞争捕获 ``StateVersionConflictError`` 后重读既有记录
        返回，不向调用方上抛）；dirty → bounded rebuild（rebuild 失败
        时返回 fail-closed 的 dirty 状态，调用方经 coverage 得到
        unknown，不得解释为 complete）。
        """

        with self._access.scope_lock(scope_digest):
            record = self._access.get_security_state(scope_digest)
            if record is None:
                # Crash window: a projection envelope may have committed before
                # the online-state CAS. Missing state is therefore not proof of
                # an empty history; rebuild when any bounded input exists.
                if self._access.list_rebuild_inputs(scope_digest, limit=1):
                    state, _alert = rebuild_locked(
                        self._access, scope_digest, limit=rebuild_limit
                    )
                    return state
                empty = empty_online_state()
                try:
                    self._access.cas_security_state(
                        scope_digest,
                        0,
                        SecurityStateRecord(
                            scope_digest=scope_digest,
                            state_version=0,
                            canonical_payload=empty.model_dump(mode="json"),
                            dirty=False,
                            dirty_domains=[],
                            projector_version=PROJECTOR_VERSION,
                            updated_at=utc_now_iso(),
                        ),
                    )
                except StateVersionConflictError:
                    # 良性竞争（F9）：另一编排已抢先完成首次初始化，
                    # 重读既有记录返回，不把冲突上抛。
                    reread = self._access.get_security_state(scope_digest)
                    if reread is not None:
                        return state_from_record(reread)
                    raise
                return empty
            if record.dirty or record.projector_version != PROJECTOR_VERSION:
                state, _alert = rebuild_locked(
                    self._access, scope_digest, limit=rebuild_limit
                )
                return state
            return state_from_record(record)

    def reconcile_projection_history(
        self,
        scope_digest: str,
        *,
        rebuild_limit: int = DEFAULT_REBUILD_LIMIT,
    ) -> OnlineSecurityState:
        """Rebuild every bounded envelope while a scope transaction is held.

        This is the Product commit→project recovery primitive.  The caller
        holds both the process-local scope lock and the backend transaction;
        any truncation or invalid history remains a fail-closed projector
        error rather than a partially accepted online state.
        """

        state, alert = rebuild_locked(
            self._access,
            scope_digest,
            limit=rebuild_limit,
        )
        if alert is not None:
            raise SecurityStateProjectError(alert)
        return state
