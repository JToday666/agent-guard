"""SecurityStateService：V21-04 安全状态对外 API 门面。

本期纯新增：不接线 evaluation 编排 / main / routers（接线属 V21-08），
不新增 HTTP 路由与环境变量。对外三个入口：

- ``project_committed``：已 commit 权威记录的投影 + 应用编排；
- ``read_snapshot``：判定输入快照（dirty/缺态自动 bounded rebuild，
  task 域直读权威 TaskFact head）；
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

from .models import ProjectApplyResult
from .projector import CommittedVerifier, SecurityStateProjector
from .rebuild import DEFAULT_REBUILD_LIMIT, rebuild_locked, state_from_record
from .snapshot_builder import get_snapshot
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
            if record.dirty:
                state, _alert = rebuild_locked(
                    self._access, scope_digest, limit=rebuild_limit
                )
                return state
            return state_from_record(record)
