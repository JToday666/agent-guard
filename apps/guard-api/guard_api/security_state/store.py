"""ControlPlaneStore V21-04 新方法的薄封装 + per-scope 锁注册表。

锁纪律（与 postgres 行锁/advisory lock 互补）：

- 锁**仅覆盖内存编排段**（同进程 read-modify-write 串行化），不跨 DB
  事务持有；postgres 侧由 ``pg_advisory_xact_lock`` + 条件 UPDATE 自行
  保护，两层保护互不依赖；
- 注册表按 scope_digest 分配 ``RLock``（rebuild/snapshot 编排允许同
  scope 嵌套加锁），注册表自身由全局锁保护。
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from agentguard_core.security_context import OnlineSecurityState, StateWatermarks

from guard_api.storage.base import (
    ControlPlaneStore,
    ProjectionIdentityRecord,
    SecurityStateRecord,
)


def empty_online_state() -> OnlineSecurityState:
    """空白 OnlineSecurityState（version=0，全空水位）：缺态初始化口径。"""

    return OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )


class SecurityStateStoreAccess:
    """对 ControlPlaneStore 六个 V21-04 新方法的薄封装。

    不在本层做任何业务判定：幂等三分支、CAS、dirty 语义全部由存储契约
    （``storage/base.py`` docstring）与 core 纯函数承担。
    """

    def __init__(self, store: ControlPlaneStore) -> None:
        self._store = store
        self._registry_lock = threading.Lock()
        self._scope_locks: dict[str, threading.RLock] = {}

    @property
    def raw(self) -> ControlPlaneStore:
        """底层 store（供需要既有方法如 task_facts 的编排读取）。"""

        return self._store

    @contextmanager
    def scope_lock(self, scope_digest: str) -> Iterator[None]:
        """per-scope 编排锁：只覆盖内存编排段，不跨 DB 事务持有。"""

        with self._registry_lock:
            lock = self._scope_locks.get(scope_digest)
            if lock is None:
                lock = threading.RLock()
                self._scope_locks[scope_digest] = lock
        with lock:
            yield

    def get_security_state(self, scope_digest: str) -> SecurityStateRecord | None:
        return self._store.get_security_state(scope_digest)

    def read_revoked_grant_ids(self, scope_digest: str) -> list[str]:
        """online state record 的 revoked 集只读入口（D3）。

        与 snapshot 同源的 ``get_security_state`` 记录读取路径，持
        per-scope 编排锁窗口内读取，缺态返回空表；不新增存储方法、
        不新增写面。需要与 snapshot 严格同版本一致的消费方应用
        ``SecurityStateService.read_snapshot_with_revoked``（同一次
        调用链同源同锁）；本入口供仅需撤销集的轻量读取。
        """

        with self.scope_lock(scope_digest):
            record = self._store.get_security_state(scope_digest)
        if record is None:
            return []
        state = OnlineSecurityState.model_validate(record.canonical_payload)
        return list(state.revoked_grant_ids)

    def cas_security_state(
        self,
        scope_digest: str,
        expected_state_version: int,
        record: SecurityStateRecord,
    ) -> bool:
        return self._store.cas_security_state(
            scope_digest, expected_state_version, record
        )

    def mark_security_state_dirty(self, scope_digest: str, domains: list[str]) -> None:
        self._store.mark_security_state_dirty(scope_digest, domains)

    def record_projection(
        self, record: ProjectionIdentityRecord
    ) -> tuple[ProjectionIdentityRecord, bool]:
        return self._store.record_projection(record)

    def get_projection(
        self,
        scope_digest: str,
        source_record_type: str,
        source_record_id: str,
        source_revision: int,
        projector_version: str,
    ) -> ProjectionIdentityRecord | None:
        return self._store.get_projection(
            scope_digest,
            source_record_type,
            source_record_id,
            source_revision,
            projector_version,
        )

    def list_rebuild_inputs(
        self, scope_digest: str, *, limit: int
    ) -> list[ProjectionIdentityRecord]:
        return self._store.list_rebuild_inputs(scope_digest, limit=limit)
