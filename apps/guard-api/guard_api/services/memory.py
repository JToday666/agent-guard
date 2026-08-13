"""Memory change lifecycle service."""

from __future__ import annotations

from agentguard_core import AuditEvent, MemoryGuardChange, utc_now_iso

from guard_api.storage.base import ControlPlaneStore

from .audit import AuditService
from .evidence import _should_quarantine_memory_change


class MemoryGuardService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        audit_service: AuditService | None = None,
    ) -> None:
        self.store = store
        self.audit_service = audit_service

    def propose(
        self,
        change: MemoryGuardChange,
        *,
        runtime: str | None = None,
        agent_id: str | None = None,
        principal_id: str | None = None,
    ) -> MemoryGuardChange:
        status = (
            "quarantined" if _should_quarantine_memory_change(change) else "proposed"
        )
        # 提议方身份一律以认证上下文为准，覆盖客户端自报绑定。
        proposed = change.model_copy(
            update={
                "status": status,
                "runtime": runtime,
                "agent_id": agent_id,
                "principal_id": principal_id,
                "updated_at": utc_now_iso(),
            }
        )
        return self.store.create_memory_change(proposed)

    def get(self, change_id: str) -> MemoryGuardChange | None:
        return self.store.get_memory_change(change_id)

    def commit(self, change_id: str, *, operator_id: str) -> MemoryGuardChange:
        return self._transition(change_id, "committed", operator_id=operator_id)

    def rollback(self, change_id: str, *, operator_id: str) -> MemoryGuardChange:
        return self._transition(change_id, "rolled_back", operator_id=operator_id)

    def _transition(
        self, change_id: str, target_status: str, *, operator_id: str
    ) -> MemoryGuardChange:
        # 状态机与并发安全由存储层的前态条件更新保证；非法转换在此抛出。
        # 状态变更与转换审计在同一原子窗口内提交或回滚，不留
        # 「状态已改、链上无记录」的部分状态。
        with self.store.memory_change_transaction(change_id):
            # 结构化结果携带存储层读到的权威前态：仅在本次调用真正执行了
            # 转换（applied=True）时入链审计，幂等重放与并发落败方不再重复写入。
            result = self.store.update_memory_change_status(change_id, target_status)
            if result.applied:
                self._record_transition_audit(
                    result.previous_status, result.change, operator_id=operator_id
                )
            return result.change

    def _record_transition_audit(
        self,
        previous_status: str,
        updated: MemoryGuardChange,
        *,
        operator_id: str,
    ) -> None:
        # 仅在实际发生转换时入链；最小化记录，不携带 value 全文。
        if self.audit_service is None:
            return
        self.audit_service.submit(
            _memory_change_transition_audit(
                previous_status, updated, operator_id=operator_id
            )
        )


def _memory_change_transition_audit(
    from_status: str,
    updated: MemoryGuardChange,
    *,
    operator_id: str,
) -> AuditEvent:
    decision = "deny" if updated.status in {"rejected", "rolled_back"} else "allow"
    return AuditEvent(
        schema_version="0.4",
        record_type="config_audit",
        trace_id=updated.trace_id,
        runtime=updated.runtime or "langgraph",
        stage="memory_guard",
        event_type="memory_change_transition",
        summary=(
            f"Memory change {updated.change_id} transitioned "
            f"{from_status} -> {updated.status}"
        ),
        decision=decision,
        risk_score=0,
        severity="low",
        blocked=decision == "deny",
        reason=f"memory_change:{from_status}->{updated.status}",
        links={"memory_change_id": updated.change_id},
        metadata={
            "from_status": from_status,
            "to_status": updated.status,
            "operator_id": operator_id,
        },
    )
