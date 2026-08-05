"""Memory change lifecycle service."""

from __future__ import annotations

from agentguard_core import MemoryGuardChange, utc_now_iso

from guard_api.storage.base import ControlPlaneStore

from .evidence import _should_quarantine_memory_change


class MemoryGuardService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def propose(self, change: MemoryGuardChange) -> MemoryGuardChange:
        status = (
            "quarantined" if _should_quarantine_memory_change(change) else "proposed"
        )
        proposed = change.model_copy(
            update={"status": status, "updated_at": utc_now_iso()}
        )
        return self.store.create_memory_change(proposed)

    def commit(self, change_id: str) -> MemoryGuardChange:
        return self.store.update_memory_change_status(change_id, "committed")

    def rollback(self, change_id: str) -> MemoryGuardChange:
        return self.store.update_memory_change_status(change_id, "rolled_back")
