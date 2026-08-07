"""Policy snapshot service."""

from __future__ import annotations

from collections.abc import Callable

from agentguard_core import PolicyBundle

from guard_api.storage.base import ControlPlaneStore, PolicySnapshotRecord


class PolicyService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore | None = None,
        policy_bundle: PolicyBundle | None = None,
        policy_provider: Callable[[], PolicyBundle] | None = None,
    ) -> None:
        if policy_bundle is not None and policy_provider is not None:
            raise ValueError(
                "PolicyService accepts either policy_bundle or policy_provider, not both"
            )
        self.store = store
        self.policy_bundle = policy_bundle or PolicyBundle()
        self.policy_provider = policy_provider

    def current_snapshot(self) -> PolicyBundle:
        if self.store is not None:
            snapshot = self.store.get_policy_snapshot()
            if snapshot is not None:
                return snapshot
        if self.policy_provider is not None:
            return self.policy_provider()
        return self.policy_bundle

    def save_snapshot(
        self, policy_bundle: PolicyBundle, *, updated_by: str = "system"
    ) -> PolicyBundle:
        if self.store is not None:
            return self.store.save_policy_snapshot(
                policy_bundle, updated_by=updated_by
            ).policy_bundle
        self.policy_bundle = policy_bundle
        return policy_bundle

    def current_snapshot_record(self) -> PolicySnapshotRecord | None:
        if self.store is None:
            return None
        history = self.store.list_policy_snapshot_history(limit=1)
        if not history:
            return None
        return history[0]

    def list_history(self, *, limit: int = 100) -> list[PolicySnapshotRecord]:
        if self.store is None:
            return []
        return self.store.list_policy_snapshot_history(limit=limit)
