"""Explicit runtime credential fixtures for Guard API tests."""

from __future__ import annotations

import hashlib

from guard_api.models import ADAPTER_CREDENTIAL_SCOPES, CredentialRecord
from guard_api.storage.base import ControlPlaneStore
from guard_api.storage.memory import MemoryControlPlaneStore


def add_adapter_credential(
    store: ControlPlaneStore,
    *,
    token: str = "adapter-secret",
    runtime: str = "langgraph",
    agent_id: str = "main",
    principal_id: str = "cred_adapter_main",
) -> str:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    store.create_credential(
        CredentialRecord(
            credential_id=f"cred_test_{token_hash[:16]}",
            token_hash=token_hash,
            principal_type="component",
            principal_id=principal_id,
            role="adapter",
            scopes=list(ADAPTER_CREDENTIAL_SCOPES),
            runtime=runtime,
            agent_id=agent_id,
        )
    )
    return token


def memory_store_with_adapter(
    *,
    token: str = "adapter-secret",
    runtime: str = "langgraph",
    agent_id: str = "main",
    principal_id: str = "cred_adapter_main",
) -> MemoryControlPlaneStore:
    store = MemoryControlPlaneStore()
    add_adapter_credential(
        store,
        token=token,
        runtime=runtime,
        agent_id=agent_id,
        principal_id=principal_id,
    )
    return store
