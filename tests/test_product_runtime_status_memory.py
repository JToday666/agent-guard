"""Memory-store contracts for exact-identity Product V2 runtime status."""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from agentguard_core import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    RuntimeEventCapabilityV2,
    build_runtime_capability_report,
    openclaw_event_residual_boundaries,
)
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from guard_api.runtime_status import ProductRuntime, ProductRuntimeStatusV2
from guard_api.storage.memory import MemoryControlPlaneStore

pytestmark = pytest.mark.contract

_DIGEST = "sha256:" + "a" * 64
_PROFILE_IDS: dict[ProductRuntime, str] = {
    "langgraph": "agentguard-langgraph-v2",
    "openclaw": "agentguard-openclaw-v2-restricted",
}
_RUNTIME_VERSIONS: dict[ProductRuntime, str] = {
    "langgraph": "1.2.7",
    "openclaw": "2026.7.1-2",
}
_PLUGIN_VERSIONS: dict[ProductRuntime, str] = {
    "langgraph": "0.1.0rc1",
    "openclaw": "0.1.0-rc.1",
}


def _event_capabilities(runtime: ProductRuntime) -> list[RuntimeEventCapabilityV2]:
    enforcement = {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "message_send_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "tool_result_produced": "post_execution_isolation",
    }
    return [
        RuntimeEventCapabilityV2(
            event_type=event_type,
            supported=True,
            active=True,
            enforcement=cast(object, enforcement[event_type]),  # type: ignore[arg-type]
            residual_boundaries=(
                list(openclaw_event_residual_boundaries(event_type))
                if runtime == "openclaw"
                else []
            ),
        )
        for event_type in PRODUCT_EVENT_TYPES
    ]


def _status(
    *,
    runtime: ProductRuntime = "openclaw",
    agent_id: str = "main",
    principal_id: str = "cred_adapter_main",
    runtime_id: str = "openclaw-gateway",
    last_heartbeat_at: str = "2026-09-01T00:00:00+00:00",
) -> ProductRuntimeStatusV2:
    runtime_binding_id = f"binding:{principal_id}"
    report = build_runtime_capability_report(
        runtime=runtime,
        agent_id=agent_id,
        runtime_binding_id=runtime_binding_id,
        profile_id=_PROFILE_IDS[runtime],
        supported=True,
        active=True,
        c0_registration=True,
        c1_pre_execution_interception=True,
        c2_correlation=True,
        c3_atomic_replace_and_seal=runtime == "langgraph",
        c4_outcome_receipts=True,
        events=_event_capabilities(runtime),
        residual_boundaries=(
            list(OPENCLAW_RESIDUAL_BOUNDARIES) if runtime == "openclaw" else []
        ),
    )
    return ProductRuntimeStatusV2(
        schema_version="2.0",
        status="loaded",
        loaded=True,
        runtime_id=runtime_id,
        agent_id=agent_id,
        runtime_binding_id=runtime_binding_id,
        profile_id=_PROFILE_IDS[runtime],
        runtime_version=_RUNTIME_VERSIONS[runtime],
        plugin_version=_PLUGIN_VERSIONS[runtime],
        profile_digest=_DIGEST,
        adapter_artifact_digest=_DIGEST,
        reported_activation_ref_digest=_DIGEST,
        host_inventory_digest=_DIGEST,
        plugin_inventory_digest=_DIGEST if runtime == "openclaw" else None,
        plugin_order_inventory_digest=_DIGEST if runtime == "openclaw" else None,
        tool_inventory_digest=_DIGEST,
        capability_report=report,
        source="memory-test",
        hook_count=2,
        expected_hook_count=2,
        hooks=["before_tool_call", "message_sending"],
        fail_closed_stages=["before_tool_call", "message_sending"],
        enforcement_mode="enforce",
        runtime=runtime,
        principal_id=principal_id,
        last_heartbeat_at=last_heartbeat_at,
    )


def test_product_runtime_status_uses_exact_identity_and_latest_write_order() -> None:
    store = MemoryControlPlaneStore()
    first = _status(agent_id="agent-a", principal_id="cred-a", runtime_id="host-a")
    second = _status(agent_id="agent-b", principal_id="cred-b", runtime_id="host-b")
    updated_first = _status(
        agent_id="agent-a",
        principal_id="cred-a",
        runtime_id="host-a-updated",
        last_heartbeat_at="2026-09-01T00:02:00+00:00",
    )

    store.save_product_runtime_status(first)
    store.save_product_runtime_status(second)
    store.save_product_runtime_status(updated_first)

    assert store.get_product_runtime_status(first.identity()).runtime_id == "host-a-updated"  # type: ignore[union-attr]
    assert store.get_product_runtime_status(second.identity()).runtime_id == "host-b"  # type: ignore[union-attr]
    rows = store.list_product_runtime_statuses(runtime="openclaw")
    assert [row.runtime_id for row in rows] == ["host-a-updated", "host-b"]
    assert len(store.product_runtime_statuses_v2) == 2
    assert store.product_runtime_status_write_sequence == 3

    legacy = store.get_adapter_status("openclaw")
    assert legacy is not None
    assert legacy["runtime_id"] == "host-a-updated"
    assert legacy["capabilities"] == {
        "event_types": list(PRODUCT_EVENT_TYPES),
    }
    assert "runtime_binding_id" not in legacy
    assert "profile_id" not in legacy
    assert "reported_activation_ref_digest" not in legacy


def test_product_runtime_status_list_filters_limits_and_rejects_invalid_bounds() -> (
    None
):
    store = MemoryControlPlaneStore()
    langgraph = _status(
        runtime="langgraph",
        agent_id="langgraph-main",
        principal_id="cred-langgraph",
        runtime_id="langgraph-host",
    )
    openclaw_a = _status(agent_id="agent-a", principal_id="cred-a", runtime_id="host-a")
    openclaw_b = _status(agent_id="agent-b", principal_id="cred-b", runtime_id="host-b")
    for record in (langgraph, openclaw_a, openclaw_b):
        store.save_product_runtime_status(record)

    assert [
        row.runtime_id
        for row in store.list_product_runtime_statuses(runtime="openclaw", limit=1)
    ] == ["host-b"]
    assert [row.runtime_id for row in store.list_product_runtime_statuses(limit=3)] == [
        "host-b",
        "host-a",
        "langgraph-host",
    ]
    with pytest.raises(ValueError, match="runtime must be"):
        store.list_product_runtime_statuses(runtime=cast(ProductRuntime, "unknown"))
    for invalid_limit in (0, 501, True):
        with pytest.raises(ValueError, match="integer between"):
            store.list_product_runtime_statuses(limit=invalid_limit)


def test_product_runtime_status_save_and_reads_are_deep_copies() -> None:
    store = MemoryControlPlaneStore()
    original = _status()

    returned = store.save_product_runtime_status(original)
    original.hooks.append("caller-mutated-original")
    returned.hooks.append("caller-mutated-return")
    listed = store.list_product_runtime_statuses(runtime="openclaw")
    listed[0].hooks.append("caller-mutated-list")
    legacy = store.get_adapter_status("openclaw")
    assert legacy is not None
    legacy["capabilities"]["event_types"].append("caller-mutated-legacy")

    stored = store.get_product_runtime_status(original.identity())
    assert stored is not None
    assert stored.hooks == ["before_tool_call", "message_sending"]
    assert store.get_adapter_status("openclaw")["capabilities"] == {  # type: ignore[index]
        "event_types": list(PRODUCT_EVENT_TYPES),
    }


def test_invalid_product_status_cannot_partially_update_dual_projection() -> None:
    store = MemoryControlPlaneStore()
    original = _status(runtime_id="known-good")
    store.save_product_runtime_status(original)
    product_before = store.list_product_runtime_statuses()
    legacy_before = store.list_adapter_statuses()
    invalid = {**original.model_dump(mode="json"), "runtime": "langgraph"}

    with pytest.raises(ValidationError, match="runtime differs"):
        store.save_product_runtime_status(invalid)

    assert store.list_product_runtime_statuses() == product_before
    assert store.list_adapter_statuses() == legacy_before
    assert store.product_runtime_status_write_sequence == 1


def test_legacy_adapter_status_methods_remain_latest_per_runtime() -> None:
    store = MemoryControlPlaneStore()
    legacy = {
        "status": "loaded",
        "loaded": True,
        "runtime_id": "legacy-host",
        "agent_id": "legacy-agent",
    }

    returned = store.save_adapter_status("openclaw", legacy)
    returned["runtime_id"] = "caller-mutated"
    assert store.get_adapter_status("openclaw")["runtime_id"] == "legacy-host"  # type: ignore[index]

    product = _status(runtime_id="product-host")
    store.save_product_runtime_status(product)
    assert store.get_adapter_status("openclaw")["runtime_id"] == "product-host"  # type: ignore[index]

    store.save_adapter_status("openclaw", legacy)
    assert store.get_adapter_status("openclaw")["runtime_id"] == "legacy-host"  # type: ignore[index]
    exact = store.get_product_runtime_status(product.identity())
    assert exact is not None
    assert exact.runtime_id == "product-host"


def test_legacy_status_preserve_heartbeat_ignores_caller_without_existing_value() -> (
    None
):
    store = MemoryControlPlaneStore()

    saved = store.save_adapter_status(
        "openclaw",
        {
            "status": "loaded",
            "loaded": True,
            "runtime_id": "legacy-host",
            "last_heartbeat_at": "2999-01-01T00:00:00+00:00",
        },
        preserve_heartbeat=True,
    )

    assert saved["last_heartbeat_at"] is None
    assert store.get_adapter_status("openclaw")["last_heartbeat_at"] is None  # type: ignore[index]


def test_legacy_status_preserve_heartbeat_is_atomic_and_leaves_product_row_untouched() -> (
    None
):
    store = MemoryControlPlaneStore()
    product = _status(
        runtime_id="product-host",
        last_heartbeat_at="2026-09-01T00:03:00+00:00",
    )
    store.save_product_runtime_status(product)
    product_before = store.get_product_runtime_status(product.identity())

    saved = store.save_adapter_status(
        "openclaw",
        {
            "status": "error",
            "loaded": False,
            "runtime_id": "operator-updated-host",
            "error": "operator-observed-error",
            "last_heartbeat_at": "2999-01-01T00:00:00+00:00",
        },
        preserve_heartbeat=True,
    )

    assert saved["status"] == "error"
    assert saved["runtime_id"] == "operator-updated-host"
    assert saved["last_heartbeat_at"] == "2026-09-01T00:03:00+00:00"
    assert store.get_adapter_status("openclaw") == saved
    assert store.get_product_runtime_status(product.identity()) == product_before
