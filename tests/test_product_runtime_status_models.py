"""Product V2 runtime status model contracts."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from agentguard_core import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    RuntimeCapabilityReportV2,
    RuntimeEventCapabilityV2,
    build_runtime_capability_report,
    openclaw_event_residual_boundaries,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.models import AdapterStatusRecord
from guard_api.runtime_status import (
    ProductRuntime,
    ProductRuntimeHeartbeatV2,
    ProductRuntimeStatusIdentityV1,
    ProductRuntimeStatusV2,
)

pytestmark = pytest.mark.unit

_EVENT_TYPES = (
    "context_assembled",
    "memory_write_proposed",
    "message_send_proposed",
    "model_input_prepared",
    "model_output_produced",
    "tool_call_proposed",
    "tool_result_produced",
)
_ENFORCEMENT = {
    "langgraph": {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c3",
        "message_send_proposed": "pre_execution_c3",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c3",
        "tool_result_produced": "post_execution_isolation",
    },
    "openclaw": {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c1",
        "message_send_proposed": "pre_execution_c1",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c1",
        "tool_result_produced": "post_execution_isolation",
    },
}


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _runtime_profile(runtime: ProductRuntime) -> str:
    return {
        "langgraph": "agentguard-langgraph-v2",
        "openclaw": "agentguard-openclaw-v2-restricted",
    }[runtime]


def _runtime_version(runtime: ProductRuntime) -> str:
    return {"langgraph": "1.2.7", "openclaw": "2026.7.1-2"}[runtime]


def _plugin_version(runtime: ProductRuntime) -> str:
    return {"langgraph": "0.1.0rc1", "openclaw": "0.1.0-rc.1"}[runtime]


def _capability_report(
    runtime: ProductRuntime,
    *,
    active: bool = True,
) -> RuntimeCapabilityReportV2:
    events = [
        RuntimeEventCapabilityV2(
            event_type=event_type,
            supported=True,
            active=active,
            enforcement=_ENFORCEMENT[runtime][event_type],  # type: ignore[arg-type]
            residual_boundaries=(
                list(openclaw_event_residual_boundaries(event_type))
                if runtime == "openclaw"
                else []
            ),
        )
        for event_type in _EVENT_TYPES
    ]
    return build_runtime_capability_report(
        runtime=runtime,
        agent_id="main",
        runtime_binding_id=f"binding:{runtime}:main",
        profile_id=_runtime_profile(runtime),
        supported=True,
        active=active,
        c0_registration=True,
        c1_pre_execution_interception=True,
        c2_correlation=True,
        c3_atomic_replace_and_seal=runtime == "langgraph",
        c4_outcome_receipts=True,
        events=events,
        residual_boundaries=(
            list(OPENCLAW_RESIDUAL_BOUNDARIES) if runtime == "openclaw" else []
        ),
    )


def _heartbeat_payload(
    runtime: ProductRuntime,
    *,
    active: bool = True,
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "status": "loaded",
        "loaded": True,
        "runtime_id": f"{runtime}-host",
        "agent_id": "main",
        "runtime_binding_id": f"binding:{runtime}:main",
        "profile_id": _runtime_profile(runtime),
        "runtime_version": _runtime_version(runtime),
        "plugin_version": _plugin_version(runtime),
        "profile_digest": _digest("1"),
        "adapter_artifact_digest": _digest("2"),
        "reported_activation_ref_digest": _digest("3"),
        "host_inventory_digest": _digest("4"),
        "plugin_inventory_digest": (_digest("5") if runtime == "openclaw" else None),
        "plugin_order_inventory_digest": (
            _digest("6") if runtime == "openclaw" else None
        ),
        "tool_inventory_digest": _digest("7"),
        "capability_report": _capability_report(runtime, active=active).model_dump(
            mode="json"
        ),
        "source": f"{runtime}-adapter",
        "error": None,
        "hook_count": 2,
        "expected_hook_count": 3,
        "hooks": ["before_agent_run", "before_tool_call"],
        "fail_closed_stages": ["before_agent_run", "before_tool_call"],
        "enforcement_mode": "enforce",
    }


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("active", [False, True])
def test_product_runtime_heartbeat_accepts_both_frozen_profiles(
    runtime: ProductRuntime,
    active: bool,
) -> None:
    heartbeat = ProductRuntimeHeartbeatV2.model_validate(
        _heartbeat_payload(runtime, active=active)
    )

    assert heartbeat.capability_report is not None
    assert heartbeat.capability_report.runtime == runtime
    assert heartbeat.capability_report.active is active
    assert heartbeat.reported_activation_ref_digest == _digest("3")
    assert "runtime" not in heartbeat.model_dump(mode="json")
    assert "principal_id" not in heartbeat.model_dump(mode="json")
    assert "last_heartbeat_at" not in heartbeat.model_dump(mode="json")


def test_product_heartbeat_requires_explicit_schema_discriminator() -> None:
    payload = _heartbeat_payload("openclaw")
    payload.pop("schema_version")

    with pytest.raises(ValidationError, match="schema_version"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime", "openclaw"),
        ("principal_id", "openclaw:main"),
        ("last_heartbeat_at", "2026-09-01T00:00:00+00:00"),
        ("activation_ack", {"ack_token": "hmac-sha256:" + "0" * 64}),
        ("last_activation_ack_server_accepted", True),
    ],
)
def test_product_heartbeat_rejects_server_owned_fields(
    field: str,
    value: object,
) -> None:
    payload = _heartbeat_payload("openclaw")
    payload[field] = value

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "other-agent"),
        ("runtime_binding_id", "binding:other"),
        ("profile_id", "agentguard-langgraph-v2"),
    ],
)
def test_product_heartbeat_rejects_capability_identity_drift(
    field: str,
    value: str,
) -> None:
    payload = _heartbeat_payload("openclaw")
    payload[field] = value

    with pytest.raises(ValidationError, match="capability_report differs"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


@pytest.mark.parametrize(
    ("runtime", "field", "value"),
    [
        ("langgraph", "runtime_version", "1.2.6"),
        ("langgraph", "plugin_version", "0.1.0"),
        ("openclaw", "runtime_version", "2026.7.1-1"),
        ("openclaw", "plugin_version", "0.1.0-rc.0"),
    ],
)
def test_product_heartbeat_preserves_observed_version_drift(
    runtime: ProductRuntime,
    field: str,
    value: str,
) -> None:
    payload = _heartbeat_payload(runtime)
    payload[field] = value

    heartbeat = ProductRuntimeHeartbeatV2.model_validate(payload)

    assert getattr(heartbeat, field) == value


@pytest.mark.parametrize(
    "field",
    [
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
        "capability_report",
    ],
)
def test_loaded_openclaw_heartbeat_requires_complete_observations(field: str) -> None:
    payload = _heartbeat_payload("openclaw")
    payload[field] = None

    with pytest.raises(ValidationError, match="requires"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


def test_loaded_langgraph_accepts_observed_plugin_inventories() -> None:
    payload = _heartbeat_payload("langgraph")
    payload["plugin_inventory_digest"] = _digest("8")
    payload["plugin_order_inventory_digest"] = _digest("9")

    heartbeat = ProductRuntimeHeartbeatV2.model_validate(payload)

    assert heartbeat.plugin_inventory_digest == _digest("8")
    assert heartbeat.plugin_order_inventory_digest == _digest("9")


@pytest.mark.parametrize("status", ["error", "not_loaded", "unknown"])
def test_unloaded_heartbeat_can_record_missing_discovery(
    status: str,
) -> None:
    payload = _heartbeat_payload("openclaw", active=False)
    payload.update(
        {
            "status": status,
            "loaded": False,
            "host_inventory_digest": None,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": None,
            "capability_report": None,
            "error": "runtime discovery incomplete",
            "enforcement_mode": "disabled",
        }
    )

    heartbeat = ProductRuntimeHeartbeatV2.model_validate(payload)

    assert heartbeat.capability_report is None
    assert heartbeat.host_inventory_digest is None
    assert heartbeat.tool_inventory_digest is None
    assert heartbeat.error == "runtime discovery incomplete"


def test_error_heartbeat_requires_nonempty_reason() -> None:
    payload = _heartbeat_payload("openclaw", active=False)
    payload.update({"status": "error", "loaded": False, "error": None})

    with pytest.raises(ValidationError, match="requires an error reason"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


def test_loaded_heartbeat_rejects_error_reason() -> None:
    payload = _heartbeat_payload("openclaw")
    payload["error"] = "stale failure"

    with pytest.raises(ValidationError, match="cannot carry an error reason"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


@pytest.mark.parametrize(
    ("status", "enforcement_mode"),
    [("error", "enforce"), ("not_loaded", "enforce"), ("loaded", "disabled")],
)
def test_active_capability_report_requires_loaded_enforcement(
    status: str,
    enforcement_mode: str,
) -> None:
    payload = _heartbeat_payload("openclaw")
    payload["status"] = status
    payload["loaded"] = status == "loaded"
    payload["enforcement_mode"] = enforcement_mode
    if status == "error":
        payload["error"] = "runtime failed"

    with pytest.raises(ValidationError, match="active capability report"):
        ProductRuntimeHeartbeatV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("loaded", False, "status=loaded"),
        (
            "hooks",
            ["before_tool_call", "before_agent_run"],
            "canonically sorted",
        ),
        (
            "hooks",
            ["before_agent_run", "before_agent_run"],
            "canonically sorted",
        ),
        (
            "fail_closed_stages",
            ["before_tool_call", "before_agent_run"],
            "canonically sorted",
        ),
    ],
)
def test_product_heartbeat_rejects_inconsistent_status_and_lists(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _heartbeat_payload("openclaw")
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        ProductRuntimeHeartbeatV2.model_validate(payload)


def test_product_heartbeat_rejects_c3_misreport_for_each_runtime() -> None:
    cases: tuple[tuple[ProductRuntime, bool], ...] = (
        ("langgraph", False),
        ("openclaw", True),
    )
    for runtime, invalid_c3 in cases:
        payload = _heartbeat_payload(runtime)
        report = deepcopy(payload["capability_report"])
        assert isinstance(report, dict)
        report["c3_atomic_replace_and_seal"] = invalid_c3
        projection = {
            key: value for key, value in report.items() if key != "report_digest"
        }
        report["report_digest"] = canonical_sha256(projection)
        payload["capability_report"] = report

        with pytest.raises(ValidationError) as rejected:
            ProductRuntimeHeartbeatV2.model_validate(payload)
        assert "C3" in str(rejected.value) or "C0-C4" in str(rejected.value)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_persisted_status_builds_identity_and_safe_legacy_projection(
    runtime: ProductRuntime,
) -> None:
    heartbeat = ProductRuntimeHeartbeatV2.model_validate(_heartbeat_payload(runtime))
    status = ProductRuntimeStatusV2.model_validate(
        {
            **heartbeat.model_dump(mode="json"),
            "runtime": runtime,
            "principal_id": f"{runtime}:main",
            "last_heartbeat_at": "2026-09-01T08:15:00+08:00",
        }
    )

    assert status.last_heartbeat_at == "2026-09-01T00:15:00+00:00"
    assert status.identity() == ProductRuntimeStatusIdentityV1(
        runtime=runtime,
        agent_id="main",
        runtime_binding_id=f"binding:{runtime}:main",
        profile_id=_runtime_profile(runtime),
    )

    legacy = status.to_legacy_adapter_status()
    legacy_payload = legacy.model_dump(mode="json")
    assert set(legacy_payload) == set(AdapterStatusRecord.model_fields)
    assert legacy_payload["capabilities"] == {"event_types": list(_EVENT_TYPES)}
    assert legacy_payload["last_heartbeat_at"] == status.last_heartbeat_at
    forbidden = {
        "runtime",
        "principal_id",
        "runtime_binding_id",
        "profile_id",
        "profile_digest",
        "adapter_artifact_digest",
        "reported_activation_ref_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
        "capability_report",
        "activation_ack",
    }
    assert forbidden.isdisjoint(legacy_payload)


def test_persisted_status_rejects_runtime_drift_and_naive_server_time() -> None:
    payload = _heartbeat_payload("openclaw") | {
        "runtime": "langgraph",
        "principal_id": "openclaw:main",
        "last_heartbeat_at": "2026-09-01T00:00:00+00:00",
    }
    with pytest.raises(ValidationError, match="capability_report.runtime"):
        ProductRuntimeStatusV2.model_validate(payload)

    payload["runtime"] = "openclaw"
    payload["last_heartbeat_at"] = "2026-09-01T00:00:00"
    with pytest.raises(ValidationError, match="timezone"):
        ProductRuntimeStatusV2.model_validate(payload)


@pytest.mark.parametrize(
    ("runtime", "profile_id"),
    [
        ("langgraph", "agentguard-openclaw-v2-restricted"),
        ("openclaw", "agentguard-langgraph-v2"),
    ],
)
def test_persisted_error_status_rejects_runtime_profile_drift(
    runtime: ProductRuntime,
    profile_id: str,
) -> None:
    payload = _heartbeat_payload("openclaw", active=False)
    payload.update(
        {
            "status": "error",
            "loaded": False,
            "profile_id": profile_id,
            "capability_report": None,
            "host_inventory_digest": None,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": None,
            "error": "runtime discovery failed",
            "enforcement_mode": "disabled",
            "runtime": runtime,
            "principal_id": "runtime-principal",
            "last_heartbeat_at": "2026-09-01T00:00:00+00:00",
        }
    )

    with pytest.raises(ValidationError, match="persisted runtime status requires"):
        ProductRuntimeStatusV2.model_validate(payload)


def test_persisted_status_keeps_principal_and_binding_independent() -> None:
    payload = _heartbeat_payload("openclaw") | {
        "runtime": "openclaw",
        "principal_id": "another-principal",
        "last_heartbeat_at": "2026-09-01T00:00:00+00:00",
    }

    status = ProductRuntimeStatusV2.model_validate(payload)

    assert status.principal_id == "another-principal"
    assert status.runtime_binding_id == "binding:openclaw:main"


def test_product_runtime_identity_requires_the_frozen_profile() -> None:
    with pytest.raises(ValidationError, match="requires profile_id"):
        ProductRuntimeStatusIdentityV1(
            runtime="openclaw",
            agent_id="main",
            runtime_binding_id="binding:openclaw:main",
            profile_id="agentguard-langgraph-v2",
        )


def test_product_runtime_identity_allows_non_whitespace_uri_characters() -> None:
    identity = ProductRuntimeStatusIdentityV1(
        runtime="openclaw",
        agent_id="agent@example.com",
        runtime_binding_id="binding:https://runtime.example/agent@example.com",
        profile_id="agentguard-openclaw-v2-restricted",
    )
    assert identity.agent_id == "agent@example.com"

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        ProductRuntimeStatusIdentityV1(
            runtime="openclaw",
            agent_id="agent with spaces",
            runtime_binding_id="binding:openclaw:main",
            profile_id="agentguard-openclaw-v2-restricted",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "agent\nmain"),
        ("runtime_binding_id", "binding:\u00e9quipe:main"),
        ("profile_id", "agentguard-openclaw-v2-restricted\t"),
    ],
)
def test_product_runtime_identity_rejects_non_visible_ascii(
    field: str,
    value: str,
) -> None:
    payload = {
        "runtime": "openclaw",
        "agent_id": "main",
        "runtime_binding_id": "binding:openclaw:main",
        "profile_id": "agentguard-openclaw-v2-restricted",
    }
    payload[field] = value

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        ProductRuntimeStatusIdentityV1.model_validate(payload)
