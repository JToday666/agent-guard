"""Guard API integration tests for Product V2 runtime status heartbeats."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agentguard_core import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    RuntimeEventCapabilityV2,
    build_runtime_capability_report,
    openclaw_event_residual_boundaries,
)
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from guard_api.main import create_app
import guard_api.routers.system as system_routes
from guard_api.runtime_status import ProductRuntime
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential, memory_store_with_adapter

pytestmark = pytest.mark.integration

_DIGEST = "sha256:" + "b" * 64
_SERVER_TIME = "2026-09-01T08:00:00+00:00"
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
            enforcement=enforcement[event_type],  # type: ignore[arg-type]
            residual_boundaries=(
                list(openclaw_event_residual_boundaries(event_type))
                if runtime == "openclaw"
                else []
            ),
        )
        for event_type in PRODUCT_EVENT_TYPES
    ]


def _heartbeat_payload(
    *,
    runtime: ProductRuntime = "openclaw",
    agent_id: str = "main",
    runtime_binding_id: str | None = None,
    runtime_id: str = "openclaw-gateway",
) -> dict:
    observed_binding_id = runtime_binding_id or f"binding:{runtime}:{agent_id}"
    report = build_runtime_capability_report(
        runtime=runtime,
        agent_id=agent_id,
        runtime_binding_id=observed_binding_id,
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
    return {
        "schema_version": "2.0",
        "status": "loaded",
        "loaded": True,
        "runtime_id": runtime_id,
        "agent_id": agent_id,
        "runtime_binding_id": observed_binding_id,
        "profile_id": _PROFILE_IDS[runtime],
        "runtime_version": _RUNTIME_VERSIONS[runtime],
        "plugin_version": _PLUGIN_VERSIONS[runtime],
        "profile_digest": _DIGEST,
        "adapter_artifact_digest": _DIGEST,
        "reported_activation_ref_digest": _DIGEST,
        "host_inventory_digest": _DIGEST,
        "plugin_inventory_digest": _DIGEST if runtime == "openclaw" else None,
        "plugin_order_inventory_digest": (_DIGEST if runtime == "openclaw" else None),
        "tool_inventory_digest": _DIGEST,
        "capability_report": report.model_dump(mode="json"),
        "source": "api-test",
        "hook_count": 2,
        "expected_hook_count": 2,
        "hooks": ["before_tool_call", "message_sending"],
        "fail_closed_stages": ["before_tool_call", "message_sending"],
        "enforcement_mode": "enforce",
    }


def _app() -> tuple[MemoryControlPlaneStore, TestClient]:
    store = memory_store_with_adapter(
        runtime="openclaw",
        agent_id="main",
        principal_id="cred_adapter_main",
    )
    app = create_app(
        store=store,
        settings=GuardApiSettings(control_token="control-secret"),
    )
    return store, TestClient(app)


def _login_dashboard(client: TestClient) -> None:
    launch = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    assert launch.status_code == 200
    exchange = client.post(
        "/v1/auth/browser/exchange",
        json={"launch_code": launch.json()["launch_code"]},
    )
    assert exchange.status_code == 200


def test_product_heartbeat_injects_server_identity_time_and_dual_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client = _app()
    monkeypatch.setattr(system_routes, "utc_now_iso", lambda: _SERVER_TIME)

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_heartbeat_payload(),
    )

    assert response.status_code == 200
    assert set(response.json()) == {"runtime_status"}
    status = response.json()["runtime_status"]
    assert status["runtime"] == "openclaw"
    assert status["principal_id"] == "cred_adapter_main"
    assert status["agent_id"] == "main"
    assert status["runtime_binding_id"] == "binding:openclaw:main"
    assert status["runtime_binding_id"] != f"binding:{status['principal_id']}"
    assert status["last_heartbeat_at"] == _SERVER_TIME
    serialized = json.dumps(response.json(), sort_keys=True)
    assert "activation_ack" not in serialized
    assert "restricted_ask_release" not in serialized

    rows = store.list_product_runtime_statuses(runtime="openclaw")
    assert [row.model_dump(mode="json") for row in rows] == [status]
    legacy = store.get_adapter_status("openclaw")
    assert legacy is not None
    assert legacy["last_heartbeat_at"] == _SERVER_TIME
    assert legacy["capabilities"] == {"event_types": list(PRODUCT_EVENT_TYPES)}
    assert "runtime_binding_id" not in legacy
    assert "profile_id" not in legacy


def test_product_heartbeat_persists_observed_version_drift_without_admission() -> None:
    store, client = _app()
    payload = _heartbeat_payload()
    payload["runtime_version"] = "2026.7.1-drift"
    payload["plugin_version"] = "0.1.0-rc.drift"

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )

    assert response.status_code == 200
    status = response.json()["runtime_status"]
    assert status["runtime_version"] == "2026.7.1-drift"
    assert status["plugin_version"] == "0.1.0-rc.drift"
    assert store.list_product_runtime_statuses()[0].runtime_version == (
        "2026.7.1-drift"
    )


def test_product_heartbeat_records_inventory_discovery_failure() -> None:
    store, client = _app()
    payload = _heartbeat_payload()
    payload.update(
        {
            "status": "error",
            "loaded": False,
            "reported_activation_ref_digest": None,
            "host_inventory_digest": None,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": None,
            "capability_report": None,
            "error": "inventory discovery failed",
            "hook_count": 0,
            "hooks": [],
            "fail_closed_stages": [],
            "enforcement_mode": "disabled",
        }
    )

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )

    assert response.status_code == 200
    status = response.json()["runtime_status"]
    assert status["error"] == "inventory discovery failed"
    assert status["host_inventory_digest"] is None
    assert status["tool_inventory_digest"] is None
    assert status["capability_report"] is None
    legacy = store.get_adapter_status("openclaw")
    assert legacy is not None
    assert legacy["status"] == "error"
    assert legacy["capabilities"] == {"event_types": []}


@pytest.mark.parametrize(
    "caller_time",
    ["2000-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"],
)
def test_legacy_heartbeat_always_overwrites_caller_time(
    monkeypatch: pytest.MonkeyPatch,
    caller_time: str,
) -> None:
    store, client = _app()
    monkeypatch.setattr(system_routes, "utc_now_iso", lambda: _SERVER_TIME)

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json={
            "status": "loaded",
            "loaded": True,
            "runtime_id": "legacy-gateway",
            "agent_id": "main",
            "last_heartbeat_at": caller_time,
        },
    )

    assert response.status_code == 200
    assert "runtime_status" not in response.json()
    assert response.json()["last_heartbeat_at"] == _SERVER_TIME
    assert store.get_adapter_status("openclaw")["last_heartbeat_at"] == _SERVER_TIME  # type: ignore[index]
    assert store.list_product_runtime_statuses() == []


def test_legacy_status_put_cannot_write_heartbeat_freshness() -> None:
    store, client = _app()

    response = client.put(
        "/v1/adapters/openclaw/status",
        headers={"Authorization": "Bearer adapter-secret"},
        json={
            "status": "loaded",
            "loaded": True,
            "runtime_id": "legacy-telemetry",
            "agent_id": "main",
            "last_heartbeat_at": "2099-01-01T00:00:00+00:00",
        },
    )

    assert response.status_code == 200
    assert response.json()["last_heartbeat_at"] is None
    assert store.get_adapter_status("openclaw")["last_heartbeat_at"] is None  # type: ignore[index]
    assert store.list_product_runtime_statuses() == []


def test_legacy_status_put_preserves_existing_server_heartbeat_and_product_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client = _app()
    monkeypatch.setattr(system_routes, "utc_now_iso", lambda: _SERVER_TIME)
    heartbeat = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_heartbeat_payload(),
    )
    assert heartbeat.status_code == 200
    product_before = store.list_product_runtime_statuses(runtime="openclaw")

    response = client.put(
        "/v1/adapters/openclaw/status",
        headers={"Authorization": "Bearer adapter-secret"},
        json={
            "status": "loaded",
            "loaded": True,
            "runtime_id": "release-gate-update",
            "agent_id": "main",
            "last_heartbeat_at": "2099-01-01T00:00:00+00:00",
        },
    )

    assert response.status_code == 200
    assert response.json()["runtime_id"] == "release-gate-update"
    assert response.json()["last_heartbeat_at"] == _SERVER_TIME
    assert store.get_adapter_status("openclaw")["last_heartbeat_at"] == _SERVER_TIME  # type: ignore[index]
    assert store.list_product_runtime_statuses(runtime="openclaw") == product_before


@pytest.mark.parametrize(
    ("path_runtime", "payload", "token", "expected_code"),
    [
        (
            "openclaw",
            _heartbeat_payload(agent_id="different-agent"),
            "adapter-secret",
            "RUNTIME_IDENTITY_MISMATCH",
        ),
        (
            "langgraph",
            _heartbeat_payload(),
            "adapter-secret",
            "RUNTIME_IDENTITY_MISMATCH",
        ),
        (
            "openclaw",
            _heartbeat_payload(),
            "control-secret",
            "CREDENTIAL_IDENTITY_INCOMPLETE",
        ),
    ],
)
def test_product_heartbeat_requires_authenticated_runtime_and_agent(
    path_runtime: str,
    payload: dict,
    token: str,
    expected_code: str,
) -> None:
    store, client = _app()

    response = client.post(
        f"/v1/adapters/{path_runtime}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == expected_code
    assert store.list_product_runtime_statuses() == []
    assert store.get_adapter_status(path_runtime) is None


@pytest.mark.parametrize(
    "server_field", ["runtime", "principal_id", "last_heartbeat_at"]
)
def test_product_heartbeat_rejects_server_owned_fields(server_field: str) -> None:
    store, client = _app()
    payload = _heartbeat_payload()
    payload[server_field] = "caller-controlled"

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert store.list_product_runtime_statuses() == []


def test_product_heartbeat_requires_explicit_v2_discriminator() -> None:
    store, client = _app()
    payload = _heartbeat_payload()
    payload.pop("schema_version")

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )

    assert response.status_code == 422
    assert store.list_product_runtime_statuses() == []


def test_product_heartbeat_rejects_report_runtime_different_from_path() -> None:
    store, client = _app()

    response = client.post(
        "/v1/adapters/openclaw/heartbeat",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_heartbeat_payload(runtime="langgraph"),
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert store.list_product_runtime_statuses() == []
    assert store.get_adapter_status("openclaw") is None


def test_exact_status_and_plural_list_are_additive_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, client = _app()
    add_adapter_credential(
        store,
        token="adapter-b-secret",
        runtime="openclaw",
        agent_id="agent-b",
        principal_id="cred-b",
    )
    monkeypatch.setattr(system_routes, "utc_now_iso", lambda: _SERVER_TIME)
    first_payload = _heartbeat_payload(runtime_id="host-a")
    second_payload = _heartbeat_payload(
        agent_id="agent-b",
        runtime_id="host-b",
    )
    assert (
        client.post(
            "/v1/adapters/openclaw/heartbeat",
            headers={"Authorization": "Bearer adapter-secret"},
            json=first_payload,
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/v1/adapters/openclaw/heartbeat",
            headers={"Authorization": "Bearer adapter-b-secret"},
            json=second_payload,
        ).status_code
        == 200
    )
    control_headers = {"Authorization": "Bearer control-secret"}

    exact = client.get(
        "/v1/adapters/openclaw/status",
        headers=control_headers,
        params={
            "agent_id": "main",
            "runtime_binding_id": "binding:openclaw:main",
            "profile_id": "agentguard-openclaw-v2-restricted",
        },
    )
    legacy = client.get(
        "/v1/adapters/openclaw/status",
        headers=control_headers,
    )
    limited = client.get(
        "/v1/adapters/openclaw/statuses?limit=1",
        headers=control_headers,
    )

    assert exact.status_code == 200
    assert exact.json()["runtime_id"] == "host-a"
    assert legacy.status_code == 200
    assert legacy.json()["runtime_id"] == "host-b"
    assert limited.status_code == 200
    assert isinstance(limited.json(), list)
    assert [row["runtime_id"] for row in limited.json()] == ["host-b"]
    assert all("runtime_status" not in row for row in limited.json())

    for invalid_limit in (0, 501, "true"):
        response = client.get(
            f"/v1/adapters/openclaw/statuses?limit={invalid_limit}",
            headers=control_headers,
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize(
    "params",
    [
        {"agent_id": "main"},
        {"runtime_binding_id": "binding:cred_adapter_main"},
        {"profile_id": "agentguard-openclaw-v2-restricted"},
        {"agent_id": "main", "runtime_binding_id": "binding:cred_adapter_main"},
        {"agent_id": "main", "profile_id": "agentguard-openclaw-v2-restricted"},
        {
            "runtime_binding_id": "binding:cred_adapter_main",
            "profile_id": "agentguard-openclaw-v2-restricted",
        },
        {
            "agent_id": "",
            "runtime_binding_id": "binding:cred_adapter_main",
            "profile_id": "agentguard-openclaw-v2-restricted",
        },
    ],
)
def test_exact_status_rejects_partial_or_empty_identity(params: dict[str, str]) -> None:
    _, client = _app()

    response = client.get(
        "/v1/adapters/openclaw/status",
        headers={"Authorization": "Bearer control-secret"},
        params=params,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_exact_missing_is_404_while_legacy_missing_remains_unknown() -> None:
    _, client = _app()
    headers = {"Authorization": "Bearer control-secret"}

    legacy = client.get("/v1/adapters/openclaw/status", headers=headers)
    exact = client.get(
        "/v1/adapters/openclaw/status",
        headers=headers,
        params={
            "agent_id": "missing-agent",
            "runtime_binding_id": "binding:missing-principal",
            "profile_id": "agentguard-openclaw-v2-restricted",
        },
    )

    assert legacy.status_code == 200
    assert legacy.json()["status"] == "unknown"
    assert exact.status_code == 404
    assert exact.json()["error"]["code"] == "NOT_FOUND"


def test_product_status_list_uses_control_or_browser_read_auth() -> None:
    _, client = _app()

    missing = client.get("/v1/adapters/openclaw/statuses")
    adapter = client.get(
        "/v1/adapters/openclaw/statuses",
        headers={"Authorization": "Bearer adapter-secret"},
    )
    control = client.get(
        "/v1/adapters/openclaw/statuses",
        headers={"Authorization": "Bearer control-secret"},
    )
    invalid_runtime = client.get(
        "/v1/adapters/unknown/statuses",
        headers={"Authorization": "Bearer control-secret"},
    )
    _login_dashboard(client)
    browser = client.get("/v1/adapters/openclaw/statuses")

    assert missing.status_code == 401
    assert adapter.status_code == 403
    assert adapter.json()["error"]["code"] == "SCOPE_DENIED"
    assert control.status_code == 200
    assert control.json() == []
    assert invalid_runtime.status_code == 422
    assert browser.status_code == 200
    assert browser.json() == []
