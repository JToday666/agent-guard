"""Product Active loader/fuse wiring at the real Guard API composition root."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guard_api.main import create_app
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

pytestmark = pytest.mark.integration


def _settings(path: Path) -> GuardApiSettings:
    shadow_secret = base64.urlsafe_b64encode(
        b"product-main-wiring-shadow-secret-01"
    ).decode("ascii")
    task_secret = base64.urlsafe_b64encode(
        b"product-main-wiring-task-secret-0001"
    ).decode("ascii")
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_mode="active",
        v21_product_activation_path=str(path),
        v21_product_activation_server_secret=(TEST_PRODUCT_ACTIVATION_SECRET_B64),
        v21_product_activation_signer_key_id="product-test-key",
        v21_shadow_server_secret=shadow_secret,
        task_scope_active_key_id="product-main-task-key",
        task_scope_keys=json.dumps({"product-main-task-key": task_secret}),
        rte05_strong_binding_enabled=True,
    )


def _event() -> dict[str, object]:
    return {
        "schema_version": "0.3",
        "event_id": "evt_product_main_wiring",
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": "trace_product_main_wiring",
        # The Product fuse must run before timestamp parsing.
        "timestamp": "not-rfc3339",
        "pre_execution": True,
        "security_context": {
            "agent_id": "main",
            "user_task": "prove composition-root containment",
        },
        "payload": {
            "tool": {"name": "safe_tool", "call_id": "call:product-main"},
            "arguments": {},
            "derived_resources": [],
        },
        "metadata": {},
    }


@pytest.mark.parametrize(
    ("record_observations", "expected_code"),
    [
        (False, "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH"),
        (True, "V21_PRODUCT_SELECTOR_NOT_WIRED"),
    ],
)
def test_create_app_arms_product_fuse_without_current_fallback(
    tmp_path: Path,
    record_observations: bool,
    expected_code: str,
) -> None:
    now = datetime.now(timezone.utc)
    fixture = build_test_product_activation(now=now)
    path = write_test_product_activation(tmp_path / "product-activation.json", fixture)
    store = MemoryControlPlaneStore()
    add_adapter_credential(
        store,
        principal_id="principal:lg",
        runtime="langgraph",
        agent_id="main",
    )
    if record_observations:
        for runtime in ("langgraph", "openclaw"):
            store.save_product_runtime_status(
                product_runtime_status_for_activation(
                    fixture,
                    runtime,
                    last_heartbeat_at=now,
                )
            )

    app = create_app(store=store, settings=_settings(path))
    with TestClient(app) as client:
        response = client.post(
            "/v1/guard/evaluate",
            headers={"Authorization": "Bearer adapter-secret"},
            json=_event(),
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == expected_code
    assert "current" not in response.text
    assert store.audit_events == []
    assert store.approvals == {}
    assert store.enforcement_bindings == {}
    assert store.memory_changes == {}
