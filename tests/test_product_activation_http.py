"""Public HTTP coverage for Product V2 Active heartbeat-to-evaluate wiring."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import pytest
from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from fastapi.testclient import TestClient

from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

pytestmark = pytest.mark.integration

Runtime = Literal["langgraph", "openclaw"]

_CONTROL_HEADERS = {"Authorization": "Bearer control-secret"}
_TASK_SCOPE_KEY_ID = "product-http-task-key"
_TASK_SCOPE_KEY_B64 = base64.urlsafe_b64encode(
    b"product-http-task-scope-secret-material-01"
).decode("ascii")
_SHADOW_SECRET_B64 = base64.urlsafe_b64encode(
    b"product-http-independent-shadow-secret-01"
).decode("ascii")
_ACTION_TYPES = [
    "context_build",
    "memory_write",
    "message_send",
    "model_call",
    "tool_call",
    "tool_result",
]


def _settings(
    activation_path: Path,
    fixture: ProductActivationFixture,
) -> GuardApiSettings:
    return GuardApiSettings(
        storage_backend="memory",
        control_token="control-secret",
        v21_mode="active",
        v21_product_activation_path=str(activation_path),
        v21_product_activation_server_secret=TEST_PRODUCT_ACTIVATION_SECRET_B64,
        v21_product_activation_signer_key_id=fixture.signer_key_id,
        v21_shadow_server_secret=_SHADOW_SECRET_B64,
        task_scope_active_key_id=_TASK_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({_TASK_SCOPE_KEY_ID: _TASK_SCOPE_KEY_B64}),
        rte05_strong_binding_enabled=True,
    )


def _heartbeat_payload(
    fixture: ProductActivationFixture,
    runtime: Runtime,
) -> dict[str, Any]:
    status = product_runtime_status_for_activation(fixture, runtime)
    return status.model_dump(
        mode="json",
        exclude={"runtime", "principal_id", "last_heartbeat_at"},
    )


def _safe_payload(event_type: str) -> dict[str, Any]:
    payloads: dict[str, dict[str, Any]] = {
        "tool_call_proposed": {
            "tool": {
                "name": "safe_product_http_tool",
                "call_id": "call:product-http-tool",
            },
            "arguments": {},
            "derived_resources": [],
        },
        "context_assembled": {
            "sources": [],
            "will_enter_context": True,
            "sanitized": True,
        },
        "model_input_prepared": {
            "phase": "input",
            "content_preview": "safe model input",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": True,
        },
        "model_output_produced": {
            "phase": "output",
            "content_preview": "safe model output",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": True,
        },
        "tool_result_produced": {
            "tool": {
                "name": "safe_product_http_tool",
                "call_id": "call:product-http-result",
            },
            "result": {
                "content_preview": "safe tool result",
                "content_type": "text/plain",
                "size_bytes": 16,
            },
            "will_enter_context": False,
            "will_persist": False,
            "sanitized": True,
            "contains_sensitive_data": False,
            "contains_instruction_like_text": False,
        },
        "memory_write_proposed": {
            "memory": {
                "namespace": "product-http",
                "key": "safe-key",
                "value_preview": "safe value",
                "source_trust": "trusted",
                "operation": "write",
            },
            "will_persist": True,
            "requires_approval": False,
        },
        "message_send_proposed": {
            "channel": "test",
            "recipient": "recipient:internal",
            "content_preview": "safe message",
        },
    }
    return payloads[event_type]


def _task_payload(
    runtime: Runtime,
    fixture: ProductActivationFixture,
    *,
    trace_id: str,
    session_id: str,
) -> dict[str, Any]:
    entry = fixture.bundle.runtime_entry(runtime)
    return {
        "task_text": "exercise the public Product Active HTTP chain",
        "runtime": runtime,
        "runtime_binding_id": entry.runtime_binding_id,
        "trace_id": trace_id,
        "session_id": session_id,
        "action_constraints": [{"action_types": _ACTION_TYPES}],
        "resource_constraints": [],
        "destination_constraints": [],
    }


def _event_payload(
    runtime: Runtime,
    event_type: str,
    task_id: str,
    *,
    trace_id: str,
    session_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": "0.3",
        "event_id": f"evt:product-http:{runtime}:{event_type}",
        "event_type": event_type,
        "runtime": runtime,
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pre_execution": event_type
        not in {"model_output_produced", "tool_result_produced"},
        "security_context": {
            "agent_id": "main",
            "session_id": session_id,
            "user_task": "exercise the public Product Active HTTP chain",
            "source_type": "user",
            "source_trust": "trusted",
        },
        "payload": _safe_payload(event_type),
        "metadata": {"task_id": task_id},
    }


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("event_type", PRODUCT_EVENT_TYPES)
def test_product_active_http_heartbeat_task_and_all_events_use_v2_authority(
    tmp_path: Path,
    runtime: Runtime,
    event_type: str,
) -> None:
    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = write_test_product_activation(
        tmp_path / f"product-http-{runtime}-{event_type}.json",
        fixture,
    )
    store = MemoryControlPlaneStore()
    store.save_policy_snapshot(
        policy,
        expected_revision=0,
        updated_by="product-http-test",
    )

    runtime_tokens: dict[Runtime, str] = {
        "langgraph": "product-http-langgraph-secret",
        "openclaw": "product-http-openclaw-secret",
    }
    for observed_runtime in ("langgraph", "openclaw"):
        entry = fixture.bundle.runtime_entry(observed_runtime)
        add_adapter_credential(
            store,
            token=runtime_tokens[observed_runtime],
            runtime=observed_runtime,
            agent_id=entry.agent_id,
            principal_id=entry.principal_id,
        )

    trace_id = f"trace:product-http:{runtime}:{event_type}"
    session_id = f"session:product-http:{runtime}:{event_type}"
    app = create_app(store=store, settings=_settings(activation_path, fixture))
    with TestClient(app) as client:
        activation_acks: dict[Runtime, dict[str, Any]] = {}
        for observed_runtime in ("langgraph", "openclaw"):
            heartbeat = client.post(
                f"/v1/adapters/{observed_runtime}/heartbeat",
                headers={
                    "Authorization": f"Bearer {runtime_tokens[observed_runtime]}"
                },
                json=_heartbeat_payload(fixture, observed_runtime),
            )
            assert heartbeat.status_code == 200, heartbeat.text
            assert heartbeat.headers["cache-control"] == "no-store"
            heartbeat_body = heartbeat.json()
            assert set(heartbeat_body) == {"runtime_status", "activation_ack"}
            ack = heartbeat_body["activation_ack"]
            entry = fixture.bundle.runtime_entry(observed_runtime)
            assert ack["runtime"] == observed_runtime
            assert ack["agent_id"] == entry.agent_id
            assert ack["runtime_binding_id"] == entry.runtime_binding_id
            assert ack["profile_id"] == entry.profile_id
            assert (
                ack["activation_ref_digest"]
                == fixture.bundle.activation_ref_digest
            )
            activation_acks[observed_runtime] = ack

        task = client.post(
            "/v1/tasks",
            headers=_CONTROL_HEADERS,
            json=_task_payload(
                runtime,
                fixture,
                trace_id=trace_id,
                session_id=session_id,
            ),
        )
        assert task.status_code == 200, task.text
        task_body = task.json()
        assert task_body["status"] == "active"
        # Product evaluation requires a reconciled online-state anchor.  There
        # is intentionally no public mutation route for this internal state;
        # initialize the empty scope after proving TaskFact creation over HTTP.
        SecurityStateService(store).ensure_ready(task_body["scope_digest"])

        evaluated = client.post(
            "/v1/guard/evaluate",
            headers={
                "Authorization": f"Bearer {runtime_tokens[runtime]}",
                "X-AgentGuard-Activation-Ack": activation_acks[runtime][
                    "ack_token"
                ],
            },
            json=_event_payload(
                runtime,
                event_type,
                task_body["task_id"],
                trace_id=trace_id,
                session_id=session_id,
            ),
        )

    assert evaluated.status_code == 200, evaluated.text
    body = evaluated.json()
    assert body["decision"]["decision_id"].startswith("dec:v21-product:")
    authority = body["decision_authority"]
    assert authority["source"] == "v21"
    assert authority["mode"] == "active"
    assert authority["selection_basis"] == "profile_all"
    assert authority["matched_path_ids"] == []
    assert authority["activation_ref_digest"] == (
        fixture.bundle.activation_ref_digest
    )
    assert authority["legacy_floor_applied"] is False
    directive = body["approval_release_directive"]
    assert directive["activation_ref_digest"] == (
        fixture.bundle.activation_ref_digest
    )
    assert directive["capability_digest"] == (
        fixture.bundle.runtime_entry(runtime).capability_report_digest
    )
    assert "current" not in json.dumps(authority, sort_keys=True)

    audit = store.get_policy_evaluation_by_event_id(
        f"evt:product-http:{runtime}:{event_type}"
    )
    assert audit is not None
    assert audit.metadata["product_authority_digest"].startswith("sha256:")
    assert audit.metadata["product_replay_authority_digest"].startswith("sha256:")
