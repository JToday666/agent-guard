"""Real localhost HTTP/CSRF restricted release, with explicit controlled ASK.

This is transport evidence, not a native Host loop or browser UI qualification.
"""

from __future__ import annotations

import pytest

from guard_api.security_state import SecurityStateService
from tests.support.product_runtime_http import product_runtime_http
from tests.test_product_activation_http import (
    _event_payload,
    _heartbeat_payload,
    _task_payload,
)
from tests.test_product_v21_service_selector import _force_current_decision

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("resolution", ["allow_once", "deny"])
def test_restricted_http_launch_csrf_approval_consume_and_exact_replay(
    tmp_path, monkeypatch, resolution
):
    _force_current_decision(monkeypatch, "ask")
    with product_runtime_http(tmp_path) as http:
        client = http.client
        for runtime in ("langgraph", "openclaw"):
            heartbeat = client.post(
                f"/v1/adapters/{runtime}/heartbeat",
                headers={"Authorization": f"Bearer {http.runtime_tokens[runtime]}"},
                json=_heartbeat_payload(http.fixture, runtime),
            )
            assert heartbeat.status_code == 200
            if runtime == "openclaw":
                evaluation_ack = heartbeat.json()["activation_ack"]
        task = client.post(
            "/v1/tasks",
            headers={"Authorization": "Bearer control-secret"},
            json=_task_payload(
                "openclaw",
                http.fixture,
                trace_id=http.trace_id,
                session_id=http.session_id,
            ),
        )
        assert task.status_code == 200
        SecurityStateService(http.store).ensure_ready(task.json()["scope_digest"])
        event = _event_payload(
            "openclaw",
            "tool_call_proposed",
            task.json()["task_id"],
            trace_id=http.trace_id,
            session_id=http.session_id,
        )
        event["security_context"]["source_type"] = "user"
        event["security_context"]["source_trust"] = "trusted"
        event["payload"] = {
            "tool": {"name": "read_file", "call_id": "call:restricted-http"},
            "arguments": {"path": "/docs/approved-report.txt"},
            "derived_resources": [],
        }
        headers = {
            "Authorization": f"Bearer {http.runtime_tokens['openclaw']}",
            "X-AgentGuard-Activation-Ack": evaluation_ack["ack_token"],
        }
        evaluated = client.post("/v1/guard/evaluate", json=event, headers=headers)
        assert evaluated.status_code == 200
        body = evaluated.json()
        assert body["decision"]["decision"] == "ask"
        assert body.get("enforcement_binding") is None
        assert body["approval_release_directive"]["mode"] == "restricted_allow_once"
        assert {
            k: body["decision_authority"][k]
            for k in ("source", "mode", "selection_basis")
        } == {"source": "v21", "mode": "active", "selection_basis": "profile_all"}
        approval_id = body["approval"]["approval_id"]
        binding = http.store.get_enforcement_binding(approval_id)
        assert binding and binding.release_mode == "restricted_allow_once"
        assert binding.authorization_fingerprint not in evaluated.text

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
        pending = client.get("/v1/approvals/pending")
        assert pending.status_code == 200 and any(
            item["approval_id"] == approval_id for item in pending.json()
        )
        resolve_path = f"/v1/approvals/{approval_id}/resolve"
        rejected = client.post(
            resolve_path,
            json={"decision": resolution},
            headers={"X-AgentGuard-CSRF": "invalid-synthetic-csrf"},
        )
        assert rejected.status_code == 403
        assert http.store.get_approval(approval_id).status == "pending"
        resolved = client.post(
            resolve_path,
            json={"decision": resolution},
            headers={"X-AgentGuard-CSRF": exchange.json()["csrf_token"]},
        )
        assert resolved.status_code == 200
        assert http.store.get_approval(approval_id).resolution_source == "human"

        replay = client.post("/v1/guard/evaluate", json=event, headers=headers)
        assert replay.status_code == 200, replay.json()
        assert replay.json()["decision"] == body["decision"]
        assert replay.json().get("enforcement_binding") is None
        refreshed = http.heartbeat_openclaw()
        assert refreshed.status_code == 200
        consume_headers = {
            **headers,
            "X-AgentGuard-Activation-Ack": refreshed.json()["activation_ack"][
                "ack_token"
            ],
        }
        consume_path = f"/v1/approvals/{approval_id}/execution-leases/consume"
        consume_body = {"mode": "restricted_allow_once", "action_id": binding.action_id}
        invalid = client.post(
            consume_path,
            json={
                **consume_body,
                "authorization_fingerprint": binding.authorization_fingerprint,
            },
            headers=consume_headers,
        )
        assert invalid.status_code == 422
        assert binding.authorization_fingerprint not in invalid.text
        assert not http.store.approval_execution_was_consumed(approval_id)
        first = client.post(consume_path, json=consume_body, headers=consume_headers)
        if resolution == "deny":
            assert first.status_code == 409
            assert not http.store.approval_execution_was_consumed(approval_id)
            return
        assert first.status_code == 200
        repeated = client.post(consume_path, json=consume_body, headers=consume_headers)
        assert repeated.status_code == 200 and repeated.json() == first.json()
        assert set(first.json()) == {
            "lease_id",
            "consumption_id",
            "lease_token",
            "expires_at",
        }
        assert binding.authorization_fingerprint not in first.text
        requests = [
            item for item in http.requests_for(consume_path) if item.status_code == 200
        ]
        assert len(requests) == 2
        assert requests[0].body == requests[1].body == consume_body
        assert requests[0].activation_ack_header == requests[1].activation_ack_header
