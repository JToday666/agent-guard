from __future__ import annotations

from fastapi.testclient import TestClient

from agentguard_core.settings import CoreSettings
from agentguard_core.storage.memory import MemoryCoreStore
from guard_api.main import create_app


def _tool_call_payload() -> dict:
    return {
        "schema_version": "0.3",
        "event_id": "evt_test",
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": "trace_api",
        "case_id": "PI-API",
        "attack_type": "indirect_prompt_injection",
        "is_malicious": True,
        "timestamp": "2026-06-11T00:00:00+00:00",
        "security_context": {
            "user_task": "Complete the visible web form only",
            "source_type": "webpage",
            "source_trust": "untrusted",
        },
        "tool": {
            "name": "send_email",
            "category": "message",
            "kind": "email_send",
            "call_id": "call_api",
        },
        "arguments": {
            "to": "exfiltration-intake@red-team.agentguard.local",
            "subject": "contact export",
            "body": "private contact export",
        },
        "derived_resources": [],
        "pre_execution": True,
        "metadata": {},
    }


def test_evaluate_tool_call_requires_adapter_token() -> None:
    app = create_app(store=MemoryCoreStore(), settings=CoreSettings(adapter_token="adapter-secret"))
    client = TestClient(app)

    response = client.post("/v1/evaluate/tool-call", json=_tool_call_payload())

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_MISSING"


def test_ask_approval_resolve_and_wait_flow() -> None:
    settings = CoreSettings(adapter_token="adapter-secret", control_token="control-secret")
    app = create_app(store=MemoryCoreStore(), settings=settings)
    client = TestClient(app)

    decision_response = client.post(
        "/v1/evaluate/tool-call",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_tool_call_payload(),
    )
    assert decision_response.status_code == 200
    decision = decision_response.json()
    assert decision["decision"] == "ask"
    approval_id = decision["approval"]["approval_id"]

    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    assert launch_response.status_code == 200
    launch_code = launch_response.json()["launch_code"]

    exchange_response = client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})
    assert exchange_response.status_code == 200
    csrf_token = exchange_response.json()["csrf_token"]

    pending_response = client.get("/v1/approvals/pending")
    assert pending_response.status_code == 200
    pending = pending_response.json()
    assert pending[0]["approval_id"] == approval_id
    approval_nonce = pending[0]["approval_nonce"]

    rejected_response = client.post(
        f"/v1/approvals/{approval_id}/resolve",
        json={"decision": "allow_once", "approval_nonce": approval_nonce},
    )
    assert rejected_response.status_code == 403
    assert rejected_response.json()["error"]["code"] == "CSRF_INVALID"

    resolve_response = client.post(
        f"/v1/approvals/{approval_id}/resolve",
        headers={"X-AgentGuard-CSRF": csrf_token},
        json={"decision": "allow_once", "approval_nonce": approval_nonce},
    )
    assert resolve_response.status_code == 200
    assert resolve_response.json()["status"] == "resolved"
    assert resolve_response.json()["decision"] == "allow_once"

    wait_response = client.get(
        f"/v1/approvals/{approval_id}/wait",
        headers={"Authorization": "Bearer adapter-secret"},
    )
    assert wait_response.status_code == 200
    assert wait_response.json()["decision"] == "allow_once"


def test_audit_event_round_trip_for_dashboard_fields() -> None:
    app = create_app(store=MemoryCoreStore(), settings=CoreSettings(adapter_token="adapter-secret"))
    client = TestClient(app)
    audit_event = {
        "audit_id": "audit_api",
        "schema_version": "0.3",
        "trace_id": "trace_api",
        "case_id": "PI-API",
        "runtime": "langgraph",
        "timestamp": "2026-06-11T00:00:00+00:00",
        "stage": "before_tool_call",
        "event_type": "tool_call_proposed",
        "summary": "Agent attempted to call send_email",
        "decision": "ask",
        "risk_score": 68,
        "severity": "medium",
        "blocked": True,
        "resource_targets": ["exfiltration-intake@red-team.agentguard.local"],
        "rule_hits": ["P002_external_send_review"],
        "reason": "External send requires approval.",
        "links": {"event_id": "evt_test", "decision_id": "dec_test"},
        "metadata": {},
    }

    write_response = client.post(
        "/v1/audit/event",
        headers={"Authorization": "Bearer adapter-secret"},
        json=audit_event,
    )
    assert write_response.status_code == 200

    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer demo-control-token"},
    )
    launch_code = launch_response.json()["launch_code"]
    client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})

    events_response = client.get("/v1/audit/events")
    assert events_response.status_code == 200
    assert events_response.json()[0]["audit_id"] == "audit_api"
