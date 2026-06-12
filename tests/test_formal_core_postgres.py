from __future__ import annotations

import os
import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from agentguard_core.models import AuditEvent
from agentguard_core.models import SecurityContext, ToolCallEvent, ToolDescriptor
from agentguard_core.service import AgentGuardCore
from agentguard_core.settings import CoreSettings
from agentguard_core.storage.base import AuditEventFilters, EvalMetricFilters
from agentguard_core.storage.postgres import PostgresCoreStore
from guard_api.auth import ApiAuthError, CapabilityAuthService


def _event(*, trace_id: str, case_id: str, tool_name: str, arguments: dict, user_task: str) -> ToolCallEvent:
    return ToolCallEvent(
        trace_id=trace_id,
        case_id=case_id,
        attack_type="postgres_integration",
        is_malicious=True,
        security_context=SecurityContext(
            user_task=user_task,
            source_trust="untrusted",
            source_type="postgres-test",
        ),
        tool=ToolDescriptor(name=tool_name, call_id=f"call_{uuid4().hex}"),
        arguments=arguments,
    )


def test_postgres_store_exposes_sqlalchemy_lifecycle_methods() -> None:
    store = PostgresCoreStore("postgresql://postgres:123456@127.0.0.1:5432/agent_guard")

    assert callable(store.initialize)
    assert callable(store.health_check)
    assert callable(store.expire_approval)
    assert store.database_url == "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"


def test_postgres_store_persists_audit_and_approval_across_instances() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    run_id = uuid4().hex
    trace_id = f"trace_pg_{run_id}"
    case_id = f"PG-{run_id}"
    approval_id: str | None = None
    store = PostgresCoreStore(database_url)
    try:
        store.initialize()
        core = AgentGuardCore(store=store)

        decision = core.evaluate_tool_call(
            _event(
                trace_id=trace_id,
                case_id=case_id,
                tool_name="send_email",
                arguments={"to": "postgres-external@example.com"},
                user_task="Complete the visible web form only",
            )
        )

        assert decision.decision == "ask"
        assert decision.approval is not None
        approval_id = decision.approval["approval_id"]
        restarted_core = AgentGuardCore(store=PostgresCoreStore(database_url))
        audits = [event for event in restarted_core.list_audit_events() if event.trace_id == trace_id]
        approval = restarted_core.get_approval(approval_id)

        assert len(audits) == 1
        assert audits[0].case_id == case_id
        assert audits[0].decision == "ask"
        assert approval is not None
        assert approval.status == "pending"

        approval.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        store.create_approval(approval)
        expired = restarted_core.get_approval(approval_id)

        assert expired is not None
        assert expired.status == "expired"
        assert expired.decision == "deny"
        assert restarted_core.get_approval(approval_id).status == "expired"
    finally:
        _cleanup_test_rows(database_url, trace_id, approval_id)


def test_postgres_store_persists_auth_state_across_instances() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    run_id = uuid4().hex
    approval_id = f"app_pg_auth_{run_id}"
    tool_call_id = f"call_pg_auth_{run_id}"
    launch_code: str | None = None
    session_id: str | None = None
    store = PostgresCoreStore(database_url)
    try:
        store.initialize()
        settings = CoreSettings(control_token="control-secret")
        first_auth = CapabilityAuthService(settings=settings, store=store)
        launch_code = first_auth.create_launch_code()
        second_auth = CapabilityAuthService(settings=settings, store=PostgresCoreStore(database_url))
        session = second_auth.exchange_launch_code(launch_code)
        session_id = session.session_id
        third_auth = CapabilityAuthService(settings=settings, store=PostgresCoreStore(database_url))

        restored = third_auth.verify_browser_session(session.session_id)
        nonce = third_auth.issue_approval_nonce(
            approval_id=approval_id,
            session_id=session.session_id,
            tool_call_id=tool_call_id,
        )
        fourth_auth = CapabilityAuthService(settings=settings, store=PostgresCoreStore(database_url))
        fourth_auth.consume_approval_nonce(
            nonce=nonce,
            approval_id=approval_id,
            session_id=session.session_id,
            tool_call_id=tool_call_id,
        )

        assert restored.session_id == session.session_id
        assert restored.csrf_token == session.csrf_token
        with pytest.raises(ApiAuthError) as launch_error:
            first_auth.exchange_launch_code(launch_code)
        assert launch_error.value.code == "LAUNCH_CODE_INVALID"
        with pytest.raises(ApiAuthError) as nonce_error:
            third_auth.consume_approval_nonce(
                nonce=nonce,
                approval_id=approval_id,
                session_id=session.session_id,
                tool_call_id=tool_call_id,
            )
        assert nonce_error.value.code == "APPROVAL_NONCE_INVALID"
    finally:
        _cleanup_auth_rows(database_url, approval_id, launch_code, session_id)


def test_postgres_store_filters_audit_and_aggregates_metrics() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    run_id = uuid4().hex
    trace_id = f"trace_pg_metric_{run_id}"
    other_trace_id = f"trace_pg_other_{run_id}"
    store = PostgresCoreStore(database_url)
    try:
        store.initialize()
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_allow_{run_id}",
                trace_id=trace_id,
                decision="allow",
                runtime="langgraph",
                blocked=False,
                is_malicious=False,
                latency_ms=10,
            )
        )
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_deny_{run_id}",
                trace_id=trace_id,
                decision="deny",
                runtime="langgraph",
                blocked=True,
                is_malicious=True,
                latency_ms=30,
            )
        )
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_skip_{run_id}",
                trace_id=other_trace_id,
                decision="ask",
                runtime="openclaw",
                blocked=True,
                is_malicious=False,
                latency_ms=50,
            )
        )

        denied = store.list_audit_events(AuditEventFilters(trace_id=trace_id, decision="deny", limit=10))
        metrics = store.eval_metrics(EvalMetricFilters(trace_id=trace_id))

        assert [event.audit_id for event in denied] == [f"audit_pg_deny_{run_id}"]
        assert metrics["event_count"] == 2
        assert metrics["allow_count"] == 1
        assert metrics["deny_count"] == 1
        assert metrics["ask_count"] == 0
        assert metrics["blocked_count"] == 1
        assert metrics["block_rate"] == 0.5
        assert metrics["fpr"] == 0.0
        assert metrics["fnr"] == 0.0
        assert metrics["average_latency_ms"] == 20.0
    finally:
        _cleanup_test_rows(database_url, trace_id, None)
        _cleanup_test_rows(database_url, other_trace_id, None)


def test_postgres_metrics_are_not_limited_by_audit_list_default() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    run_id = uuid4().hex
    trace_id = f"trace_pg_many_{run_id}"
    store = PostgresCoreStore(database_url)
    try:
        store.initialize()
        for index in range(505):
            store.add_audit_event(
                _audit_event(
                    audit_id=f"audit_pg_many_{run_id}_{index}",
                    trace_id=trace_id,
                    decision="allow",
                    runtime="langgraph",
                    blocked=False,
                    is_malicious=False,
                    latency_ms=1,
                )
            )

        listed = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
        metrics = store.eval_metrics(EvalMetricFilters(trace_id=trace_id))

        assert len(listed) == 500
        assert metrics["event_count"] == 505
        assert metrics["allow_count"] == 505
        assert metrics["blocked_count"] == 0
    finally:
        _cleanup_test_rows(database_url, trace_id, None)


def _cleanup_test_rows(database_url: str, trace_id: str, approval_id: str | None) -> None:
    try:
        engine = create_engine(PostgresCoreStore(database_url).database_url)
        with engine.begin() as conn:
            if approval_id is not None:
                conn.execute(text("DELETE FROM approvals WHERE approval_id = :approval_id"), {"approval_id": approval_id})
            conn.execute(
                text("DELETE FROM audit_events WHERE payload_json ->> 'trace_id' = :trace_id"),
                {"trace_id": trace_id},
            )
    except Exception:
        return None


def _cleanup_auth_rows(
    database_url: str,
    approval_id: str,
    launch_code: str | None,
    session_id: str | None,
) -> None:
    try:
        engine = create_engine(PostgresCoreStore(database_url).database_url)
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    DELETE FROM approval_nonces
                    WHERE approval_id = :approval_id
                    """
                ),
                {"approval_id": approval_id},
            )
            if launch_code is not None:
                conn.execute(
                    text("DELETE FROM launch_codes WHERE code_hash = :code_hash"),
                    {"code_hash": _token_hash(launch_code)},
                )
            if session_id is not None:
                conn.execute(
                    text("DELETE FROM browser_sessions WHERE session_hash = :session_hash"),
                    {"session_hash": _token_hash(session_id)},
                )
    except Exception:
        return None


def _audit_event(
    *,
    audit_id: str,
    trace_id: str,
    decision: str,
    runtime: str,
    blocked: bool,
    is_malicious: bool | None,
    latency_ms: int,
) -> AuditEvent:
    return AuditEvent(
        audit_id=audit_id,
        trace_id=trace_id,
        case_id="PG-METRIC",
        runtime=runtime,
        summary=f"Postgres metric audit {audit_id}",
        decision=decision,  # type: ignore[arg-type]
        risk_score=90 if blocked else 0,
        severity="critical" if blocked else "low",
        blocked=blocked,
        reason="postgres metric test",
        is_malicious=is_malicious,
        latency_ms=latency_ms,
    )


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
