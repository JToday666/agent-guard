from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from agentguard_core import AuditEvent, PolicyBundle
from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.main import create_app
from guard_api.models import ApprovalRequest
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import AuditEventFilters, EvalMetricFilters
from guard_api.storage.postgres import PostgresControlPlaneStore


def test_postgres_store_exposes_control_plane_lifecycle_methods() -> None:
    store = PostgresControlPlaneStore("postgresql://postgres:123456@127.0.0.1:5432/agent_guard")

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
    approval_id = f"app_pg_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
        store.initialize()
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_{run_id}",
                trace_id=trace_id,
                decision="ask",
                runtime="langgraph",
                blocked=True,
                is_malicious=True,
                latency_ms=10,
            )
        )
        store.create_approval(
            ApprovalRequest(
                approval_id=approval_id,
                trace_id=trace_id,
                tool_call_id=f"call_pg_{run_id}",
                requesting_principal_id="cred_adapter_main",
                runtime="langgraph",
                agent_id="main",
                tool="send_email",
                resource="external@example.com",
                reason="approval required",
                risk_score=62,
                severity="medium",
            )
        )

        restarted_store = PostgresControlPlaneStore(database_url)
        audits = restarted_store.list_audit_events(AuditEventFilters(trace_id=trace_id))
        approvals = restarted_store.list_approvals(trace_id=trace_id)
        approval = restarted_store.get_approval(approval_id)

        assert [event.trace_id for event in audits] == [trace_id]
        assert [item.approval_id for item in approvals] == [approval_id]
        assert approval is not None
        assert approval.status == "pending"
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
    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
        store.initialize()
        settings = GuardApiSettings(control_token="control-secret")
        first_auth = CapabilityAuthService(settings=settings, store=store)
        launch_code = first_auth.create_launch_code()
        second_auth = CapabilityAuthService(settings=settings, store=PostgresControlPlaneStore(database_url))
        session = second_auth.exchange_launch_code(launch_code)
        session_id = session.session_id
        third_auth = CapabilityAuthService(settings=settings, store=PostgresControlPlaneStore(database_url))

        restored = third_auth.verify_browser_session(session.session_id)
        nonce = third_auth.issue_approval_nonce(
            approval_id=approval_id,
            session_id=session.session_id,
            tool_call_id=tool_call_id,
        )
        fourth_auth = CapabilityAuthService(settings=settings, store=PostgresControlPlaneStore(database_url))
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
    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
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


def test_postgres_store_persists_policy_snapshot_across_instances() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
        store.initialize()
        first_record = store.save_policy_snapshot(
            PolicyBundle(
                bundle_id="pg-policy-1",
                allowed_email_domains=["pg.example"],
                sensitive_text_markers=["pg-secret="],
            ),
            updated_by="tester",
        )
        second_record = store.save_policy_snapshot(
            PolicyBundle(
                bundle_id="pg-policy-2",
                allowed_email_domains=["pg.example"],
                sensitive_text_markers=["pg-secret="],
            ),
            updated_by="tester",
        )

        restarted_store = PostgresControlPlaneStore(database_url)
        snapshot = restarted_store.get_policy_snapshot()
        history = restarted_store.list_policy_snapshot_history()

        assert first_record.revision == 1
        assert second_record.revision == 2
        assert snapshot is not None
        assert snapshot.bundle_id == "pg-policy-2"
        assert snapshot.allowed_email_domains == ["pg.example"]
        assert snapshot.sensitive_text_markers == ["pg-secret="]
        assert [record.revision for record in history] == [2, 1]
        assert [record.policy_bundle.bundle_id for record in history] == ["pg-policy-2", "pg-policy-1"]
        assert {record.updated_by for record in history} == {"tester"}
    finally:
        _cleanup_policy_snapshot(database_url)


def test_postgres_migration_creates_policy_snapshots_table() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
        store.initialize()
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            exists = conn.execute(text("SELECT to_regclass('public.policy_snapshots')")).scalar_one()
            history_exists = conn.execute(
                text("SELECT to_regclass('public.policy_snapshot_history')")
            ).scalar_one()
            columns = {
                row[0]
                for row in conn.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'policy_snapshots'
                        """
                    )
                )
            }

        assert exists == "policy_snapshots"
        assert history_exists == "policy_snapshot_history"
        assert {"revision", "updated_by"}.issubset(columns)
    finally:
        _cleanup_policy_snapshot(database_url)


def test_postgres_trace_route_aggregates_audit_approval_and_metrics() -> None:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")

    run_id = uuid4().hex
    trace_id = f"trace_pg_route_{run_id}"
    approval_id = f"app_pg_route_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        _reset_control_plane_schema(database_url)
        store.initialize()
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_route_{run_id}",
                trace_id=trace_id,
                decision="ask",
                runtime="langgraph",
                blocked=True,
                is_malicious=True,
                latency_ms=15,
            )
        )
        store.create_approval(
            ApprovalRequest(
                approval_id=approval_id,
                trace_id=trace_id,
                tool_call_id=f"call_pg_route_{run_id}",
                requesting_principal_id="cred_adapter_main",
                runtime="langgraph",
                agent_id="main",
                tool="send_email",
                resource="external@example.com",
                reason="approval required",
                risk_score=62,
                severity="medium",
            )
        )
        client = TestClient(
            create_app(
                store=PostgresControlPlaneStore(database_url),
                settings=GuardApiSettings(control_token="control-secret"),
            )
        )
        _login_dashboard(client, control_token="control-secret")

        trace_response = client.get(f"/v1/traces/{trace_id}")

        assert trace_response.status_code == 200
        trace = trace_response.json()
        assert trace["trace_id"] == trace_id
        assert [event["audit_id"] for event in trace["audit_events"]] == [f"audit_pg_route_{run_id}"]
        assert [approval["approval_id"] for approval in trace["approvals"]] == [approval_id]
        assert trace["metrics"]["event_count"] == 1
        assert trace["metrics"]["ask_count"] == 1
    finally:
        _cleanup_test_rows(database_url, trace_id, approval_id)


def _cleanup_test_rows(database_url: str, trace_id: str, approval_id: str | None) -> None:
    try:
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            if approval_id is not None:
                conn.execute(
                    text("DELETE FROM approval_requests WHERE approval_id = :approval_id"),
                    {"approval_id": approval_id},
                )
            conn.execute(
                text("DELETE FROM audit_events WHERE payload_json ->> 'trace_id' = :trace_id"),
                {"trace_id": trace_id},
            )
    except Exception:
        return None


def _reset_control_plane_schema(database_url: str) -> None:
    engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
    with engine.begin() as conn:
        for table in [
            "policy_snapshot_history",
            "policy_snapshots",
            "approval_nonces",
            "browser_sessions",
            "launch_codes",
            "approval_requests",
            "approvals",
            "audit_events",
            "alembic_version",
        ]:
            conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))


def _cleanup_auth_rows(
    database_url: str,
    approval_id: str,
    launch_code: str | None,
    session_id: str | None,
) -> None:
    try:
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM approval_nonces WHERE approval_id = :approval_id"),
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


def _cleanup_policy_snapshot(database_url: str) -> None:
    try:
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM policy_snapshot_history"))
            conn.execute(text("DELETE FROM policy_snapshots"))
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


def _login_dashboard(client: TestClient, *, control_token: str) -> None:
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": f"Bearer {control_token}"},
    )
    assert launch_response.status_code == 200
    exchange_response = client.post(
        "/v1/auth/browser/exchange",
        json={"launch_code": launch_response.json()["launch_code"]},
    )
    assert exchange_response.status_code == 200
