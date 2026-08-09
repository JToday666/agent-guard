from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from uuid import uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from agentguard_core import AuditEvent, PolicyBundle
from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.main import create_app
from guard_api.models import ApprovalRequest
from guard_api.services.metric_rules import aggregate_policy_metrics
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditEventFilters,
    AuditIdConflictError,
    AuditWindowQuery,
    PolicyRevisionConflictError,
)
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import (
    get_test_database_url,
    reset_control_plane_schema,
)


def test_postgres_store_exposes_control_plane_lifecycle_methods() -> None:
    store = PostgresControlPlaneStore(
        "postgresql://postgres:123456@127.0.0.1:5432/agent_guard"
    )

    assert callable(store.initialize)
    assert callable(store.health_check)
    assert callable(store.resolve_approval)
    assert (
        store.database_url
        == "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
    )


def test_postgres_store_persists_audit_and_approval_across_instances() -> None:
    database_url = get_test_database_url()

    run_id = uuid4().hex
    trace_id = f"trace_pg_{run_id}"
    approval_id = f"app_pg_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
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
                subject_id=f"call_pg_{run_id}",
                subject_type="tool_call",
                action_id=f"call_pg_{run_id}",
                action_name="send_email",
                requesting_principal_id="cred_adapter_main",
                runtime="langgraph",
                agent_id="main",
                resource="external@example.com",
                reason="approval required",
                risk_score=62,
                severity="medium",
                expires_at="2099-01-01T00:00:00+00:00",
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
    database_url = get_test_database_url()

    launch_code: str | None = None
    session_id: str | None = None
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        settings = GuardApiSettings(control_token="control-secret")
        first_auth = CapabilityAuthService(settings=settings, store=store)
        launch_code = first_auth.create_launch_code()
        second_auth = CapabilityAuthService(
            settings=settings, store=PostgresControlPlaneStore(database_url)
        )
        session = second_auth.exchange_launch_code(launch_code)
        session_id = session.session_id
        third_auth = CapabilityAuthService(
            settings=settings, store=PostgresControlPlaneStore(database_url)
        )

        restored = third_auth.verify_browser_session(session.session_id)

        assert restored.session_id == session.session_id
        assert restored.csrf_token == session.csrf_token
        with pytest.raises(ApiAuthError) as launch_error:
            first_auth.exchange_launch_code(launch_code)
        assert launch_error.value.code == "LAUNCH_CODE_INVALID"
    finally:
        _cleanup_auth_rows(database_url, launch_code, session_id)


def test_postgres_store_roundtrips_dashboard_todo_state() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        evaluation = store.save_evaluation_run(
            {
                "run_id": "eval_pg_latest",
                "run_at": "2026-06-28T00:00:00+00:00",
                "asr_before": 0.75,
                "asr_after": 0.05,
                "per_attack": {
                    "prompt_injection": {"asr_before": 0.8, "asr_after": 0.1}
                },
                "cases": [
                    {
                        "case_id": "PI-PG",
                        "attack_type": "prompt_injection",
                        "runtime": "openclaw",
                        "expected_decision": "deny",
                        "actual_decision": "deny",
                        "blocked": True,
                        "attack_success": False,
                        "trace_id": "trace_pg_eval",
                    }
                ],
            }
        )
        store.save_adapter_status(
            "openclaw",
            {
                "status": "loaded",
                "loaded": True,
                "hook_count": 16,
                "expected_hook_count": 16,
                "last_verified_at": "2026-06-28T00:01:00+00:00",
                "error": None,
                "source": "agentguardctl",
            },
        )

        from agentguard_core import ConfigAuditEvent, ConfigAuditFinding

        event = ConfigAuditEvent(
            event_id="cfg_pg_findings",
            runtime="openclaw",
            target_type="plugin_config",
            target_id="agentguard-security",
            action="before_install",
            metadata={"trace_id": "trace_pg_findings"},
            timestamp="2026-06-28T00:02:00+00:00",
        )
        finding = ConfigAuditFinding(
            finding_id="finding_pg_high",
            severity="high",
            category="openclaw.plugin",
            title="Raw conversation access enabled",
            subject="hooks.allowConversationAccess",
            description="Plugin can read raw conversation content.",
        )
        store.add_config_audit_finding(event, finding)

        restarted = PostgresControlPlaneStore(database_url)
        latest = restarted.get_latest_evaluation_run()
        status = restarted.get_adapter_status("openclaw")
        findings = restarted.list_config_audit_findings(
            trace_id="trace_pg_findings",
            target_id="agentguard-security",
            severity="high",
            limit=10,
        )

        assert evaluation["run_id"] == "eval_pg_latest"
        assert latest is not None
        assert latest["run_id"] == "eval_pg_latest"
        assert latest["cases"][0]["trace_id"] == "trace_pg_eval"
        assert status is not None
        assert status["status"] == "loaded"
        assert status["hook_count"] == 16
        assert len(findings) == 1
        assert findings[0].trace_id == "trace_pg_findings"
        assert findings[0].finding.finding_id == "finding_pg_high"
    finally:
        reset_control_plane_schema(database_url)


def test_postgres_migration_promotes_state_and_canonicalizes_json_contracts() -> None:
    database_url = get_test_database_url()

    run_id = uuid4().hex
    approval_id = f"app_pg_state_{run_id}"
    trace_id = f"trace_pg_state_{run_id}"
    subject_id = f"call_pg_state_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        command.upgrade(store._alembic_config(), "0007_policy_eval_unique_event")
        approval_payload = {
            "approval_id": approval_id,
            "trace_id": trace_id,
            "subject_id": subject_id,
            "subject_type": "tool_call",
            "action_id": subject_id,
            "action_name": "send_email",
            "tool_call_id": subject_id,
            "requesting_principal_id": "cred_adapter_main",
            "runtime": "langgraph",
            "agent_id": "main",
            "status": "pending",
            "decision_options": ["allow_once", "deny"],
            "decision": None,
            "tool": "send_email",
            "resource": "external@example.com",
            "reason": "approval required",
            "risk_score": 62,
            "severity": "medium",
            "created_at": "2026-06-25T00:00:00+00:00",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "resolved_at": None,
        }
        audit_id = f"audit_pg_state_{run_id}"
        audit_payload = _audit_event(
            audit_id=audit_id,
            trace_id=trace_id,
            decision="ask",
            runtime="langgraph",
            blocked=True,
            is_malicious=True,
            latency_ms=17,
            links={"event_id": f"evt_{run_id}", "decision_id": f"dec_{run_id}"},
        ).model_dump(mode="json")
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO audit_events (
                        audit_id, payload_json, created_at, chain_id,
                        sequence, prev_hash, event_hash
                    )
                    VALUES (
                        :audit_id, CAST(:payload_json AS jsonb), :created_at,
                        'default', 1, NULL, :event_hash
                    )
                    """
                ),
                {
                    "audit_id": audit_id,
                    "payload_json": json.dumps(audit_payload),
                    "created_at": audit_payload["timestamp"],
                    "event_hash": "a" * 64,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO approval_requests (approval_id, payload_json, status, created_at)
                    VALUES (:approval_id, CAST(:payload_json AS jsonb), 'pending', :created_at)
                    """
                ),
                {
                    "approval_id": approval_id,
                    "payload_json": json.dumps(approval_payload),
                    "created_at": "2026-06-25T00:00:00+00:00",
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO adapter_statuses (adapter_id, payload_json, updated_at)
                    VALUES ('openclaw', CAST(:payload_json AS jsonb), :updated_at)
                    """
                ),
                {
                    "payload_json": json.dumps(
                        {
                            "status": "loaded",
                            "loaded": True,
                            "runtime": "openclaw",
                            "runtime_id": "openclaw-gateway",
                            "agent_id": "main",
                        }
                    ),
                    "updated_at": "2026-06-25T00:00:00+00:00",
                },
            )

        command.upgrade(store._alembic_config(), "head")

        with engine.begin() as conn:
            columns = dict(
                conn.execute(
                    text(
                        """
                        SELECT column_name, data_type
                        FROM information_schema.columns
                        WHERE table_name = 'approval_requests'
                        """
                    )
                ).all()
            )
            audit_columns = dict(
                conn.execute(
                    text(
                        """
                        SELECT column_name, data_type
                        FROM information_schema.columns
                        WHERE table_name = 'audit_events'
                        """
                    )
                ).all()
            )
            audit_indexes = set(
                conn.execute(
                    text(
                        """
                        SELECT indexname
                        FROM pg_indexes
                        WHERE schemaname = current_schema()
                          AND tablename = 'audit_events'
                        """
                    )
                ).scalars()
            )
            audit_projection = (
                conn.execute(
                    text(
                        """
                        SELECT occurred_at, ingested_at, record_type, trace_id,
                               runtime, decision, event_id, decision_id,
                               is_malicious, latency_ms
                        FROM audit_events
                        WHERE audit_id = :audit_id
                        """
                    ),
                    {"audit_id": audit_id},
                )
                .mappings()
                .one()
            )
            nonce_table = conn.execute(
                text("SELECT to_regclass('public.approval_nonces')")
            ).scalar_one()

        approval = store.get_approval(approval_id)
        adapter_status = store.get_adapter_status("openclaw")

        assert "status" not in columns
        assert columns["created_at"] == "timestamp with time zone"
        assert columns["expires_at"] == "timestamp with time zone"
        assert columns["resolved_at"] == "timestamp with time zone"
        assert "created_at" not in audit_columns
        assert audit_columns["occurred_at"] == "timestamp with time zone"
        assert audit_columns["ingested_at"] == "timestamp with time zone"
        assert audit_columns["sequence"] == "bigint"
        assert audit_columns["record_type"] == "text"
        assert audit_columns["trace_id"] == "text"
        assert audit_columns["event_id"] == "text"
        assert "ux_audit_events_chain_sequence" in audit_indexes
        assert "ix_audit_events_policy_occurred_sequence" in audit_indexes
        assert audit_projection["ingested_at"] == audit_projection["occurred_at"]
        assert audit_projection["record_type"] == "policy_evaluation"
        assert audit_projection["trace_id"] == trace_id
        assert audit_projection["runtime"] == "langgraph"
        assert audit_projection["decision"] == "ask"
        assert audit_projection["event_id"] == f"evt_{run_id}"
        assert audit_projection["decision_id"] == f"dec_{run_id}"
        assert audit_projection["is_malicious"] is True
        assert audit_projection["latency_ms"] == 17
        assert nonce_table is None
        assert approval is not None
        assert approval.status == "pending"
        assert approval.subject_id == subject_id
        assert "tool_call_id" not in approval.model_dump(mode="json")
        assert "tool" not in approval.model_dump(mode="json")
        assert adapter_status is not None
        assert adapter_status["runtime_id"] == "openclaw-gateway"
        assert "runtime" not in adapter_status
    finally:
        reset_control_plane_schema(database_url)


def test_postgres_store_filters_audit_and_aggregates_metrics() -> None:
    database_url = get_test_database_url()

    run_id = uuid4().hex
    trace_id = f"trace_pg_metric_{run_id}"
    other_trace_id = f"trace_pg_other_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
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

        with create_engine(store.database_url).connect() as conn:
            projection = (
                conn.execute(
                    text(
                        """
                        SELECT occurred_at, ingested_at, record_type, trace_id,
                               case_id, runtime, decision, is_malicious, latency_ms
                        FROM audit_events
                        WHERE audit_id = :audit_id
                        """
                    ),
                    {"audit_id": f"audit_pg_allow_{run_id}"},
                )
                .mappings()
                .one()
            )

        assert projection["occurred_at"].tzinfo is not None
        assert projection["ingested_at"].tzinfo is not None
        assert projection["record_type"] == "policy_evaluation"
        assert projection["trace_id"] == trace_id
        assert projection["case_id"] == "PG-METRIC"
        assert projection["runtime"] == "langgraph"
        assert projection["decision"] == "allow"
        assert projection["is_malicious"] is False
        assert projection["latency_ms"] == 10

        denied = store.list_audit_events(
            AuditEventFilters(trace_id=trace_id, decision="deny", limit=10)
        )
        metrics = aggregate_policy_metrics(
            store.read_audit_events_bounded(
                AuditWindowQuery(trace_id=trace_id, limit=100)
            )
        )

        assert [event.audit_id for event in denied] == [f"audit_pg_deny_{run_id}"]
        assert metrics["evaluation_count"] == 2
        assert metrics["allow_count"] == 1
        assert metrics["deny_count"] == 1
        assert metrics["ask_count"] == 0
        assert metrics["intervention_count"] == 1
        assert metrics["intervention_rate"] == 0.5
        assert metrics["policy_intervention_fpr"] == 0.0
        assert metrics["policy_intervention_fnr"] == 0.0
        assert metrics["average_decision_latency_ms"] == 20.0
    finally:
        _cleanup_test_rows(database_url, trace_id, None)
        _cleanup_test_rows(database_url, other_trace_id, None)


def test_postgres_store_persists_policy_snapshot_across_instances() -> None:
    database_url = get_test_database_url()

    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        first_record = store.save_policy_snapshot(
            PolicyBundle(
                bundle_id="pg-policy-1",
                allowed_email_domains=["pg.example"],
                sensitive_text_markers=["pg-secret="],
            ),
            expected_revision=0,
            updated_by="tester",
        )
        second_record = store.save_policy_snapshot(
            PolicyBundle(
                bundle_id="pg-policy-2",
                allowed_email_domains=["pg.example"],
                sensitive_text_markers=["pg-secret="],
            ),
            expected_revision=1,
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
        assert [record.policy_bundle.bundle_id for record in history] == [
            "pg-policy-2",
            "pg-policy-1",
        ]
        assert {record.updated_by for record in history} == {"tester"}
    finally:
        _cleanup_policy_snapshot(database_url)


def test_postgres_policy_snapshot_concurrent_writes_reject_stale_revisions() -> None:
    database_url = get_test_database_url()

    worker_count = 16
    try:
        reset_control_plane_schema(database_url)
        PostgresControlPlaneStore(database_url).initialize()

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(
                    _save_policy_snapshot,
                    database_url,
                    f"pg-concurrent-policy-{index}",
                )
                for index in range(worker_count)
            ]
            results = []
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except PolicyRevisionConflictError as exc:
                    results.append(exc)

        history = PostgresControlPlaneStore(database_url).list_policy_snapshot_history(
            limit=worker_count
        )
        records = [
            item for item in results if not isinstance(item, PolicyRevisionConflictError)
        ]
        conflicts = [
            item for item in results if isinstance(item, PolicyRevisionConflictError)
        ]

        assert [record.revision for record in records] == [1]
        assert len(conflicts) == worker_count - 1
        assert all(conflict.current_revision == 1 for conflict in conflicts)
        assert [record.revision for record in history] == [1]
    finally:
        _cleanup_policy_snapshot(database_url)


def test_postgres_migration_creates_policy_snapshots_table() -> None:
    database_url = get_test_database_url()

    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            exists = conn.execute(
                text("SELECT to_regclass('public.policy_snapshots')")
            ).scalar_one()
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


def test_postgres_trace_route_aggregates_audit_approval_and_window_scope() -> None:
    database_url = get_test_database_url()

    run_id = uuid4().hex
    trace_id = f"trace_pg_route_{run_id}"
    approval_id = f"app_pg_route_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
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
                subject_id=f"call_pg_route_{run_id}",
                subject_type="tool_call",
                action_id=f"call_pg_route_{run_id}",
                action_name="send_email",
                requesting_principal_id="cred_adapter_main",
                runtime="langgraph",
                agent_id="main",
                resource="external@example.com",
                reason="approval required",
                risk_score=62,
                severity="medium",
                expires_at="2099-01-01T00:00:00+00:00",
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
        assert [event["audit_id"] for event in trace["audit_events"]] == [
            f"audit_pg_route_{run_id}"
        ]
        assert [approval["approval_id"] for approval in trace["approvals"]] == [
            approval_id
        ]
        assert trace["audit_window"]["limit"] == 1000
        assert trace["audit_window"]["returned_count"] == 1
        assert trace["audit_window"]["has_more"] is False
        assert trace["audit_window"]["next_cursor"] is None
        assert isinstance(trace["audit_window"]["snapshot_id"], str)
        assert trace["approval_window"] == {
            "limit": 1000,
            "returned_count": 1,
            "has_more": False,
        }
        assert "metrics" not in trace
    finally:
        _cleanup_test_rows(database_url, trace_id, approval_id)


def test_postgres_store_persists_terminal_control_plane_registry_state() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        credential = {
            "credential_id": "cred_pg_openclaw",
            "token_hash": _token_hash("pg-generated-token"),
            "principal_type": "component",
            "principal_id": "openclaw-main",
            "role": "adapter",
            "scopes": [
                "event:evaluate",
                "event:audit:write",
                "approval:wait",
                "adapter:status:write",
            ],
            "runtime": "openclaw",
            "agent_id": "main",
        }
        store.create_credential(credential)
        store.save_adapter_status(
            "openclaw",
            {
                "status": "loaded",
                "loaded": True,
                "runtime_id": "openclaw-gateway",
                "agent_id": "main",
                "plugin_version": "0.1.0",
                "runtime_version": "2026.6.6",
                "capabilities": {"event_types": ["tool_call_proposed"]},
                "hooks": ["before_tool_call"],
                "last_heartbeat_at": "2026-06-28T00:03:00+00:00",
            },
        )
        store.save_evaluation_run(
            {
                "run_id": "eval_pg_terminal",
                "run_at": "2026-06-28T00:04:00+00:00",
                "dataset_id": "attackbench",
                "dataset_version": "v1",
                "per_family": {"prompt_injection": {"case_count": 1}},
                "per_rule": {"P101_prompt_injection": {"hit_count": 1}},
                "cases": [],
            }
        )

        restarted = PostgresControlPlaneStore(database_url)
        stored_credential = restarted.get_credential_by_token_hash(
            _token_hash("pg-generated-token")
        )
        listed_credentials = restarted.list_credentials()
        status = restarted.get_adapter_status("openclaw")
        runs = restarted.list_evaluation_runs(
            dataset_id="attackbench", dataset_version="v1"
        )
        run = restarted.get_evaluation_run("eval_pg_terminal")
        revoked = restarted.revoke_credential(
            "cred_pg_openclaw", revoked_at="2026-06-28T00:05:00+00:00"
        )

        assert stored_credential is not None
        assert stored_credential.principal_id == "openclaw-main"
        assert [item.credential_id for item in listed_credentials] == [
            "cred_pg_openclaw"
        ]
        assert status is not None
        assert status["last_heartbeat_at"] == "2026-06-28T00:03:00+00:00"
        assert status["capabilities"]["event_types"] == ["tool_call_proposed"]
        assert [item["run_id"] for item in runs] == ["eval_pg_terminal"]
        assert run is not None
        assert run["per_rule"]["P101_prompt_injection"]["hit_count"] == 1
        assert revoked.revoked_at == "2026-06-28T00:05:00+00:00"
        assert (
            restarted.get_credential_by_token_hash(_token_hash("pg-generated-token"))
            is None
        )
    finally:
        reset_control_plane_schema(database_url)


def test_postgres_store_looks_up_policy_evaluation_by_event_id() -> None:
    database_url = get_test_database_url()

    run_id = uuid4().hex
    event_id = f"evt_pg_lookup_{run_id}"
    trace_id = f"trace_pg_lookup_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        store.add_audit_event(
            _audit_event(
                audit_id=f"audit_pg_lookup_{run_id}",
                trace_id=trace_id,
                decision="deny",
                runtime="langgraph",
                blocked=True,
                is_malicious=True,
                latency_ms=10,
                links={"event_id": event_id, "decision_id": f"dec_{run_id}"},
            )
        )

        found = store.get_policy_evaluation_by_event_id(event_id)
        missing = store.get_policy_evaluation_by_event_id(f"evt_pg_missing_{run_id}")

        assert found is not None
        assert found.links["event_id"] == event_id
        assert found.audit_id == f"audit_pg_lookup_{run_id}"
        assert missing is None
    finally:
        _cleanup_test_rows(database_url, trace_id, None)


def _cleanup_test_rows(
    database_url: str, trace_id: str, approval_id: str | None
) -> None:
    try:
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            if approval_id is not None:
                conn.execute(
                    text(
                        "DELETE FROM approval_requests WHERE approval_id = :approval_id"
                    ),
                    {"approval_id": approval_id},
                )
            conn.execute(
                text("DELETE FROM audit_events WHERE trace_id = :trace_id"),
                {"trace_id": trace_id},
            )
    except Exception:
        return None


def _cleanup_auth_rows(
    database_url: str,
    launch_code: str | None,
    session_id: str | None,
) -> None:
    try:
        engine = create_engine(PostgresControlPlaneStore(database_url).database_url)
        with engine.begin() as conn:
            if launch_code is not None:
                conn.execute(
                    text("DELETE FROM launch_codes WHERE code_hash = :code_hash"),
                    {"code_hash": _token_hash(launch_code)},
                )
            if session_id is not None:
                conn.execute(
                    text(
                        "DELETE FROM browser_sessions WHERE session_hash = :session_hash"
                    ),
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


def _save_policy_snapshot(database_url: str, bundle_id: str):
    return PostgresControlPlaneStore(database_url).save_policy_snapshot(
        PolicyBundle(bundle_id=bundle_id),
        expected_revision=0,
        updated_by="concurrent-tester",
    )


def _audit_event(
    *,
    audit_id: str,
    trace_id: str,
    decision: str,
    runtime: str,
    blocked: bool,
    is_malicious: bool | None,
    latency_ms: int,
    links: dict[str, str] | None = None,
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
        links=links or {},
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


def test_postgres_store_audit_id_idempotent_and_conflict() -> None:
    database_url = get_test_database_url()
    run_id = uuid4().hex
    audit_id = f"audit_pg_idem_{run_id}"
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        event = _audit_event(
            audit_id=audit_id,
            trace_id=f"trace_pg_idem_{run_id}",
            decision="ask",
            runtime="langgraph",
            blocked=True,
            is_malicious=True,
            latency_ms=10,
        )

        assert store.add_audit_event(event) is True
        assert store.add_audit_event(event) is False

        different = _audit_event(
            audit_id=audit_id,
            trace_id=f"trace_pg_idem_{run_id}",
            decision="deny",
            runtime="langgraph",
            blocked=True,
            is_malicious=True,
            latency_ms=10,
        )
        with pytest.raises(AuditIdConflictError):
            store.add_audit_event(different)
    finally:
        reset_control_plane_schema(database_url)
