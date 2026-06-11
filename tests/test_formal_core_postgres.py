from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from agentguard_core.models import SecurityContext, ToolCallEvent, ToolDescriptor
from agentguard_core.service import AgentGuardCore
from agentguard_core.storage.postgres import PostgresCoreStore


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
    store = PostgresCoreStore("postgresql://agentguard:agentguard@127.0.0.1:5432/agent_guard")

    assert callable(store.initialize)
    assert callable(store.health_check)
    assert callable(store.expire_approval)
    assert store.database_url == "postgresql+psycopg://agentguard:agentguard@127.0.0.1:5432/agent_guard"


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
