"""Real PostgreSQL migration invariants using controlled database rows.

These rows exercise schema preservation/locking only. They are not accepted
approvals, Product model evidence, Host invocations, or qualification results.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

from alembic import command
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

pytestmark = pytest.mark.postgres
BEFORE = "0019_product_activation_ack"
AFTER = "0020_restricted_approval_mode"


@pytest.fixture
def migration_store():
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        yield store, engine
    finally:
        engine.dispose()
        reset_control_plane_schema(database_url)


def _seed(connection, suffix, *, mode=None):
    # Minimal FK-valid pending SQL rows, deliberately lacking real API evidence.
    connection.execute(
        text("""
        INSERT INTO approval_requests
        (approval_id, trace_id, runtime, agent_id, subject_id, action_id,
         payload_json, created_at, expires_at)
        VALUES (:approval, :trace, 'openclaw', 'migration-agent', 'migration-subject',
                :action, '{}', now(), now() + interval '1 hour')
    """),
        {
            "approval": f"approval-{suffix}",
            "trace": f"trace-{suffix}",
            "action": f"action-{suffix}",
        },
    )
    mode_column = ", release_mode" if mode is not None else ""
    mode_value = ", :mode" if mode is not None else ""
    connection.execute(
        text(f"""
        INSERT INTO enforcement_bindings
        (event_id, policy_audit_id, approval_id, action_id, action_type,
         authorization_fingerprint, runtime_binding_id, scope_digest, principal_id,
         runtime, agent_id, policy_revision, requires_execution_lease, created_at{mode_column})
        VALUES (:event, :audit, :approval, :action, 'tool_call',
                :fingerprint, 'migration-binding', :scope, 'migration-principal',
                'openclaw', 'migration-agent', 'migration-policy', true,
                '2026-09-08T00:00:00+00:00'{mode_value})
    """),
        {
            "event": f"event-{suffix}",
            "audit": f"audit-{suffix}",
            "approval": f"approval-{suffix}",
            "action": f"action-{suffix}",
            "fingerprint": "hmac-sha256:" + "a" * 64,
            "scope": "sha256:" + "b" * 64,
            "mode": mode,
        },
    )


def test_upgrade_preserves_existing_strong_row_with_explicit_default(migration_store):
    store, engine = migration_store
    command.upgrade(store._alembic_config(), BEFORE)
    with engine.begin() as connection:
        _seed(connection, "old")
        before = dict(
            connection.execute(text("SELECT * FROM enforcement_bindings"))
            .mappings()
            .one()
        )
    command.upgrade(store._alembic_config(), AFTER)
    with engine.connect() as connection:
        after = dict(
            connection.execute(text("SELECT * FROM enforcement_bindings"))
            .mappings()
            .one()
        )
    assert after.pop("release_mode") == "strong_binding"
    assert after == before
    command.downgrade(store._alembic_config(), BEFORE)
    with engine.connect() as connection:
        assert (
            dict(
                connection.execute(text("SELECT * FROM enforcement_bindings"))
                .mappings()
                .one()
            )
            == before
        )


def test_downgrade_refuses_existing_restricted_authority_without_changing_schema(
    migration_store,
):
    store, engine = migration_store
    command.upgrade(store._alembic_config(), AFTER)
    with engine.begin() as connection:
        _seed(connection, "restricted", mode="restricted_allow_once")
    with pytest.raises(
        RuntimeError, match="restricted approvals prevent release-mode downgrade"
    ):
        command.downgrade(store._alembic_config(), BEFORE)
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT release_mode FROM enforcement_bindings")
            ).scalar_one()
            == "restricted_allow_once"
        )
        assert (
            connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            == AFTER
        )


def test_downgrade_holds_exclusive_lock_before_existence_check(migration_store):
    store, engine = migration_store
    command.upgrade(store._alembic_config(), AFTER)
    with engine.begin() as connection:
        _seed(connection, "old")
    checked = Event()
    continue_ddl = Event()
    migration_pids = []

    def pause_after_check(connection, _cursor, statement, _parameters, _context, _many):
        if "SELECT EXISTS (SELECT 1 FROM enforcement_bindings" not in statement:
            return
        migration_pids.append(
            connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        )
        checked.set()
        if not continue_ddl.wait(15):
            raise AssertionError("migration synchronization timed out")

    event.listen(Engine, "after_cursor_execute", pause_after_check)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(command.downgrade, store._alembic_config(), BEFORE)
            try:
                assert checked.wait(10), (
                    "downgrade did not reach the guarded existence check"
                )
                with engine.connect() as connection:
                    assert (
                        connection.execute(
                            text("""
                        SELECT count(*) FROM pg_locks
                        WHERE pid=:pid AND relation='enforcement_bindings'::regclass
                          AND mode='AccessExclusiveLock' AND granted
                    """),
                            {"pid": migration_pids[0]},
                        ).scalar_one()
                        == 1
                    )
                # A second writer starts precisely after SELECT, before DROP.
                # It must not introduce a row whose discriminator could be lost.
                with pytest.raises(DBAPIError) as raised:
                    with engine.begin() as connection:
                        connection.execute(text("SET LOCAL lock_timeout='500ms'"))
                        _seed(connection, "racing", mode="restricted_allow_once")
                assert getattr(raised.value.orig, "sqlstate", None) == "55P03"
            finally:
                continue_ddl.set()
            future.result(timeout=10)
    finally:
        continue_ddl.set()
        event.remove(Engine, "after_cursor_execute", pause_after_check)
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT event_id FROM enforcement_bindings")
        ).scalars().all() == ["event-old"]
        assert (
            connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            == BEFORE
        )
