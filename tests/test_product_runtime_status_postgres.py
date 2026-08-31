"""PostgreSQL persistence and migration tests for Product Runtime Status V2."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from agentguard_core import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    RuntimeEventCapabilityV2,
    build_runtime_capability_report,
    openclaw_event_residual_boundaries,
)
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from guard_api.models import AdapterStatusRecord
from guard_api.runtime_status import ProductRuntimeStatusV2
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

pytestmark = pytest.mark.postgres

_DIGESTS = {character: f"sha256:{character * 64}" for character in "0123456789abcdef"}


def _event_capabilities() -> list[RuntimeEventCapabilityV2]:
    enforcement = {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c1",
        "message_send_proposed": "pre_execution_c1",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c1",
        "tool_result_produced": "post_execution_isolation",
    }
    return [
        RuntimeEventCapabilityV2(
            event_type=event_type,
            supported=True,
            active=True,
            enforcement=enforcement[event_type],  # type: ignore[arg-type]
            residual_boundaries=list(openclaw_event_residual_boundaries(event_type)),
        )
        for event_type in PRODUCT_EVENT_TYPES
    ]


def _status(
    *,
    agent_id: str = "main",
    source: str = "openclaw-plugin",
    heartbeat_at: str = "2026-09-01T00:00:00+00:00",
) -> ProductRuntimeStatusV2:
    principal_id = f"principal:{agent_id}"
    runtime_binding_id = f"binding:{principal_id}"
    profile_id = "agentguard-openclaw-v2-restricted"
    capability_report = build_runtime_capability_report(
        runtime="openclaw",
        agent_id=agent_id,
        runtime_binding_id=runtime_binding_id,
        profile_id=profile_id,
        supported=True,
        active=True,
        c0_registration=True,
        c1_pre_execution_interception=True,
        c2_correlation=True,
        c3_atomic_replace_and_seal=False,
        c4_outcome_receipts=True,
        events=_event_capabilities(),
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
    )
    return ProductRuntimeStatusV2(
        schema_version="2.0",
        status="loaded",
        loaded=True,
        runtime_id="openclaw-gateway",
        agent_id=agent_id,
        runtime_binding_id=runtime_binding_id,
        profile_id=profile_id,
        runtime_version="2026.7.1-2",
        plugin_version="0.1.0-rc.1",
        profile_digest=_DIGESTS["1"],
        adapter_artifact_digest=_DIGESTS["2"],
        reported_activation_ref_digest=_DIGESTS["3"],
        host_inventory_digest=_DIGESTS["4"],
        plugin_inventory_digest=_DIGESTS["5"],
        plugin_order_inventory_digest=_DIGESTS["6"],
        tool_inventory_digest=_DIGESTS["7"],
        capability_report=capability_report,
        source=source,
        hook_count=2,
        expected_hook_count=2,
        hooks=["before_agent_run", "before_tool_call"],
        fail_closed_stages=["before_tool_call"],
        enforcement_mode="enforce",
        runtime="openclaw",
        principal_id=principal_id,
        last_heartbeat_at=heartbeat_at,
    )


def _legacy_row(store: PostgresControlPlaneStore) -> dict[str, object] | None:
    with create_engine(store.database_url).connect() as connection:
        row = connection.execute(text("""
                    SELECT adapter_id, status, loaded, runtime_id, agent_id,
                           enforcement_mode, last_heartbeat_at, payload_json,
                           updated_at
                    FROM adapter_statuses
                    WHERE adapter_id = 'openclaw'
                    """)).mappings().one_or_none()
    return dict(row) if row is not None else None


def _v2_row(store: PostgresControlPlaneStore) -> dict[str, object] | None:
    with create_engine(store.database_url).connect() as connection:
        row = connection.execute(text("""
                    SELECT runtime, agent_id, runtime_binding_id, profile_id,
                           write_sequence, payload_json, updated_at
                    FROM product_runtime_statuses_v2
                    WHERE runtime = 'openclaw' AND agent_id = 'main'
                    """)).mappings().one_or_none()
    return dict(row) if row is not None else None


def test_migration_from_0017_is_zero_backfill_and_preserves_legacy_row() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        command.upgrade(store._alembic_config(), "0017_enforcement_bindings")
        store.save_adapter_status(
            "openclaw",
            {
                "status": "loaded",
                "loaded": True,
                "runtime_id": "legacy-gateway",
                "agent_id": "legacy-agent",
                "source": "legacy-writer",
                "last_heartbeat_at": "2026-08-31T23:59:00+00:00",
            },
        )
        legacy_before = _legacy_row(store)

        command.upgrade(store._alembic_config(), "head")

        assert _legacy_row(store) == legacy_before
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM product_runtime_statuses_v2")
                ).scalar_one()
                == 0
            )
            columns = {row[0]: row[1] for row in connection.execute(text("""
                        SELECT column_name, is_nullable
                        FROM information_schema.columns
                        WHERE table_name = 'product_runtime_statuses_v2'
                        """))}
            constraints = set(connection.execute(text("""
                        SELECT constraint_name
                        FROM information_schema.table_constraints
                        WHERE table_name = 'product_runtime_statuses_v2'
                        """)).scalars())
        assert columns["runtime_id"] == "NO"
        assert columns["enforcement_mode"] == "NO"
        assert columns["last_heartbeat_at"] == "NO"
        assert {
            "pk_product_runtime_statuses_v2",
            "uq_product_runtime_statuses_v2_write_sequence",
            "ck_product_runtime_statuses_v2_exact_identity",
            "ck_product_runtime_statuses_v2_status",
            "ck_product_runtime_statuses_v2_loaded_status",
            "ck_product_runtime_statuses_v2_enforcement_mode",
        } <= constraints
    finally:
        reset_control_plane_schema(database_url)


def test_product_status_dual_write_is_typed_deep_and_legacy_stripped() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        status = _status()

        saved = store.save_product_runtime_status(status)
        exact = store.get_product_runtime_status(status.identity())
        legacy = store.get_adapter_status("openclaw")
        v2_row = _v2_row(store)
        legacy_row = _legacy_row(store)

        assert isinstance(saved, ProductRuntimeStatusV2)
        assert saved == status
        assert saved is not status
        assert exact == status
        assert legacy == status.to_legacy_adapter_status().model_dump(mode="json")
        assert legacy is not None
        assert set(legacy) == set(AdapterStatusRecord.model_fields)
        for forbidden in (
            "runtime",
            "principal_id",
            "runtime_binding_id",
            "profile_id",
            "profile_digest",
            "reported_activation_ref_digest",
            "host_inventory_digest",
            "plugin_inventory_digest",
            "plugin_order_inventory_digest",
            "tool_inventory_digest",
            "capability_report",
        ):
            assert forbidden not in legacy
        assert v2_row is not None
        assert v2_row["payload_json"] == status.model_dump(mode="json")
        assert legacy_row is not None
        assert v2_row["updated_at"] == legacy_row["updated_at"]

        saved.hooks.append("mutated-after-save")
        reread = store.get_product_runtime_status(status.identity())
        assert reread is not None
        assert "mutated-after-save" not in reread.hooks
    finally:
        reset_control_plane_schema(database_url)


def test_legacy_status_preserve_heartbeat_ignores_caller_without_existing_value() -> (
    None
):
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()

        saved = store.save_adapter_status(
            "openclaw",
            {
                "status": "loaded",
                "loaded": True,
                "runtime_id": "legacy-host",
                "last_heartbeat_at": "2999-01-01T00:00:00+00:00",
            },
            preserve_heartbeat=True,
        )

        assert saved["last_heartbeat_at"] is None
        assert store.get_adapter_status("openclaw")["last_heartbeat_at"] is None  # type: ignore[index]
        row = _legacy_row(store)
        assert row is not None
        assert row["last_heartbeat_at"] is None
    finally:
        reset_control_plane_schema(database_url)


def test_legacy_status_preserve_heartbeat_is_atomic_and_leaves_product_row_untouched() -> (
    None
):
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        product = _status(heartbeat_at="2026-09-01T00:03:00+00:00")
        store.save_product_runtime_status(product)
        product_before = _v2_row(store)

        saved = store.save_adapter_status(
            "openclaw",
            {
                "status": "error",
                "loaded": False,
                "runtime_id": "operator-updated-host",
                "error": "operator-observed-error",
                "last_heartbeat_at": "2999-01-01T00:00:00+00:00",
            },
            preserve_heartbeat=True,
        )

        assert saved["status"] == "error"
        assert saved["runtime_id"] == "operator-updated-host"
        assert saved["last_heartbeat_at"] == "2026-09-01T00:03:00+00:00"
        assert store.get_adapter_status("openclaw") == saved
        assert _v2_row(store) == product_before
    finally:
        reset_control_plane_schema(database_url)


def test_two_identities_upsert_and_restart_use_write_sequence_order() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        first = _status(agent_id="agent-a", source="first")
        second = _status(
            agent_id="agent-b",
            source="second",
            heartbeat_at="2026-09-01T00:00:01+00:00",
        )
        store.save_product_runtime_status(first)
        store.save_product_runtime_status(second)

        assert [item.source for item in store.list_product_runtime_statuses()] == [
            "second",
            "first",
        ]
        assert store.list_product_runtime_statuses(limit=1) == [second]
        assert store.get_product_runtime_status(first.identity()) == first
        with pytest.raises(ValueError, match="between 1 and 500"):
            store.list_product_runtime_statuses(limit=0)
        with pytest.raises(ValueError, match="between 1 and 500"):
            store.list_product_runtime_statuses(limit=501)

        rewritten = _status(
            agent_id="agent-a",
            source="third",
            heartbeat_at="2026-09-01T00:00:02+00:00",
        )
        store.save_product_runtime_status(rewritten)
        listed = store.list_product_runtime_statuses(runtime="openclaw")

        assert [item.source for item in listed] == ["third", "second"]
        assert store.get_adapter_status("openclaw") == (
            rewritten.to_legacy_adapter_status().model_dump(mode="json")
        )
        with engine.connect() as connection:
            rows = connection.execute(text("""
                    SELECT agent_id, write_sequence
                    FROM product_runtime_statuses_v2
                    ORDER BY write_sequence DESC
                    """)).all()
        assert [row.agent_id for row in rows] == ["agent-a", "agent-b"]
        assert rows[0].write_sequence > rows[1].write_sequence

        restarted = PostgresControlPlaneStore(database_url)
        assert restarted.get_product_runtime_status(rewritten.identity()) == rewritten
        assert restarted.list_product_runtime_statuses() == listed
    finally:
        reset_control_plane_schema(database_url)


def test_runtime_lock_keeps_concurrent_legacy_projection_with_latest_v2() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        statuses = [
            _status(agent_id="agent-a", source="concurrent-a"),
            _status(agent_id="agent-b", source="concurrent-b"),
        ]
        barrier = Barrier(len(statuses))

        def save(status: ProductRuntimeStatusV2) -> ProductRuntimeStatusV2:
            barrier.wait()
            return store.save_product_runtime_status(status)

        with ThreadPoolExecutor(max_workers=2) as executor:
            saved = list(executor.map(save, statuses))

        assert {item.source for item in saved} == {
            "concurrent-a",
            "concurrent-b",
        }
        listed = store.list_product_runtime_statuses(runtime="openclaw")
        assert len(listed) == 2
        assert store.get_adapter_status("openclaw") == (
            listed[0].to_legacy_adapter_status().model_dump(mode="json")
        )
    finally:
        reset_control_plane_schema(database_url)


def test_legacy_failure_rolls_back_v2_row_and_legacy_projection() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        baseline = _status(source="baseline")
        store.save_product_runtime_status(baseline)
        v2_before = _v2_row(store)
        legacy_before = _legacy_row(store)
        with engine.begin() as connection:
            connection.execute(text("""
                    ALTER TABLE adapter_statuses
                    ADD CONSTRAINT ck_test_reject_runtime_status_projection
                    CHECK ((payload_json ->> 'source') IS DISTINCT FROM 'rollback')
                    """))

        rejected = _status(
            source="rollback",
            heartbeat_at="2026-09-01T00:00:05+00:00",
        )
        with pytest.raises(IntegrityError):
            store.save_product_runtime_status(rejected)

        assert _v2_row(store) == v2_before
        assert _legacy_row(store) == legacy_before
        assert store.get_product_runtime_status(baseline.identity()) == baseline
    finally:
        with engine.begin() as connection:
            connection.execute(text("""
                    ALTER TABLE IF EXISTS adapter_statuses
                    DROP CONSTRAINT IF EXISTS
                    ck_test_reject_runtime_status_projection
                    """))
        reset_control_plane_schema(database_url)


def test_database_rejects_non_visible_ascii_identity_and_loaded_status_mismatch() -> (
    None
):
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        insert_sql = text("""
            INSERT INTO product_runtime_statuses_v2 (
                runtime, agent_id, runtime_binding_id, profile_id,
                status, loaded, runtime_id, enforcement_mode,
                last_heartbeat_at, payload_json
            ) VALUES (
                'openclaw', :agent_id, :runtime_binding_id, :profile_id,
                'loaded', :loaded, 'openclaw-gateway', 'enforce',
                '2026-09-01T00:00:00+00:00', CAST(:payload_json AS jsonb)
            )
            """)
        base_identity = {
            "agent_id": "raw-agent",
            "runtime_binding_id": "binding:openclaw:raw",
            "profile_id": "agentguard-openclaw-v2-restricted",
            "loaded": True,
            "payload_json": json.dumps({}),
        }
        invalid_identities = (
            {"agent_id": "raw agent"},
            {"agent_id": "raw\nagent"},
            {"agent_id": "raw-agent-代理"},
            {"runtime_binding_id": "binding:openclaw raw"},
            {"runtime_binding_id": "binding:openclaw:\x01raw"},
            {"runtime_binding_id": "binding:openclaw:代理"},
            {"profile_id": "agentguard-openclaw-v2 restricted"},
            {"profile_id": "agentguard-openclaw-v2\nrestricted"},
            {"profile_id": "agentguard-openclaw-v2-代理"},
        )
        for identity_override in invalid_identities:
            with pytest.raises(IntegrityError):
                with engine.begin() as connection:
                    connection.execute(
                        insert_sql,
                        {**base_identity, **identity_override},
                    )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    insert_sql,
                    {
                        **base_identity,
                        "loaded": False,
                    },
                )
    finally:
        reset_control_plane_schema(database_url)


def test_downgrade_drops_only_v2_and_reupgrade_stays_zero_backfill() -> None:
    database_url = get_test_database_url()
    store = PostgresControlPlaneStore(database_url)
    engine = create_engine(store.database_url)
    try:
        reset_control_plane_schema(database_url)
        store.initialize()
        status = _status()
        store.save_product_runtime_status(status)
        legacy_before = _legacy_row(store)

        command.downgrade(store._alembic_config(), "0017_enforcement_bindings")

        assert _legacy_row(store) == legacy_before
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT to_regclass('product_runtime_statuses_v2')")
                ).scalar_one()
                is None
            )

        command.upgrade(store._alembic_config(), "head")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM product_runtime_statuses_v2")
                ).scalar_one()
                == 0
            )
        assert _legacy_row(store) == legacy_before
    finally:
        reset_control_plane_schema(database_url)
