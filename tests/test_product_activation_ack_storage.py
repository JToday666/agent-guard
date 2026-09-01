"""Private Product ActivationAck issuance storage parity contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from guard_api.runtime_status import activation_ack_token_digest
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.support.product_activation import (
    build_test_product_activation,
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
)


@pytest.fixture(params=("memory", "postgres"))
def store(request):
    if request.param == "memory":
        return MemoryControlPlaneStore()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres = PostgresControlPlaneStore(database_url)
    postgres.initialize()
    return postgres


def test_ack_registry_keeps_overlapping_generations_without_raw_token(store) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fixture = build_test_product_activation(now=now)
    first_status = product_runtime_status_for_activation(
        fixture,
        "langgraph",
        last_heartbeat_at=now,
    )
    first_ack = product_activation_ack_for_status(fixture, first_status)
    second_status = product_runtime_status_for_activation(
        fixture,
        "langgraph",
        last_heartbeat_at=now + timedelta(seconds=10),
    )
    second_ack = product_activation_ack_for_status(fixture, second_status)

    store.save_product_runtime_status(first_status, activation_ack=first_ack)
    store.save_product_runtime_status(second_status, activation_ack=second_ack)

    first = store.get_product_activation_ack(
        activation_ack_token_digest(first_ack.ack_token)
    )
    second = store.get_product_activation_ack(
        activation_ack_token_digest(second_ack.ack_token)
    )
    latest = store.get_latest_product_activation_ack(second_status.identity())
    assert first is not None
    assert second is not None
    assert latest == second
    assert first.rebuild(first_ack.ack_token) == first_ack
    assert second.rebuild(second_ack.ack_token) == second_ack
    assert first_ack.ack_token not in repr(first)
    assert first_ack.ack_token not in first.model_dump_json()
    assert first_ack.ack_token not in str(store.list_product_runtime_statuses())


def test_ack_registry_revokes_all_exact_identity_generations(store) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fixture = build_test_product_activation(now=now)
    statuses = [
        product_runtime_status_for_activation(
            fixture,
            "openclaw",
            last_heartbeat_at=now + timedelta(seconds=offset),
        )
        for offset in (0, 10)
    ]
    acks = [product_activation_ack_for_status(fixture, status) for status in statuses]
    for status, ack in zip(statuses, acks, strict=True):
        store.save_product_runtime_status(status, activation_ack=ack)

    revoked_at = (now + timedelta(seconds=20)).isoformat()
    assert (
        store.revoke_product_activation_acks(
            statuses[-1].identity(),
            revoked_at=revoked_at,
        )
        == 2
    )
    assert store.get_latest_product_activation_ack(statuses[-1].identity()) is None
    for ack in acks:
        record = store.get_product_activation_ack(
            activation_ack_token_digest(ack.ack_token)
        )
        assert record is not None
        assert record.revoked_at == revoked_at


def test_status_and_ack_write_rolls_back_on_mismatched_pair(store) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fixture = build_test_product_activation(now=now)
    status = product_runtime_status_for_activation(
        fixture,
        "langgraph",
        last_heartbeat_at=now,
    )
    mismatched_status = product_runtime_status_for_activation(
        fixture,
        "langgraph",
        last_heartbeat_at=now + timedelta(seconds=1),
    )
    ack = product_activation_ack_for_status(fixture, status)

    with pytest.raises(ValueError, match="does not match runtime status"):
        store.save_product_runtime_status(mismatched_status, activation_ack=ack)

    assert store.get_product_runtime_status(status.identity()) is None
    assert (
        store.get_product_activation_ack(
            activation_ack_token_digest(ack.ack_token)
        )
        is None
    )
