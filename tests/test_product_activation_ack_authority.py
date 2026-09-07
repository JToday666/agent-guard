"""Product ActivationAck heartbeat and request-authority boundaries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentguard_core import (
    GuardEvent,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    verify_activation_ack,
)

from guard_api.auth import AuthContext
from guard_api.runtime_status import (
    ProductRuntimeHeartbeatV2,
    activation_ack_token_digest,
)
from guard_api.services.product_activation import (
    ACTIVATION_ACK_NOT_CURRENT,
    ACTIVATION_ACK_REQUIRED,
    RUNTIME_IDENTITY_MISMATCH,
    RUNTIME_OBSERVATION_MISMATCH,
    FrozenProductActivation,
    ProductActivationAuthorityService,
)
from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_activation import (
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)


def _frozen(fixture: ProductActivationFixture) -> FrozenProductActivation:
    return FrozenProductActivation(
        bundle=fixture.bundle,
        source_path="/test/product-activation.json",
        content_digest=canonical_sha256(fixture.bundle.model_dump(mode="json")),
    )


def _heartbeat(
    fixture: ProductActivationFixture,
    runtime: str,
) -> ProductRuntimeHeartbeatV2:
    status = product_runtime_status_for_activation(
        fixture,
        runtime,
        last_heartbeat_at=_NOW,
    )
    return ProductRuntimeHeartbeatV2.model_validate(
        status.model_dump(
            mode="json",
            exclude={"runtime", "principal_id", "last_heartbeat_at"},
        )
    )


def _auth(fixture: ProductActivationFixture, runtime: str) -> AuthContext:
    entry = fixture.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
    return AuthContext(
        principal_type="component",
        principal_id=entry.principal_id,
        role="adapter",
        scopes=["adapter:status:write", "event:evaluate"],
        auth_method="bearer",
        runtime=entry.runtime,
        agent_id=entry.agent_id,
    )


def _event() -> GuardEvent:
    return GuardEvent(
        event_id="evt:activation-ack-authority",
        runtime="langgraph",
        trace_id="trace:activation-ack-authority",
        timestamp=_NOW.isoformat(),
        security_context=SecurityContext(agent_id="main"),
        payload=ToolCallPayload(
            tool=ToolDescriptor(name="safe_tool", call_id="call:activation-ack"),
            arguments={},
            derived_resources=[],
        ),
    )


def _authority(
    fixture: ProductActivationFixture,
    store: MemoryControlPlaneStore,
    clock: list[datetime],
) -> ProductActivationAuthorityService:
    return ProductActivationAuthorityService(
        activation=_frozen(fixture),
        store=store,
        server_secret=fixture.server_secret,
        clock=lambda: clock[0],
    )


def _accept(
    authority: ProductActivationAuthorityService,
    fixture: ProductActivationFixture,
    runtime: str,
):
    return authority.accept_heartbeat(
        runtime,
        _heartbeat(fixture, runtime),
        _auth(fixture, runtime),
    )


def test_heartbeat_mints_server_timed_ack_with_exclusive_120_second_expiry() -> None:
    fixture = build_test_product_activation(now=_NOW)
    store = MemoryControlPlaneStore()
    clock = [_NOW]
    authority = _authority(fixture, store, clock)

    accepted = _accept(authority, fixture, "langgraph")
    ack = accepted.activation_ack
    expiry = _NOW + timedelta(seconds=120)

    assert accepted.runtime_status.last_heartbeat_at == _NOW.isoformat()
    assert ack.issued_at == _NOW.isoformat()
    assert ack.expires_at == expiry.isoformat()
    assert verify_activation_ack(ack, server_secret=fixture.server_secret, now=_NOW)
    assert verify_activation_ack(
        ack,
        server_secret=fixture.server_secret,
        now=expiry - timedelta(microseconds=1),
    )
    assert not verify_activation_ack(
        ack,
        server_secret=fixture.server_secret,
        now=expiry,
    )


def test_heartbeat_ack_expiry_is_clamped_to_activation_expiry() -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation_expiry = datetime.fromisoformat(fixture.bundle.expires_at)
    clock = [activation_expiry - timedelta(seconds=30)]
    authority = _authority(fixture, MemoryControlPlaneStore(), clock)

    ack = _accept(authority, fixture, "openclaw").activation_ack

    assert ack.issued_at == clock[0].isoformat()
    assert ack.expires_at == activation_expiry.isoformat()
    assert datetime.fromisoformat(ack.expires_at) - datetime.fromisoformat(
        ack.issued_at
    ) == timedelta(seconds=30)


def test_overlapping_ack_generations_remain_valid_until_each_exact_expiry() -> None:
    fixture = build_test_product_activation(now=_NOW)
    store = MemoryControlPlaneStore()
    clock = [_NOW]
    authority = _authority(fixture, store, clock)

    first = {
        runtime: _accept(authority, fixture, runtime).activation_ack
        for runtime in ("langgraph", "openclaw")
    }
    clock[0] = _NOW + timedelta(seconds=60)
    second = {
        runtime: _accept(authority, fixture, runtime).activation_ack
        for runtime in ("langgraph", "openclaw")
    }

    assert first["langgraph"].ack_token != second["langgraph"].ack_token
    assert store.get_product_activation_ack(
        activation_ack_token_digest(first["langgraph"].ack_token)
    ) is not None
    assert store.get_product_activation_ack(
        activation_ack_token_digest(second["langgraph"].ack_token)
    ) is not None

    before_first_expiry = _NOW + timedelta(seconds=120, microseconds=-1)
    assert (
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            first["langgraph"].ack_token,
            reference_time=before_first_expiry,
        )
        == first["langgraph"]
    )

    at_first_expiry = _NOW + timedelta(seconds=120)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            first["langgraph"].ack_token,
            reference_time=at_first_expiry,
        )
    assert raised.value.code == ACTIVATION_ACK_NOT_CURRENT

    assert (
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            second["langgraph"].ack_token,
            reference_time=at_first_expiry,
        )
        == second["langgraph"]
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            second["langgraph"].ack_token,
            reference_time=_NOW + timedelta(seconds=180),
        )
    assert raised.value.code == RUNTIME_OBSERVATION_MISMATCH


def test_drift_heartbeat_revokes_all_prior_exact_identity_generations() -> None:
    fixture = build_test_product_activation(now=_NOW)
    store = MemoryControlPlaneStore()
    clock = [_NOW]
    authority = _authority(fixture, store, clock)

    first = _accept(authority, fixture, "langgraph").activation_ack
    _accept(authority, fixture, "openclaw")
    clock[0] = _NOW + timedelta(seconds=10)
    second = _accept(authority, fixture, "langgraph").activation_ack

    clock[0] = _NOW + timedelta(seconds=20)
    drifted = _heartbeat(fixture, "langgraph").model_copy(
        update={"runtime_version": "drifted-host"}
    )
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.accept_heartbeat(
            "langgraph",
            drifted,
            _auth(fixture, "langgraph"),
        )
    assert raised.value.code == RUNTIME_OBSERVATION_MISMATCH

    for ack in (first, second):
        issuance = store.get_product_activation_ack(
            activation_ack_token_digest(ack.ack_token)
        )
        assert issuance is not None
        assert issuance.revoked_at == clock[0].isoformat()

    clock[0] = _NOW + timedelta(seconds=30)
    recovered = _accept(authority, fixture, "langgraph").activation_ack
    assert (
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            recovered.ack_token,
        )
        == recovered
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            second.ack_token,
        )
    assert raised.value.code == ACTIVATION_ACK_NOT_CURRENT


@pytest.mark.parametrize(
    ("principal_id", "runtime", "agent_id"),
    [
        ("principal:other", "langgraph", "main"),
        ("principal:oc", "openclaw", "main"),
        ("principal:lg", "langgraph", "other-agent"),
    ],
)
def test_unrelated_adapter_heartbeat_cannot_write_or_revoke_entry_ack(
    principal_id: str,
    runtime: str,
    agent_id: str,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    store = MemoryControlPlaneStore()
    clock = [_NOW]
    authority = _authority(fixture, store, clock)
    accepted = _accept(authority, fixture, "langgraph")
    before_statuses = store.list_product_runtime_statuses()
    token_digest = activation_ack_token_digest(accepted.activation_ack.ack_token)
    before_issuance = store.get_product_activation_ack(token_digest)
    assert before_issuance is not None

    clock[0] = _NOW + timedelta(seconds=10)
    unrelated = AuthContext(
        principal_type="component",
        principal_id=principal_id,
        role="adapter",
        scopes=["adapter:status:write"],
        auth_method="bearer",
        runtime=runtime,
        agent_id=agent_id,
    )
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.accept_heartbeat(
            "langgraph",
            _heartbeat(fixture, "langgraph"),
            unrelated,
        )

    assert raised.value.code == RUNTIME_IDENTITY_MISMATCH
    assert store.list_product_runtime_statuses() == before_statuses
    assert store.get_product_activation_ack(token_digest) == before_issuance
    assert (
        store.get_latest_product_activation_ack(
            accepted.runtime_status.identity()
        )
        == before_issuance
    )


def test_ack_secret_and_raw_tokens_do_not_leak_from_private_status_surfaces() -> None:
    fixture = build_test_product_activation(now=_NOW)
    store = MemoryControlPlaneStore()
    clock = [_NOW]
    authority = _authority(fixture, store, clock)

    accepted = _accept(authority, fixture, "langgraph")
    _accept(authority, fixture, "openclaw")
    ack = accepted.activation_ack
    issuance = store.get_product_activation_ack(
        activation_ack_token_digest(ack.ack_token)
    )
    assert issuance is not None

    secret_text = fixture.server_secret.decode("ascii")
    public_surfaces = (
        repr(authority),
        repr(accepted),
        repr(ack),
        accepted.runtime_status.model_dump_json(),
        issuance.model_dump_json(),
        repr(store.list_product_runtime_statuses()),
        repr(accepted.runtime_status.to_legacy_adapter_status()),
    )
    for surface in public_surfaces:
        assert ack.ack_token not in surface
        assert secret_text not in surface

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            None,
        )
    assert raised.value.code == ACTIVATION_ACK_REQUIRED
    assert ack.ack_token not in str(raised.value)

    tampered_token = ack.ack_token[:-1] + (
        "0" if ack.ack_token[-1] != "0" else "1"
    )
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        authority.enforce_evaluation(
            _event(),
            _auth(fixture, "langgraph"),
            tampered_token,
        )
    assert raised.value.code == ACTIVATION_ACK_NOT_CURRENT
    assert tampered_token not in str(raised.value)
