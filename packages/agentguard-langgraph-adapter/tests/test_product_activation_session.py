"""Protected ACK transport, exact identities, and concurrent refresh behavior."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from threading import Event, Lock
from typing import Any

import pytest
from pydantic import ValidationError

from agentguard_langgraph_adapter.activation_ack import (
    ActivationAckV1,
    ProductActivationError,
    datetime_nanoseconds,
    timestamp_nanoseconds,
)
import agentguard_langgraph_adapter.activation_session as sessions
from agentguard_langgraph_adapter.activation_session import ProductActivationSession
from agentguard_langgraph_adapter.product_manifest import (
    LangGraphCapabilityReportV2,
    ProductActivationManifest,
    ProductRuntimeObservation,
    canonical_sha256,
)

pytestmark = pytest.mark.integration
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
TOKEN = "hmac-sha256:" + "a" * 64
ROOT = Path(__file__).resolve().parents[3]


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _report() -> dict[str, Any]:
    enforcement = {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c3",
        "message_send_proposed": "pre_execution_c3",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c3",
        "tool_result_produced": "post_execution_isolation",
    }
    raw = {
        "schema_version": "2.0",
        "runtime": "langgraph",
        "agent_id": "main",
        "runtime_binding_id": "binding:langgraph:main",
        "profile_id": "agentguard-langgraph-v2",
        "supported": True,
        "active": True,
        "c0_registration": True,
        "c1_pre_execution_interception": True,
        "c2_correlation": True,
        "c3_atomic_replace_and_seal": True,
        "c4_outcome_receipts": True,
        "events": [
            {
                "event_type": name,
                "supported": True,
                "active": True,
                "enforcement": level,
                "residual_boundaries": [],
            }
            for name, level in enforcement.items()
        ],
        "residual_boundaries": [],
    }
    return {**raw, "report_digest": canonical_sha256(raw)}


def _manifest_payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "runtime": "langgraph",
        "runtime_version": "1.2.7",
        "plugin_version": "0.1.0rc1",
        "principal_id": "cred_langgraph_main",
        "agent_id": "main",
        "runtime_binding_id": "binding:langgraph:main",
        "profile_id": "agentguard-langgraph-v2",
        "profile_digest": _digest("1"),
        "activation_ref_digest": _digest("2"),
        "adapter_artifact_digest": _digest("3"),
        "capability_report_digest": _report()["report_digest"],
        "host_inventory_digest": _digest("4"),
        "tool_inventory_digest": _digest("5"),
    }


def _write_manifest(
    path: Path, payload: dict[str, Any] | None = None
) -> ProductActivationManifest:
    path.parent.chmod(0o700)
    path.write_text(json.dumps(payload or _manifest_payload()), encoding="utf8")
    path.chmod(0o600)
    return ProductActivationManifest.from_file(path)


def _observation(manifest: ProductActivationManifest) -> ProductRuntimeObservation:
    return ProductRuntimeObservation.model_validate(
        {
            "runtime": "langgraph",
            "runtime_version": manifest.runtime_version,
            "plugin_version": manifest.plugin_version,
            "loaded": True,
            "enforcement_mode": "enforce",
            "adapter_artifact_digest": manifest.adapter_artifact_digest,
            "host_inventory_digest": manifest.host_inventory_digest,
            "tool_inventory_digest": manifest.tool_inventory_digest,
            "capability_report": _report(),
        }
    )


def _ack(
    manifest: ProductActivationManifest, now: datetime = NOW, token: str = TOKEN
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "runtime": "langgraph",
        "runtime_version": manifest.runtime_version,
        "plugin_version": manifest.plugin_version,
        "agent_id": manifest.agent_id,
        "runtime_binding_id": manifest.runtime_binding_id,
        "profile_id": manifest.profile_id,
        "activation_ref_digest": manifest.activation_ref_digest,
        "capability_digest": manifest.capability_report_digest,
        "host_inventory_digest": manifest.host_inventory_digest,
        "plugin_inventory_digest": None,
        "plugin_order_inventory_digest": None,
        "tool_inventory_digest": manifest.tool_inventory_digest,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=120)).isoformat(),
        "ack_token": token,
    }


def _response(
    manifest: ProductActivationManifest,
    heartbeat: dict[str, Any],
    now: datetime = NOW,
    token: str = TOKEN,
) -> dict[str, Any]:
    return {
        "runtime_status": {
            **deepcopy(heartbeat),
            "runtime": "langgraph",
            "principal_id": manifest.principal_id,
            "last_heartbeat_at": now.isoformat(),
        },
        "activation_ack": _ack(manifest, now, token),
    }


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest = _write_manifest(tmp_path / "manifest.json")
    observed = _observation(manifest)
    clock = {"now": NOW}
    monkeypatch.setattr(sessions, "_now_utc", lambda: clock["now"])
    monkeypatch.setattr(
        sessions,
        "_installed_version",
        lambda name: "1.2.7" if name == "langgraph" else "0.1.0rc1",
    )
    yield manifest, observed, clock


def test_ack_roundtrips_only_through_explicit_wire_and_is_immutable(setup) -> None:
    manifest, _, _ = setup
    wire = _ack(manifest)
    ack = ActivationAckV1.read(wire, expected=manifest, now=NOW)
    assert ack.to_wire() == wire
    assert ack.header_value() == TOKEN
    assert TOKEN not in repr(ack)
    assert "ack_token" not in ack.model_dump()
    assert TOKEN not in ack.model_dump_json()
    with pytest.raises(ValidationError):
        ack.agent_id = "other"
    wire["agent_id"] = "other"
    assert ack.agent_id == "main"


@pytest.mark.parametrize(
    "field", list(_ack(ProductActivationManifest.model_validate(_manifest_payload())))
)
def test_ack_requires_every_wire_field(setup, field: str) -> None:
    manifest, _, _ = setup
    wire = _ack(manifest)
    del wire[field]
    with pytest.raises(ProductActivationError, match="invalid_ack"):
        ActivationAckV1.read(wire, expected=manifest, now=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime", "openclaw"),
        ("runtime_version", "1.2.6"),
        ("plugin_version", "0.1.0"),
        ("profile_id", "agentguard-openclaw-v2-restricted"),
        ("agent_id", "other"),
        ("runtime_binding_id", "binding:other"),
        ("activation_ref_digest", _digest("f")),
        ("capability_digest", _digest("f")),
        ("host_inventory_digest", _digest("f")),
        ("tool_inventory_digest", _digest("f")),
        ("plugin_inventory_digest", _digest("f")),
        ("plugin_order_inventory_digest", _digest("f")),
        ("unexpected", TOKEN),
        ("ack_token", "bearer-private-value"),
        ("agent_id", 123),
    ],
)
def test_ack_rejects_shape_pins_and_independent_identity_without_leaking_input(
    setup, field, value
) -> None:
    manifest, _, _ = setup
    wire = {**_ack(manifest), field: value}
    with pytest.raises(ProductActivationError) as failure:
        ActivationAckV1.read(wire, expected=manifest, now=NOW)
    assert TOKEN not in str(failure.value)
    assert "bearer-private-value" not in str(failure.value)
    assert failure.value.__cause__ is None


def test_nanosecond_windows_are_not_rounded_to_microseconds(setup) -> None:
    manifest, _, _ = setup
    wire = _ack(manifest)
    wire["issued_at"] = "2026-09-08T12:00:00.000000001Z"
    wire["expires_at"] = "2026-09-08T12:02:00Z"
    with pytest.raises(ProductActivationError, match="ack_not_yet_valid"):
        ActivationAckV1.read(wire, expected=manifest, now=NOW)
    wire["issued_at"] = "2026-09-08T12:00:00Z"
    wire["expires_at"] = "2026-09-08T12:02:00.000000001Z"
    with pytest.raises(ProductActivationError, match="invalid_validity_window"):
        ActivationAckV1.read(wire, expected=manifest, now=NOW)
    assert (
        timestamp_nanoseconds("2026-09-08T20:00:00.000000001+08:00")
        == datetime_nanoseconds(NOW) + 1
    )


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-08",
        "2026-09-08T12:00:00",
        "2026-02-30T12:00:00Z",
        "2026-09-08T12:00:60Z",
        "2026-09-08T12:00:00+24:00",
        "2026-09-08T12:00:00+00:60",
        "2026-09-08T12:00:00.0000000001Z",
        "２０２６-09-08T12:00:00Z",
    ],
)
def test_timestamp_reader_rejects_invalid_calendar_and_timezone(timestamp) -> None:
    with pytest.raises(ProductActivationError, match="invalid_timestamp"):
        timestamp_nanoseconds(timestamp)


def test_ack_expiry_is_exclusive_and_max_age_never_extends_server_window(setup) -> None:
    manifest, _, _ = setup
    ack = ActivationAckV1.read(_ack(manifest), expected=manifest, now=NOW)
    assert ack.remaining_seconds(now=NOW + timedelta(seconds=30)) == 90
    with pytest.raises(ProductActivationError, match="ack_expired"):
        ack.remaining_seconds(now=NOW + timedelta(seconds=120))
    with pytest.raises(ProductActivationError, match="ack_too_old"):
        ack.remaining_seconds(now=NOW + timedelta(seconds=31), max_age_seconds=30)
    for invalid in [True, 0, -1, 121, 10**1000, float("nan"), float("inf")]:
        with pytest.raises(ProductActivationError, match="invalid_max_age"):
            ack.remaining_seconds(now=NOW, max_age_seconds=invalid)
    with pytest.raises(ProductActivationError, match="invalid_clock"):
        ack.remaining_seconds(now=NOW.replace(tzinfo=None))


def test_canonical_digest_matches_frozen_golden_vector_and_core_profile() -> None:
    golden = json.loads(
        (ROOT / "tests/fixtures/product_activation_v2_golden.json").read_text()
    )
    assert (
        canonical_sha256(golden["canonical_value"]) == golden["canonical_value_digest"]
    )
    from agentguard_core import RuntimeCapabilityReportV2

    report = LangGraphCapabilityReportV2.model_validate(_report())
    assert (
        RuntimeCapabilityReportV2.model_validate(
            report.model_dump(mode="json")
        ).report_digest
        == report.report_digest
    )
    for invalid in [1.2, {1: "value"}, {"key": (1, 2)}, {"key": float("nan")}]:
        with pytest.raises(ProductActivationError):
            canonical_sha256(invalid)


def test_observation_and_heartbeat_match_canonical_server_model(setup) -> None:
    manifest, observed, _ = setup
    from guard_api.runtime_status import ProductRuntimeHeartbeatV2

    heartbeat = manifest.make_heartbeat(observed)
    assert ProductRuntimeHeartbeatV2.model_validate(heartbeat).loaded is True
    assert heartbeat["reported_activation_ref_digest"] == manifest.activation_ref_digest
    assert observed.capability_report.events[0].event_type == "context_assembled"
    with pytest.raises(ValidationError):
        observed.capability_report.events[0].active = False
    assert isinstance(observed.capability_report.events, tuple)


@pytest.mark.parametrize(
    "field,value",
    [
        ("loaded", False),
        ("enforcement_mode", "observe"),
        ("adapter_artifact_digest", _digest("e")),
        ("host_inventory_digest", _digest("e")),
        ("tool_inventory_digest", _digest("e")),
        ("runtime_version", "1.2.6"),
        ("plugin_version", "0.1.0"),
    ],
)
def test_actual_observation_cannot_be_replaced_with_manifest_expectations(
    setup, field, value
) -> None:
    manifest, observed, _ = setup
    changed = observed.model_copy(update={field: value})
    with pytest.raises(ProductActivationError, match="observation_drift"):
        manifest.make_heartbeat(changed)


@pytest.mark.parametrize(
    "change",
    [
        "missing_event",
        "reorder",
        "wrong_enforcement",
        "residual",
        "c3_off",
        "inactive_event",
        "digest",
    ],
)
def test_capability_report_cannot_claim_incomplete_or_changed_profile(change) -> None:
    report = _report()
    if change == "missing_event":
        report["events"].pop()
    elif change == "reorder":
        report["events"].reverse()
    elif change == "wrong_enforcement":
        report["events"][1]["enforcement"] = "pre_execution_c1"
    elif change == "residual":
        report["residual_boundaries"] = ["host limitation"]
    elif change == "c3_off":
        report["c3_atomic_replace_and_seal"] = False
    elif change == "inactive_event":
        report["events"][0]["active"] = False
    else:
        report["report_digest"] = _digest("e")
    with pytest.raises((ValidationError, ProductActivationError)):
        LangGraphCapabilityReportV2.model_validate(report)


def test_protected_manifest_detects_content_replacement_and_symlinks(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.json"
    manifest = _write_manifest(path)
    manifest.assert_unchanged()
    replacement = tmp_path / "replacement.json"
    _write_manifest(replacement)
    replacement.replace(path)
    with pytest.raises(ProductActivationError, match="manifest_changed"):
        manifest.assert_unchanged()
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ProductActivationError, match="manifest_insecure"):
        ProductActivationManifest.from_file(link)


@pytest.mark.parametrize(
    "case",
    [
        "file_mode",
        "parent_mode",
        "hardlink",
        "oversize",
        "duplicate",
        "extra",
        "relative",
    ],
)
def test_manifest_rejects_insecure_or_ambiguous_sources(
    tmp_path: Path, case: str
) -> None:
    path = tmp_path / "manifest.json"
    _write_manifest(path)
    if case == "file_mode":
        path.chmod(0o644)
    elif case == "parent_mode":
        tmp_path.chmod(0o755)
    elif case == "hardlink":
        os.link(path, tmp_path / "other.json")
    elif case == "oversize":
        path.write_bytes(b" " * (128 * 1024 + 1))
    elif case == "duplicate":
        path.write_text('{"schema_version":"1.0","schema_version":"1.0"}')
    elif case == "extra":
        path.write_text(json.dumps({**_manifest_payload(), "ack_token": TOKEN}))
    else:
        path = Path("relative-manifest.json")
    with pytest.raises(ProductActivationError) as failure:
        ProductActivationManifest.from_file(path)
    assert str(tmp_path) not in str(failure.value)
    assert TOKEN not in str(failure.value)


def test_unprotected_in_memory_manifest_cannot_create_session() -> None:
    manifest = ProductActivationManifest.model_validate(_manifest_payload())
    with pytest.raises(ProductActivationError, match="manifest_not_file_backed"):
        ProductActivationSession(
            manifest,
            send_heartbeat=lambda _: {},
            observe=lambda: _observation(manifest),
        )


def test_manifest_rejects_fifo_without_waiting_for_a_writer(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "manifest.pipe"
    os.mkfifo(path, mode=0o600)
    with ThreadPoolExecutor(max_workers=1) as pool:
        read = pool.submit(ProductActivationManifest.from_file, path)
        try:
            with pytest.raises(ProductActivationError, match="manifest_insecure"):
                read.result(timeout=1)
        finally:
            # Release a regressed blocking reader before joining the executor.
            if not read.done():
                writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                os.close(writer)


@pytest.mark.parametrize("interval", [True, 0, 120, 10**1000, float("nan")])
def test_session_rejects_unbounded_refresh_intervals(setup, interval) -> None:
    manifest, observed, _ = setup
    with pytest.raises(ProductActivationError, match="invalid_refresh_interval"):
        ProductActivationSession(
            manifest,
            send_heartbeat=lambda body: _response(manifest, body),
            observe=lambda: observed,
            refresh_interval_seconds=interval,
        )


def test_session_requires_start_and_snapshot_never_sends_or_refreshes(setup) -> None:
    manifest, observed, clock = setup
    calls = []

    def send(body):
        calls.append(body)
        return _response(manifest, body, clock["now"])

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        with pytest.raises(ProductActivationError, match="session_not_started"):
            session.snapshot()
        ack = session.start()
        assert session.snapshot() is ack
        assert len(calls) == 1
        clock["now"] += timedelta(seconds=121)
        with pytest.raises(ProductActivationError, match="ack_expired"):
            session.snapshot()
        assert len(calls) == 1
    finally:
        session.close()


def test_actual_installed_adapter_version_is_checked_before_any_heartbeat(
    setup, monkeypatch
) -> None:
    manifest, observed, _ = setup
    checked = []

    def installed(name):
        checked.append(name)
        return "1.2.7" if name == "langgraph" else "0.1.0"

    monkeypatch.setattr(sessions, "_installed_version", installed)
    sent = []
    session = ProductActivationSession(
        manifest,
        send_heartbeat=lambda body: sent.append(body),
        observe=lambda: observed,
    )
    try:
        with pytest.raises(ProductActivationError, match="version_mismatch"):
            session.start()
        assert checked == ["langgraph", "agentguard-langgraph-adapter"]
        assert sent == []
        monkeypatch.setattr(
            sessions,
            "_installed_version",
            lambda name: "1.2.7" if name == "langgraph" else "0.1.0rc1",
        )
        with pytest.raises(ProductActivationError, match="version_mismatch"):
            session.refresh()
    finally:
        session.close()


def test_failed_refresh_blocks_new_actions_but_success_recovers_and_history_remains(
    setup,
) -> None:
    manifest, observed, clock = setup
    state = {"fail": False, "generation": 0}

    def send(body):
        if state["fail"]:
            raise ValueError(TOKEN)
        state["generation"] += 1
        return _response(
            manifest, body, clock["now"], "hmac-sha256:" + f'{state["generation"]:064x}'
        )

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        original = session.start()
        original_wire = original.to_wire()
        state["fail"] = True
        with pytest.raises(
            ProductActivationError, match="heartbeat_unavailable"
        ) as failure:
            session.refresh()
        assert TOKEN not in str(failure.value)
        with pytest.raises(ProductActivationError, match="heartbeat_unavailable"):
            session.snapshot()
        assert original.to_wire() == original_wire
        state["fail"] = False
        clock["now"] += timedelta(seconds=30)
        refreshed = session.refresh()
        assert refreshed is session.snapshot()
        assert refreshed.to_wire() != original_wire
        assert original.to_wire() == original_wire
    finally:
        session.close()


def test_observed_inventory_drift_locks_session_even_if_observer_is_restored(
    setup,
) -> None:
    manifest, observed, _ = setup
    state = {"observation": observed}
    calls = []

    def send(body):
        calls.append(body)
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: state["observation"]
    )
    try:
        old = session.start()
        state["observation"] = observed.model_copy(
            update={"host_inventory_digest": _digest("e")}
        )
        with pytest.raises(ProductActivationError, match="observation_drift"):
            session.snapshot()
        state["observation"] = observed
        with pytest.raises(ProductActivationError, match="observation_drift"):
            session.refresh()
        assert len(calls) == 1
        assert old.to_wire()["host_inventory_digest"] == manifest.host_inventory_digest
    finally:
        session.close()


@pytest.mark.parametrize(
    "field", ["principal_id", "capability_report", "reported_activation_ref_digest"]
)
def test_heartbeat_echo_cannot_rebind_expected_runtime_identity(setup, field) -> None:
    manifest, observed, _ = setup

    def send(body):
        response = _response(manifest, body)
        response["runtime_status"][field] = "wrong"
        return response

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        with pytest.raises(ProductActivationError, match="heartbeat_identity_mismatch"):
            session.start()
        with pytest.raises(ProductActivationError, match="heartbeat_identity_mismatch"):
            session.snapshot()
    finally:
        session.close()


def _track_waiters(monkeypatch, session, count: int) -> Event:
    flight = session._flight
    assert flight is not None
    original_wait = flight.done.wait
    waiting = Event()
    lock = Lock()
    registered = 0

    def wait(timeout=None):
        nonlocal registered
        with lock:
            registered += 1
            if registered == count:
                waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(flight.done, "wait", wait)
    return waiting


def test_concurrent_refresh_is_one_flight_and_returns_same_immutable_ack(
    setup, monkeypatch
) -> None:
    manifest, observed, _ = setup
    entered, release = Event(), Event()
    calls = []

    def send(body):
        calls.append(body)
        if len(calls) > 1:
            entered.set()
            assert release.wait(3)
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        session.start()
        with ThreadPoolExecutor(max_workers=5) as pool:
            leader = pool.submit(session.refresh)
            assert entered.wait(3)
            waiting = _track_waiters(monkeypatch, session, 4)
            followers = [pool.submit(session.refresh) for _ in range(4)]
            assert waiting.wait(3)
            release.set()
            first = leader.result(timeout=3)
            assert all(future.result(timeout=3) is first for future in followers)
            assert len(calls) == 2
    finally:
        release.set()
        session.close()


def test_close_unblocks_waiters_and_discards_late_success(setup, monkeypatch) -> None:
    manifest, observed, _ = setup
    entered, release = Event(), Event()
    calls = []

    def send(body):
        calls.append(body)
        if len(calls) > 1:
            entered.set()
            assert release.wait(3)
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        session.start()
        with ThreadPoolExecutor(max_workers=2) as pool:
            leader = pool.submit(session.refresh)
            assert entered.wait(3)
            waiting = _track_waiters(monkeypatch, session, 1)
            follower = pool.submit(session.refresh)
            assert waiting.wait(3)
            session.close()
            with pytest.raises(ProductActivationError, match="session_closed"):
                follower.result(timeout=1)
            release.set()
            with pytest.raises(ProductActivationError, match="session_closed"):
                leader.result(timeout=3)
        with pytest.raises(ProductActivationError, match="session_closed"):
            session.start()
        with pytest.raises(ProductActivationError, match="session_closed"):
            session.snapshot()
    finally:
        release.set()
        session.close()


@pytest.mark.parametrize("change", ["close", "failed_refresh", "successful_refresh"])
@pytest.mark.parametrize("operation", ["snapshot", "start"])
def test_snapshot_observer_does_not_block_close_or_return_a_superseded_ack(
    setup, change, operation
) -> None:
    manifest, observed, _ = setup
    entered, release = Event(), Event()
    observe_lock = Lock()
    state = {"block_once": False, "fail": False, "generation": 0}

    def observe():
        with observe_lock:
            block = state["block_once"]
            state["block_once"] = False
        if block:
            entered.set()
            assert release.wait(3)
        return observed

    def send(body):
        if state["fail"]:
            raise ValueError(TOKEN)
        state["generation"] += 1
        return _response(
            manifest, body, token="hmac-sha256:" + f'{state["generation"]:064x}'
        )

    session = ProductActivationSession(manifest, send_heartbeat=send, observe=observe)
    try:
        old = session.start()
        state["block_once"] = True
        with ThreadPoolExecutor(max_workers=2) as pool:
            snapshot = pool.submit(getattr(session, operation))
            try:
                assert entered.wait(3)
                if change == "close":
                    pool.submit(session.close).result(timeout=1)
                    code = "session_closed"
                elif change == "failed_refresh":
                    state["fail"] = True
                    with pytest.raises(
                        ProductActivationError, match="heartbeat_unavailable"
                    ):
                        pool.submit(session.refresh).result(timeout=1)
                    code = "heartbeat_unavailable"
                else:
                    current = pool.submit(session.refresh).result(timeout=1)
                    assert current is not old
                release.set()
                if change == "successful_refresh":
                    assert snapshot.result(timeout=1) is current
                else:
                    with pytest.raises(ProductActivationError, match=code):
                        snapshot.result(timeout=1)
            finally:
                release.set()
    finally:
        release.set()
        session.close()


def test_background_refresh_uses_same_protocol_and_stops_on_close(setup) -> None:
    manifest, observed, _ = setup
    refreshed = Event()
    calls = []

    def send(body):
        calls.append(body)
        if len(calls) == 2:
            refreshed.set()
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest,
        send_heartbeat=send,
        observe=lambda: observed,
        refresh_interval_seconds=0.01,
    )
    try:
        session.start()
        assert refreshed.wait(3)
    finally:
        session.close()
    assert session._worker is not None and not session._worker.is_alive()


def test_recovery_after_failed_start_establishes_background_refresh(setup) -> None:
    manifest, observed, _ = setup
    refreshed = Event()
    calls = []

    def send(body):
        calls.append(body)
        if len(calls) == 1:
            raise OSError(TOKEN)
        if len(calls) == 3:
            refreshed.set()
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest,
        send_heartbeat=send,
        observe=lambda: observed,
        refresh_interval_seconds=0.01,
    )
    try:
        with pytest.raises(ProductActivationError, match="heartbeat_unavailable"):
            session.start()
        assert session._worker is None
        session.refresh()
        assert refreshed.wait(3)
        assert session._worker is not None
    finally:
        session.close()
    assert session._worker is not None and not session._worker.is_alive()


def test_manifest_changed_while_heartbeat_in_flight_cannot_install_ack(setup) -> None:
    manifest, observed, _ = setup

    def send(body):
        assert manifest._source_path is not None
        manifest._source_path.write_text(
            json.dumps({**_manifest_payload(), "agent_id": "changed"})
        )
        return _response(manifest, body)

    session = ProductActivationSession(
        manifest, send_heartbeat=send, observe=lambda: observed
    )
    try:
        with pytest.raises(ProductActivationError, match="manifest_changed"):
            session.start()
        with pytest.raises(ProductActivationError, match="manifest_changed"):
            session.refresh()
    finally:
        session.close()
