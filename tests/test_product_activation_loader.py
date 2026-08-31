"""Product V2 activation loading, observation, and pre-selector fuse tests."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentguard_core import GuardEvent, SecurityContext, ToolCallPayload, ToolDescriptor

import guard_api.services.product_activation as product_activation_module
from guard_api.auth import AuthContext
from guard_api.models import AdapterStatusRecord
from guard_api.services.product_activation import (
    ACTIVATION_NOT_CURRENT,
    RUNTIME_IDENTITY_MISMATCH,
    RUNTIME_OBSERVATION_MISMATCH,
    SELECTOR_NOT_WIRED,
    FrozenProductActivation,
    ProductActivePreSelectorFuse,
    load_frozen_product_activation,
    reconcile_product_runtime_observations,
)
from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    TEST_PRODUCT_ACTIVATION_SIGNER,
    ProductActivationFixture,
    build_test_product_activation,
    build_test_runtime_capability,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
_SHADOW_SECRET = base64.urlsafe_b64encode(
    b"independent-shadow-test-secret-material"
).decode("ascii")
_TASK_SECRET = base64.urlsafe_b64encode(
    b"independent-task-scope-secret-material"
).decode("ascii")


def _settings(
    path: Path,
    fixture: ProductActivationFixture,
    **overrides: object,
) -> GuardApiSettings:
    values: dict[str, object] = {
        "storage_backend": "memory",
        "v21_mode": "active",
        "v21_product_activation_path": str(path),
        "v21_product_activation_server_secret": (TEST_PRODUCT_ACTIVATION_SECRET_B64),
        "v21_product_activation_signer_key_id": fixture.signer_key_id,
        "v21_shadow_server_secret": _SHADOW_SECRET,
        "task_scope_active_key_id": "task-test-key",
        "task_scope_keys": json.dumps({"task-test-key": _TASK_SECRET}),
        "rte05_strong_binding_enabled": True,
    }
    values.update(overrides)
    return GuardApiSettings(**values)  # type: ignore[arg-type]


def _write_raw(path: Path, value: object) -> Path:
    if isinstance(value, bytes):
        path.write_bytes(value)
    elif isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o400)
    return path


def _stat_view(value: object, **updates: int) -> SimpleNamespace:
    fields = {
        name: getattr(value, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }
    fields.update(updates)
    return SimpleNamespace(**fields)


def _frozen(fixture: ProductActivationFixture) -> FrozenProductActivation:
    raw = fixture.bundle.model_dump(mode="json")
    return FrozenProductActivation(
        bundle=fixture.bundle,
        source_path="/test/product-activation.json",
        content_digest=canonical_sha256(raw),
    )


def _event(*, runtime: str = "langgraph", agent_id: str = "main") -> GuardEvent:
    return GuardEvent(
        event_id="evt_product_activation_fuse",
        runtime=runtime,
        trace_id="trace_product_activation_fuse",
        security_context=SecurityContext(agent_id=agent_id),
        payload=ToolCallPayload(
            tool=ToolDescriptor(name="safe_tool", call_id="call_product_fuse"),
            arguments={},
            derived_resources=[],
        ),
    )


def _auth(
    *,
    runtime: str = "langgraph",
    principal_id: str = "principal:lg",
    agent_id: str = "main",
) -> AuthContext:
    return AuthContext(
        principal_type="component",
        principal_id=principal_id,
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime=runtime,
        agent_id=agent_id,
    )


def _save_matching_statuses(
    store: MemoryControlPlaneStore,
    fixture: ProductActivationFixture,
    *,
    heartbeat_at: datetime | None = None,
) -> None:
    for runtime in ("langgraph", "openclaw"):
        store.save_product_runtime_status(
            product_runtime_status_for_activation(
                fixture,
                runtime,
                last_heartbeat_at=heartbeat_at,
            )
        )


def test_product_activation_defaults_are_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "AGENTGUARD_V21_PRODUCT_ACTIVATION_PATH",
        "AGENTGUARD_V21_PRODUCT_ACTIVATION_SERVER_SECRET",
        "AGENTGUARD_V21_PRODUCT_ACTIVATION_SIGNER_KEY_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = GuardApiSettings()

    assert settings.product_activation_configured() is False
    assert load_frozen_product_activation(settings) is None


@pytest.mark.parametrize(
    "configured",
    [
        {"v21_product_activation_path": "/tmp/product.json"},
        {"v21_product_activation_server_secret": (TEST_PRODUCT_ACTIVATION_SECRET_B64)},
        {"v21_product_activation_signer_key_id": TEST_PRODUCT_ACTIVATION_SIGNER},
        {
            "v21_product_activation_path": "/tmp/product.json",
            "v21_product_activation_server_secret": (
                TEST_PRODUCT_ACTIVATION_SECRET_B64
            ),
        },
    ],
)
def test_product_activation_configuration_is_all_or_none(
    configured: dict[str, str],
) -> None:
    settings = GuardApiSettings(**configured)  # type: ignore[arg-type]

    with pytest.raises(GuardApiConfigurationError, match="configured together"):
        settings.validate_for_startup()


def test_product_activation_is_active_only_and_mutually_exclusive(
    tmp_path: Path,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = tmp_path / "product.json"
    write_test_product_activation(path, fixture)

    with pytest.raises(GuardApiConfigurationError, match="MODE=active"):
        _settings(path, fixture, v21_mode="shadow").validate_for_startup()
    with pytest.raises(GuardApiConfigurationError, match="mutually exclusive"):
        _settings(
            path,
            fixture,
            v21_competition_activation_path="/tmp/competition.json",
        ).validate_for_startup()


def test_active_requires_exactly_one_activation_and_limited_remains_competition_only() -> (
    None
):
    official = {
        "storage_backend": "memory",
        "v21_shadow_server_secret": _SHADOW_SECRET,
        "task_scope_active_key_id": "task-test-key",
        "task_scope_keys": json.dumps({"task-test-key": _TASK_SECRET}),
        "rte05_strong_binding_enabled": True,
    }
    with pytest.raises(GuardApiConfigurationError, match="exactly one"):
        GuardApiSettings(v21_mode="active", **official).validate_for_startup()

    # The pre-existing competition Active and limited-enable configurations
    # remain valid and retain their original shadow/task/strong-binding gates.
    GuardApiSettings(
        v21_mode="active",
        v21_competition_activation_path="/tmp/competition.json",
        **official,
    ).validate_for_startup()
    GuardApiSettings(
        v21_mode="limited_enable",
        v21_competition_activation_path="/tmp/competition.json",
        **{**official, "rte05_strong_binding_enabled": False},
    ).validate_for_startup()


def test_loader_accepts_strict_signed_current_read_only_bundle(tmp_path: Path) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / "product.json", fixture)
    settings = _settings(path, fixture)
    settings.validate_for_startup()

    loaded = load_frozen_product_activation(settings, clock=lambda: _NOW)

    assert loaded is not None
    assert loaded.bundle == fixture.bundle
    assert loaded.source_path == str(path)
    assert loaded.content_digest == canonical_sha256(
        fixture.bundle.model_dump(mode="json")
    )


def test_loader_uses_product_secret_not_shadow_secret(tmp_path: Path) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / "product.json", fixture)
    settings = _settings(
        path,
        fixture,
        v21_shadow_server_secret=base64.urlsafe_b64encode(b"x" * 32).decode(),
    )

    assert load_frozen_product_activation(settings, clock=lambda: _NOW) is not None

    wrong_product_secret = base64.urlsafe_b64encode(b"y" * 32).decode()
    with pytest.raises(GuardApiConfigurationError, match="signature is invalid"):
        load_frozen_product_activation(
            _settings(
                path,
                fixture,
                v21_product_activation_server_secret=wrong_product_secret,
            ),
            clock=lambda: _NOW,
        )


def test_startup_rejects_reused_product_and_shadow_secret(tmp_path: Path) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / "product.json", fixture)
    settings = _settings(
        path,
        fixture,
        v21_shadow_server_secret=TEST_PRODUCT_ACTIVATION_SECRET_B64,
    )

    with pytest.raises(GuardApiConfigurationError, match="independent secrets"):
        settings.validate_for_startup()
    with pytest.raises(GuardApiConfigurationError, match="independent secrets"):
        load_frozen_product_activation(settings, clock=lambda: _NOW)


@pytest.mark.parametrize("mismatched_layer", ["bundle", "admission", "risk"])
def test_loader_requires_configured_signer_at_all_three_signed_layers(
    tmp_path: Path,
    mismatched_layer: str,
) -> None:
    configured = TEST_PRODUCT_ACTIVATION_SIGNER
    fixture = build_test_product_activation(
        now=_NOW,
        signer_key_id=("other-key" if mismatched_layer == "bundle" else configured),
        admission_signer_key_id=(
            "other-key" if mismatched_layer == "admission" else configured
        ),
        risk_signer_key_id=("other-key" if mismatched_layer == "risk" else configured),
    )
    path = write_test_product_activation(tmp_path / "product.json", fixture)

    with pytest.raises(GuardApiConfigurationError, match="signer identity"):
        load_frozen_product_activation(
            _settings(
                path,
                fixture,
                v21_product_activation_signer_key_id=configured,
            ),
            clock=lambda: _NOW,
        )


def test_loader_rejects_duplicate_keys_and_non_strict_defaulted_document(
    tmp_path: Path,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    canonical_text = fixture.bundle.model_dump_json()
    duplicate = '{"schema_version":"1.0",' + canonical_text[1:]
    duplicate_path = _write_raw(tmp_path / "duplicate.json", duplicate)

    with pytest.raises(GuardApiConfigurationError, match="invalid JSON"):
        load_frozen_product_activation(
            _settings(duplicate_path, fixture),
            clock=lambda: _NOW,
        )

    defaulted = fixture.bundle.model_dump(mode="json")
    defaulted.pop("mode")
    defaulted_path = _write_raw(tmp_path / "defaulted.json", defaulted)
    with pytest.raises(GuardApiConfigurationError, match="strict contract"):
        load_frozen_product_activation(
            _settings(defaulted_path, fixture),
            clock=lambda: _NOW,
        )


def test_loader_rejects_tamper_expiry_writable_symlink_and_oversize(
    tmp_path: Path,
) -> None:
    fixture = build_test_product_activation(now=_NOW)

    tampered = fixture.bundle.model_dump(mode="json")
    tampered["server_signature"] = f"hmac-sha256:{'0' * 64}"
    tampered_path = _write_raw(tmp_path / "tampered.json", tampered)
    with pytest.raises(GuardApiConfigurationError, match="signature is invalid"):
        load_frozen_product_activation(
            _settings(tampered_path, fixture),
            clock=lambda: _NOW,
        )

    current_path = write_test_product_activation(tmp_path / "expired.json", fixture)
    with pytest.raises(GuardApiConfigurationError, match="not currently valid"):
        load_frozen_product_activation(
            _settings(current_path, fixture),
            clock=lambda: _NOW + timedelta(days=2),
        )
    with pytest.raises(GuardApiConfigurationError, match="not currently valid"):
        load_frozen_product_activation(
            _settings(current_path, fixture),
            clock=lambda: _NOW - timedelta(days=1),
        )

    writable = tmp_path / "writable.json"
    writable.write_text(fixture.bundle.model_dump_json(), encoding="utf-8")
    writable.chmod(0o600)
    with pytest.raises(GuardApiConfigurationError, match="read-only"):
        load_frozen_product_activation(
            _settings(writable, fixture),
            clock=lambda: _NOW,
        )

    link = tmp_path / "activation-link.json"
    link.symlink_to(current_path)
    with pytest.raises(GuardApiConfigurationError, match="non-symlink"):
        load_frozen_product_activation(
            _settings(link, fixture),
            clock=lambda: _NOW,
        )

    oversized = _write_raw(tmp_path / "oversized.json", b" " * (64 * 1024 + 1))
    with pytest.raises(GuardApiConfigurationError, match="invalid size"):
        load_frozen_product_activation(
            _settings(oversized, fixture),
            clock=lambda: _NOW,
        )


def test_loader_rejects_file_owned_by_another_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / "wrong-owner.json", fixture)
    monkeypatch.setattr(
        product_activation_module.os,
        "geteuid",
        lambda: path.stat().st_uid + 1,
    )

    with pytest.raises(GuardApiConfigurationError, match="owned"):
        load_frozen_product_activation(
            _settings(path, fixture),
            clock=lambda: _NOW,
        )


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("inode", "changed while opening"),
        ("mode", "security changed while opening"),
    ],
)
def test_loader_rejects_identity_or_mode_drift_while_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    message: str,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / f"open-{drift}.json", fixture)
    real_fstat = product_activation_module.os.fstat

    def drifted_fstat(descriptor: int) -> object:
        opened = real_fstat(descriptor)
        if drift == "inode":
            return _stat_view(opened, st_ino=opened.st_ino + 1)
        return _stat_view(opened, st_mode=opened.st_mode | 0o200)

    monkeypatch.setattr(product_activation_module.os, "fstat", drifted_fstat)

    with pytest.raises(GuardApiConfigurationError, match=message):
        load_frozen_product_activation(
            _settings(path, fixture),
            clock=lambda: _NOW,
        )


def test_loader_rejects_metadata_mutation_while_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    path = write_test_product_activation(tmp_path / "mid-read-mutation.json", fixture)
    real_fstat = product_activation_module.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> object:
        nonlocal calls
        calls += 1
        observed = real_fstat(descriptor)
        if calls == 2:
            return _stat_view(observed, st_mtime_ns=observed.st_mtime_ns + 1)
        return observed

    monkeypatch.setattr(product_activation_module.os, "fstat", changing_fstat)

    with pytest.raises(GuardApiConfigurationError, match="changed while reading"):
        load_frozen_product_activation(
            _settings(path, fixture),
            clock=lambda: _NOW,
        )


def test_reconciliation_requires_both_exact_product_rows_and_ignores_legacy() -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()
    store.save_adapter_status(
        "langgraph",
        AdapterStatusRecord(
            status="loaded",
            loaded=True,
            last_heartbeat_at=_NOW.isoformat(),
            runtime_id="legacy",
            agent_id="main",
            source="legacy",
            enforcement_mode="enforce",
        ),
    )

    missing = reconcile_product_runtime_observations(activation, store)
    assert missing.matched is False
    assert missing.reason_codes == (RUNTIME_OBSERVATION_MISMATCH,)

    store.save_product_runtime_status(
        product_runtime_status_for_activation(fixture, "langgraph")
    )
    partial = reconcile_product_runtime_observations(activation, store)
    assert partial.matched is False
    assert partial.reason_codes == (RUNTIME_OBSERVATION_MISMATCH,)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", "principal:drift"),
        ("runtime_version", "drifted-host"),
        ("plugin_version", "drifted-plugin"),
        ("profile_digest", f"sha256:{'1' * 64}"),
        ("adapter_artifact_digest", f"sha256:{'2' * 64}"),
        ("reported_activation_ref_digest", f"sha256:{'3' * 64}"),
        ("host_inventory_digest", f"sha256:{'4' * 64}"),
        ("plugin_inventory_digest", f"sha256:{'5' * 64}"),
        ("plugin_order_inventory_digest", f"sha256:{'6' * 64}"),
        ("tool_inventory_digest", f"sha256:{'7' * 64}"),
    ],
)
def test_reconciliation_collapses_signed_field_drift_to_one_non_secret_code(
    field: str,
    value: str,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()
    langgraph = product_runtime_status_for_activation(fixture, "langgraph")
    openclaw = product_runtime_status_for_activation(fixture, "openclaw")
    drifted = openclaw.model_copy(update={field: value})
    store.save_product_runtime_status(langgraph)
    store.save_product_runtime_status(drifted)

    result = reconcile_product_runtime_observations(activation, store)

    assert result.matched is False
    assert result.reason_codes == (RUNTIME_OBSERVATION_MISMATCH,)
    assert field not in result.reason_codes[0].lower()


@pytest.mark.parametrize("supported", [True, False])
def test_reconciliation_requires_capability_digest_supported_and_active(
    supported: bool,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()
    _save_matching_statuses(store, fixture)
    openclaw = product_runtime_status_for_activation(fixture, "openclaw")
    inactive_report = build_test_runtime_capability(
        "openclaw",
        supported=supported,
        active=False,
    )
    store.save_product_runtime_status(
        openclaw.model_copy(update={"capability_report": inactive_report})
    )

    result = reconcile_product_runtime_observations(activation, store)

    assert result.matched is False
    assert result.reason_codes == (RUNTIME_OBSERVATION_MISMATCH,)


def test_reconciliation_matches_without_heartbeat_freshness_or_ack() -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()
    _save_matching_statuses(
        store,
        fixture,
        heartbeat_at=_NOW - timedelta(days=365),
    )

    result = reconcile_product_runtime_observations(activation, store)

    assert result.matched is True
    assert result.reason_codes == ()


def test_preselector_fuse_uses_four_stable_fail_closed_codes() -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()

    expired = ProductActivePreSelectorFuse(
        activation,
        store,
        clock=lambda: _NOW + timedelta(days=2),
    )
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        expired.enforce(_event(), _auth())
    assert raised.value.code == ACTIVATION_NOT_CURRENT

    fuse = ProductActivePreSelectorFuse(activation, store, clock=lambda: _NOW)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(_event(), None)
    assert raised.value.code == RUNTIME_IDENTITY_MISMATCH

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(_event(), _auth())
    assert raised.value.code == RUNTIME_OBSERVATION_MISMATCH

    _save_matching_statuses(store, fixture)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(_event(), _auth())
    assert raised.value.code == SELECTOR_NOT_WIRED


@pytest.mark.parametrize(
    ("event", "auth"),
    [
        (_event(runtime="openclaw"), _auth()),
        (_event(agent_id="other"), _auth()),
        (_event(), _auth(principal_id="principal:other")),
        (_event(), _auth(agent_id="other")),
        (
            _event(runtime="openclaw"),
            _auth(runtime="openclaw", principal_id="principal:oc"),
        ),
    ],
)
def test_preselector_fuse_binds_signed_runtime_auth_and_event_identity(
    event: GuardEvent,
    auth: AuthContext,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    activation = _frozen(fixture)
    store = MemoryControlPlaneStore()
    _save_matching_statuses(store, fixture)
    fuse = ProductActivePreSelectorFuse(activation, store, clock=lambda: _NOW)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(event, auth)

    expected = (
        SELECTOR_NOT_WIRED
        if auth.runtime == "openclaw"
        and event.runtime == "openclaw"
        and auth.principal_id == "principal:oc"
        and auth.agent_id == "main"
        and event.security_context.agent_id == "main"
        else RUNTIME_IDENTITY_MISMATCH
    )
    assert raised.value.code == expected
