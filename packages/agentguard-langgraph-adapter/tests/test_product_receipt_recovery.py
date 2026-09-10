"""Recovery configuration and endpoint binding; controlled transport, no Host run."""

from __future__ import annotations

from dataclasses import asdict, replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from threading import Event

import pytest

from agentguard_langgraph_adapter.activation_ack import (
    ActivationAckV1,
    ProductActivationError,
)
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.product_delivery import ProductReceiptTransportResult
from agentguard_langgraph_adapter.product_envelope_store import (
    ProductEnvelopeStore,
    ProductEnvelopeStoreError,
    ProductStoreNamespace,
)
from agentguard_langgraph_adapter.product_outbox import ProductReceiptOutbox
from agentguard_langgraph_adapter.product_receipt_recovery import (
    RECOVERY_CONFIG_SCHEMA,
    load_product_recovery_config,
    open_product_receipt_recovery,
)
from agentguard_langgraph_adapter.product_transport import (
    product_transport_binding_digest,
)
from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


def _namespace():
    return ProductStoreNamespace(
        runtime="langgraph",
        agent_id="main",
        principal_id="principal_main",
        runtime_binding_id="binding:main",
    )


@pytest.fixture
def recovery_config(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    manifest = private / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "runtime": "langgraph",
                "runtime_version": "1.2.7",
                "plugin_version": "0.1.0rc1",
                "principal_id": "principal_main",
                "agent_id": "main",
                "runtime_binding_id": "binding:main",
                "profile_id": "agentguard-langgraph-v2",
                **{
                    field: "sha256:" + str(i) * 64
                    for i, field in enumerate(
                        (
                            "profile_digest",
                            "activation_ref_digest",
                            "adapter_artifact_digest",
                            "capability_report_digest",
                            "host_inventory_digest",
                            "tool_inventory_digest",
                        ),
                        1,
                    )
                },
            }
        )
    )
    manifest.chmod(0o600)
    return AgentGuardLangGraphConfig(
        core_base_url="http://127.0.0.1:8088",
        token="isolated-recovery-test-credential",
        runtime="langgraph",
        agent_id="main",
        runtime_binding_id="binding:main",
        fail_closed=True,
        defense_enabled=True,
        context_isolation_mode="required",
        runtime_receipt_mode="required",
        product_manifest_path=str(manifest),
        product_receipt_directory=str(tmp_path / "queue"),
        product_receipt_key_path=str(tmp_path / "keys" / "key"),
    )


def _config_file(config):
    path = Path(config.product_manifest_path).parent / "recovery.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": RECOVERY_CONFIG_SCHEMA,
                "runtime": "langgraph",
                "config": asdict(config),
            }
        )
    )
    path.chmod(0o600)
    return path


def _terminal():
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    ack = ActivationAckV1.model_validate(
        {
            "schema_version": "1.0",
            "runtime": "langgraph",
            "runtime_version": "1.2.7",
            "plugin_version": "0.1.0rc1",
            "agent_id": "main",
            "runtime_binding_id": "binding:main",
            "profile_id": "agentguard-langgraph-v2",
            "activation_ref_digest": "sha256:" + "2" * 64,
            "capability_digest": "sha256:" + "4" * 64,
            "host_inventory_digest": "sha256:" + "5" * 64,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": "sha256:" + "6" * 64,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=120)).isoformat(),
            "ack_token": "hmac-sha256:" + "a" * 64,
        }
    )
    event = ToolCallEvent(
        event_id="event_recovery",
        trace_id="trace_recovery",
        security_context=SecurityContext(agent_id="main"),
        tool=ToolDescriptor(
            name="write", category="file", kind="write", call_id="action_recovery"
        ),
        arguments={"path": "fixture.txt"},
    )
    decision = PolicyDecision(
        decision_id="decision_recovery",
        decision="allow",
        risk_score=0,
        severity="low",
        reason="isolated transport fixture",
        policy_audit_id="policy_recovery",
    )
    decision._evaluation_activation_ack = ack
    return build_runtime_outcome(
        event,
        decision,
        execution_status="not_invoked",
        completed_at=(now + timedelta(seconds=1)).isoformat(),
    )


def _prepare(config, *, bound=True):
    client = AgentGuardCoreClient(config)
    sent = []

    def reject(wire):
        sent.append(wire)
        return ProductReceiptTransportResult(
            "permanent_rejected",
            json.loads(wire)["audit_id"],
            409,
            "http_permanent_rejection",
        )

    store = ProductEnvelopeStore(
        config.product_receipt_directory,
        config.product_receipt_key_path,
        namespace=_namespace(),
    )
    outbox = ProductReceiptOutbox(
        store,
        send_receipt=reject,
        transport_binding_digest=(
            client.product_receipt_transport_binding_digest if bound else None
        ),
    )
    terminal = _terminal()
    result = outbox.submit(terminal)
    assert result.status == "permanent_rejected"
    outbox.close()
    assert len(sent) == 1
    return terminal.audit_id, hashlib.sha256(sent[0]).hexdigest(), sent[0]


def test_transport_binding_known_vector_and_identity_changes():
    expected = "e66c9ce5de1d7c32e7a82c99772de846113bad05ab4a39699357203ea7e6b808"
    assert (
        product_transport_binding_digest(
            base_url="http://127.0.0.1:8088/", namespace=_namespace()
        )
        == expected
    )
    assert (
        product_transport_binding_digest(
            base_url="http://127.0.0.1:8089", namespace=_namespace()
        )
        != expected
    )
    assert (
        product_transport_binding_digest(
            base_url="http://127.0.0.1:8088",
            namespace=replace(_namespace(), principal_id="another"),
        )
        != expected
    )
    with pytest.raises(ProductActivationError):
        product_transport_binding_digest(
            base_url="http://example.invalid", namespace=_namespace()
        )


def test_client_binding_uses_captured_transport_and_allows_credential_rotation(
    recovery_config,
):
    client = AgentGuardCoreClient(recovery_config)
    original = client.product_receipt_transport_binding_digest
    recovery_config.core_base_url = "http://127.0.0.1:8181"
    assert client.product_receipt_transport_binding_digest == original
    assert (
        AgentGuardCoreClient(recovery_config).product_receipt_transport_binding_digest
        != original
    )
    rotated = replace(
        recovery_config,
        core_base_url="http://127.0.0.1:8088",
        token="rotated-test-credential",
    )
    assert (
        AgentGuardCoreClient(rotated).product_receipt_transport_binding_digest
        == original
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "world_readable",
        "parent_writable",
        "symlink",
        "hardlink",
        "duplicate",
        "extra",
        "enabled",
        "missing",
        "nan",
    ],
)
def test_recovery_configuration_rejects_unprotected_or_incompatible_inputs(
    recovery_config, mutation
):
    path = _config_file(recovery_config)
    raw = json.loads(path.read_text())
    if mutation == "world_readable":
        path.chmod(0o644)
    elif mutation == "parent_writable":
        path.parent.chmod(0o770)
    elif mutation == "symlink":
        linked = path.with_name("linked.json")
        linked.symlink_to(path)
        path = linked
    elif mutation == "hardlink":
        path.with_name("linked.json").hardlink_to(path)
    elif mutation == "duplicate":
        path.write_text(path.read_text()[:-1] + ',"runtime":"langgraph"}')
    elif mutation == "nan":
        path.write_text(path.read_text().replace('"timeout": 5.0', '"timeout": NaN'))
    else:
        if mutation == "extra":
            raw["unexpected"] = True
        elif mutation == "enabled":
            raw["config"]["product_execution_enabled"] = True
        elif mutation == "missing":
            raw["config"].pop("core_base_url")
        path.write_text(json.dumps(raw))
    with pytest.raises(ProductActivationError, match="receipt_recovery_config_invalid"):
        load_product_recovery_config(path)


def test_recovery_never_creates_a_missing_queue_or_key(recovery_config):
    loaded = load_product_recovery_config(_config_file(recovery_config))
    with pytest.raises(
        ProductActivationError, match="receipt_recovery_storage_missing"
    ):
        open_product_receipt_recovery(loaded)
    assert not Path(loaded.product_receipt_directory).exists()
    assert not Path(loaded.product_receipt_key_path).exists()


@pytest.mark.parametrize("removed", ["directory", "key", "key_parent", "owner"])
def test_storage_disappearing_after_precheck_is_never_recreated(
    recovery_config, monkeypatch, removed
):
    from agentguard_langgraph_adapter import product_receipt_recovery as module

    _prepare(recovery_config)
    original = module._require_existing_storage
    directory = Path(recovery_config.product_receipt_directory)
    key = Path(recovery_config.product_receipt_key_path)
    target = {
        "directory": directory,
        "key": key,
        "key_parent": key.parent,
        "owner": directory / ".lock",
    }[removed]

    def remove_after_check(config):
        original(config)
        target.rename(target.with_name(target.name + ".retained"))

    monkeypatch.setattr(module, "_require_existing_storage", remove_after_check)
    monkeypatch.setattr(
        AgentGuardCoreClient,
        "submit_product_receipt_wire",
        lambda *_args: pytest.fail("unavailable storage cannot send HTTP"),
    )
    with pytest.raises(ProductActivationError):
        open_product_receipt_recovery(recovery_config)
    assert not target.exists()
    assert target.with_name(target.name + ".retained").exists()


@pytest.mark.parametrize("mutation", ["endpoint", "legacy"])
def test_recovery_refuses_unproven_destination_before_any_sender(
    recovery_config, monkeypatch, mutation
):
    _prepare(recovery_config, bound=mutation != "legacy")

    def unexpected(*_args):
        pytest.fail("recovery must reject before HTTP")

    monkeypatch.setattr(AgentGuardCoreClient, "submit_product_receipt_wire", unexpected)
    config = (
        replace(recovery_config, core_base_url="http://127.0.0.1:8181")
        if mutation == "endpoint"
        else recovery_config
    )
    with pytest.raises(ProductActivationError):
        open_product_receipt_recovery(config)


def test_recovery_only_resubmits_original_wire_without_session_or_execution(
    recovery_config, monkeypatch
):
    audit_id, digest, original = _prepare(recovery_config)
    sent = []

    def success(_client, wire):
        sent.append(wire)
        return ProductReceiptTransportResult(
            "recorded", json.loads(wire)["audit_id"], 200
        )

    def forbidden(*_args, **_kwargs):
        pytest.fail("recovery called a runtime operation")

    monkeypatch.setattr(AgentGuardCoreClient, "submit_product_receipt_wire", success)
    for method in (
        "start_product_session",
        "evaluate_guard_event",
        "consume_execution_lease",
    ):
        monkeypatch.setattr(AgentGuardCoreClient, method, forbidden)
    with open_product_receipt_recovery(recovery_config) as recovery:
        assert recovery.drain_once() == ()
        result = recovery.reconcile_rejected_receipt(audit_id, digest)
        assert result.status == "recorded"
        snapshot = recovery.reconciliation_snapshot(audit_id, digest)
        assert snapshot.confirmed and snapshot.breaker_open
        assert (
            recovery.reconcile_rejected_receipt(audit_id, digest).status == "recorded"
        )
        assert recovery.status().pending_count == 0
        assert not hasattr(recovery, "submit") and not hasattr(recovery, "start")
    assert sent == [original]


def test_adapter_close_reports_inflight_ownership_without_releasing_store(
    recovery_config, monkeypatch
):
    from agentguard_langgraph_adapter import LangGraphAdapter

    entered, release = Event(), Event()

    def held_send(_client, wire):
        entered.set()
        assert release.wait(5)
        return ProductReceiptTransportResult(
            "recorded", json.loads(wire)["audit_id"], 200
        )

    monkeypatch.setattr(AgentGuardCoreClient, "submit_product_receipt_wire", held_send)
    adapter = LangGraphAdapter(config=recovery_config)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(adapter.submit_product_receipt, _terminal())
        try:
            assert entered.wait(3)
            closing = adapter.close_product_delivery()
            assert closing is not None and closing.closing
            with pytest.raises(ProductEnvelopeStoreError, match="store_locked"):
                ProductEnvelopeStore(
                    recovery_config.product_receipt_directory,
                    recovery_config.product_receipt_key_path,
                    namespace=_namespace(),
                    existing_only=True,
                )
        finally:
            release.set()
        assert future.result(timeout=3).status == "failed"
    closed = adapter.close_product_delivery()
    assert closed is not None and not closed.closing
    with ProductEnvelopeStore(
        recovery_config.product_receipt_directory,
        recovery_config.product_receipt_key_path,
        namespace=_namespace(),
        existing_only=True,
    ) as store:
        assert store.usage().record_count > 0


def test_status_cli_is_readonly_and_does_not_import_native_runtimes(recovery_config):
    _prepare(recovery_config)
    config = _config_file(recovery_config)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/product-runtime-receipts.py"),
            "status",
            "--config-file",
            str(config),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert value["product_active_started"] is False
    assert value["status"]["pending_count"] == 1
    assert value["all_receipts_confirmed"] is False
    assert recovery_config.token not in completed.stdout + completed.stderr
    assert "hmac-sha256:" not in completed.stdout + completed.stderr
    check = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import agentguard_langgraph_adapter.product_receipt_recovery; assert not any(n == 'langgraph' or n.startswith(('langgraph.', 'agentguard_core', 'agentguard_langgraph_adapter.native_')) for n in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    ("mutation", "expected_exit", "expected_error"),
    [
        ("selector", 1, "receipt_reconciliation_selector_invalid"),
        ("missing_audit", 1, "receipt_reconciliation_not_found"),
        ("digest", 1, "receipt_reconciliation_digest_mismatch"),
        ("endpoint", 1, "outbox_transport_binding_mismatch"),
        ("missing_config", 2, "receipt_recovery_config_unavailable"),
        ("invalid_config", 1, "receipt_recovery_config_invalid"),
    ],
)
def test_cli_distinguishes_rejected_selection_from_unavailable_environment(
    recovery_config, mutation, expected_exit, expected_error
):
    audit_id, digest, _wire = _prepare(recovery_config)
    if mutation == "endpoint":
        recovery_config.core_base_url = "http://127.0.0.1:8181"
    config = _config_file(recovery_config)
    if mutation == "selector":
        digest = "sha256:" + digest
    elif mutation == "missing_audit":
        audit_id = "audit_absent"
    elif mutation == "digest":
        digest = "0" * 64
    elif mutation == "missing_config":
        config.unlink()
    elif mutation == "invalid_config":
        config.chmod(0o644)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/product-runtime-receipts.py"),
            "reconcile",
            "--config-file",
            str(config),
            "--audit-id",
            audit_id,
            "--expected-wire-digest",
            digest,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == expected_exit, completed.stderr + completed.stdout
    value = json.loads(completed.stdout)
    assert value["error"] == expected_error
    assert value["exit_code"] == expected_exit
    assert value["product_active_started"] is False
    assert recovery_config.token not in completed.stdout + completed.stderr
    assert "hmac-sha256:" not in completed.stdout + completed.stderr


def test_empty_drain_does_not_claim_receipt_confirmation(recovery_config):
    client = AgentGuardCoreClient(recovery_config)
    outbox = ProductReceiptOutbox(
        ProductEnvelopeStore(
            recovery_config.product_receipt_directory,
            recovery_config.product_receipt_key_path,
            namespace=_namespace(),
        ),
        send_receipt=lambda _wire: pytest.fail("empty journal cannot send"),
        transport_binding_digest=client.product_receipt_transport_binding_digest,
    )
    outbox.close()
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/product-runtime-receipts.py"),
            "drain",
            "--config-file",
            str(_config_file(recovery_config)),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 2, completed.stderr + completed.stdout
    value = json.loads(completed.stdout)
    assert value["all_receipts_confirmed"] is False
    assert value["deliveries"] == []
    assert value["status"]["completed_count"] == 0
