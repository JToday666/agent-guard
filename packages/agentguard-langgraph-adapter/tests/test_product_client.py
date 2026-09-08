"""Official SDK transport contracts; all responses here are controlled fixtures."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.metadata
import json
import time

import httpx
import pytest

from agentguard_core import build_activation_ack
from agentguard_langgraph_adapter import (
    AgentGuardCoreClient,
    AgentGuardLangGraphConfig,
    LangGraphAdapter,
)
from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter import activation_session
from agentguard_langgraph_adapter.product_manifest import ProductRuntimeObservation
from tests.support.product_activation import (
    build_test_product_activation,
    product_runtime_status_for_activation,
)

pytestmark = pytest.mark.unit
_HTTPX_CLIENT = httpx.Client


@pytest.fixture
def official_client(tmp_path, monkeypatch):
    fixture = build_test_product_activation()
    entry = fixture.bundle.runtime_entry("langgraph")
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    manifest_path = directory / "runtime.json"
    fields = (
        "runtime",
        "runtime_version",
        "plugin_version",
        "principal_id",
        "agent_id",
        "runtime_binding_id",
        "profile_id",
        "profile_digest",
        "adapter_artifact_digest",
        "capability_report_digest",
        "host_inventory_digest",
        "tool_inventory_digest",
    )
    manifest = {key: getattr(entry, key) for key in fields}
    manifest.update(
        schema_version="1.0", activation_ref_digest=fixture.bundle.activation_ref_digest
    )
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o600)
    status = product_runtime_status_for_activation(fixture, "langgraph")
    observation = ProductRuntimeObservation.model_validate(
        {
            key: status.model_dump(mode="json")[key]
            for key in (
                "runtime",
                "runtime_version",
                "plugin_version",
                "loaded",
                "enforcement_mode",
                "adapter_artifact_digest",
                "host_inventory_digest",
                "tool_inventory_digest",
                "capability_report",
            )
        }
    )
    config = AgentGuardLangGraphConfig(
        product_manifest_path=str(manifest_path),
        product_receipt_directory=str(directory / "receipts"),
        product_receipt_key_path=str(directory / "receipt-key.bin"),
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        context_isolation_mode="required",
        runtime_receipt_mode="required",
        token="private-test-token",
    )
    actual_version = importlib.metadata.version
    monkeypatch.setattr(
        activation_session,
        "version",
        lambda name: {
            "langgraph": "1.2.7",
            "agentguard-langgraph-adapter": "0.1.0rc1",
        }.get(name)
        or actual_version(name),
    )
    client = AgentGuardCoreClient(config)
    requests = []
    authority = {
        "source": "v21",
        "mode": "active",
        "selection_basis": "profile_all",
        "matched_path_ids": [],
        "legacy_floor_applied": False,
        "activation_ref_digest": fixture.bundle.activation_ref_digest,
        "approval_release": "not_applicable",
    }
    response = {
        "decision": {
            "decision_id": "dec:product-client",
            "decision": "allow",
            "risk_score": 0,
            "severity": "low",
            "reason": "fixture",
        },
        "policy_audit_id": "audit:product-client",
        "decision_authority": authority,
        "approval_release_directive": {
            "schema_version": "2.0",
            "mode": "not_applicable",
            "required_runtime_profile": None,
            "human_only": True,
            "single_use": True,
            "action_binding": "none",
            "receipt_requirement": "not_applicable",
            "activation_ref_digest": authority["activation_ref_digest"],
            "scope_digest": "sha256:" + "a" * 64,
            "capability_digest": entry.capability_report_digest,
            "residual_boundaries": [],
        },
    }
    consume_attempts = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("/heartbeat"):
            now = datetime.now(timezone.utc)
            ack = build_activation_ack(
                server_secret=fixture.server_secret,
                runtime="langgraph",
                runtime_version="1.2.7",
                plugin_version="0.1.0rc1",
                agent_id=entry.agent_id,
                runtime_binding_id=entry.runtime_binding_id,
                profile_id=entry.profile_id,
                activation_ref_digest=fixture.bundle.activation_ref_digest,
                capability_digest=entry.capability_report_digest,
                host_inventory_digest=entry.host_inventory_digest,
                tool_inventory_digest=entry.tool_inventory_digest,
                plugin_inventory_digest=None,
                plugin_order_inventory_digest=None,
                issued_at=now.isoformat(),
                expires_at=(now + timedelta(seconds=120)).isoformat(),
            )
            return httpx.Response(
                200,
                json={
                    "runtime_status": {
                        **json.loads(request.content),
                        "runtime": "langgraph",
                        "principal_id": entry.principal_id,
                        "last_heartbeat_at": now.isoformat(),
                    },
                    "activation_ack": ack.model_dump(mode="json"),
                },
            )
        if request.url.path.endswith("/consume"):
            consume_attempts.append(request)
            if len(consume_attempts) == 1:
                return httpx.Response(503, json={"error": {"code": "TRANSIENT"}})
            return httpx.Response(
                200,
                json={
                    "lease_id": "lease:client",
                    "consumption_id": "consume:client",
                    "lease_token": "lease-v1:" + "1" * 64,
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(seconds=30)
                    ).isoformat(),
                },
            )
        if request.url.path == "/v1/audit/events":
            return httpx.Response(
                200, json={"ok": True, "audit_id": "audit:historical"}
            )
        return httpx.Response(200, json=deepcopy(response))

    actual_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: actual_client(
            transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    yield client, observation, response, requests, consume_attempts
    client.close_product_session()


def event():
    return {
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "security_context": {"agent_id": "main"},
        "payload": {},
    }


def test_session_required_and_official_ack_only_on_evaluate(official_client):
    client, observation, _, requests, _ = official_client
    with pytest.raises(ProductActivationError):
        client.evaluate_product_event(event())
    assert requests == []
    ack = client.start_product_session(observe=lambda: observation)
    raw, sent = client.evaluate_product_event(event())
    assert raw["decision_authority"]["source"] == "v21"
    assert sent is ack
    assert "x-agentguard-activation-ack" not in requests[0].headers
    assert requests[1].headers["x-agentguard-activation-ack"] == ack.header_value()
    assert ack.header_value() not in requests[1].content.decode()
    assert ack.header_value() not in repr(client)
    assert "private-test-token" not in repr(client.config)


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "shadow",
        "limited_enable",
        "path_allowlist",
        "missing",
        "activation",
        "capability",
        "legacy_floor",
        "decision_id",
        "conflicting_sibling",
    ],
)
def test_official_response_rejects_fallback_and_drift(official_client, change):
    client, observation, response, requests, _ = official_client
    client.start_product_session(observe=lambda: observation)
    authority = response["decision_authority"]
    if change == "source":
        authority["source"] = "current"
    elif change in {"shadow", "limited_enable"}:
        authority["mode"] = change
    elif change == "path_allowlist":
        authority["selection_basis"] = change
    elif change == "missing":
        del response["approval_release_directive"]
    elif change == "activation":
        authority["activation_ref_digest"] = "sha256:" + "f" * 64
    elif change == "capability":
        response["approval_release_directive"]["capability_digest"] = (
            "sha256:" + "f" * 64
        )
    elif change == "decision_id":
        del response["decision"]["decision_id"]
    elif change == "conflicting_sibling":
        response["decision"]["policy_audit_id"] = "audit:other"
    else:
        authority["legacy_floor_applied"] = True
    with pytest.raises(ProductActivationError, match="official_response_mismatch"):
        client.evaluate_product_event(event())
    count = len(requests)
    with pytest.raises(ProductActivationError):
        client.evaluate_product_event(event())
    assert len(requests) == count


@pytest.mark.parametrize(
    "name,value",
    [
        ("defense_enabled", False),
        ("fail_closed", False),
        ("api_mode", "legacy"),
        ("product_manifest_path", None),
    ],
)
def test_config_mutation_cannot_restore_compatibility_allow(
    official_client, name, value
):
    client, observation, _, requests, _ = official_client
    adapter = LangGraphAdapter(config=client.config, core_client=client)
    adapter.start_product_session(observe=lambda: observation)
    setattr(client.config, name, value)
    decision = adapter.evaluate_guard_event(event())
    assert decision.decision == "deny"
    assert len(requests) == 1


def _conservative_official_response(response, *, decision, release):
    response["decision"]["decision"] = decision
    authority = response["decision_authority"]
    authority["legacy_floor_applied"] = True
    authority["approval_release"] = (
        "strong_binding_required" if release == "strong_binding" else release
    )
    directive = response["approval_release_directive"]
    directive["mode"] = release
    if release == "strong_binding":
        directive.update(
            required_runtime_profile="C3",
            action_binding="exact",
            receipt_requirement="required_durable",
        )
        response["approval"] = {"approval_id": "approval:floor", "required": True}
        response["enforcement_binding"] = {
            "schema_version": "2.1",
            "action_id": "call:floor",
            "authorization_fingerprint": "hmac-sha256:" + "b" * 64,
            "runtime_binding_id": "binding:floor",
            "requires_execution_lease": True,
        }


@pytest.mark.parametrize(
    "decision,release",
    [
        ("ask", "strong_binding"),
        ("ask", "forbidden"),
        ("ask", "not_applicable"),
        ("deny", "not_applicable"),
    ],
)
def test_official_conservative_floor_keeps_exact_decision_and_ack(
    official_client, decision, release
):
    client, observation, response, _, _ = official_client
    ack = client.start_product_session(observe=lambda: observation)
    _conservative_official_response(response, decision=decision, release=release)
    result, sent = client.evaluate_product_event(event())
    assert result["decision"] == decision
    assert result["decision_authority"]["legacy_floor_applied"] is True
    assert result["approval_release_directive"]["mode"] == release
    assert sent is ack


@pytest.mark.parametrize(
    "change", ["binding", "approval", "source", "mode", "activation", "capability"]
)
def test_conservative_floor_cannot_bypass_release_or_authority(official_client, change):
    client, observation, response, _, _ = official_client
    client.start_product_session(observe=lambda: observation)
    _conservative_official_response(response, decision="ask", release="strong_binding")
    if change in {"binding", "approval"}:
        response.pop("enforcement_binding" if change == "binding" else "approval")
    elif change == "source":
        response["decision_authority"]["source"] = "current"
    elif change == "mode":
        response["decision_authority"]["mode"] = "shadow"
    elif change == "activation":
        response["decision_authority"]["activation_ref_digest"] = "sha256:" + "f" * 64
    else:
        response["approval_release_directive"]["capability_digest"] = (
            "sha256:" + "f" * 64
        )
    with pytest.raises(ProductActivationError, match="official_response_mismatch"):
        client.evaluate_product_event(event())


def test_consume_retries_fix_ack_and_body(official_client):
    client, observation, _, _, attempts = official_client
    first = client.start_product_session(observe=lambda: observation)
    current = client.refresh_product_ack()
    assert first.header_value() != current.header_value()
    lease = client.consume_execution_lease(
        "approval:client",
        action_id="action:client",
        authorization_fingerprint="hmac-sha256:" + "b" * 64,
        deadline=time.monotonic() + 10,
        activation_ack=current,
    )
    assert lease.consumption_id == "consume:client"
    assert len(attempts) == 2
    assert attempts[0].content == attempts[1].content
    assert attempts[0].headers["x-agentguard-activation-ack"] == current.header_value()
    assert attempts[1].headers["x-agentguard-activation-ack"] == current.header_value()


def test_closed_session_can_deliver_original_historical_receipt(official_client):
    client, observation, _, requests, _ = official_client
    ack = client.start_product_session(observe=lambda: observation)
    client.close_product_session()
    payload = {"metadata": {"activation_ack": ack.to_wire()}}
    client.config.api_mode = "legacy"
    client.config.token = "changed-credential"
    response = client.submit_audit_event(payload)
    assert response["ok"] is True
    request = requests[-1]
    assert request.url.path == "/v1/audit/events"
    assert request.headers["authorization"] == "Bearer private-test-token"
    assert "x-agentguard-activation-ack" not in request.headers
    assert json.loads(request.content) == payload


def test_injected_official_client_requires_matching_adapter_config(official_client):
    client, _, _, requests, _ = official_client
    with pytest.raises(ProductActivationError, match="adapter_configuration_mismatch"):
        LangGraphAdapter(core_client=client)
    adapter = LangGraphAdapter()
    adapter.core_client = client
    adapter.config.defense_enabled = False
    assert adapter.product_enabled
    assert adapter.evaluate_guard_event(event()).decision == "deny"
    assert requests == []


def test_original_client_closes_and_receives_history_after_config_or_client_change(
    official_client,
):
    client, observation, _, requests, _ = official_client
    adapter = LangGraphAdapter(config=client.config, core_client=client)
    ack = adapter.start_product_session(observe=lambda: observation)
    from agentguard_langgraph_adapter import AuditEvent

    class Replacement:
        def submit_audit_event(self, payload):
            raise AssertionError("history must not reach the replacement")

    adapter.core_client = Replacement()
    adapter.config.defense_enabled = False
    adapter.close_product_session()
    with pytest.raises(ProductActivationError):
        client.snapshot_product_ack()
    receipt = AuditEvent(
        audit_id="audit:historical",
        record_type="runtime_observation",
        trace_id="trace:history",
        links={"event_id": "event:history", "policy_audit_id": "policy:history"},
        summary="fixture",
        reason="fixture",
    )
    receipt._product_activation_ack = ack
    assert adapter.submit_audit_event(receipt)["ok"] is True
    adapter.core_client = None
    assert adapter.submit_audit_event(receipt)["ok"] is True
    assert requests[-1].url.path == "/v1/audit/events"
    assert adapter.evaluate_guard_event(event()).decision == "deny"
    assert ack.header_value() not in repr(adapter)
    adapter.close_product_delivery()


@pytest.mark.parametrize(
    "code",
    [
        "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
        "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
        "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
    ],
)
@pytest.mark.parametrize("phase", ["heartbeat", "consume"])
def test_server_drift_is_sticky_without_echoing_private_body(
    official_client, monkeypatch, code, phase
):
    client, observation, _, requests, _ = official_client
    ack = client.start_product_session(observe=lambda: observation)
    normal_client = httpx.Client
    rejected_requests = []

    # Replace the already controlled transport with a second fixed response.
    class Rejection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, **kwargs):
            rejected_requests.append(url)
            return httpx.Response(
                503,
                request=httpx.Request("POST", url),
                json={"error": {"code": code, "message": "private-token-from-server"}},
            )

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: Rejection())
    with pytest.raises(ProductActivationError) as rejected:
        if phase == "heartbeat":
            client.refresh_product_ack()
        else:
            client.consume_execution_lease(
                "approval:drift",
                action_id="action:drift",
                authorization_fingerprint="hmac-sha256:" + "b" * 64,
                deadline=time.monotonic() + 10,
                activation_ack=ack,
            )
    assert len(rejected_requests) == 1
    assert code in str(rejected.value)
    assert "private-token-from-server" not in str(rejected.value)
    monkeypatch.setattr(httpx, "Client", normal_client)
    count = len(requests)
    with pytest.raises(ProductActivationError):
        client.refresh_product_ack()
    assert len(requests) == count


@pytest.mark.parametrize(
    "changes",
    [
        {"api_mode": "legacy"},
        {"defense_enabled": False},
        {"fail_closed": False},
        {"context_isolation_mode": "off"},
        {"runtime_receipt_mode": "best_effort"},
        {"runtime": "openclaw"},
        {"activation_ack_max_age_seconds": 121},
        {"product_refresh_interval_seconds": float("nan")},
    ],
)
def test_product_config_rejects_incompatible_options(changes):
    values = {
        "product_manifest_path": "/private/runtime.json",
        "runtime_binding_id": "binding:main",
        "context_isolation_mode": "required",
        "runtime_receipt_mode": "required",
        **changes,
    }
    with pytest.raises(ValueError):
        AgentGuardLangGraphConfig(**values)


@pytest.mark.parametrize(
    ("http_status", "response", "expected"),
    [
        (200, {"ok": True, "audit_id": "audit:typed"}, "recorded"),
        (200, {"ok": False, "audit_id": "audit:typed"}, "failed"),
        (200, {"ok": 1, "audit_id": "audit:typed"}, "failed"),
        (200, {"ok": True, "audit_id": "audit:wrong"}, "failed"),
        (200, {"ok": True, "audit_id": "audit:typed", "skipped": "no"}, "failed"),
        (200, ["invalid"], "failed"),
        (301, {}, "permanent_rejected"),
        (400, {}, "permanent_rejected"),
        (401, {}, "permanent_rejected"),
        (403, {}, "permanent_rejected"),
        (409, {}, "permanent_rejected"),
        (422, {}, "permanent_rejected"),
        (408, {}, "retryable"),
        (429, {}, "retryable"),
        (500, {}, "retryable"),
        (503, {}, "retryable"),
    ],
)
def test_product_receipt_typed_transport_classifies_one_attempt(
    official_client, monkeypatch, http_status, response, expected
):
    client, _, _, _, _ = official_client
    payload = json.dumps(
        {
            "audit_id": "audit:typed",
            "runtime": "langgraph",
            "record_type": "runtime_observation",
        }
    ).encode()
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(http_status, json=response)

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: _HTTPX_CLIENT(
            transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    client.close_product_session()
    client.config.token = "changed-token"
    client.config.core_base_url = "https://changed.invalid"
    result = client.submit_product_receipt_wire(payload)
    assert result.status == expected
    assert result.audit_id == "audit:typed"
    assert result.http_status == http_status
    assert len(attempts) == 1
    assert attempts[0].content == payload
    assert attempts[0].headers["authorization"] == "Bearer private-test-token"
    assert "x-agentguard-activation-ack" not in attempts[0].headers
    assert attempts[0].url.host == "127.0.0.1"
    assert "private-test-token" not in repr(result)


@pytest.mark.parametrize("fault", ["read_timeout", "invalid_json", "oversized"])
def test_product_receipt_transport_bounds_and_redacts_failure(
    official_client, monkeypatch, fault
):
    client, _, _, _, _ = official_client
    secret = "transport-callback-secret"
    payload = json.dumps(
        {
            "audit_id": "audit:typed",
            "runtime": "langgraph",
            "record_type": "runtime_observation",
        }
    ).encode()

    def handler(request):
        if fault == "read_timeout":
            raise httpx.ReadTimeout(secret, request=request)
        if fault == "invalid_json":
            return httpx.Response(200, content=secret.encode())
        return httpx.Response(200, content=b"x" * (1024 * 1024 + 1))

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: _HTTPX_CLIENT(
            transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    result = client.submit_product_receipt_wire(payload)
    assert result.status == ("retryable" if fault == "read_timeout" else "failed")
    assert secret not in repr(result)


def test_product_receipt_transport_without_product_identity_sends_nothing(monkeypatch):
    def unexpected(**kwargs):
        raise AssertionError("no network before trusted Product identity")

    monkeypatch.setattr(httpx, "Client", unexpected)
    client = AgentGuardCoreClient(AgentGuardLangGraphConfig())
    assert client.submit_product_receipt_wire(b"{}").status == "failed"
