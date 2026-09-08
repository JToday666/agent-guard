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
        trace_id="trace:history",
        summary="fixture",
        reason="fixture",
    )
    assert adapter.submit_audit_event(receipt)["ok"] is True
    adapter.core_client = None
    assert adapter.submit_audit_event(receipt)["ok"] is True
    assert requests[-1].url.path == "/v1/audit/events"
    assert adapter.evaluate_guard_event(event()).decision == "deny"
    assert ack.header_value() not in repr(adapter)


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
