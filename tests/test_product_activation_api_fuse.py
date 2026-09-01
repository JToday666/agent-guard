"""Product Active pre-selector fuse placement and HTTP containment tests.

These tests intentionally exercise the boundary before the Product selector is
wired.  A configured Product activation may inspect only authenticated runtime
identity and its exact runtime observations; it must never enter legacy/current
evaluation, replay, or any side-effect path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, NoReturn, cast

import pytest
from agentguard_core import GuardEvent
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from guard_api.auth import ApiAuthError, AuthContext, CapabilityAuthService
from guard_api.errors import error_response
from guard_api.models import ADAPTER_CREDENTIAL_SCOPES, CredentialRecord
from guard_api.routers.guard import register_routes
from guard_api.runtime_status import ProductRuntimeStatusV2
from guard_api.services.evaluation import EvaluationService
from guard_api.services.product_activation import (
    ACTIVATION_NOT_CURRENT,
    RUNTIME_IDENTITY_MISMATCH,
    RUNTIME_OBSERVATION_MISMATCH,
    SELECTOR_NOT_WIRED,
    FrozenProductActivation,
    ProductActivePreSelectorFuse,
)
from guard_api.services.v21_pipeline import (
    PRODUCT_AUTHORITY_NOT_CURRENT,
    PRODUCT_CREDENTIAL_NOT_CURRENT,
    PRODUCT_POLICY_NOT_CURRENT,
    V21OfficialEvaluationUnavailableError,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_product_activation_contracts import _activation

_EVENT_PAYLOADS: dict[str, dict[str, Any]] = {
    "tool_call_proposed": {
        "tool": {"name": "safe_tool", "call_id": "call:fuse"},
        "arguments": {},
        "derived_resources": [],
    },
    "context_assembled": {
        "sources": [],
        "will_enter_context": True,
        "sanitized": True,
    },
    "model_input_prepared": {
        "phase": "input",
        "content_preview": "safe input",
        "contains_instruction_like_text": False,
        "contains_sensitive_data": False,
        "sanitized": True,
    },
    "model_output_produced": {
        "phase": "output",
        "content_preview": "safe output",
        "contains_instruction_like_text": False,
        "contains_sensitive_data": False,
        "sanitized": True,
    },
    "tool_result_produced": {
        "tool": {"name": "safe_tool", "call_id": "call:fuse"},
        "result": {
            "content_preview": "safe result",
            "content_type": "text/plain",
            "size_bytes": 11,
        },
        "will_enter_context": False,
        "will_persist": False,
        "sanitized": True,
        "contains_sensitive_data": False,
        "contains_instruction_like_text": False,
    },
    "memory_write_proposed": {
        "memory": {
            "namespace": "fuse-test",
            "key": "safe-key",
            "value_preview": "safe value",
            "source_trust": "trusted",
            "operation": "write",
        },
        "will_persist": True,
        "requires_approval": False,
    },
    "message_send_proposed": {
        "channel": "test",
        "recipient": "recipient:test",
        "content_preview": "safe message",
    },
}


def _event_payload(
    event_type: str,
    *,
    event_id: str | None = None,
    runtime: str = "langgraph",
    agent_id: str = "main",
    timestamp: str = "not-an-rfc3339-timestamp",
) -> dict[str, Any]:
    return {
        "schema_version": "0.3",
        "event_id": event_id or f"evt_product_fuse_{event_type}",
        "event_type": event_type,
        "runtime": runtime,
        "trace_id": f"trace_product_fuse_{event_type}",
        "timestamp": timestamp,
        "pre_execution": event_type
        not in {"model_output_produced", "tool_result_produced"},
        "security_context": {
            "agent_id": agent_id,
            "user_task": "exercise Product Active containment",
        },
        "payload": _EVENT_PAYLOADS[event_type],
        "metadata": {},
    }


@dataclass
class _BlockingFuse:
    code: str = "V21_PRODUCT_SELECTOR_NOT_WIRED"
    calls: list[tuple[str, str | None]] = field(default_factory=list)

    def enforce(
        self,
        event: GuardEvent,
        auth_context: AuthContext | None,
    ) -> NoReturn:
        self.calls.append(
            (
                event.event_type,
                None if auth_context is None else auth_context.principal_id,
            )
        )
        raise V21OfficialEvaluationUnavailableError(self.code)


class _ForbiddenDependency:
    """Tripwire for every legacy/current evaluation dependency."""

    def __getattr__(self, name: str) -> NoReturn:
        raise AssertionError(f"Product fuse touched forbidden dependency: {name}")


def _evaluation(fuse: _BlockingFuse) -> EvaluationService:
    forbidden = cast(Any, _ForbiddenDependency())
    service = EvaluationService(
        policy_service=forbidden,
        audit_service=forbidden,
        approval_service=forbidden,
        memory_guard_service=forbidden,
        action_critic=forbidden,
        v21_shadow_service=forbidden,
        v21_pipeline=forbidden,
        ct_projection_service=forbidden,
        context_builder_service=forbidden,
        product_active_fuse=cast(Any, fuse),
    )
    return service


def _client(
    fuse: _BlockingFuse,
) -> tuple[TestClient, MemoryControlPlaneStore]:
    settings = GuardApiSettings(control_token="control-secret")
    store = MemoryControlPlaneStore()
    token = "adapter-secret"
    store.create_credential(
        CredentialRecord(
            credential_id="cred_product_fuse",
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            principal_type="component",
            principal_id="principal:lg",
            role="adapter",
            scopes=list(ADAPTER_CREDENTIAL_SCOPES),
            runtime="langgraph",
            agent_id="main",
        )
    )
    app = FastAPI()

    @app.exception_handler(ApiAuthError)
    async def auth_error(_: Request, exc: ApiAuthError) -> JSONResponse:
        return error_response(exc.code, status_code=exc.status_code)

    @app.exception_handler(V21OfficialEvaluationUnavailableError)
    async def product_unavailable(
        _: Request,
        exc: V21OfficialEvaluationUnavailableError,
    ) -> JSONResponse:
        return error_response(exc.code, status_code=503)

    # The production route uses only these two fields.  Keeping the real route
    # here proves that bearer/scope/runtime identity checks stay ahead of the
    # service-level Product activation fuse.
    register_routes(
        app,
        cast(
            Any,
            SimpleNamespace(
                auth=CapabilityAuthService(settings=settings, store=store),
                evaluation_service=_evaluation(fuse),
            ),
        ),
    )
    return TestClient(app), store


def _auth(
    *,
    runtime: str = "langgraph",
    principal_id: str = "principal:lg",
) -> AuthContext:
    return AuthContext(
        principal_type="component",
        principal_id=principal_id,
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime=runtime,
        agent_id="main",
    )


def _frozen_activation() -> tuple[FrozenProductActivation, dict[str, Any]]:
    bundle, langgraph_capability, openclaw_capability = _activation()
    return (
        FrozenProductActivation(
            bundle=bundle,
            source_path="/process/frozen/product-activation.json",
            content_digest=canonical_sha256(bundle.model_dump(mode="json")),
        ),
        {
            "langgraph": langgraph_capability,
            "openclaw": openclaw_capability,
        },
    )


def _matching_status(
    activation: FrozenProductActivation,
    capabilities: dict[str, Any],
    *,
    runtime: str,
) -> ProductRuntimeStatusV2:
    entry = activation.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
    return ProductRuntimeStatusV2(
        schema_version="2.0",
        status="loaded",
        loaded=True,
        runtime_id=f"{runtime}-host",
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        profile_id=entry.profile_id,
        runtime_version=entry.runtime_version,
        plugin_version=entry.plugin_version,
        profile_digest=entry.profile_digest,
        adapter_artifact_digest=entry.adapter_artifact_digest,
        reported_activation_ref_digest=activation.bundle.activation_ref_digest,
        host_inventory_digest=entry.host_inventory_digest,
        plugin_inventory_digest=entry.plugin_inventory_digest,
        plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
        tool_inventory_digest=entry.tool_inventory_digest,
        capability_report=capabilities[runtime],
        source="product-fuse-test",
        hook_count=0,
        expected_hook_count=0,
        hooks=[],
        fail_closed_stages=[],
        enforcement_mode="enforce",
        runtime=entry.runtime,
        principal_id=entry.principal_id,
        last_heartbeat_at="2026-09-01T00:01:00+00:00",
    )


def _real_fuse(
    store: MemoryControlPlaneStore,
    *,
    clock: Any,
) -> tuple[ProductActivePreSelectorFuse, FrozenProductActivation, dict[str, Any]]:
    activation, capabilities = _frozen_activation()
    return (
        ProductActivePreSelectorFuse(
            activation=activation,
            store=store,
            clock=clock,
        ),
        activation,
        capabilities,
    )


def test_product_fuse_runs_after_principal_normalization_but_before_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fuse = _BlockingFuse()
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    def forbidden_parse(_: str) -> NoReturn:
        raise AssertionError("timestamp parsing must remain behind the Product fuse")

    def forbidden_digest(_: object) -> NoReturn:
        raise AssertionError("request digest must remain behind the Product fuse")

    monkeypatch.setattr(
        "guard_api.services.evaluation.parse_audit_timestamp",
        forbidden_parse,
    )
    monkeypatch.setattr(
        "guard_api.services.evaluation.canonical_sha256",
        forbidden_digest,
    )
    auth = AuthContext(
        principal_type="component",
        principal_id="principal:lg",
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime="langgraph",
        agent_id="main",
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        _evaluation(fuse).evaluate(event, auth_context=auth)

    assert raised.value.code == "V21_PRODUCT_SELECTOR_NOT_WIRED"
    assert fuse.calls == [("tool_call_proposed", "principal:lg")]


def test_product_fuse_precedes_historical_replay_and_all_side_effects() -> None:
    fuse = _BlockingFuse()
    event = GuardEvent.model_validate(
        _event_payload(
            "tool_call_proposed",
            event_id="evt_product_fuse_existing_replay",
        )
    )
    auth = AuthContext(
        principal_type="component",
        principal_id="principal:lg",
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime="langgraph",
        agent_id="main",
    )

    # Every collaborator is a tripwire.  In particular, the audit store cannot
    # be queried for this existing-looking event_id, and no replay repair,
    # detector, policy, state, approval, memory, audit, or binding entrypoint is
    # reachable.
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        _evaluation(fuse).evaluate(event, auth_context=auth)

    assert raised.value.code == "V21_PRODUCT_SELECTOR_NOT_WIRED"
    assert fuse.calls == [("tool_call_proposed", "principal:lg")]


def test_all_seven_events_are_contained_without_current_fallback() -> None:
    fuse = _BlockingFuse()
    client, store = _client(fuse)

    for event_type in _EVENT_PAYLOADS:
        response = client.post(
            "/v1/guard/evaluate",
            headers={"Authorization": "Bearer adapter-secret"},
            json=_event_payload(event_type),
        )

        assert response.status_code == 503
        assert response.json() == {
            "error": {
                "code": "V21_PRODUCT_SELECTOR_NOT_WIRED",
                "message": "Product V2 authority selector is not wired.",
                "details": [],
            }
        }

    assert [event_type for event_type, _ in fuse.calls] == list(_EVENT_PAYLOADS)
    assert {principal for _, principal in fuse.calls} == {"principal:lg"}
    assert store.audit_events == []
    assert store.approvals == {}
    assert store.enforcement_bindings == {}
    assert store.memory_changes == {}


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (
            PRODUCT_POLICY_NOT_CURRENT,
            "Product V2 policy revision or digest is not current.",
        ),
        (
            PRODUCT_AUTHORITY_NOT_CURRENT,
            "Product V2 authority changed before the evaluation committed.",
        ),
        (
            PRODUCT_CREDENTIAL_NOT_CURRENT,
            "Product V2 runtime credential is not current.",
        ),
    ],
)
def test_product_authority_failures_have_stable_http_503_envelopes(
    code: str,
    message: str,
) -> None:
    client, store = _client(_BlockingFuse(code=code))

    response = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_event_payload("tool_call_proposed"),
    )

    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": code, "message": message, "details": []}
    }
    assert store.audit_events == []


def test_http_authentication_and_runtime_identity_stay_ahead_of_product_fuse() -> None:
    fuse = _BlockingFuse()
    client, _ = _client(fuse)
    payload = _event_payload("tool_call_proposed")

    unauthenticated = client.post("/v1/guard/evaluate", json=payload)
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "AUTH_MISSING"

    wrong_runtime = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json={**payload, "runtime": "openclaw"},
    )
    assert wrong_runtime.status_code == 403
    assert wrong_runtime.json()["error"]["code"] == "RUNTIME_IDENTITY_MISMATCH"
    assert fuse.calls == []


def test_direct_active_call_without_auth_context_fails_closed_at_fuse() -> None:
    fuse = _BlockingFuse(code="V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH")
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        _evaluation(fuse).evaluate(
            event,
            requesting_principal_id="principal:lg",
        )

    assert raised.value.code == "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH"
    assert fuse.calls == [("tool_call_proposed", None)]


def test_real_fuse_rechecks_activation_expiry_during_process_lifetime() -> None:
    store = MemoryControlPlaneStore()
    now = [datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc)]
    fuse, activation, capabilities = _real_fuse(store, clock=lambda: now[0])
    for runtime in ("langgraph", "openclaw"):
        store.save_product_runtime_status(
            _matching_status(
                activation,
                capabilities,
                runtime=runtime,
            )
        )
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    with pytest.raises(V21OfficialEvaluationUnavailableError) as armed:
        fuse.enforce(event, _auth())
    assert armed.value.code == SELECTOR_NOT_WIRED

    now[0] = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as expired:
        fuse.enforce(event, _auth())
    assert expired.value.code == ACTIVATION_NOT_CURRENT


def test_real_fuse_rejects_activation_runtime_identity_before_observation() -> None:
    store = MemoryControlPlaneStore()
    fuse, _, _ = _real_fuse(
        store,
        clock=lambda: datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc),
    )
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(event, _auth(principal_id="principal:wrong"))

    assert raised.value.code == RUNTIME_IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "observed_runtimes",
    [(), ("langgraph",)],
    ids=["missing-both", "partial-langgraph-only"],
)
def test_real_fuse_requires_both_exact_runtime_observations(
    observed_runtimes: tuple[str, ...],
) -> None:
    store = MemoryControlPlaneStore()
    fuse, activation, capabilities = _real_fuse(
        store,
        clock=lambda: datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc),
    )
    for runtime in observed_runtimes:
        store.save_product_runtime_status(
            _matching_status(
                activation,
                capabilities,
                runtime=runtime,
            )
        )
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        fuse.enforce(event, _auth())

    assert raised.value.code == RUNTIME_OBSERVATION_MISMATCH


def test_real_fuse_rejects_observation_drift_and_accepts_only_full_match() -> None:
    store = MemoryControlPlaneStore()
    fuse, activation, capabilities = _real_fuse(
        store,
        clock=lambda: datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc),
    )
    langgraph = _matching_status(
        activation,
        capabilities,
        runtime="langgraph",
    )
    openclaw = _matching_status(
        activation,
        capabilities,
        runtime="openclaw",
    )
    store.save_product_runtime_status(langgraph)
    store.save_product_runtime_status(
        openclaw.model_copy(update={"runtime_version": "drifted-host-version"})
    )
    event = GuardEvent.model_validate(_event_payload("tool_call_proposed"))

    with pytest.raises(V21OfficialEvaluationUnavailableError) as drifted:
        fuse.enforce(event, _auth())
    assert drifted.value.code == RUNTIME_OBSERVATION_MISMATCH

    store.save_product_runtime_status(openclaw)
    for event_type in _EVENT_PAYLOADS:
        matched_event = GuardEvent.model_validate(_event_payload(event_type))
        with pytest.raises(V21OfficialEvaluationUnavailableError) as matched:
            fuse.enforce(matched_event, _auth())
        assert matched.value.code == SELECTOR_NOT_WIRED
