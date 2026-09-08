"""Real localhost Guard API for SDK transport contracts, not candidate admission.

Authority signatures are real signatures over the existing synthetic TEST bundle.
Its artifact/inventory digests and runtime observations are fixtures, not evidence
that a built candidate or native host has qualified for Product Active.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
from threading import Thread
import time
from typing import Any

import httpx
import uvicorn
from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.product_manifest import ProductRuntimeObservation
from fastapi import FastAPI, Request

from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.product_activation import (
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)
from tests.support.product_evaluation import product_replay_settings
from tests.test_product_activation_http import _event_payload, _task_payload


@dataclass(slots=True)
class CapturedProductRequest:
    """Only synthetic test ACKs are captured, and never in the object's repr."""

    path: str
    activation_ack_header: str | None = field(repr=False)
    body: dict[str, Any] = field(repr=False)
    status_code: int | None = None


@dataclass(slots=True)
class ProductRuntimeHttpHarness:
    fixture: ProductActivationFixture = field(repr=False)
    store: MemoryControlPlaneStore = field(repr=False)
    client: httpx.Client = field(repr=False)
    manifest_path: Path
    observation: ProductRuntimeObservation
    base_url: str
    task_id: str
    requests: list[CapturedProductRequest] = field(repr=False)
    runtime_tokens: dict[str, str] = field(repr=False)
    trace_id: str = "trace:langgraph-sdk-http-contract"
    session_id: str = "session:langgraph-sdk-http-contract"
    task_text: str = "exercise the public Product Active HTTP chain"

    def config(self) -> AgentGuardLangGraphConfig:
        entry = self.fixture.bundle.runtime_entry("langgraph")
        return AgentGuardLangGraphConfig(
            core_base_url=self.base_url,
            token=self.runtime_tokens["langgraph"],
            timeout=3.0,
            agent_id=entry.agent_id,
            runtime_binding_id=entry.runtime_binding_id,
            product_manifest_path=str(self.manifest_path),
            context_isolation_mode="required",
            runtime_receipt_mode="required",
        )

    def event(self, event_type: str = "tool_call_proposed") -> dict[str, Any]:
        # Share the seven existing public HTTP fixtures instead of inventing a
        # second event contract specifically for the SDK implementation.
        event = _event_payload(
            "langgraph",
            event_type,
            self.task_id,
            trace_id=self.trace_id,
            session_id=self.session_id,
        )
        event["security_context"]["user_task"] = self.task_text
        return event

    def requests_for(self, path: str) -> list[CapturedProductRequest]:
        return [request for request in self.requests if request.path == path]

    def heartbeat_openclaw(self, **changes: Any) -> httpx.Response:
        payload = product_runtime_status_for_activation(
            self.fixture, "openclaw"
        ).model_dump(
            mode="json", exclude={"runtime", "principal_id", "last_heartbeat_at"}
        )
        payload.update(changes)
        return self.client.post(
            "/v1/adapters/openclaw/heartbeat",
            headers={"Authorization": f"Bearer {self.runtime_tokens['openclaw']}"},
            json=payload,
        )


@contextmanager
def _localhost_server(app: FastAPI) -> Iterator[str]:
    """Run the real ASGI lifespan and HTTP stack; no ASGITransport/TestClient."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server: uvicorn.Server | None = None
    thread: Thread | None = None
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                app, log_level="error", lifespan="on", access_log=False, ws="none"
            )
        )
        thread = Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            name="product-transport-contract-api",
            daemon=True,
        )
        thread.start()
        deadline = time.monotonic() + 10.0
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("Local transport-contract API did not start")
            time.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        if server is not None:
            server.should_exit = True
        if thread is not None:
            thread.join(timeout=10.0)
        listener.close()
        if thread is not None and thread.is_alive():
            raise RuntimeError("Local transport-contract API did not stop")


@contextmanager
def product_runtime_http(
    tmp_path: Path,
    *,
    fixture: ProductActivationFixture | None = None,
    product_tool_catalog_path: Path | None = None,
    task_text: str = "exercise the public Product Active HTTP chain",
) -> Iterator[ProductRuntimeHttpHarness]:
    """Seed the peer over HTTP; the tested SDK must establish its own heartbeat."""

    policy = PolicyBundle()
    fixture = fixture or build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = write_test_product_activation(
        tmp_path / "synthetic-signed-transport-authority.json", fixture
    )
    settings = product_replay_settings(activation_path, fixture)
    settings.v21_product_tool_catalog_path = (
        str(product_tool_catalog_path)
        if product_tool_catalog_path is not None
        else None
    )
    settings.llm_approval_enabled = False
    settings.llm_approval_api_key = None
    settings.v21_semantic_enabled = False
    settings.v21_semantic_api_key = None
    store = MemoryControlPlaneStore()
    store.save_policy_snapshot(
        policy, expected_revision=0, updated_by="sdk-http-contract-test"
    )
    tokens = {
        "langgraph": "langgraph-sdk-http-contract-secret",
        "openclaw": "openclaw-sdk-http-contract-secret",
    }
    for runtime in ("langgraph", "openclaw"):
        entry = fixture.bundle.runtime_entry(runtime)
        add_adapter_credential(
            store,
            token=tokens[runtime],
            runtime=runtime,
            agent_id=entry.agent_id,
            principal_id=entry.principal_id,
        )

    entry = fixture.bundle.runtime_entry("langgraph")
    manifest_directory = tmp_path / "protected-sdk-manifest"
    manifest_directory.mkdir(mode=0o700)
    manifest_path = manifest_directory / "manifest.json"
    manifest_fields = (
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
    manifest = {name: getattr(entry, name) for name in manifest_fields}
    manifest.update(
        schema_version="1.0", activation_ref_digest=fixture.bundle.activation_ref_digest
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o600)
    observation = ProductRuntimeObservation.model_validate(
        {
            **{
                name: getattr(entry, name)
                for name in (
                    "runtime",
                    "runtime_version",
                    "plugin_version",
                    "adapter_artifact_digest",
                    "host_inventory_digest",
                    "tool_inventory_digest",
                )
            },
            "loaded": True,
            "enforcement_mode": "enforce",
            "capability_report": fixture.langgraph_capability.model_dump(mode="json"),
        }
    )
    requests: list[CapturedProductRequest] = []
    app = create_app(store=store, settings=settings)

    @app.middleware("http")
    async def capture_request(request: Request, call_next):
        raw_body = await request.body()
        captured = CapturedProductRequest(
            path=request.url.path,
            activation_ack_header=request.headers.get("X-AgentGuard-Activation-Ack"),
            body=json.loads(raw_body) if raw_body else {},
        )
        requests.append(captured)
        response = await call_next(request)
        captured.status_code = response.status_code
        return response

    with _localhost_server(app) as base_url:
        with httpx.Client(base_url=base_url, timeout=3.0, trust_env=False) as client:
            harness = ProductRuntimeHttpHarness(
                fixture=fixture,
                store=store,
                client=client,
                manifest_path=manifest_path,
                observation=observation,
                base_url=base_url,
                task_id="",
                requests=requests,
                runtime_tokens=tokens,
                task_text=task_text,
            )
            peer = harness.heartbeat_openclaw()
            assert peer.status_code == 200, peer.text
            assert peer.headers["cache-control"] == "no-store"
            task = client.post(
                "/v1/tasks",
                headers={"Authorization": "Bearer control-secret"},
                json={
                    **_task_payload(
                        "langgraph",
                        fixture,
                        trace_id=harness.trace_id,
                        session_id=harness.session_id,
                    ),
                    "task_text": task_text,
                },
            )
            assert task.status_code == 200, task.text
            task_body = task.json()
            assert task_body["status"] == "active"
            harness.task_id = task_body["task_id"]
            # This internal state has no public mutation route. The TaskFact
            # itself was authenticated and created through the real HTTP API.
            SecurityStateService(store).ensure_ready(task_body["scope_digest"])
            yield harness
