"""Actual isolated tools/catalog and HTTP; synthetic signed test admission only.

Model responses are deterministic and no Provider is contacted. Artifact digests
and candidate metadata remain explicit test assumptions. Tool schemas, execution
bindings and model-visible inventory are obtained from the actual native tools.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from tempfile import TemporaryDirectory
from typing import Any

from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_langgraph_adapter.native_tools import (
    close_isolated_product_tools,
    create_isolated_product_tools,
    native_tool_catalog_materials,
)
from agentguard_langgraph_adapter.product_manifest import ProductRuntimeObservation
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import Field, PrivateAttr

from tests.support.product_runtime_http import product_runtime_http
from tests.support.product_tool_catalog import catalog_fixture


class HttpFixtureModel(BaseChatModel):
    """One deterministic native model call, with the real BaseChatModel path."""

    responses: list[AIMessage] = Field(exclude=True)
    cache: bool = False
    max_retries: int = 0
    _messages: list[list[Any]] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "native-http-controlled-no-provider"

    def bind_tools(self, tools, **kwargs):
        return self.bind(
            tools=[convert_to_openai_tool(tool) for tool in tools], **kwargs
        )

    def _generate(self, messages, **kwargs):
        self._messages.append([message.model_copy(deep=True) for message in messages])
        return ChatResult(generations=[ChatGeneration(message=self.responses.pop(0))])


@dataclass(repr=False)
class NativeProductRuntimeHttpHarness:
    http: Any
    tools: tuple[Any, ...]
    root: Path
    received: list[dict[str, Any]]
    bound_inventory: Any
    catalog: Any

    def __getattr__(self, name):
        return getattr(self.http, name)

    def observe(self) -> ProductRuntimeObservation:
        # Every observation re-reads factory descriptors and the actual native
        # model binding; expected manifest values never supply these digests.
        materials = native_tool_catalog_materials(
            self.tools, model_visible_tools=self.bound_inventory.kwargs["tools"]
        )
        value = self.http.observation.model_dump(mode="json")
        value.update(
            tool_inventory_digest=materials["tool_inventory_digest"],
            host_inventory_digest=materials["host_inventory_digest"],
        )
        return ProductRuntimeObservation.model_validate(value)


@contextmanager
def native_product_runtime_http(
    tmp_path: Path,
    *,
    staging_tools: bool = False,
    policy: PolicyBundle | None = None,
):
    # A complete policy is fixed before catalog signing, API startup and ACKs.
    policy = policy or PolicyBundle()
    received: list[dict[str, Any]] = []

    class Inbox(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/inbox"
            received.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            body = b'{"ok":true,"messageId":"native-http-fixture"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Inbox)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    profile_directory = None
    if staging_tools:
        root = tmp_path / "native-tools"
        root.mkdir(mode=0o700)
    else:
        # A declared runtime directory, rather than /tmp executable staging.
        # The actual absolute path remains in signed catalog and policy events.
        reports = Path(__file__).resolve().parents[2] / "reports"
        reports.mkdir(exist_ok=True)
        profile_directory = TemporaryDirectory(prefix="native-tools-", dir=reports)
        root = Path(profile_directory.name).resolve()
    tools = ()
    try:
        tools = tuple(
            create_isolated_product_tools(
                root=root, inbox_url=f"http://127.0.0.1:{server.server_port}/inbox"
            )
        )
        source = root / "fixture.txt"
        source.write_text("native fixture content")
        source.chmod(0o600)
        bound = HttpFixtureModel(responses=[]).bind_tools(
            [spec.tool for spec in tools], parallel_tool_calls=False
        )
        materials = native_tool_catalog_materials(
            tools, model_visible_tools=bound.kwargs["tools"]
        )
        catalog = catalog_fixture(
            tmp_path,
            langgraph_materials=materials,
            policy_digest=canonical_sha256(policy.model_dump(mode="json")),
        )
        fixture = replace(catalog.fixture, bundle=catalog.bundle)
        with product_runtime_http(
            tmp_path,
            fixture=fixture,
            product_tool_catalog_path=catalog.path,
            policy=policy,
            task_text=(
                "Exercise this isolated product profile: read, write and edit local "
                "fixture files; exec python marker.py and list process; "
                "agentguard_memory_write and agentguard_memory_read fixture notes; "
                "send a message to the agentguard-fixture local fixture-inbox@agentguard.invalid."
            ),
        ) as http:
            yield NativeProductRuntimeHttpHarness(
                http, tools, root, received, bound, catalog
            )
    finally:
        close_isolated_product_tools(tools)
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        if profile_directory is not None:
            profile_directory.cleanup()
