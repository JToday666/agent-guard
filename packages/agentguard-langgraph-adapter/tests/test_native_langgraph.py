"""Real StateGraph/ToolNode tests with explicitly synthetic local decisions.

These controlled in-process models make no Provider request. Patching the
private composition fuse is test-only and never constitutes candidate or
Product Active evidence.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command
from pydantic import Field, PrivateAttr
import pytest

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.event_models import ToolExecutionResult
from agentguard_langgraph_adapter import native_langgraph as native
from agentguard_langgraph_adapter.native_tools import (
    close_isolated_product_tools,
    create_isolated_product_tools,
    native_tool_descriptor,
)

pytestmark = pytest.mark.e2e


class ControlledNativeModel(BaseChatModel):
    """A local model driving the actual agent loop; no network or fallback."""

    responses: list[Any] = Field(exclude=True)
    model_name: str = "non-candidate-native"
    base_url: str = "http://127.0.0.1/not-called"
    model_kwargs: dict[str, Any] = Field(default_factory=dict)
    client: Any = Field(default=None, exclude=True)
    cache: bool = False
    max_retries: int = 0
    _seen: list[list[Any]] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "controlled-native-non-candidate"

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self.bind(
            tools=[convert_to_openai_tool(tool) for tool in tools],
            **kwargs,
        )

    def _generate(self, messages: list[Any], **kwargs: Any) -> ChatResult:
        self._seen.append([message.model_copy(deep=True) for message in messages])
        output = self.responses.pop(0)
        if isinstance(output, Exception):
            raise output
        return ChatResult(generations=[ChatGeneration(message=output)])


class SyntheticBoundary:
    def __init__(self, adapter: Any, **kwargs: Any) -> None:
        self.adapter = adapter

    def invoke(self, **kwargs: Any) -> Any:
        self.adapter.boundaries.append("model")
        if self.adapter.model_block:
            return SimpleNamespace(
                blocked=True,
                output=None,
                invocation_status="not_invoked",
                delivery=None,
                error_code=None,
            )
        messages = kwargs["sources"]
        self.adapter.model_sources.append(json.loads(json.dumps(messages)))
        output = kwargs["normalize_output"](kwargs["invoke_model"](messages))
        return SimpleNamespace(
            blocked=False,
            output=output,
            invocation_status="executed",
            delivery=SimpleNamespace(status=self.adapter.model_delivery),
            error_code=None,
            visible_source_refs=("synthetic-visible-source",),
            output_source_ref=getattr(
                self.adapter, "output_source_ref", "source:model:synthetic-output"
            ),
            output_policy_audit_id=getattr(
                self.adapter, "output_policy_audit_id", "audit-synthetic-output"
            ),
        )


class SyntheticExecutor:
    def __init__(self, adapter: Any, **kwargs: Any) -> None:
        self.adapter = adapter

    def execute_action(self, prepared: Any, **kwargs: Any) -> ToolExecutionResult:
        self.adapter.boundaries.append(prepared.event_type)
        self.adapter.prepared.append(prepared)
        self.adapter.tool_security.append(kwargs["security"])
        assert kwargs["model_origin"].call_id == prepared.call_id
        assert kwargs["model_origin"].model_output_audit_id == "audit-synthetic-output"
        if self.adapter.tool_block:
            return ToolExecutionResult(
                tool_name=prepared.name,
                call_id=prepared.call_id,
                executed=False,
                blocked=True,
                decision="deny",
                status="blocked",
                runtime_receipt_status="recorded",
            )
        value = kwargs["invoke_once"]()
        if self.adapter.duplicate_execute:
            kwargs["invoke_once"]()
        return ToolExecutionResult(
            tool_name=prepared.name,
            call_id=prepared.call_id,
            executed=True,
            blocked=self.adapter.quarantine,
            decision="allow",
            status="quarantined" if self.adapter.quarantine else "executed",
            result=None if self.adapter.quarantine else value,
            runtime_receipt_status=self.adapter.tool_delivery,
        )


@pytest.fixture
def controlled_composition(monkeypatch: Any) -> Any:
    # Explicit non-candidate test seam. Public code has no corresponding flag.
    monkeypatch.setattr(
        native._execution, "assert_product_execution_available", lambda: None
    )
    monkeypatch.setattr(
        native._execution, "GuardedExecutionTemplate", SyntheticExecutor
    )
    monkeypatch.setattr(native, "GuardedModelBoundary", SyntheticBoundary)
    monkeypatch.setattr(native, "NativeGuardEventBuilder", lambda adapter: None)
    return SimpleNamespace(
        product_enabled=True,
        boundaries=[],
        prepared=[],
        tool_security=[],
        model_sources=[],
        model_block=False,
        tool_block=False,
        quarantine=False,
        model_delivery="recorded",
        tool_delivery="recorded",
        duplicate_execute=False,
    )


@pytest.fixture
def tool_profile(tmp_path: Path) -> Any:
    received: list[dict[str, Any]] = []

    class Inbox(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/inbox"
            received.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            response = b'{"ok":true,"messageId":"native-test-message"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Inbox)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    root = tmp_path / "acceptance"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root,
        inbox_url=f"http://127.0.0.1:{server.server_port}/inbox",
    )
    try:
        yield SimpleNamespace(root=root, specs=specs, received=received)
    finally:
        close_isolated_product_tools(specs)
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def call(name: str, args: dict[str, Any], identity: str = "call_1") -> AIMessage:
    return AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": identity}]
    )


def graph_for(adapter: Any, profile: Any, responses: list[Any], **kwargs: Any) -> Any:
    model = ControlledNativeModel(responses=responses)
    graph = native.build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=profile.specs,
        provider="controlled-local",
        model_name="non-candidate-native",
        **kwargs,
    )
    return graph, model


def invoke(graph: Any) -> native.NativeRunResult:
    return graph.invoke(
        sources=[{"role": "user", "content": "Run the isolated fixture."}],
        security={"agent_id": "native-test"},
        trace_id="tr_native_test",
    )


def test_public_native_fuse_rejects_before_model_or_tools(tool_profile: Any) -> None:
    graph, model = graph_for(SimpleNamespace(product_enabled=True), tool_profile, [])
    with pytest.raises(ProductActivationError):
        invoke(graph)
    assert not model._seen
    assert not tool_profile.received
    assert not (tool_profile.root / "fixture.txt").exists()


def test_real_stategraph_runs_all_eight_native_tools_once(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    actions = [
        ("write", {"path": "fixture.txt", "content": "before"}),
        ("read", {"path": "fixture.txt"}),
        (
            "edit",
            {
                "path": "fixture.txt",
                "edits": [{"oldText": "before", "newText": "after"}],
            },
        ),
        ("exec", {"command": "python marker.py"}),
        ("process", {"action": "list"}),
        ("agentguard_memory_write", {"key": "fixture", "value": "remembered"}),
        ("agentguard_memory_read", {"key": "fixture"}),
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox",
                "message": "delivered",
            },
        ),
    ]
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [
            *[
                call(name, args, f"call_{index}")
                for index, (name, args) in enumerate(actions)
            ],
            AIMessage(content="done"),
        ],
    )
    assert isinstance(graph._compiled, CompiledStateGraph)
    assert isinstance(graph._tool_node, ToolNode)
    assert graph._compiled.checkpointer is False
    assert graph._compiled.cache is None
    result = invoke(graph)
    assert not result.blocked
    assert (result.model_calls, result.tool_invocations) == (9, 8)
    assert len(model._seen) == 9
    assert len(controlled_composition.prepared) == 8
    assert all(
        item["visible_source_refs"]
        == ["source:model:synthetic-output", "synthetic-visible-source"]
        and item["source_type"] == "model"
        and item["source_trust"] == "unknown"
        for item in controlled_composition.tool_security
    )
    assert {item.name for item in controlled_composition.prepared} == {
        spec.name for spec in tool_profile.specs
    }
    assert set(controlled_composition.boundaries) == {
        "model",
        "tool_call_proposed",
        "memory_write_proposed",
        "message_send_proposed",
    }
    assert (tool_profile.root / "fixture.txt").read_text() == "after"
    assert (tool_profile.root / "command-marker.txt").read_text().count("executed") == 1
    assert tool_profile.received == [{"target": "fixture-inbox", "text": "delivered"}]
    with sqlite3.connect(tool_profile.root / "memory.sqlite") as connection:
        assert connection.execute(
            "SELECT value FROM memory WHERE key='fixture'"
        ).fetchone() == ("remembered",)
    next_round = model._seen[2]
    assert all(isinstance(message, HumanMessage) for message in next_round)
    assert json.loads(next_round[-1].content) == {
        "kind": "tool_result_evidence",
        "tool_name": "read",
        "call_id": "call_1",
        "content": "before",
    }
    assert all(
        "tool_call_id" not in source and "tool_calls" not in source
        for source in controlled_composition.model_sources[-1]
    )
    assert [
        item["function"]["name"] for item in graph._bound_model.kwargs["tools"]
    ] == [spec.name for spec in tool_profile.specs]
    assert [
        item["function"]["parameters"] for item in graph._bound_model.kwargs["tools"]
    ] == [
        convert_to_openai_tool(spec.tool)["function"]["parameters"]
        for spec in tool_profile.specs
    ]
    assert result.messages()[-1]["content"] == "done"
    result.messages().clear()
    assert len(result.messages()) == 1
    assert "remembered" not in repr(result)
    memory_results = controlled_composition.model_sources[-1][6:8]
    assert len(memory_results) == 2
    assert [item["source_type"] for item in memory_results] == ["tool_result", "memory"]
    assert all(item["source_trust"] == "untrusted" for item in memory_results)
    namespace = (
        str(tool_profile.root / "memory.sqlite")
        .replace("\\", "\\\\")
        .replace("/", "\\/")
    )
    assert memory_results[1]["source_id"] == f"memory://{namespace}/fixture"
    assert json.loads(memory_results[1]["content"]) == {
        "key": "fixture",
        "value": "remembered",
    }


def test_intermediate_model_reasoning_never_enters_next_context_or_public_answer(
    controlled_composition: Any, tool_profile: Any
) -> None:
    (tool_profile.root / "fixture.txt").write_text("complete safe tool evidence")
    (tool_profile.root / "fixture.txt").chmod(0o600)
    selection = call("read", {"path": "fixture.txt"})
    selection.content = "opaque intermediate model reasoning"
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [selection, AIMessage(content="final checked answer")],
    )
    result = invoke(graph)
    assert not result.blocked
    assert result.tool_invocations == 1
    assert len(model._seen) == 2
    sources = controlled_composition.model_sources[-1]
    assert sources[0] == {"role": "user", "content": "Run the isolated fixture."}
    assert len(sources) == 2
    assert sources[1]["source_type"] == "tool_result"
    assert sources[1]["source_trust"] == "untrusted"
    assert json.loads(sources[1]["content"])["content"] == "complete safe tool evidence"
    assert "opaque intermediate" not in json.dumps(sources)
    assert len(result.messages()) == 1
    assert result.messages()[0]["content"] == "final checked answer"
    assert "opaque intermediate" not in json.dumps(result.messages())


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_block", True),
        ("tool_delivery", "failed"),
        ("quarantine", True),
    ],
)
def test_tool_deny_or_unconfirmed_result_stops_next_model(
    controlled_composition: Any,
    tool_profile: Any,
    field: str,
    value: Any,
) -> None:
    setattr(controlled_composition, field, value)
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [
            call("write", {"path": "fixture.txt", "content": "restricted-result"}),
            AIMessage(content="must not run"),
        ],
    )
    result = invoke(graph)
    assert result.blocked
    assert len(model._seen) == 1
    assert result.tool_invocations == (0 if field == "tool_block" else 1)
    assert result.messages() == []


@pytest.mark.parametrize(
    "field,value,model_calls",
    [
        ("model_block", True, 0),
        ("model_delivery", "queued_durable", 1),
        ("model_delivery", "permanent_rejected", 1),
    ],
)
def test_model_gate_and_receipt_block_tool_execution(
    controlled_composition: Any,
    tool_profile: Any,
    field: str,
    value: Any,
    model_calls: int,
) -> None:
    setattr(controlled_composition, field, value)
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [
            call("write", {"path": "fixture.txt", "content": "forbidden"}),
        ],
    )
    result = invoke(graph)
    assert result.blocked and result.tool_invocations == 0
    assert len(model._seen) == model_calls
    assert result.messages() == []
    assert not (tool_profile.root / "fixture.txt").exists()


def test_parallel_calls_rejects_every_call_before_toolnode(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    output = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "write",
                "args": {"path": "one.txt", "content": "x"},
                "id": "call_a",
            },
            {
                "name": "write",
                "args": {"path": "two.txt", "content": "x"},
                "id": "call_b",
            },
        ],
    )
    graph, model = graph_for(controlled_composition, tool_profile, [output])
    with pytest.raises(native.NativeRuntimeError, match="native_model_calls_invalid"):
        invoke(graph)
    assert len(model._seen) == 1
    assert not controlled_composition.prepared
    assert not (tool_profile.root / "one.txt").exists()
    assert not (tool_profile.root / "two.txt").exists()


def test_duplicate_model_call_id_does_not_repeat_side_effect(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    output = call("exec", {"command": "python marker.py"})
    graph, model = graph_for(controlled_composition, tool_profile, [output, output])
    result = invoke(graph)
    assert result.blocked and result.error_code == "native_tool_call_rejected"
    assert (result.model_calls, result.tool_invocations) == (2, 1)
    assert (tool_profile.root / "command-marker.txt").read_text().count("executed") == 1


def test_native_wrapper_cannot_execute_twice(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    controlled_composition.duplicate_execute = True
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [call("exec", {"command": "python marker.py"})],
    )
    with pytest.raises(native.NativeRuntimeError, match="native_tool_already_invoked"):
        invoke(graph)
    assert (tool_profile.root / "command-marker.txt").read_text().count("executed") == 1
    assert len(model._seen) == 1


def test_tool_exception_has_no_graph_retry_or_raw_error(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(
        controlled_composition, tool_profile, [call("read", {"path": "missing.txt"})]
    )
    with pytest.raises(ProductActivationError) as caught:
        invoke(graph)
    assert len(model._seen) == len(controlled_composition.prepared) == 1
    assert "missing.txt" not in str(caught.value)


def test_model_exception_has_no_graph_retry_or_raw_error(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(
        controlled_composition, tool_profile, [RuntimeError("provider secret payload")]
    )
    with pytest.raises(
        native.NativeRuntimeError, match="^native_runtime_failed$"
    ) as caught:
        invoke(graph)
    assert "secret" not in str(caught.value)
    assert len(model._seen) == 1
    assert not controlled_composition.prepared


def test_model_loop_is_bounded_without_checkpoint_resume(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [
            call("process", {"action": "list"}, "call_1"),
            call("process", {"action": "list"}, "call_2"),
        ],
        max_model_calls=2,
    )
    result = invoke(graph)
    assert result.blocked and result.error_code == "native_model_limit"
    assert (result.model_calls, result.tool_invocations) == (2, 2)
    with pytest.raises(TypeError):
        graph.invoke(
            sources=[], security={}, config={"configurable": {"thread_id": "resume"}}
        )


def test_inventory_mutation_blocks_before_model(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(controlled_composition, tool_profile, [])
    tool_profile.specs[0].tool.description = "unexpected schema source"
    with pytest.raises(ProductActivationError, match="descriptor_drift"):
        invoke(graph)
    assert not model._seen


@pytest.mark.parametrize(
    "field,value", [("cache", True), ("max_retries", 2), ("verbose", True)]
)
def test_mutable_model_execution_settings_fail_closed(
    controlled_composition: Any,
    tool_profile: Any,
    field: str,
    value: Any,
) -> None:
    graph, model = graph_for(controlled_composition, tool_profile, [])
    setattr(model, field, value)
    with pytest.raises(native.NativeRuntimeError, match="configuration_invalid"):
        invoke(graph)
    assert not model._seen


def test_bound_model_tool_list_drift_rejected(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(controlled_composition, tool_profile, [])
    graph._bound_model.kwargs["tools"].pop()
    with pytest.raises(native.NativeRuntimeError, match="binding_invalid"):
        invoke(graph)
    assert not model._seen


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_name", "different-model"),
        ("base_url", "http://127.0.0.1/different"),
        ("model_kwargs", {"temperature": 1}),
        ("client", SimpleNamespace(base_url="http://127.0.0.1/other-client")),
        ("callbacks", []),
    ],
)
def test_effective_provider_configuration_is_frozen(
    controlled_composition: Any,
    tool_profile: Any,
    field: str,
    value: Any,
) -> None:
    graph, model = graph_for(controlled_composition, tool_profile, [])
    setattr(model, field, value)
    with pytest.raises(native.NativeRuntimeError, match="native_model_configuration_"):
        invoke(graph)
    assert not model._seen
    assert not controlled_composition.prepared


def test_model_callable_drift_blocks_before_provider(
    controlled_composition: Any,
    tool_profile: Any,
) -> None:
    graph, model = graph_for(controlled_composition, tool_profile, [])
    object.__setattr__(
        model, "_generate", lambda *args, **kwargs: pytest.fail("must not execute")
    )
    with pytest.raises(native.NativeRuntimeError, match="configuration_drift"):
        invoke(graph)
    assert not model._seen


def test_close_and_concurrent_invocation_block_new_work(
    controlled_composition: Any,
    tool_profile: Any,
    monkeypatch: Any,
) -> None:
    graph, model = graph_for(
        controlled_composition, tool_profile, [AIMessage(content="done")]
    )
    entered, released = Event(), Event()
    original = graph._model_boundary.invoke

    def pending(**kwargs: Any) -> Any:
        entered.set()
        assert released.wait(timeout=5)
        return original(**kwargs)

    monkeypatch.setattr(graph._model_boundary, "invoke", pending)
    errors: list[Exception] = []

    def run() -> None:
        try:
            invoke(graph)
        except Exception as error:
            errors.append(error)

    worker = Thread(target=run)
    worker.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(native.NativeRuntimeError, match="native_runtime_busy"):
            invoke(graph)
        graph.close()
    finally:
        released.set()
        worker.join(timeout=5)
    assert len(errors) == 1 and str(errors[0]) == "native_runtime_closed"
    assert not model._seen
    with pytest.raises(native.NativeRuntimeError, match="native_runtime_closed"):
        invoke(graph)


@pytest.mark.parametrize(
    "value",
    [
        AIMessageChunk(content="unfinished"),
        Command(update={"arbitrary": "state"}),
        AIMessage(content="hidden", additional_kwargs={"artifact": "restricted"}),
        AIMessage(
            content="bad",
            invalid_tool_calls=[
                {"name": "write", "args": "{", "id": "call_1", "error": "bad"}
            ],
        ),
    ],
)
def test_model_normalizer_rejects_incomplete_or_unbound_content(value: Any) -> None:
    with pytest.raises(native.NativeRuntimeError):
        native._normalize_model_output(value)


def test_full_model_projection_is_snapshotted_without_truncation() -> None:
    content = "a" * 4000 + "restricted tail"
    original = call("write", {"path": "fixture.txt", "content": content})
    original.content = content
    normalized = native._normalize_model_output(original)
    original.tool_calls[0]["args"]["content"] = "mutated"
    assert normalized.to_mapping()["content"] == content
    assert normalized.to_mapping()["tool_calls"][0]["args"]["content"] == content
    normalized.to_mapping()["tool_calls"].clear()
    assert len(normalized.to_mapping()["tool_calls"]) == 1


def test_raw_provider_call_must_match_parsed_call() -> None:
    original = call("read", {"path": "fixture.txt"})
    original.additional_kwargs = {
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "read",
                    "arguments": '{"path":"fixture.txt"}',
                },
            }
        ]
    }
    assert (
        native._normalize_model_output(original).to_mapping()["tool_calls"]
        == original.tool_calls
    )
    original.additional_kwargs["tool_calls"][0]["function"][
        "arguments"
    ] = '{"path":"other.txt"}'
    with pytest.raises(native.NativeRuntimeError, match="metadata_invalid"):
        native._normalize_model_output(original)


def test_factory_descriptors_are_exact_native_schemas(tool_profile: Any) -> None:
    for spec in tool_profile.specs:
        descriptor = native_tool_descriptor(spec)
        assert (
            descriptor["input_schema"] == spec.tool.tool_call_schema.model_json_schema()
        )
        assert descriptor["event_type"] == spec.event_type


def test_wrong_native_version_fails_before_model(
    controlled_composition: Any,
    tool_profile: Any,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(native, "_installed_version", lambda _: "0.0.0")
    with pytest.raises(native.NativeRuntimeError, match="native_version_mismatch"):
        graph_for(controlled_composition, tool_profile, [])


def test_base_sdk_does_not_import_optional_native_dependencies() -> None:
    script = """
import importlib.abc
import sys
class RejectNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'langchain_core', 'langgraph', 'langsmith'}:
            raise ModuleNotFoundError('native extra absent', name=fullname)
sys.meta_path.insert(0, RejectNative())
import agentguard_langgraph_adapter as sdk
assert sdk.LangGraphAdapter is not None
assert not any(key.startswith(('langchain_core', 'langgraph', 'langsmith')) for key in sys.modules)
try:
    sdk.build_native_product_graph
except ImportError as error:
    assert 'agentguard-langgraph-adapter[native]' in str(error)
else:
    raise AssertionError('native import must require the optional extra')
"""
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    "raw,parsed",
    [
        ('{"path":"unchecked.txt","path":"fixture.txt"}', {"path": "fixture.txt"}),
        (
            '{"options":{"content":"unchecked","content":"checked"}}',
            {"options": {"content": "checked"}},
        ),
    ],
)
def test_raw_provider_duplicate_keys_are_rejected_before_content_loss(raw, parsed):
    original = call("read", parsed)
    original.additional_kwargs = {
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "read", "arguments": raw},
            }
        ]
    }
    with pytest.raises(native.NativeRuntimeError, match="metadata_invalid"):
        native._normalize_model_output(original)


@pytest.mark.parametrize("field", ["output_source_ref", "output_policy_audit_id"])
def test_missing_recorded_model_origin_prevents_toolnode_execution(
    controlled_composition, tool_profile, field
):
    setattr(controlled_composition, field, None)
    graph, model = graph_for(
        controlled_composition,
        tool_profile,
        [call("write", {"path": "unpublished.txt", "content": "must not write"})],
    )
    result = invoke(graph)
    assert result.blocked and result.tool_invocations == 0
    assert result.error_code == "native_tool_call_rejected"
    assert len(model._seen) == 1
    assert not controlled_composition.prepared
    assert not (tool_profile.root / "unpublished.txt").exists()
