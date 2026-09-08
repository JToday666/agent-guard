"""Actual isolated tools; these fixtures do not qualify a Product candidate."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sqlite3
from threading import Thread

import pytest
from langchain_core.utils.function_calling import convert_to_openai_tool

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.native_tools import (
    NATIVE_TOOL_NAMES,
    PreparedNativeToolCall,
    close_isolated_product_tools,
    create_isolated_product_tools,
    native_tool_catalog_materials,
    native_tool_descriptor,
    native_tool_inventory_digest,
    prepare_native_tool_call,
)

pytestmark = pytest.mark.e2e


@contextmanager
def inbox(*, status=200, reply=None):
    messages = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/inbox"
            messages.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            body = json.dumps(
                reply
                if reply is not None
                else {"ok": True, "messageId": "fixture:actual-local-message"}
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/inbox", messages
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.fixture
def toolkit(tmp_path):
    root = tmp_path / "acceptance"
    root.mkdir(mode=0o700)
    (root / "seed.txt").write_text("original fixture")
    (root / "seed.txt").chmod(0o600)
    with inbox() as (url, messages):
        tools = create_isolated_product_tools(root=root, inbox_url=url)
        try:
            yield root, tools, messages
        finally:
            close_isolated_product_tools(tools)


def call(tools, name, arguments, call_id="native-fixture-call"):
    spec = next(tool for tool in tools if tool.name == name)
    prepared = prepare_native_tool_call(spec, call_id, arguments)
    return spec.tool.invoke(prepared.arguments())


def test_memory_overwrite_is_rejected_before_evaluation_and_at_execution(toolkit):
    root, tools, _ = toolkit
    spec = next(tool for tool in tools if tool.name == "agentguard_memory_write")
    stale = prepare_native_tool_call(
        spec, "pending-write", {"key": "note", "value": "replacement"}
    )
    call(tools, spec.name, {"key": "note", "value": "original"})
    with pytest.raises(ProductActivationError, match="memory_overwrite_not_supported"):
        prepare_native_tool_call(
            spec, "second-write", {"key": "note", "value": "replacement"}
        )
    with pytest.raises(ProductActivationError, match="memory_overwrite_not_supported"):
        spec.tool.invoke(stale.arguments())
    with sqlite3.connect(root / "memory.sqlite") as db:
        assert db.execute("SELECT key,value FROM memory").fetchall() == [
            ("note", "original")
        ]


def test_actual_eight_tools_have_frozen_schemas_and_real_side_effects(toolkit):
    root, tools, messages = toolkit
    assert tuple(tool.name for tool in tools) == NATIVE_TOOL_NAMES
    assert native_tool_inventory_digest(tools).startswith("sha256:")
    for spec in tools:
        descriptor = native_tool_descriptor(spec)
        schema = descriptor["input_schema"]
        assert len(schema["required"]) == len(set(schema["required"]))
        assert set(schema["required"]) == set(schema["properties"])
        assert descriptor["execution_schema"]["additionalProperties"] is False
        assert descriptor["fixture_id"] == f"langgraph:{spec.name}:isolated-v1"
    assert call(tools, "read", {"path": "seed.txt"}) == "original fixture"
    assert json.loads(
        call(tools, "write", {"path": "created.txt", "content": "created fixture"})
    )["ok"]
    assert (root / "created.txt").read_text() == "created fixture"
    call(
        tools,
        "edit",
        {
            "path": "seed.txt",
            "edits": [{"oldText": "original fixture", "newText": "edited fixture"}],
        },
    )
    assert (root / "seed.txt").read_text() == "edited fixture"
    assert (
        json.loads(call(tools, "exec", {"command": "python marker.py"}))["exit_code"]
        == 0
    )
    assert (root / "command-marker.txt").read_text() == "isolated command executed\n"
    assert json.loads(call(tools, "process", {"action": "list"}))["processes"] == [
        {"sequence": 1, "exit_code": 0}
    ]
    call(
        tools,
        "agentguard_memory_write",
        {"key": "note", "value": "accepted fixture value"},
    )
    assert (
        json.loads(call(tools, "agentguard_memory_read", {"key": "note"}))["value"]
        == "accepted fixture value"
    )
    with sqlite3.connect(root / "memory.sqlite") as db:
        assert db.execute("SELECT key,value FROM memory").fetchall() == [
            ("note", "accepted fixture value")
        ]
    assert json.loads(
        call(
            tools,
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox",
                "message": "fixture status",
            },
        )
    )["ok"]
    assert messages == [{"target": "fixture-inbox", "text": "fixture status"}]
    assert (root / "created.txt").stat().st_mode & 0o777 == 0o600


def test_prepared_is_full_immutable_projection_and_copies(toolkit):
    root, tools, _ = toolkit
    spec = next(tool for tool in tools if tool.name == "write")
    args = {"path": "created.txt", "content": "original"}
    prepared = prepare_native_tool_call(spec, "call:immutable", args)
    args["content"] = "changed"
    prepared.arguments()["content"] = "changed again"
    prepared.resources()[0]["target"] = "/outside"
    assert prepared.arguments()["content"] == "original"
    assert prepared.resources()[0]["target"] == str(root / "created.txt")
    assert "original" not in repr(prepared)
    spec.tool.invoke(prepared.arguments())
    assert (root / "created.txt").read_text() == "original"


def test_actual_catalog_export_matches_core_and_fixed_script_bytes(toolkit):
    from agentguard_core.actions.product_tools import (
        langgraph_host_inventory_digest,
        product_command_script,
        product_model_visible_tools,
    )

    root, tools, _ = toolkit
    actual_visible = [convert_to_openai_tool(spec.tool) for spec in tools]
    exported = native_tool_catalog_materials(tools, model_visible_tools=actual_visible)
    assert exported["model_visible_tools"] == actual_visible
    assert exported["model_visible_tools"] == product_model_visible_tools(
        exported["tools"]
    )
    assert exported["host_inventory_digest"] == langgraph_host_inventory_digest(
        actual_visible
    )
    assert exported["tool_inventory_digest"] == native_tool_inventory_digest(tools)
    assert exported["execution"]["root"] == str(root)
    assert exported["execution"]["memory_namespace"] == str(root / "memory.sqlite")
    assert (root / "marker.py").read_bytes() == product_command_script("langgraph")
    actual_visible[0]["function"]["name"] = "changed"
    exported["tools"][0]["input_schema"]["properties"].clear()
    exported["execution"]["root"] = "/changed"
    again = native_tool_catalog_materials(
        tools, model_visible_tools=[convert_to_openai_tool(spec.tool) for spec in tools]
    )
    assert again["execution"]["root"] == str(root)
    assert again["tools"][0]["input_schema"]["properties"]
    assert again["model_visible_tools"][0]["function"]["name"] == NATIVE_TOOL_NAMES[0]


@pytest.mark.parametrize(
    "change", ["missing", "reordered", "duplicate", "schema", "extra"]
)
def test_catalog_capture_rejects_provider_inventory_drift(toolkit, change):
    tools = toolkit[1]
    visible = [convert_to_openai_tool(spec.tool) for spec in tools]
    if change == "missing":
        visible.pop()
    elif change == "reordered":
        visible.reverse()
    elif change == "duplicate":
        visible[-1] = visible[0]
    elif change == "schema":
        visible[0]["function"]["parameters"]["additionalProperties"] = False
    else:
        visible[0]["function"]["strict"] = True
    with pytest.raises(ProductActivationError, match="model_inventory_mismatch"):
        native_tool_catalog_materials(tools, model_visible_tools=visible)


def test_catalog_capture_cannot_mix_factories_or_use_closed_runtime(toolkit, tmp_path):
    root = tmp_path / "other"
    root.mkdir(mode=0o700)
    other = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:19002/inbox"
    )
    tools = toolkit[1]
    try:
        mixed = (other[0], *tools[1:])
        with pytest.raises(ProductActivationError, match="inventory_runtime_mismatch"):
            native_tool_catalog_materials(
                mixed,
                model_visible_tools=[
                    convert_to_openai_tool(spec.tool) for spec in mixed
                ],
            )
    finally:
        close_isolated_product_tools(other)
    with pytest.raises(ProductActivationError, match="closed"):
        native_tool_catalog_materials(
            other,
            model_visible_tools=[convert_to_openai_tool(spec.tool) for spec in other],
        )


@pytest.mark.parametrize(
    "name,args",
    [
        ("write", {"path": "x.txt", "content": 12}),
        ("write", {"path": "x.txt"}),
        ("write", {"path": "x.txt", "content": "v", "runtime": {}}),
        ("write", {"path": "../x.txt", "content": "v"}),
        ("write", {"path": "/tmp/x.txt", "content": "v"}),
        ("write", {"path": "marker.py", "content": "v"}),
        ("exec", {"command": "python marker.py; touch outside"}),
        ("process", {"action": "kill"}),
        (
            "message",
            {
                "action": "send",
                "channel": "email",
                "target": "fixture-inbox",
                "message": "x",
            },
        ),
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "outside",
                "message": "x",
            },
        ),
        ("agentguard_memory_write", {"key": "../escape", "value": "v"}),
    ],
)
def test_noncanonical_or_unscoped_arguments_reject_before_host_call(
    toolkit, name, args
):
    root, tools, messages = toolkit
    spec = next(tool for tool in tools if tool.name == name)
    with pytest.raises(ProductActivationError):
        prepare_native_tool_call(spec, "call:invalid", args)
    assert not (root / "x.txt").exists()
    assert not (root / "command-marker.txt").exists()
    assert not messages


@pytest.mark.parametrize(
    "mutation", ["function", "schema", "description", "metadata", "async"]
)
def test_descriptor_drift_invalidates_already_prepared_call(toolkit, mutation):
    _, tools, _ = toolkit
    spec = next(tool for tool in tools if tool.name == "read")
    prepared = prepare_native_tool_call(spec, "call:drift", {"path": "seed.txt"})
    if mutation == "function":
        spec.tool.func = lambda **_: "changed"
    elif mutation == "schema":
        spec.tool.args_schema = {"type": "object"}
    elif mutation == "description":
        spec.tool.description = "changed"
    elif mutation == "metadata":
        spec.tool.metadata = {"changed": True}
    else:

        async def replacement(**_):
            return "changed"

        spec.tool.coroutine = replacement
    with pytest.raises(ProductActivationError):
        prepared.assert_current()


def test_copied_spec_and_prepared_are_not_factory_issued(toolkit):
    _, tools, _ = toolkit
    spec = next(tool for tool in tools if tool.name == "read")
    with pytest.raises(ProductActivationError):
        native_tool_descriptor(replace(spec))
    prepared = prepare_native_tool_call(spec, "call:copy", {"path": "seed.txt"})
    with pytest.raises(ProductActivationError):
        replace(prepared).assert_current()
    assert isinstance(prepared, PreparedNativeToolCall)
    with pytest.raises(ProductActivationError):
        native_tool_inventory_digest(tools[:-1])
    with pytest.raises(ProductActivationError):
        native_tool_inventory_digest(tools[::-1])


def test_callback_closure_drift_cannot_substitute_another_tool(toolkit):
    root, tools, _ = toolkit
    spec = next(tool for tool in tools if tool.name == "write")
    prepared = prepare_native_tool_call(
        spec, "call:closure", {"path": "created.txt", "content": "approved"}
    )
    function = spec.tool.func
    assert function is not None
    cells = dict(zip(function.__code__.co_freevars, function.__closure__))
    cells["tool_name"].cell_contents = "exec"
    with pytest.raises(ProductActivationError):
        prepared.assert_current()
    assert not (root / "created.txt").exists()
    assert not (root / "command-marker.txt").exists()


def test_closed_and_duplicate_runtime_cannot_execute(toolkit):
    root, tools, _ = toolkit
    with pytest.raises(ProductActivationError):
        create_isolated_product_tools(
            root=root, inbox_url="http://127.0.0.1:9999/inbox"
        )
    spec = next(tool for tool in tools if tool.name == "read")
    prepared = prepare_native_tool_call(spec, "call:closed", {"path": "seed.txt"})
    close_isolated_product_tools(tools)
    with pytest.raises(ProductActivationError):
        prepared.assert_current()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "mode"])
def test_host_file_protection_rejects_nonprivate_files(toolkit, tmp_path, kind):
    root, tools, _ = toolkit
    target = tmp_path / "outside.txt"
    target.write_text("unchanged")
    target.chmod(0o600)
    path = root / "created.txt"
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "fifo":
        os.mkfifo(path, mode=0o600)
    else:
        path.write_text("wrong permissions")
        path.chmod(0o644)
    with pytest.raises(ProductActivationError):
        call(tools, "write", {"path": "created.txt", "content": "changed"})
    assert target.read_text() == "unchanged"


def test_script_drift_never_launches_command(toolkit):
    root, tools, _ = toolkit
    (root / "marker.py").write_text("raise RuntimeError('unexpected')")
    with pytest.raises(ProductActivationError):
        call(tools, "exec", {"command": "python marker.py"})
    assert not (root / "command-marker.txt").exists()


def test_unbounded_result_and_nonunique_edit_do_not_release_content(toolkit):
    root, tools, _ = toolkit
    (root / "seed.txt").write_text("x" * (64 * 1024 + 1))
    with pytest.raises(ProductActivationError):
        call(tools, "read", {"path": "seed.txt"})
    (root / "seed.txt").write_text("duplicate duplicate")
    with pytest.raises(ProductActivationError):
        call(
            tools,
            "edit",
            {"path": "seed.txt", "edits": [{"oldText": "duplicate", "newText": "v"}]},
        )
    assert (root / "seed.txt").read_text() == "duplicate duplicate"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/inbox",
        "http://localhost:12/inbox",
        "http://127.0.0.1:99999/inbox",
        "http://127.0.0.1:12/inbox?x=1",
    ],
)
def test_inbox_must_be_explicit_literal_loopback(tmp_path, url):
    with pytest.raises(ProductActivationError):
        create_isolated_product_tools(root=tmp_path, inbox_url=url)


@pytest.mark.parametrize(
    "status,reply",
    [
        (302, {"ok": True}),
        (200, {"ok": False}),
        (200, {"ok": True}),
        (503, {"error": "private failure"}),
    ],
)
def test_message_negative_response_is_one_attempt_and_bounded_error(
    tmp_path, status, reply
):
    with inbox(status=status, reply=reply) as (url, messages):
        tools = create_isolated_product_tools(root=tmp_path, inbox_url=url)
        try:
            with pytest.raises(ProductActivationError) as exc:
                call(
                    tools,
                    "message",
                    {
                        "action": "send",
                        "channel": "agentguard-fixture",
                        "target": "fixture-inbox",
                        "message": "only local",
                    },
                )
            assert "private failure" not in str(exc.value)
            assert len(messages) == 1
        finally:
            close_isolated_product_tools(tools)
