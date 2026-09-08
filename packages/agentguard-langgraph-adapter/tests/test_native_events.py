"""Real native projections against the signed synthetic catalog; no Provider."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json

import pytest
from langchain_core.utils.function_calling import convert_to_openai_tool

from agentguard_core.actions.product_tools import product_tool_arguments
from agentguard_core.events import GuardEvent
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.core_client import _guard_api_v03_event
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.native_events import (
    NativeBoundaryError,
    NativeGuardEventBuilder,
    NativeModelOrigin,
)
from agentguard_langgraph_adapter.native_tools import (
    close_isolated_product_tools,
    create_isolated_product_tools,
    native_tool_catalog_materials,
    prepare_native_tool_call,
)
from guard_api.services.product_tool_catalog import load_product_tool_catalog
from tests.support.product_tool_catalog import catalog_fixture

pytestmark = pytest.mark.integration


@pytest.fixture
def context(tmp_path):
    root = tmp_path / "actual-native-tools"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:19001/inbox"
    )
    try:
        material = native_tool_catalog_materials(
            specs,
            model_visible_tools=[convert_to_openai_tool(spec.tool) for spec in specs],
        )
        data = catalog_fixture(tmp_path, langgraph_materials=material)
        catalog = load_product_tool_catalog(str(data.path), activation=data.bundle)
        builder = NativeGuardEventBuilder(
            LangGraphAdapter(config=AgentGuardLangGraphConfig(agent_id="main"))
        )
        yield builder, {spec.name: spec for spec in specs}, catalog, data.bundle
    finally:
        close_isolated_product_tools(specs)


def origin(call_id="call_actual"):
    return NativeModelOrigin("audit_actual_output", "source:model:evt_actual", call_id)


def security():
    return {
        "source_type": "model",
        "source_trust": "unknown",
        "visible_source_refs": ["source:model:evt_actual", "source:user:evt_task:0"],
        "task_id": "task_actual",
    }


@pytest.mark.parametrize(
    "name,args",
    [
        ("read", {"path": "input.txt"}),
        ("write", {"path": "output.txt", "content": "value" * 1000 + "tail"}),
        (
            "edit",
            {"path": "input.txt", "edits": [{"oldText": "old", "newText": "new"}]},
        ),
        ("exec", {"command": "python marker.py"}),
        ("process", {"action": "list"}),
        ("agentguard_memory_read", {"key": "note"}),
        ("agentguard_memory_write", {"key": "note", "value": "中文" * 1500 + "tail"}),
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox",
                "message": "content" * 1000 + "tail",
            },
        ),
    ],
)
def test_actual_native_event_roundtrips_original_arguments_into_server_catalog(
    context, name, args
):
    builder, specs, catalog, activation = context
    prepared = prepare_native_tool_call(specs[name], "call_actual", args)
    event = builder.build_specialized_action(
        prepared, security(), "trace_actual", model_origin=origin()
    )
    if event is None:
        event = builder.build_tool_call(
            prepared, security(), "trace_actual", model_origin=origin()
        )
    raw = _guard_api_v03_event(event.model_dump(mode="json"))
    core_event = GuardEvent.model_validate(raw)
    assert product_tool_arguments(core_event) == (name, "call_actual", args)
    verified = catalog.resolve(core_event, activation=activation)
    assert verified is not None
    assert verified.arguments() == args
    assert event.metadata["product_model_content"] == origin().to_mapping()
    assert event.security_context.source_type == "model"
    assert event.security_context.source_trust == "unknown"
    if name in {"agentguard_memory_write", "message"}:
        assert event.metadata["product_tool_call"] == {
            "tool_name": name,
            "call_id": "call_actual",
        }
    if name == "agentguard_memory_write":
        assert event.payload["memory"]["source_trust"] == "unknown"
        assert event.payload["requires_approval"] is True


@pytest.mark.parametrize("kind", ["tool", "specialized"])
@pytest.mark.parametrize(
    "change",
    [
        {"source_type": "user"},
        {"source_trust": "trusted"},
        {"visible_source_refs": []},
        {"visible_source_refs": ["source:model:evt_actual"] * 2},
        {"visible_source_refs": ["source:model:another"]},
    ],
)
def test_action_origin_rejects_inherited_user_trust_or_missing_model(
    context, kind, change
):
    builder, specs, *_ = context
    name = "read" if kind == "tool" else "agentguard_memory_write"
    args = {"path": "input.txt"} if kind == "tool" else {"key": "note", "value": "x"}
    prepared = prepare_native_tool_call(specs[name], "call_actual", args)
    method = (
        builder.build_tool_call if kind == "tool" else builder.build_specialized_action
    )
    with pytest.raises(NativeBoundaryError, match="^native_model_origin_mismatch$"):
        method(prepared, {**security(), **change}, "trace", model_origin=origin())


@pytest.mark.parametrize("bad", [None, {}, "private-token", 1])
def test_action_origin_cannot_be_supplied_via_user_metadata(context, bad):
    builder, specs, *_ = context
    prepared = prepare_native_tool_call(
        specs["read"], "call_actual", {"path": "input.txt"}
    )
    claimed = {
        **security(),
        "metadata": {"product_model_content": origin().to_mapping()},
    }
    with pytest.raises(NativeBoundaryError, match="^native_model_origin_invalid$"):
        builder.build_tool_call(prepared, claimed, "trace", model_origin=bad)
    with pytest.raises(NativeBoundaryError, match="^native_model_origin_mismatch$"):
        builder.build_tool_call(
            prepared, claimed, "trace", model_origin=origin("another")
        )


def test_origin_is_private_frozen_and_event_projection_is_independent(context):
    builder, specs, *_ = context
    value = origin()
    assert "audit_actual_output" not in repr(value)
    with pytest.raises(FrozenInstanceError):
        value.call_id = "another"
    prepared = prepare_native_tool_call(
        specs["read"], "call_actual", {"path": "input.txt"}
    )
    event = builder.build_tool_call(prepared, security(), "trace", model_origin=value)
    event.metadata["product_model_content"]["call_id"] = "mutated"
    value.to_mapping()["call_id"] = "also mutated"
    assert value.call_id == "call_actual"


@pytest.mark.parametrize(
    "values",
    [
        ("", "source:model:evt_actual", "call_actual"),
        (1, "source:model:evt_actual", "call_actual"),
        ("audit", "source:user:evt_actual", "call_actual"),
        ("audit", "source:model:", "call_actual"),
        ("audit", "source:model:evt_actual", "secret\nvalue"),
    ],
)
def test_origin_malformed_identity_fails_without_reflecting_values(values):
    with pytest.raises(NativeBoundaryError) as caught:
        NativeModelOrigin(*values)
    assert str(caught.value) == "native_model_origin_invalid"


@pytest.mark.parametrize(
    "phase,audit", [("output", None), ("output", ""), ("input", "audit")]
)
def test_model_input_policy_anchor_is_required_only_on_output(context, phase, audit):
    builder = context[0]
    with pytest.raises(
        NativeBoundaryError, match="^native_model_input_identity_invalid$"
    ):
        builder.build_model(
            phase=phase,
            content="private model body",
            security={},
            trace_id="trace",
            provider="local",
            model="controlled",
            model_input_audit_id=audit,
        )


def test_model_output_carries_exact_input_audit_without_content_replacement(context):
    builder = context[0]
    content = {"content": "完整内容" * 500, "tool_calls": [], "invalid_tool_calls": []}
    event = builder.build_model(
        phase="output",
        content=content,
        security={},
        trace_id="trace",
        provider="local",
        model="controlled",
        model_input_audit_id="audit_actual_input",
    )
    assert event.metadata["product_model_input_audit_id"] == "audit_actual_input"
    assert json.loads(event.payload["content_preview"]) == content


@pytest.mark.parametrize("field", ["content_preview", "phase", "provider", "sanitized"])
def test_context_identity_cannot_replace_full_model_projection(context, field):
    builder = context[0]
    with pytest.raises(NativeBoundaryError, match="^native_context_identity_invalid$"):
        builder.build_model(
            phase="input",
            content="complete original body",
            security={},
            trace_id="trace",
            provider="local",
            model="controlled",
            context_identity={field: "replacement"},
        )
