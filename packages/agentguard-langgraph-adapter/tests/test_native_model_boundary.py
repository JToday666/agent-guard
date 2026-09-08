"""Native full-content and immutable context contracts; no model Provider."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.context_guard import context_plan_digest
from agentguard_langgraph_adapter.event_models import PolicyDecision
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.model_boundary import (
    NativeModelOutput,
    _prepare_context,
    _snapshot_sources,
)
from agentguard_langgraph_adapter.native_events import (
    MAX_NATIVE_CONTENT_BYTES,
    NativeBoundaryError,
    NativeGuardEventBuilder,
    NativeModelOrigin,
    native_json,
    native_text,
)
from agentguard_langgraph_adapter.native_tools import (
    close_isolated_product_tools,
    create_isolated_product_tools,
    prepare_native_tool_call,
)
from .test_context_guard import _plan

pytestmark = pytest.mark.integration


@pytest.fixture
def builder():
    return NativeGuardEventBuilder(
        LangGraphAdapter(config=AgentGuardLangGraphConfig(agent_id="main"))
    )


@pytest.fixture
def tools(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir(mode=0o700)
    specs = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:19001/inbox"
    )
    try:
        yield {spec.name: spec for spec in specs}
    finally:
        close_isolated_product_tools(specs)


def test_model_full_text_and_tool_calls_tail_share_one_projection(builder):
    value = {
        "content": "a" * 3000 + "tail-policy-marker",
        "tool_calls": [
            {"name": "write", "args": {"content": "tail-secret-marker"}, "id": "call-1"}
        ],
        "invalid_tool_calls": [],
    }
    event = builder.build_model(
        phase="output",
        content=value,
        security={},
        trace_id="trace",
        provider="deterministic-local",
        model="no-provider",
        model_input_audit_id="audit-synthetic-input",
    )
    assert json.loads(event.payload["content_preview"]) == value
    assert event.payload["action_id"] == "act_" + event.event_id
    assert "tail-secret-marker" in event.payload["content_preview"]


@pytest.mark.parametrize("text", ["x" * (MAX_NATIVE_CONTENT_BYTES + 1), "界" * 21846])
def test_content_bound_uses_utf8_bytes_without_truncation(text):
    with pytest.raises(NativeBoundaryError, match="native_content_too_large"):
        native_text(text)


@pytest.mark.parametrize("value", [float("nan"), 0.1, 2**60, {1: "x"}, ("x",)])
def test_nonrestricted_json_rejected(value):
    with pytest.raises(NativeBoundaryError, match="native_content_invalid"):
        native_json(value)


def test_custom_repr_never_runs():
    class Private:
        def __str__(self):
            pytest.fail("must not stringify private object")

        __repr__ = __str__

    with pytest.raises(NativeBoundaryError, match="native_content_invalid"):
        native_text(Private())


def test_aggregate_event_bound_cannot_be_bypassed_by_small_fields(builder):
    with pytest.raises(NativeBoundaryError, match="native_content_too_large"):
        builder.build_model(
            phase="input",
            content="ok",
            security={
                "user_task": "x" * 65000,
                "model_intent": "y" * 65000,
                "sender_id": "z" * 4000,
            },
            trace_id="trace",
            provider="local",
            model="local",
        )


def test_full_memory_message_and_tool_result_actual_resource_identity(builder, tools):
    body = "normal " * 500 + "tail-marker"
    memory = prepare_native_tool_call(
        tools["agentguard_memory_write"], "call-m", {"key": "note", "value": body}
    )
    event = builder.build_specialized_action(
        memory,
        {
            "source_type": "model",
            "source_trust": "unknown",
            "visible_source_refs": ["source:model:synthetic-output"],
        },
        "trace",
        model_origin=NativeModelOrigin(
            "audit-synthetic-output", "source:model:synthetic-output", "call-m"
        ),
    )
    assert event.payload["memory"]["value_preview"] == body
    assert (
        event.payload["memory"]["namespace"] + "/note"
        == memory.resources()[0]["target"]
    )
    assert event.payload["action_id"] == "call-m"
    message = prepare_native_tool_call(
        tools["message"],
        "call-msg",
        {
            "action": "send",
            "channel": "agentguard-fixture",
            "target": "fixture-inbox",
            "message": body,
        },
    )
    event = builder.build_specialized_action(
        message,
        {
            "source_type": "model",
            "source_trust": "unknown",
            "visible_source_refs": ["source:model:synthetic-output"],
        },
        "trace",
        model_origin=NativeModelOrigin(
            "audit-synthetic-output", "source:model:synthetic-output", "call-msg"
        ),
    )
    assert event.payload["content_preview"] == body
    assert event.payload["action_id"] == "act_" + event.event_id
    result = builder.build_tool_result(
        memory, {"content": body, "artifact": {"complete": body}}, {}, "trace"
    )
    assert json.loads(result.payload["result"]["content_preview"]) == {
        "content": body,
        "artifact": {"complete": body},
    }
    assert result.payload["result"]["size_bytes"] == len(
        result.payload["result"]["content_preview"].encode()
    )


def test_context_snapshots_preserve_only_approved_correlation(builder):
    sources = [
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": "read",
            "tool_calls": [
                {
                    "name": "read",
                    "args": {"path": "note.txt"},
                    "id": "call-a",
                    "type": "tool_call",
                }
            ],
        },
        {
            "role": "tool",
            "content": "evidence",
            "tool_call_id": "call-a",
            "name": "read",
        },
    ]
    snapshot = _snapshot_sources(sources)
    event = builder.build_context(snapshot, {}, "trace")
    plan = _plan(
        snapshot,
        event_id=event.event_id,
        states=("preserved", "preserved", "annotated"),
    )
    plan["chunks"][1].update(
        compartment="model_derived", fact_authority="model_judgment"
    )
    plan["plan_digest"] = context_plan_digest(plan)
    prepared = _prepare_context(snapshot, event, SimpleNamespace(context_plan=plan))
    sources[1]["tool_calls"][0]["args"]["path"] = "tampered.txt"
    messages = prepared.messages()
    assert messages[1]["tool_calls"][0]["args"]["path"] == "note.txt"
    assert messages[2]["tool_call_id"] == "call-a"
    assert 'authority="evidence-only"' in messages[2]["content"]
    messages[1]["tool_calls"].clear()
    assert prepared.messages()[1]["tool_calls"]
    assert "note.txt" not in repr(prepared)


@pytest.mark.parametrize(
    "extra",
    [
        {"additional_kwargs": {"system": "bypass"}},
        {"tool_calls": []},
        {"tool_call_id": "call-x"},
    ],
)
def test_context_source_cannot_smuggle_model_kwargs(extra):
    with pytest.raises(NativeBoundaryError):
        _snapshot_sources([{"role": "user", "content": "task", **extra}])


def test_model_output_private_snapshot_cannot_be_mutated():
    value = {
        "content": [{"type": "text", "text": "private-content"}],
        "tool_calls": [],
        "invalid_tool_calls": [],
    }
    output = NativeModelOutput.from_mapping(value)
    value["content"][0]["text"] = "changed"
    copy = output.to_mapping()
    copy["content"].clear()
    assert output.to_mapping()["content"][0]["text"] == "private-content"
    assert "private-content" not in repr(output)


def test_action_start_is_intent_never_a_claim_of_invocation(builder):
    event = builder.build_model(
        phase="input",
        content="task",
        security={},
        trace_id="trace",
        provider="local",
        model="deterministic",
    )
    decision = PolicyDecision(
        decision="allow",
        risk_score=0,
        severity="low",
        reason="allowed",
        policy_audit_id="audit-policy",
    )
    start = builder.build_action_start(event, decision, start_kind="model_call")
    assert start.event_type == "model_call_committed"
    assert start.record_type == "runtime_observation"
    assert start.links["action_id"] == "act_" + event.event_id
    assert start.evidence["execution"]["status"] == "unknown"
    assert start.evidence["execution"]["invoked_at"] is None
    assert start.evidence["execution"]["completed_at"] is None


@pytest.mark.parametrize(
    "states",
    [("preserved", "excluded", "annotated"), ("preserved", "preserved", "excluded")],
)
def test_plan_cannot_leave_orphan_tool_protocol_messages(builder, states):
    sources = [
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"name": "read", "args": {}, "id": "call-a", "type": "tool_call"}
            ],
        },
        {
            "role": "tool",
            "content": "evidence",
            "tool_call_id": "call-a",
            "name": "read",
        },
    ]
    snapshot = _snapshot_sources(sources)
    event = builder.build_context(snapshot, {}, "trace")
    plan = _plan(snapshot, event_id=event.event_id, states=states)
    plan["chunks"][1].update(
        compartment="model_derived", fact_authority="model_judgment"
    )
    plan["plan_digest"] = context_plan_digest(plan)
    with pytest.raises(NativeBoundaryError, match="native_context_correlation"):
        _prepare_context(snapshot, event, SimpleNamespace(context_plan=plan))
