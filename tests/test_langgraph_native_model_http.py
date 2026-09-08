"""Deterministic model + actual localhost Guard API, not candidate admission.

Only test metadata and the still-closed composition fuse are substituted. The
context plan, original ACKs, policy evaluation, AES-GCM queue and receipts are
real. The API uses MemoryControlPlaneStore; no external Provider is requested.
"""

from __future__ import annotations

from dataclasses import replace
from importlib.metadata import version
import json
from typing import Any

import pytest
from agentguard_langgraph_adapter import activation_session, execution_template
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.execution_template import GuardedExecutionTemplate
from agentguard_langgraph_adapter.model_boundary import (
    GuardedModelBoundary,
    NativeModelOutput,
)
from agentguard_langgraph_adapter.native_events import (
    NativeGuardEventBuilder,
    NativeModelOrigin,
)
from agentguard_langgraph_adapter.native_tools import (
    prepare_native_tool_call,
)

from tests.support.native_product_runtime import native_product_runtime_http

pytestmark = pytest.mark.e2e


@pytest.fixture
def native_model_http(tmp_path, monkeypatch, request):
    monkeypatch.setenv("AGENTGUARD_CONTEXT_BUILDER_ENABLED", "true")
    monkeypatch.setenv("AGENTGUARD_CT_FACT_PROJECTION_ENABLED", "true")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    with native_product_runtime_http(tmp_path, **getattr(request, "param", {})) as http:

        def assumed_candidate(distribution):
            return (
                http.fixture.bundle.runtime_entry("langgraph").plugin_version
                if distribution == "agentguard-langgraph-adapter"
                else version(distribution)
            )

        monkeypatch.setattr(activation_session, "_installed_version", assumed_candidate)
        monkeypatch.setattr(
            execution_template, "assert_product_execution_available", lambda: None
        )
        adapter = LangGraphAdapter(
            config=replace(
                http.config(),
                product_receipt_directory=str(tmp_path / "queue"),
                product_receipt_key_path=str(tmp_path / "keys" / "queue.key"),
            )
        )
        ack = adapter.start_product_session(observe=http.observe)
        builder = NativeGuardEventBuilder(adapter)
        boundary = GuardedModelBoundary(
            adapter,
            event_builder=builder,
            executor=GuardedExecutionTemplate(adapter, event_builder=builder),
        )
        try:
            yield http, adapter, boundary, ack
        finally:
            adapter.close_product_session()
            adapter.close_product_delivery()


def _invoke(
    http, boundary, callback, *, content=None, extra_sources=(), include_task=True
):
    security = dict(http.event()["security_context"])
    security["task_id"] = http.task_id
    return boundary.invoke(
        sources=(
            [
                {
                    "role": "user",
                    "content": content or security["user_task"],
                    "source_id": "native-authenticated-task",
                    "source_type": "user",
                    "source_trust": "trusted",
                },
            ]
            if include_task
            else []
        )
        + list(extra_sources),
        security=security,
        trace_id=http.trace_id,
        model_call_id="deterministic-http-model-1",
        invoke_model=callback,
        normalize_output=NativeModelOutput.from_mapping,
        provider="deterministic-local-contract",
        model="recording-model-no-provider",
        tool_descriptors=http.bound_inventory.kwargs["tools"],
    )


def test_real_context_plan_and_original_model_ack_terminal(native_model_http):
    http, adapter, boundary, ack = native_model_http
    calls: list[Any] = []

    def model(messages):
        calls.append(messages)
        return {
            "content": "The authenticated task is ready.",
            "tool_calls": [],
            "invalid_tool_calls": [],
        }

    result = _invoke(http, boundary, model)
    assert result.error_code is None
    assert result.invocation_status == "executed"
    assert result.output is not None
    assert result.delivery.status == "recorded"
    assert len(calls) == 1
    evaluated = http.requests_for("/v1/guard/evaluate")
    assert [item.body["event_type"] for item in evaluated] == [
        "context_assembled",
        "model_input_prepared",
        "model_output_produced",
    ]
    model_input = evaluated[1].body
    projection = json.loads(model_input["payload"]["content_preview"])
    assert projection["messages"] == calls[0]
    assert model_input["payload"]["context_plan_digest"].startswith("sha256:")
    receipts = [
        item.body
        for item in http.requests_for("/v1/audit/events")
        if item.body.get("record_type") == "runtime_outcome"
    ]
    terminal = next(
        item
        for item in receipts
        if item["links"]["event_id"] == model_input["event_id"]
    )
    assert terminal["links"]["action_id"] == "act_" + model_input["event_id"]
    assert terminal["metadata"]["activation_ack"] == ack.to_wire()
    assert terminal["evidence"]["execution"]["status"] == "executed"
    starts = [
        item.body
        for item in http.requests_for("/v1/audit/events")
        if item.body.get("event_type") == "model_call_committed"
    ]
    assert len(starts) == 1
    assert starts[0]["evidence"]["execution"]["invoked_at"] is None
    assert adapter.product_delivery_status().breaker_open is False
    policies = {
        item.event_type: item
        for item in http.store.audit_events
        if item.record_type == "policy_evaluation"
    }
    input_domains = policies["model_input_prepared"].evidence["decision_v21"][
        "payload"
    ]["required_domains"]
    output_domains = policies["model_output_produced"].evidence["decision_v21"][
        "payload"
    ]["required_domains"]
    assert {"source", "dataflow"} <= set(input_domains)
    assert "memory" not in input_domains
    assert "behavior" in output_domains
    assert not {"source", "dataflow"} & set(output_domains)
    assert result.visible_source_refs == tuple(
        model_input["payload"]["visible_source_refs"]
    )
    assert result.output_source_ref == "source:model:" + evaluated[2].body["event_id"]
    assert result.output_policy_audit_id == policies["model_output_produced"].audit_id
    assert (
        evaluated[2].body["metadata"]["product_model_input_audit_id"]
        == policies["model_input_prepared"].audit_id
    )


def test_model_exception_has_one_call_and_fixed_failed_terminal(native_model_http):
    http, adapter, boundary, _ = native_model_http
    calls = 0

    def model(_messages):
        nonlocal calls
        calls += 1
        raise ValueError("private deterministic model content must stay private")

    result = _invoke(http, boundary, model)
    assert calls == 1
    assert result.blocked and result.output is None
    assert result.output_source_ref is None
    assert result.invocation_status == "failed"
    receipts = [item.body for item in http.requests_for("/v1/audit/events")]
    assert "private deterministic" not in json.dumps(receipts)
    assert any(
        item.get("evidence", {}).get("execution", {}).get("status") == "failed"
        for item in receipts
    )
    adapter.drain_product_receipts()
    assert calls == 1


def test_actual_read_result_is_annotated_evidence_not_authenticated_task(
    native_model_http, tmp_path, monkeypatch
):
    http, adapter, boundary, _ = native_model_http
    plans = []
    evaluate = LangGraphAdapter.evaluate_guard_event

    def capture(self, event):
        decision = evaluate(self, event)
        if event.event_type == "context_assembled":
            plans.append(decision.context_plan)
        return decision

    monkeypatch.setattr(LangGraphAdapter, "evaluate_guard_event", capture)
    calls = []

    def model(messages):
        calls.append(messages)
        return {
            "content": "ready",
            "tool_calls": (
                [
                    {
                        "name": "read",
                        "args": {"path": "note.txt"},
                        "id": "actual-read-evidence",
                        "type": "tool_call",
                    }
                ]
                if len(calls) == 1
                else []
            ),
            "invalid_tool_calls": [],
        }

    content = "Local fixture evidence. " + "a" * 2500 + " Complete final marker."
    source = http.root / "note.txt"
    source.write_text(content, encoding="utf-8")
    source.chmod(0o600)
    first = _invoke(http, boundary, model)
    assert not first.blocked and first.delivery.status == "recorded", first
    spec = next(item for item in http.tools if item.name == "read")
    prepared = prepare_native_tool_call(
        spec, "actual-read-evidence", {"path": "note.txt"}
    )
    security = dict(http.event()["security_context"])
    security.update(
        task_id=http.task_id,
        source_type="model",
        source_trust="unknown",
        visible_source_refs=[first.output_source_ref, *first.visible_source_refs],
    )
    builder = NativeGuardEventBuilder(adapter)
    tool_result = GuardedExecutionTemplate(
        adapter, event_builder=builder
    ).execute_action(
        prepared,
        security=security,
        trace_id=http.trace_id,
        invoke_once=lambda: spec.tool.invoke(prepared.arguments()),
        model_origin=NativeModelOrigin(
            first.output_policy_audit_id, first.output_source_ref, prepared.call_id
        ),
    )
    assert tool_result.executed and not tool_result.blocked, {
        "error": tool_result.error,
        "semantics": tool_result.block_semantics,
        "http": [(r.path, r.status_code) for r in http.requests],
        "policy": [
            (p.event_type, p.decision)
            for p in http.store.audit_events
            if p.record_type == "policy_evaluation"
        ],
    }
    assert tool_result.runtime_receipt_status == "recorded"
    assert tool_result.result == content
    evidence = json.dumps(
        {
            "tool_name": prepared.name,
            "tool_call_id": prepared.call_id,
            "content": tool_result.result,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    result = _invoke(
        http,
        boundary,
        model,
        extra_sources=[
            {
                "role": "user",
                "content": evidence,
                "source_id": "native-actual-read-evidence",
                "source_type": "tool_result",
                "source_trust": "untrusted",
            }
        ],
    )

    assert not result.blocked and result.delivery.status == "recorded", result
    assert len(calls) == 2
    chunk = next(
        item for item in plans[-1]["chunks"] if item["source_type"] == "tool_result"
    )
    assert chunk["compartment"] == "untrusted_evidence"
    assert chunk["transform_state"] == "annotated"
    assert chunk["trust"] == "untrusted"
    assert chunk["fact_authority"] == "untrusted_claim"
    assert "UNTRUSTED_EVIDENCE_ANNOTATED" in plans[-1]["reason_codes"]
    message = calls[-1][-1]
    assert message["role"] == "user"
    assert 'authority="evidence-only"' in message["content"]
    assert content in message["content"]
    assert all(item["role"] not in {"assistant", "tool"} for item in calls[-1])


def test_oversized_context_rejected_without_http_or_model(native_model_http):
    http, _, boundary, _ = native_model_http
    before = len(http.requests)

    def model(_messages):
        pytest.fail("oversized content must not call a model")

    result = _invoke(http, boundary, model, content="x" * (64 * 1024 + 1))
    assert result.blocked and result.invocation_status == "not_invoked"
    assert len(http.requests) == before


@pytest.mark.parametrize("phase", ["context_assembled", "model_output_produced"])
@pytest.mark.parametrize(
    "change",
    [{"source": "current"}, {"mode": "shadow"}, {"legacy_floor_applied": True}],
)
def test_changed_local_authority_cannot_publish(
    native_model_http, monkeypatch, phase, change
):
    http, adapter, boundary, _ = native_model_http
    original = adapter.evaluate_guard_event

    def tampered(self, event):
        assert self is adapter
        result = original(event)
        if event.event_type == phase:
            result.decision_authority = result.decision_authority.model_copy(
                update=change
            )
        return result

    monkeypatch.setattr(LangGraphAdapter, "evaluate_guard_event", tampered)
    calls = []

    def model(messages):
        calls.append(messages)
        return {"content": "safe content", "tool_calls": [], "invalid_tool_calls": []}

    result = _invoke(http, boundary, model)
    assert result.blocked and result.output is None
    assert len(calls) == (0 if phase == "context_assembled" else 1)
    if phase == "model_output_produced":
        assert result.invocation_status == "executed"
        terminals = [
            request.body
            for request in http.requests_for("/v1/audit/events")
            if request.body.get("record_type") == "runtime_outcome"
            and request.body["evidence"]["execution"]["status"] == "executed"
        ]
        assert any(
            item["evidence"]["result"]["disposition"] == "quarantined"
            for item in terminals
        )


def test_real_output_tail_is_evaluated_and_withheld_after_one_model_call(
    native_model_http,
):
    http, _, boundary, _ = native_model_http
    body = (
        "ordinary content " * 200 + " API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890"
    )
    calls = []

    def model(messages):
        calls.append(messages)
        return {"content": body, "tool_calls": [], "invalid_tool_calls": []}

    result = _invoke(http, boundary, model)
    assert len(calls) == 1
    output_event = next(
        request.body
        for request in http.requests_for("/v1/guard/evaluate")
        if request.body["event_type"] == "model_output_produced"
    )
    assert json.loads(output_event["payload"]["content_preview"])["content"] == body
    assert result.blocked and result.output is None
    assert result.invocation_status == "executed"
    terminals = [
        request.body
        for request in http.requests_for("/v1/audit/events")
        if request.body.get("record_type") == "runtime_outcome"
    ]
    assert any(
        item["evidence"]["execution"]["status"] == "executed"
        and item["evidence"]["result"]["disposition"] == "quarantined"
        for item in terminals
    )
    # A legacy-floor detection is still a block, never claimed as a pure V2 pass.


@pytest.mark.parametrize("include_task", [True, False])
def test_real_unproved_memory_is_excluded_never_silently_downgraded(
    native_model_http, monkeypatch, include_task
):
    http, adapter, boundary, _ = native_model_http
    original = LangGraphAdapter.evaluate_guard_event
    plans = []

    def capture_plan(self, event):
        decision = original(self, event)
        if event.event_type == "context_assembled":
            plans.append(decision.context_plan)
        return decision

    monkeypatch.setattr(LangGraphAdapter, "evaluate_guard_event", capture_plan)
    calls = []

    def model(messages):
        calls.append(messages)
        return {"content": "ready", "tool_calls": [], "invalid_tool_calls": []}

    result = _invoke(
        http,
        boundary,
        model,
        include_task=include_task,
        extra_sources=[
            {
                "role": "user",
                "content": "unverified remembered note",
                "source_id": "native-memory-contract-source",
                "source_type": "memory",
                "source_trust": "untrusted",
            }
        ],
    )
    assert result.delivery.status == "recorded", result
    memory_chunk = next(
        chunk for chunk in plans[0]["chunks"] if chunk["source_type"] == "memory"
    )
    assert memory_chunk["transform_state"] == "excluded"
    assert memory_chunk["source_ref"].startswith("memory:")
    assert "MEMORY_FACT_UNPROVED" in plans[0]["reason_codes"]
    assert len(calls) == (1 if include_task else 0)
    assert "unverified remembered note" not in json.dumps(calls)
    if include_task:
        assert not result.blocked
        model_input = next(
            request.body
            for request in http.requests_for("/v1/guard/evaluate")
            if request.body["event_type"] == "model_input_prepared"
        )
        assert all(
            not ref.startswith("memory:")
            for ref in model_input["security_context"]["visible_source_refs"]
        )
    else:
        assert result.blocked and result.invocation_status == "not_invoked"
        assert not any(
            request.body.get("event_type") == "model_input_prepared"
            for request in http.requests
        )
