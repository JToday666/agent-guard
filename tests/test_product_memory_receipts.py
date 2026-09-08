"""Real local SQLite + Product HTTP receipts, without fake memory facts.

Admission metadata is explicitly synthetic through the shared transport fixture.
No external model/provider is invoked; the test operator uses real approval HTTP.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from agentguard_langgraph_adapter.execution_template import GuardedExecutionTemplate
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter import product_outbox
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
from guard_api.services.ct_projection import decode_ct_transient_facts
from guard_api.services.memory import MemoryGuardService
from guard_api.services.context_builder import _context_snapshot_plan
from guard_api.security_state import SecurityStateService
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from guard_api.services.product_memory import verify_product_memory_source
from guard_api.services.audit import AuditService
from guard_api.storage.memory import MemoryControlPlaneStore
from agentguard_core import ContextSource
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.runtime_status import activation_ack_token_digest
from langchain_core.messages import AIMessage
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
from tests.support.native_product_runtime import HttpFixtureModel

from tests.test_langgraph_native_model_http import native_model_http  # noqa: F401
from tests.test_langgraph_native_graph_http import _automated_test_operator

pytestmark = pytest.mark.e2e


@pytest.fixture
def memory_http(native_model_http):  # noqa: F811
    http, adapter, _, _ = native_model_http
    tools = http.tools
    builder = NativeGuardEventBuilder(adapter)
    security = dict(http.event()["security_context"])
    security["task_id"] = http.task_id
    template = GuardedExecutionTemplate(
        adapter, event_builder=builder, approval_timeout=5
    )
    return http, adapter, tools, template, security, builder


def _write(
    rig, *, key="receipt-key", value="public fixture note", fail=False, tainted=False
):
    http, adapter, tools, template, security, builder = rig
    spec = next(item for item in tools if item.name == "agentguard_memory_write")
    prepared = prepare_native_tool_call(
        spec, "call_" + key, {"key": key, "value": value}
    )
    boundary = GuardedModelBoundary(adapter, event_builder=builder, executor=template)
    sources = [
        {
            "role": "user",
            "content": security["user_task"],
            "source_id": "actual-authorized-memory-task",
            "source_type": "user",
            "source_trust": "trusted",
        }
    ]
    if tainted:
        sources.append(
            {
                "role": "user",
                "content": "An external note has untrusted origin.",
                "source_id": "external-memory-source",
                "source_type": "tool_result",
                "source_trust": "untrusted",
            }
        )
    model_calls = []

    def model(messages):
        model_calls.append(messages)
        return {
            "content": "",
            "tool_calls": [
                {
                    "type": "tool_call",
                    "id": prepared.call_id,
                    "name": prepared.name,
                    "args": prepared.arguments(),
                }
            ],
            "invalid_tool_calls": [],
        }

    generated = boundary.invoke(
        sources=sources,
        security=security,
        trace_id=http.trace_id,
        model_call_id="model_" + key,
        invoke_model=model,
        normalize_output=NativeModelOutput.from_mapping,
        provider="deterministic-local-contract",
        model="memory-source-no-provider",
        tool_descriptors=http.bound_inventory.kwargs["tools"],
    )
    assert len(model_calls) == 1
    assert generated.output is not None, generated
    assert generated.output_policy_audit_id and generated.output_source_ref
    action_security = {
        **security,
        "source_type": "model",
        "source_trust": "unknown",
        "visible_source_refs": [
            generated.output_source_ref,
            *generated.visible_source_refs,
        ],
    }
    calls = []

    def actual_write():
        calls.append(1)
        if fail:
            raise OSError("controlled local write failure")
        return spec.tool.invoke(prepared.arguments())

    with _automated_test_operator(http):
        result = template.execute_action(
            prepared,
            security=action_security,
            trace_id=http.trace_id,
            invoke_once=actual_write,
            model_origin=NativeModelOrigin(
                generated.output_policy_audit_id,
                generated.output_source_ref,
                prepared.call_id,
            ),
        )
    return result, calls


def _change(rig):
    http = rig[0]
    parent = next(
        item
        for item in http.store.audit_events
        if item.record_type == "policy_evaluation"
        and item.event_type == "memory_write_proposed"
    )
    change = http.store.get_memory_change(parent.links["memory_change_id"])
    assert change is not None
    return parent, change


def test_actual_write_terminal_commits_existing_ct_fact(memory_http):
    result, calls = _write(memory_http)
    diagnostic = {
        "error": result.error,
        "policies": [
            {
                "event_type": item.event_type,
                "decision": item.decision,
                "legacy_floor_applied": item.evidence["decision_authority"]["payload"][
                    "decision_authority"
                ]["legacy_floor_applied"],
                "release_mode": item.evidence["decision_authority"]["payload"][
                    "approval_release_directive"
                ]["mode"],
                "coverage": {
                    domain: (value["status"], value.get("reason_codes"))
                    for domain, value in item.evidence.get("decision_v21", {})
                    .get("payload", {})
                    .get("coverage", {})
                    .items()
                },
            }
            for item in memory_http[0].store.audit_events
            if item.record_type == "policy_evaluation"
            and item.event_type == "memory_write_proposed"
        ],
        "requests": [(item.path, item.status_code) for item in memory_http[0].requests],
    }
    if calls != [1]:
        pytest.fail(json.dumps(diagnostic))
    assert result.executed, result
    assert result.runtime_receipt_status == "recorded", result
    http, _, tools, _, _, _ = memory_http
    parent, change = _change(memory_http)
    assert change.status == "committed"
    assert parent.metadata["action_name"] == "agentguard_memory_write"
    assert parent.evidence["guard_event"]["tool"] == {
        "name": "agentguard_memory_write",
        "category": "memory",
        "call_id": "call_receipt-key",
    }
    original = decode_ct_transient_facts(parent)
    assert original.kind == "full" and original.bundle is not None
    assert len(original.bundle.memory_facts) == 1
    assert original.bundle.memory_facts[0].trust_state == "unknown"
    assert change.source_trust == "unknown"
    state = http.store.get_security_state(original.bundle.scope_digest)
    assert state is not None
    committed_fact = next(
        item
        for item in state.canonical_payload["memory_index"]
        if item["change_id"] == change.change_id
    )
    assert committed_fact["change_status"] == "committed"
    assert committed_fact["trust_state"] == "quarantined"
    assert committed_fact["taints"] == original.bundle.memory_facts[0].taints
    coverage = parent.evidence["decision_v21"]["payload"]
    assert {"source", "dataflow", "memory"} <= set(coverage["required_domains"])
    assert all(
        coverage["coverage"][domain]["status"] == "complete"
        for domain in ("source", "dataflow", "memory")
    )
    terminal = http.store.get_audit_event(
        f"audit_outcome_{parent.links['event_id']}_execution_completed"
    )
    assert terminal is not None
    assert terminal.evidence["execution"]["status"] == "executed"
    assert parent.evidence["product_action_data"]["first_write_memory_ref"] == (
        original.bundle.memory_facts[0].memory_id
    )
    assert terminal.metadata["product_ack_validation"]["schema_version"] == "1.0"
    assert terminal.links["lease_id"] and terminal.links["consumption_id"]
    consumption = next(
        item
        for item in http.requests
        if item.path.endswith("/execution-leases/consume")
    )
    assert consumption.status_code == 200
    assert _terminal_wire(http)["metadata"]["activation_ack"]["ack_token"] == (
        consumption.activation_ack_header
    )
    assert (
        len(
            [
                item
                for item in http.store.audit_events
                if item.event_type == "memory_change_transition"
            ]
        )
        == 1
    )
    read = next(item for item in tools if item.name == "agentguard_memory_read")
    assert (
        json.loads(read.tool.invoke({"key": change.key}))["value"]
        == change.value_preview
    )


def _terminal_wire(http):
    parent = next(
        item
        for item in http.store.audit_events
        if item.record_type == "policy_evaluation"
        and item.event_type == "memory_write_proposed"
    )
    return next(
        item.body
        for item in http.requests_for("/v1/audit/events")
        if item.body.get("metadata", {}).get("outcome_kind") == "execution_completed"
        and item.body.get("links", {}).get("event_id") == parent.links["event_id"]
    )


def test_product_memory_audit_projection_requires_bound_identity(memory_http):
    from agentguard_core import DecisionAuthority, GuardDecision, GuardEvent
    from guard_api.services.evidence import build_audit_event
    from guard_api.services.competition import CriticalDecisionEvidenceError
    from guard_api.services.product_model_content import ProductModelContentUnavailable

    result, calls = _write(memory_http)
    assert result.executed and calls == [1]
    http = memory_http[0]
    parent, _ = _change(memory_http)
    request = next(
        item.body
        for item in http.requests_for("/v1/guard/evaluate")
        if item.body["event_id"] == parent.links["event_id"]
    )
    decision = GuardDecision.model_validate(parent.evidence["guard_decision"])
    kwargs = {
        "policy_bundle": http.store.get_policy_snapshot(),
        "policy_revision": None,
        "approval_id": parent.links["approval_id"],
        "decision_authority": DecisionAuthority.model_validate(
            parent.model_extra["decision_authority"]
        ),
        "decision_authority_evidence": {
            "decision_authority": parent.evidence["decision_authority"]
        },
        "v21_evidence": {"decision_v21": parent.evidence["decision_v21"]},
        "product_action_data": parent.evidence["product_action_data"],
    }
    rebuilt = build_audit_event(GuardEvent.model_validate(request), decision, **kwargs)
    assert rebuilt.evidence["guard_event"]["tool"] == (
        parent.evidence["guard_event"]["tool"]
    )
    for mutation in ("name", "call_id", "value", "proof", "authority"):
        raw, changed = deepcopy(request), deepcopy(kwargs)
        if mutation == "name":
            raw["metadata"]["product_tool_call"]["tool_name"] = "read"
        elif mutation == "call_id":
            raw["metadata"]["product_tool_call"]["call_id"] = "another_call"
        elif mutation == "value":
            raw["payload"]["memory"]["value_preview"] = "unevaluated replacement"
        elif mutation == "proof":
            changed["product_action_data"]["proof_digest"] = "sha256:" + "0" * 64
        else:
            changed["decision_authority_evidence"] = None
        with pytest.raises(
            (ValueError, CriticalDecisionEvidenceError, ProductModelContentUnavailable)
        ):
            build_audit_event(GuardEvent.model_validate(raw), decision, **changed)
    unproved = {**kwargs, "product_action_data": None}
    legacy = build_audit_event(GuardEvent.model_validate(request), decision, **unproved)
    assert legacy.evidence["guard_event"]["tool"] is None
    assert legacy.metadata["action_name"] == "memory_write_proposed"


def _post(http, body):
    return http.client.post(
        "/v1/audit/events",
        json=body,
        headers={
            "Authorization": "Bearer " + http.runtime_tokens["langgraph"],
        },
    )


@pytest.mark.parametrize("mutation", ["token", "missing_ack", "parent", "action"])
def test_invalid_receipt_never_drives_memory_transition(
    memory_http, monkeypatch, mutation
):
    _, calls = _write(memory_http)
    assert calls == [1]
    http = memory_http[0]
    body = deepcopy(_terminal_wire(http))
    if mutation == "token":
        body["metadata"]["activation_ack"]["ack_token"] = "hmac-sha256:" + "0" * 64
    elif mutation == "missing_ack":
        body["metadata"].pop("activation_ack")
    elif mutation == "parent":
        body["links"]["policy_audit_id"] = "audit_missing_original_memory_parent"
    else:
        body["links"]["action_id"] = "call_wrong_action"
    transitions = []
    monkeypatch.setattr(
        MemoryGuardService, "commit", lambda *a, **k: transitions.append(1)
    )
    response = _post(http, body)
    assert response.status_code in {409, 422}
    assert transitions == []
    assert _change(memory_http)[1].status == "committed"


def test_commit_crash_replay_repairs_fact_without_reinvocation(
    memory_http, monkeypatch
):
    commit = MemoryGuardService.commit

    def unavailable(*args, **kwargs):
        raise OSError("controlled lifecycle storage failure")

    monkeypatch.setattr(MemoryGuardService, "commit", unavailable)
    result, calls = _write(memory_http)
    assert calls == [1] and result.executed
    http = memory_http[0]
    parent, change = _change(memory_http)
    assert change.status == "quarantined"
    assert (
        http.store.get_audit_event(
            f"audit_outcome_{parent.links['event_id']}_execution_completed"
        )
        is not None
    )
    assert any(
        item.status_code == 503 for item in http.requests_for("/v1/audit/events")
    )
    monkeypatch.setattr(MemoryGuardService, "commit", commit)
    body = _terminal_wire(http)
    for _ in range(2):
        response = _post(http, body)
        assert response.status_code == 200, response.text
        assert response.json()["idempotent_replay"] is True
    assert _change(memory_http)[1].status == "committed"
    assert calls == [1]
    assert (
        len(
            [
                item
                for item in http.store.audit_events
                if item.event_type == "memory_change_transition"
            ]
        )
        == 1
    )


def test_failed_tool_does_not_commit_memory(memory_http):
    result, calls = _write(memory_http, fail=True)
    assert calls == [1]
    assert result.executed  # The real callback was entered and raised.
    parent, change = _change(memory_http)
    assert change.status == "quarantined"
    http = memory_http[0]
    failed = http.store.get_audit_event(
        f"audit_outcome_{parent.links['event_id']}_execution_failed"
    )
    assert failed is not None and failed.evidence["execution"]["status"] == "failed"
    assert not any(
        item.event_type == "memory_change_transition"
        for item in http.store.audit_events
    )


def test_restart_repairs_commit_with_original_consumption_ack_only(
    memory_http, monkeypatch
):
    http, adapter, _, _, _, _ = memory_http
    commit = MemoryGuardService.commit

    def unavailable(*_args, **_kwargs):
        raise OSError("controlled lifecycle outage")

    monkeypatch.setattr(MemoryGuardService, "commit", unavailable)
    result, calls = _write(memory_http)
    assert calls == [1] and result.executed
    wire = deepcopy(_terminal_wire(http))
    issuance = http.store.get_product_activation_ack(
        activation_ack_token_digest(wire["metadata"]["activation_ack"]["ack_token"])
    )
    assert issuance is not None
    http.store.revoke_product_activation_acks(
        issuance.identity(), revoked_at=datetime.now(timezone.utc).isoformat()
    )
    adapter.close_product_session()
    adapter.close_product_delivery()
    monkeypatch.setattr(MemoryGuardService, "commit", commit)
    due = product_outbox._now_ms() + 60_000
    monkeypatch.setattr(product_outbox, "_now_ms", lambda: due)
    recovered = LangGraphAdapter(config=adapter.config)
    before = len(http.requests)
    try:
        recovered.drain_product_receipts()
        assert recovered.product_delivery_status().pending_count == 0
        assert recovered.product_delivery_status().unknown_action_count == 0
    finally:
        recovered.close_product_delivery()
    replayed = http.requests[before:]
    assert replayed and all(item.path == "/v1/audit/events" for item in replayed)
    assert all(item.body == wire and item.status_code == 200 for item in replayed)
    assert calls == [1]
    parent, change = _change(memory_http)
    assert change.status == "committed"
    assert change.source_trust == "unknown"
    assert (
        http.store.get_audit_event(wire["audit_id"]).metadata["product_ack_validation"][
            "token_digest"
        ]
        == issuance.token_digest
    )
    assert (
        sum(
            item.event_type == "memory_change_transition"
            for item in http.store.audit_events
        )
        == 1
    )
    assert parent.links["event_id"] == wire["links"]["event_id"]


def test_actual_read_full_body_binding_rejects_replacement(memory_http, monkeypatch):
    _, calls = _write(memory_http)
    assert calls == [1]
    http, adapter, tools, _, security, builder = memory_http
    parent, change = _change(memory_http)
    original = decode_ct_transient_facts(parent)
    assert original.bundle is not None
    memory_id = original.bundle.memory_facts[0].memory_id
    read = next(item for item in tools if item.name == "agentguard_memory_read")
    body = read.tool.invoke({"key": change.key})
    event = builder.build_context(
        [
            {
                "role": "user",
                "content": body,
                "source_id": memory_id,
                "source_type": "memory",
                "source_trust": "untrusted",
            }
        ],
        security,
        http.trace_id,
    )
    task_record = http.store.get_task_fact(http.task_id)
    assert task_record is not None
    task = task_record.task_fact
    entry = http.fixture.bundle.runtime_entry("langgraph")
    policy = http.store.get_policy_snapshot_record()
    assert policy is not None
    snapshot = SecurityStateService(http.store).read_snapshot(
        task.scope_digest,
        scope=SecurityStateScope(
            principal_id=entry.principal_id,
            runtime="langgraph",
            runtime_binding_id=entry.runtime_binding_id,
            trace_id=http.trace_id,
            session_id=http.session_id,
            scope_digest=task.scope_digest,
        ),
        task_fact_head=task,
        evaluation_clock=EvaluationClock(
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            clock_version="test-actual-memory-read",
        ),
        policy_revision=str(policy.revision),
        policy_digest=canonical_sha256(policy.policy_bundle.model_dump(mode="json")),
        plan=_context_snapshot_plan(),
        authoritative_head_revision=task.revision,
    )
    fact = next(item for item in snapshot.memory_facts if item.memory_id == memory_id)
    source = ContextSource.model_validate(event.payload["sources"][0])
    assert verify_product_memory_source(
        store=http.store, source=source, memory_fact=fact, snapshot=snapshot
    )
    assert fact.trust_state == "quarantined"
    decision = adapter.evaluate_guard_event(event)
    assert decision.context_plan is not None
    assert all(
        chunk["transform_state"] == "excluded"
        for chunk in decision.context_plan["chunks"]
    )
    for altered in [
        json.dumps({"key": change.key, "value": "forged replacement"}),
        json.dumps({"key": "wrong-key", "value": change.value_preview}),
        json.dumps(
            {"key": change.key, "value": change.value_preview, "extra": "ignored"}
        ),
        '{"key":"receipt-key","value":"first","value":"public fixture note"}',
    ]:
        claim = source.model_copy(
            update={"summary": altered, "content_digest": canonical_sha256(altered)}
        )
        assert not verify_product_memory_source(
            store=http.store, source=claim, memory_fact=fact, snapshot=snapshot
        )
    stale_hash = source.model_copy(update={"summary": body + " "})
    assert not verify_product_memory_source(
        store=http.store, source=stale_hash, memory_fact=fact, snapshot=snapshot
    )
    # Matching a replaced read against a replaced change is still insufficient:
    # the actual model's original full-value commitment remains immutable.
    replacement = "storage replacement is not the evaluated value"
    altered = json.dumps({"key": change.key, "value": replacement})
    http.store.memory_changes[change.change_id] = change.model_copy(
        update={"value_preview": replacement}
    )
    claim = source.model_copy(
        update={"summary": altered, "content_digest": canonical_sha256(altered)}
    )
    assert not verify_product_memory_source(
        store=http.store, source=claim, memory_fact=fact, snapshot=snapshot
    )


def test_actual_graph_reads_committed_quarantined_memory_without_model_release(
    memory_http,
):
    """The graph reads known state; only remaining authorized context continues."""
    written, writes = _write(memory_http, key="graph-read-key")
    assert written.executed and writes == [1]
    http, adapter, tools, _, security, _ = memory_http
    parent, change = _change(memory_http)
    assert change.status == "committed" and change.source_trust == "unknown"
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "agentguard_memory_read",
                        "args": {"key": change.key},
                        "id": "read_committed_memory",
                    }
                ],
            ),
            AIMessage(content="The isolated request completed."),
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=tools,
        provider="controlled-local-contract",
        model_name="committed-memory-read-no-provider",
    )
    before = len(http.store.audit_events)
    try:
        result = graph.invoke(
            sources=[
                {
                    "role": "user",
                    "content": security["user_task"],
                    "source_id": "actual-authorized-memory-task",
                    "source_type": "user",
                    "source_trust": "trusted",
                }
            ],
            security=security,
            trace_id=http.trace_id,
        )
    finally:
        graph.close()
    policies = [
        item
        for item in http.store.audit_events[before:]
        if item.record_type == "policy_evaluation"
    ]
    diagnostic = {
        "written": (written.error, written.runtime_receipt_status),
        "http": [(item.path, item.status_code) for item in http.requests],
        "delivery": repr(adapter.product_delivery_status()),
        "error": result.error_code,
        "models": result.model_calls,
        "tools": result.tool_invocations,
        "policies": [
            {
                "event_type": item.event_type,
                "decision": item.decision,
                "coverage": {
                    name: (coverage["status"], coverage["reason_codes"])
                    for name, coverage in item.evidence.get("decision_v21", {})
                    .get("payload", {})
                    .get("coverage", {})
                    .items()
                },
            }
            for item in http.store.audit_events
            if item.record_type == "policy_evaluation"
        ],
    }
    assert result.tool_invocations == 1, json.dumps(diagnostic)
    read = next(item for item in policies if item.event_type == "tool_call_proposed")
    assert read.decision == "allow", diagnostic
    assert not result.blocked, json.dumps(diagnostic)
    assert result.model_calls == len(model._messages) == 2
    assert len(model._messages[1]) == 1
    assert model._messages[1][0].content == security["user_task"]
    assert change.value_preview not in json.dumps(result.messages())
    assert result.messages()[0]["content"] == "The isolated request completed."
    context_inputs = [
        item.body
        for item in http.requests_for("/v1/guard/evaluate")
        if item.body["event_type"] == "context_assembled"
    ]
    read_source = context_inputs[-1]["payload"]["sources"][-1]
    assert read_source["source_type"] == "memory"
    assert read_source["source_trust"] == "untrusted"
    assert json.loads(read_source["summary"]) == {
        "key": change.key,
        "value": change.value_preview,
    }
    assert writes == [1]
    original = decode_ct_transient_facts(parent)
    state = http.store.get_security_state(original.bundle.scope_digest)
    fact = next(
        item
        for item in state.canonical_payload["memory_index"]
        if item["change_id"] == change.change_id
    )
    assert fact["change_status"] == "committed"
    assert fact["trust_state"] == "quarantined"
    assert read_source["source_id"] == fact["memory_id"]
    assert adapter.product_delivery_status().pending_count == 0
    assert not adapter.product_delivery_status().breaker_open


def test_memory_bridge_assembly_is_one_time_and_same_store():
    store = MemoryControlPlaneStore()
    audit = AuditService(store=store)
    MemoryGuardService(store=store, audit_service=audit)
    with pytest.raises(ValueError, match="V21_PRODUCT_MEMORY_BRIDGE_ALREADY_BOUND"):
        MemoryGuardService(store=store, audit_service=audit)
    with pytest.raises(ValueError, match="V21_PRODUCT_MEMORY_BRIDGE_ALREADY_BOUND"):
        MemoryGuardService(
            store=MemoryControlPlaneStore(), audit_service=AuditService(store=store)
        )


def test_receipt_replay_cannot_reactivate_rolled_back_memory(memory_http):
    _, calls = _write(memory_http)
    assert calls == [1]
    http = memory_http[0]
    _, change = _change(memory_http)
    response = http.client.post(
        f"/v1/memory/changes/{change.change_id}/rollback",
        headers={
            "Authorization": "Bearer " + http.runtime_tokens["langgraph"],
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rolled_back"
    replay = _post(http, _terminal_wire(http))
    assert replay.status_code == 200 and replay.json()["idempotent_replay"] is True
    assert _change(memory_http)[1].status == "rolled_back"
    assert (
        len(
            [
                item
                for item in http.store.audit_events
                if item.event_type == "memory_change_transition"
            ]
        )
        == 2
    )


def test_quarantined_proposal_is_not_laundered_into_active_memory(memory_http):
    _, calls = _write(memory_http, tainted=True)
    assert calls == []
    http = memory_http[0]
    parent, change = _change(memory_http)
    assert change.status == "quarantined"
    original = decode_ct_transient_facts(parent)
    assert original.bundle is not None
    record = http.store.get_security_state(original.bundle.scope_digest)
    assert record is not None
    facts = record.canonical_payload["memory_index"]
    fact = next(item for item in facts if item["change_id"] == change.change_id)
    assert fact["trust_state"] == "quarantined"
