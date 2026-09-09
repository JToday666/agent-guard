"""Actual StateGraph, tools, Guard HTTP and encrypted receipts; no Provider.

The imported fixture signs synthetic TEST admission and patches only the closed
composition fuse/version observation. These are implementation conformance
tests, not final candidate or Product Active acceptance evidence.
"""

from contextlib import contextmanager
import json
from threading import Event, Thread

import httpx
from langchain_core.messages import AIMessage, HumanMessage
import pytest

from agentguard_core import PolicyBundle
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
from tests.support.native_product_runtime import HttpFixtureModel
from tests.test_langgraph_native_model_http import native_model_http  # noqa: F401

pytestmark = pytest.mark.e2e


_ACTIONS = {
    "read_only": [("read", {"path": "fixture.txt"})],
    "write_only": [
        ("write", {"path": "fixture.txt", "content": "native fixture content"})
    ],
    "edit_only": [
        (
            "edit",
            {
                "path": "fixture.txt",
                "edits": [
                    {
                        "oldText": "native fixture content",
                        "newText": "native fixture edited",
                    }
                ],
            },
        )
    ],
    "exec_only": [("exec", {"command": "python marker.py"})],
    "process_only": [("process", {"action": "list"})],
    "file": [
        ("write", {"path": "fixture.txt", "content": "native fixture content"}),
        (
            "edit",
            {
                "path": "fixture.txt",
                "edits": [
                    {
                        "oldText": "native fixture content",
                        "newText": "native fixture edited",
                    }
                ],
            },
        ),
        ("read", {"path": "fixture.txt"}),
    ],
    "memory": [
        (
            "agentguard_memory_write",
            {"key": "fixture", "value": "native fixture memory"},
        ),
        ("agentguard_memory_read", {"key": "fixture"}),
    ],
    "command": [
        ("exec", {"command": "python marker.py"}),
        ("process", {"action": "list"}),
    ],
    "message": [
        (
            "message",
            {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": "fixture-inbox@agentguard.invalid",
                "message": "native fixture message",
            },
        ),
    ],
}


@contextmanager
def _automated_test_operator(http, *, decision="allow_once"):
    """Real launch/session/CSRF HTTP, explicitly not browser UI acceptance."""
    stopped = Event()
    resolutions = []
    errors = []
    with httpx.Client(base_url=http.base_url, trust_env=False, timeout=3) as client:
        launch = client.post(
            "/v1/auth/browser/launch",
            headers={"Authorization": "Bearer control-secret"},
        )
        launch.raise_for_status()
        exchange = client.post(
            "/v1/auth/browser/exchange",
            json={"launch_code": launch.json()["launch_code"]},
        )
        exchange.raise_for_status()
        csrf = exchange.json()["csrf_token"]

        def operate():
            try:
                while not stopped.is_set():
                    pending = client.get("/v1/approvals/pending")
                    pending.raise_for_status()
                    for approval in pending.json():
                        if approval["trace_id"] != http.trace_id:
                            continue
                        resolved = client.post(
                            f"/v1/approvals/{approval['approval_id']}/resolve",
                            headers={"X-AgentGuard-CSRF": csrf},
                            json={"decision": decision},
                        )
                        resolved.raise_for_status()
                        resolutions.append(
                            {
                                "approval_id": approval["approval_id"],
                                "operator": "native-http-automated-test",
                                "decision": resolved.json()["decision"],
                                "authorization": "isolated synthetic fixture only",
                            }
                        )
                    stopped.wait(0.05)
            except Exception as error:
                errors.append(type(error).__name__)

        worker = Thread(target=operate, daemon=True)
        worker.start()
        try:
            yield resolutions
        finally:
            stopped.set()
            worker.join(timeout=4)
        assert not worker.is_alive()
        assert not errors, errors


@pytest.mark.parametrize(
    "native_model_http,expected",
    [
        (
            {
                "policy": PolicyBundle(
                    allowed_email_domains=[
                        *PolicyBundle().allowed_email_domains,
                        "agentguard.invalid",
                    ]
                )
            },
            "allow",
        ),
        ({"policy": PolicyBundle()}, "ask"),
        (
            {
                "policy": PolicyBundle(
                    rule_overrides={"P005_external_send": {"decision": "deny"}}
                )
            },
            "deny",
        ),
    ],
    indirect=["native_model_http"],
    ids=["allowed-local-domain", "default-review", "tightened-deny"],
)
def test_actual_native_message_policy_matrix(native_model_http, expected):  # noqa: F811
    """Actual action decisions and local sends; synthetic admission, no Provider."""
    http, adapter, _, _ = native_model_http
    arguments = _ACTIONS["message"][0][1].copy()
    call_id = "native-message-policy-" + expected
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[{"name": "message", "args": arguments, "id": call_id}],
            ),
            AIMessage(content="The local message fixture completed."),
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="synthetic-admission-message-policy",
    )
    graph._executor._approval_timeout = 5.0
    security = dict(http.event()["security_context"], task_id=http.task_id)
    try:
        with _automated_test_operator(http) as resolutions:
            result = graph.invoke(
                sources=[
                    {
                        "role": "user",
                        "content": security["user_task"],
                        "source_id": "native-message-authenticated-task",
                        "source_type": "user",
                        "source_trust": "trusted",
                    }
                ],
                security=security,
                trace_id=http.trace_id,
            )
        action_requests = [
            request
            for request in http.requests_for("/v1/guard/evaluate")
            if request.body["event_type"] == "message_send_proposed"
        ]
        assert len(action_requests) == 1
        request = action_requests[0]
        assert request.status_code == 200
        event = request.body
        assert event["payload"]["recipient"] == arguments["target"]
        assert event["payload"]["channel"] == arguments["channel"]
        policy = http.store.get_policy_evaluation_by_event_id(event["event_id"])
        selected = policy.evidence["decision_authority"]["payload"]
        assert selected["selected_decision"]["decision"] == expected
        authority = selected["decision_authority"]
        assert authority["source"] == "v21"
        assert authority["mode"] == "active"
        assert authority["selection_basis"] == "profile_all"
        consume = [
            item for item in http.requests if "/execution-leases/consume" in item.path
        ]
        assert len(consume) == (1 if expected == "ask" else 0)
        assert len(resolutions) == (1 if expected == "ask" else 0)
        if expected == "ask":
            assert resolutions[0]["decision"] == "allow_once"
            assert consume[0].status_code == 200
        invoked = expected != "deny"
        assert result.tool_invocations == int(invoked)
        assert result.model_calls == (2 if invoked else 1)
        assert result.blocked is not invoked
        assert http.received == (
            [{"target": arguments["target"], "text": arguments["message"]}]
            if invoked
            else []
        )
        receipts = [
            item
            for item in http.requests_for("/v1/audit/events")
            if item.body["record_type"] == "runtime_outcome"
            and item.body["links"]["event_id"] == event["event_id"]
        ]
        assert len(receipts) == 1
        receipt = receipts[0]
        assert receipt.status_code == 200
        assert receipt.body["evidence"]["execution"]["status"] == (
            "executed" if invoked else "not_invoked"
        )
        assert receipt.body["links"]["policy_audit_id"] == policy.audit_id
        stored = http.store.get_audit_event(receipt.body["audit_id"])
        assert stored is not None and stored.metadata["product_ack_validation"]
        assert adapter.product_delivery_status().pending_count == 0
        assert not adapter.product_delivery_status().breaker_open
    finally:
        graph.close()


@pytest.mark.parametrize("category", list(_ACTIONS))
def test_actual_native_graph_guard_tool_and_next_model(
    native_model_http,  # noqa: F811 - imported pytest fixture
    tmp_path,
    category,
):
    http, adapter, _, _ = native_model_http
    received = http.received
    root = http.root
    tools = http.tools
    actions = _ACTIONS[category]
    model = HttpFixtureModel(
        responses=[
            *[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": name,
                            "args": args,
                            "id": f"native_http_{index}",
                        }
                    ],
                )
                for index, (name, args) in enumerate(actions)
            ],
            AIMessage(content="The isolated fixture completed."),
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=tools,
        provider="controlled-local-contract",
        model_name="non-candidate-http-fixture",
    )
    # Bound failure waits in the local conformance fixture, never bypass them.
    graph._executor._approval_timeout = 5.0
    action_results = []
    execute_action = graph._executor.execute_action

    def observed_action(*args, **kwargs):
        outcome = execute_action(*args, **kwargs)
        action_results.append(
            (outcome.error, outcome.runtime_receipt_status, outcome.block_semantics)
        )
        return outcome

    graph._executor.execute_action = observed_action
    security = dict(http.event()["security_context"])
    security["task_id"] = http.task_id
    try:
        with _automated_test_operator(http) as resolutions:
            result = graph.invoke(
                sources=[
                    {
                        "role": "user",
                        "content": security["user_task"],
                        "source_id": "native-http-authenticated-task",
                        "source_type": "user",
                        "source_trust": "trusted",
                    }
                ],
                security=security,
                trace_id=http.trace_id,
            )
        diagnostic = {
            "error_code": result.error_code,
            "actions": action_results,
            "delivery": repr(adapter.product_delivery_status()),
            "http": [(item.path, item.status_code) for item in http.requests],
            "policies": [
                {
                    "event_type": item.event_type,
                    "decision": item.decision,
                    "reason": item.reason,
                    "authority": item.evidence.get("decision_authority", {})
                    .get("payload", {})
                    .get("decision_authority"),
                    "coverage": {
                        domain: {
                            "status": coverage["status"],
                            "reason_codes": coverage.get("reason_codes", []),
                        }
                        for domain, coverage in item.evidence.get("decision_v21", {})
                        .get("payload", {})
                        .get("coverage", {})
                        .items()
                    },
                }
                for item in http.store.audit_events
                if item.record_type == "policy_evaluation"
            ],
        }
        if result.blocked:
            pytest.fail(json.dumps(diagnostic))
        assert result.tool_invocations == len(actions)
        assert result.model_calls == len(actions) + 1
        assert len(model._messages) == len(actions) + 1
        assert all(
            isinstance(message, HumanMessage)
            for messages in model._messages
            for message in messages
        )
        assert result.messages()[-1]["content"] == "The isolated fixture completed."
        if category != "memory":
            # Context Builder annotates untrusted evidence, retaining the full
            # ordinary JSON call correlation without a chat ToolMessage.
            assert f"native_http_{len(actions)-1}" in model._messages[-1][-1].content
        if category in {"file", "read_only", "write_only", "edit_only"}:
            assert (root / "fixture.txt").read_text() == (
                "native fixture edited"
                if category in {"file", "edit_only"}
                else "native fixture content"
            )
        elif category in {"command", "exec_only"}:
            assert (root / "command-marker.txt").read_text().count("executed") == 1
        elif category == "memory":
            # The actual read is observed, while model-origin memory retains
            # unknown trust and is excluded from the next model's context.
            assert "native fixture memory" not in json.dumps(
                [
                    [message.content for message in messages]
                    for messages in model._messages
                ]
            )
            assert "native fixture memory" not in json.dumps(result.messages())
            memory_policy = next(
                policy
                for policy in http.store.audit_events
                if policy.record_type == "policy_evaluation"
                and policy.event_type == "memory_write_proposed"
            )
            change = http.store.get_memory_change(
                memory_policy.links["memory_change_id"]
            )
            assert change.status == "committed" and change.source_trust == "unknown"
        elif category == "message":
            assert received == [
                {
                    "target": "fixture-inbox@agentguard.invalid",
                    "text": "native fixture message",
                }
            ]
        evaluations = http.requests_for("/v1/guard/evaluate")
        kinds = [item.body["event_type"] for item in evaluations]
        assert kinds.count("model_input_prepared") == len(actions) + 1
        assert kinds.count("model_output_produced") == len(actions) + 1
        assert kinds.count("tool_result_produced") == len(actions)
        assert ("memory_write_proposed" in kinds) == (category == "memory")
        assert ("message_send_proposed" in kinds) == (category == "message")
        if category == "memory":
            read_result = next(
                request.body
                for request in evaluations
                if request.body["event_type"] == "tool_result_produced"
                and request.body["payload"]["tool"]["name"] == "agentguard_memory_read"
            )
            assert json.loads(read_result["payload"]["result"]["content_preview"]) == {
                "key": "fixture",
                "value": "native fixture memory",
            }
        policy_inputs = [
            item.body
            for item in evaluations
            if item.body["event_type"] == "model_input_prepared"
        ]
        for event in policy_inputs:
            assert (
                json.loads(event["payload"]["content_preview"])["tools"]
                == graph._bound_model.kwargs["tools"]
            )
        for request in evaluations:
            event = request.body
            if event["event_type"] not in {
                "tool_call_proposed",
                "memory_write_proposed",
                "message_send_proposed",
            }:
                continue
            assert event["security_context"]["source_type"] == "model"
            assert event["security_context"]["source_trust"] == "unknown"
            policy = http.store.get_policy_evaluation_by_event_id(event["event_id"])
            proof = policy.evidence["product_action_data"]
            origin = event["metadata"]["product_model_content"]
            assert proof["model_output_audit_id"] == origin["model_output_audit_id"]
            assert proof["model_source_ref"] == origin["model_source_ref"]
            output_policy = http.store.get_audit_event(proof["model_output_audit_id"])
            commitment = output_policy.evidence["product_model_content"]
            input_policy = http.store.get_audit_event(
                commitment["model_input_audit_id"]
            )
            for parent in (input_policy, output_policy):
                terminal = http.store.get_audit_event(
                    f"audit_outcome_{parent.links['event_id']}_execution_completed"
                )
                assert terminal is not None
                assert terminal.evidence["execution"]["status"] == "executed"
                assert terminal.evidence["result"]["disposition"] == "passed_through"
                assert terminal.metadata["product_ack_validation"]
        receipts = [item.body for item in http.requests_for("/v1/audit/events")]
        assert all(
            item.status_code == 200 for item in http.requests_for("/v1/audit/events")
        )
        assert sum(
            item.get("event_type") == "tool_call_committed" for item in receipts
        ) == len(actions)
        assert adapter.product_delivery_status().pending_count == 0
        assert not adapter.product_delivery_status().breaker_open
        if category in {
            "file",
            "message",
            "write_only",
            "edit_only",
        }:
            assert (
                resolutions
            ), "high-impact native actions must use real approval consumption"
            assert all(item["decision"] == "allow_once" for item in resolutions)
            assert any(
                "/execution-leases/consume" in item.path and item.status_code == 200
                for item in http.requests
            )
    finally:
        graph.close()


@pytest.mark.parametrize("phase", ["model_output_produced", "model_input_prepared"])
@pytest.mark.parametrize("fault", ["disconnect_before", "disconnect_after"])
def test_model_parent_receipt_outage_withholds_origin_and_never_invokes_tool(
    native_model_http, monkeypatch, phase, fault  # noqa: F811
):
    """Real socket failure; recovery sends only the original frozen receipts."""
    from dataclasses import replace
    from agentguard_langgraph_adapter import product_outbox
    from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient
    from tests.support.product_delivery_http import (
        DeliveryProxy,
        product_delivery_proxy,
    )

    http, adapter, _, original_ack = native_model_http
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "write",
                        "args": {
                            "path": "never-written.txt",
                            "content": "private-action-content",
                        },
                        "id": "receipt-gated-write",
                    }
                ],
            )
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="receipt-gated-model",
    )
    original_exchange = DeliveryProxy._next_fault
    injected = False
    with product_delivery_proxy(http.base_url) as proxy:
        sender = AgentGuardCoreClient(
            replace(adapter.config, core_base_url=proxy.base_url)
        )
        monkeypatch.setattr(
            adapter._product_outbox, "_send", sender.submit_product_receipt_wire
        )

        def interrupt(self, body):
            nonlocal injected
            receipt = json.loads(body)
            parent = http.store.get_audit_event(receipt["links"]["policy_audit_id"])
            if (
                not injected
                and receipt["record_type"] == "runtime_outcome"
                and parent.event_type == phase
            ):
                injected = True
                proxy.inject(fault)
            return original_exchange(self, body)

        monkeypatch.setattr(DeliveryProxy, "_next_fault", interrupt)
        security = dict(http.event()["security_context"], task_id=http.task_id)
        result = graph.invoke(
            sources=[
                {
                    "role": "user",
                    "content": security["user_task"],
                    "source_type": "user",
                    "source_trust": "trusted",
                }
            ],
            security=security,
            trace_id=http.trace_id,
        )
        assert injected and result.blocked
        assert result.model_calls == 1 and result.tool_invocations == 0
        assert result.messages() == []
        assert not (http.root / "never-written.txt").exists()
        assert not any(
            r.body.get("event_type") == "tool_call_proposed"
            for r in http.requests_for("/v1/guard/evaluate")
        )
        assert adapter.product_delivery_status().pending_count > 0
        # A new ACK never rewrites historical receipt authority.
        refreshed = adapter.refresh_product_ack()
        assert refreshed.issued_at != original_ack.issued_at
        adapter.close_product_session()
        proxy.inject("none")
        now = product_outbox._now_ms()
        monkeypatch.setattr(product_outbox, "_now_ms", lambda: now + 60_000)
        adapter.drain_product_receipts()
        assert adapter.product_delivery_status().pending_count == 0
        assert len(model._messages) == 1
        assert not (http.root / "never-written.txt").exists()
        runtime_receipts = [
            json.loads(e.request_body)
            for e in proxy.exchanges
            if json.loads(e.request_body).get("record_type") == "runtime_outcome"
        ]
        assert runtime_receipts
        assert all(
            r["metadata"]["activation_ack"] == original_ack.to_wire()
            for r in runtime_receipts
        )
        for receipt in runtime_receipts:
            assert http.store.get_audit_event(receipt["audit_id"]) is not None
    graph.close()


@pytest.mark.parametrize("change", ["arguments", "call_id", "source_ref", "audit_id"])
def test_actual_model_commitment_rejects_changed_next_action(
    native_model_http, monkeypatch, change  # noqa: F811
):
    """A post-policy mutation cannot borrow the accepted original model proof."""
    from dataclasses import replace
    from agentguard_langgraph_adapter.model_boundary import NativeModelOutput

    http, adapter, _, _ = native_model_http
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "read",
                        "args": {"path": "fixture.txt"},
                        "id": "committed-read",
                    }
                ],
            )
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="commitment-model",
    )
    original = graph._model_boundary.invoke

    def tamper(**kwargs):
        result = original(**kwargs)
        assert result.output is not None and result.delivery.status == "recorded"
        assert result.output_policy_audit_id and result.output_source_ref
        if change == "audit_id":
            return replace(result, output_policy_audit_id="audit:unrelated")
        if change == "source_ref":
            return replace(result, output_source_ref="source:model:unrelated")
        projection = result.output.to_mapping()
        if change == "arguments":
            projection["tool_calls"][0]["args"]["path"] = "different.txt"
        else:
            projection["tool_calls"][0]["id"] = "different-call"
        return replace(result, output=NativeModelOutput.from_mapping(projection))

    monkeypatch.setattr(graph._model_boundary, "invoke", tamper)
    security = dict(http.event()["security_context"], task_id=http.task_id)
    result = graph.invoke(
        sources=[
            {
                "role": "user",
                "content": security["user_task"],
                "source_type": "user",
                "source_trust": "trusted",
            }
        ],
        security=security,
        trace_id=http.trace_id,
    )
    assert result.blocked and result.tool_invocations == 0
    assert result.model_calls == 1 and len(model._messages) == 1
    assert result.messages() == []
    evaluations = http.requests_for("/v1/guard/evaluate")
    assert evaluations[-1].body["event_type"] == "tool_call_proposed"
    assert evaluations[-1].status_code == 503
    assert not any(
        r.body.get("event_type") == "tool_call_committed"
        for r in http.requests_for("/v1/audit/events")
    )
    graph.close()


def test_actual_browser_session_denial_prevents_tool_and_next_model(
    native_model_http,  # noqa: F811
):
    http, adapter, _, _ = native_model_http
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "write",
                        "args": {"path": "denied.txt", "content": "not approved"},
                        "id": "denied-write",
                    }
                ],
            ),
            AIMessage(content="must not run"),
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="approval-denial-model",
    )
    graph._executor._approval_timeout = 5
    security = dict(http.event()["security_context"], task_id=http.task_id)
    with _automated_test_operator(http, decision="deny") as resolutions:
        result = graph.invoke(
            sources=[
                {
                    "role": "user",
                    "content": security["user_task"],
                    "source_type": "user",
                    "source_trust": "trusted",
                }
            ],
            security=security,
            trace_id=http.trace_id,
        )
    assert result.blocked and result.tool_invocations == 0
    assert result.model_calls == 1 and len(model._messages) == 1
    assert result.messages() == []
    assert len(resolutions) == 1 and resolutions[0]["decision"] == "deny"
    assert not (http.root / "denied.txt").exists()
    assert not any("/execution-leases/consume" in r.path for r in http.requests)
    terminals = [
        r.body
        for r in http.requests_for("/v1/audit/events")
        if r.body.get("record_type") == "runtime_outcome"
        and r.body["links"].get("action_id") == "denied-write"
    ]
    assert len(terminals) == 1
    assert terminals[0]["evidence"]["execution"]["status"] == "not_invoked"
    graph.close()


@pytest.mark.parametrize("native_model_http", [{"staging_tools": True}], indirect=True)
def test_executable_in_actual_staging_path_retains_current_policy_deny(
    native_model_http,  # noqa: F811
):
    """A signed inventory does not suppress P108's executable staging rule."""
    http, adapter, _, _ = native_model_http
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "exec",
                        "args": {"command": "python marker.py"},
                        "id": "staging-exec",
                    }
                ],
            )
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="staging-deny-model",
    )
    security = dict(http.event()["security_context"], task_id=http.task_id)
    result = graph.invoke(
        sources=[
            {
                "role": "user",
                "content": security["user_task"],
                "source_type": "user",
                "source_trust": "trusted",
            }
        ],
        security=security,
        trace_id=http.trace_id,
    )
    assert result.blocked and result.tool_invocations == 0
    assert result.model_calls == 1 and result.messages() == []
    assert not (http.root / "command-marker.txt").exists()
    policy = next(
        p
        for p in http.store.audit_events
        if p.record_type == "policy_evaluation" and p.event_type == "tool_call_proposed"
    )
    authority = policy.evidence["decision_authority"]["payload"]
    assert authority["selected_decision"]["decision"] == "deny"
    assert authority["decision_authority"]["legacy_floor_applied"] is True
    assert any(
        hit["rule_id"] == "P108_agent_abuse"
        for hit in authority["selected_decision"]["rule_hits"]
    )
    graph.close()
