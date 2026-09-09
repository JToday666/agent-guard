"""Real native assembly and permit contracts with synthetic candidate/HTTP evidence.

Only artifact installation/version and Guard responses are controlled; the factory,
ACK lifecycle, eight native tools, encrypted outbox and one-use gate are real.
No provider, candidate admission or end-to-end qualification is claimed here.
"""

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import importlib.metadata

import httpx
import pytest
from langchain_core.messages import AIMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from agentguard_core import build_activation_ack
from agentguard_core.actions import product_tools as core_product_tools
from agentguard_langgraph_adapter import AgentGuardLangGraphConfig, LangGraphAdapter
from agentguard_langgraph_adapter import (
    activation_session,
    product_composition as composition,
)
from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.execution_template import (
    assert_product_execution_available,
)
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
from agentguard_langgraph_adapter.native_tools import (
    create_isolated_product_tools,
    close_isolated_product_tools,
    native_tool_catalog_materials,
)
from tests.support.product_tool_catalog import catalog_fixture
from .test_native_langgraph import ControlledNativeModel

pytestmark = pytest.mark.integration


@pytest.fixture
def assembled(tmp_path, monkeypatch, request):
    root = tmp_path / "tools"
    root.mkdir(mode=0o700)
    tools = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:19001/inbox"
    )
    materials = native_tool_catalog_materials(
        tools, model_visible_tools=[convert_to_openai_tool(x.tool) for x in tools]
    )
    with monkeypatch.context() as contract:
        if getattr(request, "param", None) == "previous-tool-semantics":
            contract.setattr(
                core_product_tools,
                "PRODUCT_TOOL_SEMANTICS_VERSION",
                "isolated-product-tools-1",
            )
        fixture = catalog_fixture(tmp_path, langgraph_materials=materials)
    entry = fixture.bundle.runtime_entry("langgraph")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    manifest = {
        name: getattr(entry, name)
        for name in (
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
    }
    manifest.update(
        schema_version="1.0", activation_ref_digest=fixture.bundle.activation_ref_digest
    )
    path = private / "runtime.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    config = AgentGuardLangGraphConfig(
        product_execution_enabled=True,
        product_adapter_wheel_path=str(private / "synthetic-not-a-release.whl"),
        product_manifest_path=str(path),
        product_receipt_directory=str(private / "receipts"),
        product_receipt_key_path=str(private / "key"),
        token="synthetic-credential",
        context_isolation_mode="required",
        runtime_receipt_mode="required",
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
    )
    actual_version = importlib.metadata.version

    def version(name):
        return (
            "0.1.0rc1"
            if name == "agentguard-langgraph-adapter"
            else actual_version(name)
        )

    monkeypatch.setattr(composition, "version", version)
    monkeypatch.setattr(activation_session, "version", version)
    artifact = SimpleNamespace(
        digest=entry.adapter_artifact_digest, assert_current=lambda: None
    )
    monkeypatch.setattr(
        composition, "verify_installed_product_artifact", lambda *a, **kw: artifact
    )
    requests = []

    def handler(request):
        requests.append(request)
        body = json.loads(request.content)
        if request.url.path.endswith("/heartbeat"):
            now = datetime.now(timezone.utc)
            ack = build_activation_ack(
                server_secret=fixture.fixture.server_secret,
                runtime=entry.runtime,
                runtime_version=entry.runtime_version,
                plugin_version=entry.plugin_version,
                agent_id=entry.agent_id,
                runtime_binding_id=entry.runtime_binding_id,
                profile_id=entry.profile_id,
                activation_ref_digest=fixture.bundle.activation_ref_digest,
                capability_digest=entry.capability_report_digest,
                host_inventory_digest=entry.host_inventory_digest,
                tool_inventory_digest=entry.tool_inventory_digest,
                plugin_inventory_digest=None,
                plugin_order_inventory_digest=None,
                issued_at=now.isoformat(),
                expires_at=(now + timedelta(seconds=120)).isoformat(),
            )
            return httpx.Response(
                200,
                json={
                    "runtime_status": {
                        **body,
                        "runtime": "langgraph",
                        "principal_id": entry.principal_id,
                        "last_heartbeat_at": now.isoformat(),
                    },
                    "activation_ack": ack.model_dump(mode="json"),
                },
            )
        return httpx.Response(
            200, json={"ok": True, "audit_id": body.get("audit_id", "audit-synthetic")}
        )

    client_class = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: client_class(transport=httpx.MockTransport(handler), **kw),
    )
    adapter = LangGraphAdapter(config)
    model = ControlledNativeModel(responses=[AIMessage(content="safe")])
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=tools,
        provider="controlled-test",
        model_name=model.model_name,
    )
    try:
        yield SimpleNamespace(
            graph=graph,
            adapter=adapter,
            model=model,
            tools=tools,
            requests=requests,
            artifact=artifact,
            manifest=path,
            config=config,
        )
    finally:
        graph.close()
        adapter.close_product_delivery()
        close_isolated_product_tools(tools)


def test_explicit_start_observes_actual_inventory_and_owns_ack(assembled):
    rig = assembled
    with pytest.raises(ProductActivationError):
        rig.graph.snapshot()
    with pytest.raises(ProductActivationError):
        rig.graph.invoke(sources=[{"role": "user", "content": "safe"}], security={})
    assert not rig.requests
    ack = rig.graph.start()
    assert ack.runtime == "langgraph"
    assert rig.graph.snapshot()["ready"] is True
    assert len(rig.requests) == 1
    body = json.loads(rig.requests[0].content)
    assert len(body["capability_report"]["events"]) == 7
    with pytest.raises(ProductActivationError, match="session_owner_mismatch"):
        rig.adapter.start_product_session(observe=rig.graph._composition.observe)


@pytest.mark.parametrize("assembled", ["previous-tool-semantics"], indirect=True)
def test_old_semantics_profile_rejected_before_heartbeat_or_tool_call(assembled):
    with pytest.raises(ProductActivationError, match="product_profile_drift"):
        assembled.graph.start()
    assert assembled.requests == []


@pytest.mark.parametrize(
    "change",
    [
        "disable",
        "model",
        "callback",
        "tool",
        "topology",
        "outbox",
        "observer",
        "manifest",
        "artifact",
        "close",
    ],
)
def test_post_start_drift_blocks_every_new_permit(assembled, change):
    rig = assembled
    rig.graph.start()
    graph = rig.graph
    if change == "disable":
        rig.config.product_execution_enabled = False
    elif change == "model":
        rig.model.model_kwargs["temperature"] = 1
    elif change == "callback":
        graph._executor.execute_action = lambda **kw: None
    elif change == "tool":
        graph._tool_node.tools_by_name.pop("read")
    elif change == "topology":
        graph._compiled.cache = object()
    elif change == "outbox":
        rig.adapter._product_outbox._send = lambda wire: None
    elif change == "observer":
        rig.adapter._product_client()._product_session._observe = lambda: None
    elif change == "manifest":
        rig.manifest.write_text("{}")
        rig.manifest.chmod(0o600)
    elif change == "artifact":
        rig.artifact.assert_current = lambda: (_ for _ in ()).throw(
            ValueError("private-marker")
        )
    elif change == "close":
        graph.close()
    with pytest.raises(ProductActivationError):
        graph._composition.assert_current()
    assert not rig.model._seen
    assert len(rig.requests) == 1


def test_owner_callback_subject_and_single_use(assembled):
    graph = assembled.graph
    graph.start()
    owner = graph._executor

    def callback():
        return None

    with graph._composition.run():
        with graph._composition.invocation(owner, callback, "subject") as permit:
            for changed in (
                {"owner": graph._model_boundary},
                {"callback": lambda: None},
                {"subject": "other"},
                {"permit": object()},
            ):
                kwargs = dict(
                    owner=owner, permit=permit, callback=callback, subject="subject"
                )
                kwargs.update(changed)
                with pytest.raises(ProductActivationError):
                    assert_product_execution_available(**kwargs)
            assert_product_execution_available(
                owner=owner, permit=permit, callback=callback, subject="subject"
            )
            assert_product_execution_available(
                owner=owner,
                permit=permit,
                callback=callback,
                subject="subject",
                consume=True,
            )
            with pytest.raises(ProductActivationError):
                assert_product_execution_available(
                    owner=owner,
                    permit=permit,
                    callback=callback,
                    subject="subject",
                    consume=True,
                )
        with pytest.raises(ProductActivationError):
            assert_product_execution_available(
                owner=owner, permit=permit, callback=callback, subject="subject"
            )


def test_closed_during_confirmed_start_never_consumes_callback_permit(assembled):
    graph = assembled.graph
    graph.start()

    def callback():
        return None

    with graph._composition.run():
        with graph._composition.invocation(
            graph._executor, callback, "subject"
        ) as permit:
            assert_product_execution_available(
                owner=graph._executor,
                permit=permit,
                callback=callback,
                subject="subject",
            )
            graph.close()
            with pytest.raises(ProductActivationError):
                assert_product_execution_available(
                    owner=graph._executor,
                    permit=permit,
                    callback=callback,
                    subject="subject",
                    consume=True,
                )


def test_missing_composition_never_opens_generic_executor(assembled):
    rig = assembled
    rig.graph.start()
    with pytest.raises(ProductActivationError):
        assert_product_execution_available()
    with pytest.raises(ProductActivationError):
        rig.graph._executor.run_guarded_action(
            None,
            None,
            action_id="a",
            invoke_once=lambda: None,
            postprocess=lambda value: value,
            start_kind="model_call",
        )


@pytest.mark.parametrize(
    "change", ["consumer", "node_function", "extra_retry", "missing_tool"]
)
def test_pre_start_assembly_mutation_never_heartbeats(assembled, change):
    graph = assembled.graph
    if change == "consumer":
        graph._builder.build_tool_result = lambda *a: None
    elif change == "node_function":
        graph._compiled.nodes["model"].bound.func = lambda state: state
    elif change == "extra_retry":
        from langgraph.types import RetryPolicy

        graph._compiled.nodes["tools"].retry_policy = (RetryPolicy(max_attempts=2),)
    elif change == "missing_tool":
        graph._tool_node.tools_by_name.pop("exec")
    with pytest.raises(ProductActivationError):
        graph.start()
    assert not assembled.requests


def test_transport_session_cannot_be_adopted_by_native_factory(assembled):
    rig = assembled
    rig.adapter.start_product_session(observe=rig.graph._composition.observe)
    with pytest.raises(ProductActivationError, match="session_owner_mismatch"):
        rig.graph.start()
    assert len(rig.requests) == 1
    rig.adapter.close_product_session()


def test_second_graph_cannot_share_owned_ack(assembled):
    rig = assembled
    rig.graph.start()
    second = build_native_product_graph(
        adapter=rig.adapter,
        model=ControlledNativeModel(responses=[]),
        tools=rig.tools,
        provider="controlled-test",
        model_name="non-candidate-native",
    )
    try:
        with pytest.raises(ProductActivationError, match="session_owner_mismatch"):
            second.start()
        assert rig.graph.snapshot()["ready"] is True
    finally:
        second.close()
    assert rig.graph.snapshot()["ready"] is True


def test_persisted_breaker_blocks_new_graph_actions(assembled):
    rig = assembled
    rig.graph.start()
    rig.adapter.product_action_barrier.block_actions()
    assert rig.adapter.product_delivery_status().breaker_open
    with pytest.raises(ProductActivationError):
        rig.graph.snapshot()
    assert not rig.model._seen


def test_parent_permit_only_delegates_one_callback(assembled):
    graph = assembled.graph
    graph.start()

    def parent_callback(messages):
        return messages

    def child_callback():
        return None

    def postprocess(value):
        return value

    with graph._composition.run():
        with graph._composition.invocation(
            graph._model_boundary, parent_callback, "parent", postprocess
        ) as parent:
            assert_product_execution_available(
                owner=graph._model_boundary,
                permit=parent,
                callback=parent_callback,
                subject="parent",
                postprocess=postprocess,
            )
            with composition.delegated_invocation(
                parent,
                owner=graph._model_boundary,
                executor=graph._executor,
                callback=child_callback,
                subject="child",
                postprocess=postprocess,
            ) as child:
                assert_product_execution_available(
                    owner=graph._executor,
                    permit=child,
                    callback=child_callback,
                    subject="child",
                    postprocess=postprocess,
                )
            with pytest.raises(ProductActivationError):
                with composition.delegated_invocation(
                    parent,
                    owner=graph._model_boundary,
                    executor=graph._executor,
                    callback=child_callback,
                    subject="child",
                    postprocess=postprocess,
                ):
                    pytest.fail("second delegation")


def test_default_execution_is_off_and_boolean_is_strict():
    assert AgentGuardLangGraphConfig().product_execution_enabled is False
    for value in (1, "true", None):
        with pytest.raises((ProductActivationError, ValueError)):
            AgentGuardLangGraphConfig(product_execution_enabled=value)
    with pytest.raises((ProductActivationError, ValueError)):
        AgentGuardLangGraphConfig(product_execution_enabled=True)


def test_close_during_final_observation_cannot_consume_late_success(
    assembled, monkeypatch
):
    from threading import Event, Thread

    graph = assembled.graph
    graph.start()
    entered, released, closed = Event(), Event(), Event()
    errors = []
    calls = []
    original = graph._composition.assert_current

    def late_check():
        original()
        entered.set()
        if not released.wait(3):
            raise RuntimeError("test observation timeout")

    def callback():
        calls.append(True)

    def execute():
        try:
            with graph._composition.run():
                with graph._composition.invocation(
                    graph._executor, callback, "fixed"
                ) as permit:
                    assert_product_execution_available(
                        owner=graph._executor,
                        permit=permit,
                        callback=callback,
                        subject="fixed",
                    )
                    monkeypatch.setattr(
                        graph._composition, "assert_current", late_check
                    )
                    try:
                        assert_product_execution_available(
                            owner=graph._executor,
                            permit=permit,
                            callback=callback,
                            subject="fixed",
                            consume=True,
                        )
                        callback()
                    except ProductActivationError:
                        errors.append("blocked")
        finally:
            released.set()

    worker = Thread(target=execute)
    worker.start()
    assert entered.wait(3)

    def close():
        graph.close()
        closed.set()

    closer = Thread(target=close)
    closer.start()
    # close sets its revocation flag before waiting for the held permit lock.
    import time

    deadline = time.monotonic() + 3
    while not graph._composition._closed and time.monotonic() < deadline:
        time.sleep(0.001)
    assert graph._composition._closed
    released.set()
    worker.join(3)
    closer.join(3)
    assert not worker.is_alive() and not closer.is_alive()
    assert errors == ["blocked"] and not calls and closed.is_set()


@pytest.mark.parametrize("change", ["sender", "age", "session"])
def test_owned_session_transport_or_instance_mutation_is_rejected(assembled, change):
    rig = assembled
    rig.graph.start()
    client = rig.adapter._product_client()
    original = client._product_session
    if change == "sender":
        original._send_heartbeat = lambda body: {}
    elif change == "age":
        original._max_ack_age = 900
    else:
        client._product_session = activation_session.ProductActivationSession(
            client._product_manifest,
            send_heartbeat=client._send_product_heartbeat,
            observe=rig.graph._composition._observer,
        )
    with pytest.raises(ProductActivationError):
        rig.graph.snapshot()
    rig.graph.close()
    assert original._closed
    assert len(rig.requests) == 1


def test_foreign_graph_cannot_reuse_or_close_another_composition(assembled):
    rig = assembled
    rig.graph.start()
    second = build_native_product_graph(
        adapter=rig.adapter,
        model=ControlledNativeModel(responses=[]),
        tools=rig.tools,
        provider="controlled-test",
        model_name="non-candidate-native",
    )
    original = second._composition
    second._composition = rig.graph._composition
    try:
        with pytest.raises(ProductActivationError):
            second.start()
        with pytest.raises(ProductActivationError):
            second.snapshot()
        second.close()
        assert rig.graph.snapshot()["ready"] is True
    finally:
        original.close()
