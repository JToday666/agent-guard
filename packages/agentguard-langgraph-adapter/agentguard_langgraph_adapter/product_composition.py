"""Instance-owned native composition and single-use callback permissions.

This is an SDK misuse boundary, not a sandbox against arbitrary Python code
executing inside the owning process. No process-global execution flag exists.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import version
from threading import RLock, get_ident
from typing import Any, Iterator
import weakref

from .activation_ack import ActivationAckV1, ProductActivationError
from .config import validate_product_execution_configuration
from .product_artifact import (
    InstalledProductArtifact,
    verify_installed_product_artifact,
)
from .product_manifest import (
    PRODUCT_EVENT_TYPES,
    _ENFORCEMENT,
    LangGraphCapabilityReportV2,
    ProductRuntimeObservation,
    canonical_sha256,
)

_FACTORY_KEY = object()
_PERMITS: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()
_PERMIT_LOCK = RLock()


def _fail(code: str = "product_execution_unavailable") -> ProductActivationError:
    return ProductActivationError(code)


class _InvocationPermit:
    __slots__ = ("__weakref__",)

    def __repr__(self) -> str:
        return "ProductInvocationPermit(<private>)"

    def __reduce__(self) -> Any:
        raise _fail()


@dataclass
class _Grant:
    composition: Any
    owner: Any
    callback: Any
    subject: str
    postprocess: Any
    thread: int
    claimed: bool = False
    consumed: bool = False
    delegated: bool = False


def invocation_subject(value: Any) -> str:
    from .native_events import native_json

    # Only security content is hashed; callbacks/owners are checked by identity.
    import hashlib

    return hashlib.sha256(native_json(value).encode()).hexdigest()


def assert_invocation_permit(
    *,
    owner: Any,
    permit: Any,
    callback: Any,
    subject: str,
    postprocess: Any = None,
    consume: bool = False,
) -> None:
    with _PERMIT_LOCK:
        grant = _PERMITS.get(permit) if type(permit) is _InvocationPermit else None
        if (
            grant is None
            or grant.owner is not owner
            or grant.callback is not callback
            or grant.subject != subject
            or grant.postprocess is not postprocess
            or grant.thread != get_ident()
            or grant.consumed
            or (not consume and grant.claimed)
            or (consume and not grant.claimed)
        ):
            raise _fail()
        grant.composition.assert_current()
        if (
            grant.composition._closed
            or grant.composition._failed
            or not grant.composition._running
            or _PERMITS.get(permit) is not grant
        ):
            raise _fail()
        if consume:
            grant.consumed = True
        else:
            grant.claimed = True


@contextmanager
def delegated_invocation(
    parent: Any,
    *,
    owner: Any,
    executor: Any,
    callback: Any,
    subject: str,
    postprocess: Any,
) -> Iterator[Any]:
    # The exact registered model boundary may authorize only one internal
    # callback after it has assembled and evaluated the complete model input.
    with _PERMIT_LOCK:
        grant = _PERMITS.get(parent) if type(parent) is _InvocationPermit else None
        if (
            grant is None
            or grant.owner is not owner
            or not grant.claimed
            or grant.consumed
            or grant.delegated
            or grant.thread != get_ident()
            or executor is not grant.composition.graph()._executor
        ):
            raise _fail()
        grant.delegated = True
        composition = grant.composition
    with composition.invocation(executor, callback, subject, postprocess) as permit:
        yield permit


def tool_subject(prepared: Any, security: Any, trace_id: str, origin: Any) -> str:
    return invocation_subject(
        {
            "name": prepared.name,
            "call_id": prepared.call_id,
            "arguments": prepared.arguments(),
            "resources": prepared.resources(),
            "security": security,
            "trace_id": trace_id,
            "origin": {
                "model_output_audit_id": origin.model_output_audit_id,
                "model_source_ref": origin.model_source_ref,
                "call_id": origin.call_id,
            },
        }
    )


def action_subject(event: Any, decision: Any, action_id: str, start_kind: str) -> str:
    return invocation_subject(
        {
            "event": event.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "action_id": action_id,
            "start_kind": start_kind,
        }
    )


def _method(value: Any, name: str) -> tuple[Any, Any]:
    method = getattr(value, name)
    if not callable(method):
        raise _fail("product_composition_drift")
    function = getattr(method, "__func__", method)
    return function, getattr(function, "__code__", None)


def _static_identity(value: Any, depth: int = 0) -> Any:
    if depth > 16:
        raise _fail("product_composition_drift")
    if value is None or type(value) in (str, bool, int, float):
        return type(value), value
    if type(value) in (list, tuple):
        return type(value), tuple(_static_identity(item, depth + 1) for item in value)
    if type(value) is dict:
        return tuple(
            (_static_identity(k, depth + 1), _static_identity(v, depth + 1))
            for k, v in value.items()
        )
    if type(value) in (set, frozenset):
        return frozenset(_static_identity(item, depth + 1) for item in value)
    function = getattr(value, "__func__", value)
    if callable(value):
        return (
            id(function),
            getattr(function, "__code__", None),
            id(getattr(value, "__self__", None)),
            _static_identity(getattr(function, "__defaults__", None), depth + 1),
            _static_identity(getattr(function, "__kwdefaults__", None), depth + 1),
        )
    return type(value), id(value)


def _runnable_identity(value: Any) -> tuple[Any, ...]:
    return (
        type(value),
        id(value),
        tuple(
            (name, _method(value, name))
            for name in ("func", "afunc", "invoke")
            if callable(getattr(value, name, None))
        ),
        _static_identity(
            {
                name: getattr(value, name, None)
                for name in (
                    "name",
                    "tags",
                    "kwargs",
                    "trace",
                    "recurse",
                    "explode_args",
                    "writes",
                    "func_accepts",
                )
            }
        ),
    )


class ProductComposition:
    def __init__(self, key: object, graph: Any) -> None:
        if key is not _FACTORY_KEY:
            raise _fail()
        self.graph = weakref.ref(graph)
        self._started = False
        self._closed = False
        self._failed = False
        self._running = False
        self._mutex = RLock()
        self._artifact: InstalledProductArtifact | None = None
        self._observer = self.observe
        self._components: tuple[Any, ...] | None = None
        self._methods: tuple[Any, ...] | None = None
        self._client: Any = None
        self._initial_identity = self._identity()

    def __repr__(self) -> str:
        return "ProductComposition(<private>)"

    def _identity(self) -> tuple[Any, ...]:
        graph = self.graph()
        if graph is None:
            raise _fail()
        compiled = graph._compiled
        node = graph._tool_node
        return (
            (
                graph._provider,
                graph._model_name,
                graph._max_model_calls,
                graph._inventory_digest,
            ),
            tuple(
                id(getattr(graph, name))
                for name in (
                    "_adapter",
                    "_builder",
                    "_executor",
                    "_model_boundary",
                    "_tool_node",
                    "_compiled",
                    "_bound_model",
                    "_model",
                    "_tools",
                )
            ),
            tuple((name, id(spec)) for name, spec in graph._specs.items()),
            tuple((name, id(tool)) for name, tool in node.tools_by_name.items()),
            _method(node, "_wrap_tool_call"),
            node._handle_tool_errors,
            compiled.checkpointer,
            compiled.store,
            compiled.cache,
            tuple(compiled.interrupt_before_nodes),
            tuple(compiled.interrupt_after_nodes),
            tuple(
                (
                    name,
                    id(value),
                    _runnable_identity(value.bound),
                    tuple(value.triggers),
                    tuple(_runnable_identity(writer) for writer in value.writers),
                    tuple(value.retry_policy or ()),
                )
                for name, value in compiled.nodes.items()
            ),
            tuple(
                _method(graph, name)
                for name in (
                    "_model_step",
                    "_tool_step",
                    "_wrap_tool_call",
                    "_assert_binding",
                    "_assert_current",
                )
            ),
            tuple(
                _method(graph._executor, name)
                for name in (
                    "execute_action",
                    "run_guarded_action",
                    "_run_guarded_action",
                )
            ),
            _method(graph._model_boundary, "invoke"),
            tuple(
                _method(graph._builder, name)
                for name in (
                    "build_context",
                    "build_model",
                    "build_tool_call",
                    "build_specialized_action",
                    "build_tool_result",
                    "build_action_start",
                )
            ),
        )

    def _assembly(self) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
        from langgraph.graph.state import CompiledStateGraph
        from langgraph.prebuilt import ToolNode
        from .core_client import AgentGuardCoreClient
        from .execution_template import GuardedExecutionTemplate
        from .langgraph_adapter import LangGraphAdapter
        from .model_boundary import GuardedModelBoundary
        from .native_events import NativeGuardEventBuilder
        from .native_langgraph import NativeProductGraph
        from .product_action_barrier import ProductActionBarrier
        from .product_outbox import ProductReceiptOutbox

        graph = self.graph()
        if graph is None or type(graph) is not NativeProductGraph:
            raise _fail()
        adapter = graph._adapter
        if type(adapter) is not LangGraphAdapter:
            raise _fail()
        client = adapter._product_client()
        parts = (
            graph._builder,
            graph._executor,
            graph._model_boundary,
            graph._tool_node,
            graph._compiled,
            adapter,
            client,
            adapter._product_outbox,
            adapter._product_barrier,
            graph._bound_model,
            graph._model,
        )
        if (
            type(client) is not AgentGuardCoreClient
            or type(graph._builder) is not NativeGuardEventBuilder
            or type(graph._executor) is not GuardedExecutionTemplate
            or type(graph._model_boundary) is not GuardedModelBoundary
            or type(graph._tool_node) is not ToolNode
            or type(graph._compiled) is not CompiledStateGraph
            or type(adapter._product_outbox) is not ProductReceiptOutbox
            or type(adapter._product_barrier) is not ProductActionBarrier
            or graph._executor._adapter is not adapter
            or graph._executor._events is not graph._builder
            or graph._model_boundary.adapter is not adapter
            or graph._model_boundary.event_builder is not graph._builder
            or graph._model_boundary.executor is not graph._executor
            or adapter._product_barrier._outbox is not adapter._product_outbox
        ):
            raise _fail()
        if self._identity() != self._initial_identity:
            raise _fail("product_composition_drift")
        if (
            getattr(graph._tool_node._wrap_tool_call, "__self__", None) is not graph
            or getattr(graph._tool_node._wrap_tool_call, "__func__", None)
            is not type(graph)._wrap_tool_call
            or graph._tool_node._handle_tool_errors is not False
            or set(graph._tool_node.tools_by_name) != set(graph._specs)
            or any(
                graph._tool_node.tools_by_name[name] is not spec.tool
                for name, spec in graph._specs.items()
            )
            or graph._compiled.checkpointer is not False
            or graph._compiled.store is not None
            or graph._compiled.cache is not None
            or graph._compiled.interrupt_before_nodes
            or graph._compiled.interrupt_after_nodes
            or adapter._product_outbox._send != client.submit_product_receipt_wire
        ):
            raise _fail("product_composition_drift")
        graph._assert_binding()
        methods = tuple(
            _method(instance, name)
            for instance, names in (
                (graph, ("_model_step", "_tool_step", "_wrap_tool_call")),
                (
                    graph._builder,
                    (
                        "build_context",
                        "build_model",
                        "build_tool_call",
                        "build_specialized_action",
                        "build_tool_result",
                        "build_action_start",
                    ),
                ),
                (
                    graph._executor,
                    ("execute_action", "run_guarded_action", "_run_guarded_action"),
                ),
                (graph._model_boundary, ("invoke", "_checkpoint")),
                (
                    adapter,
                    (
                        "evaluate_guard_event",
                        "submit_product_receipt",
                        "refresh_product_ack",
                        "consume_execution_lease",
                    ),
                ),
                (
                    adapter._product_barrier,
                    ("assert_ready", "begin_action", "finish_action"),
                ),
                (adapter._product_outbox, ("submit", "_begin", "_finish", "status")),
                (graph._compiled, ("invoke",)),
                (graph._tool_node, ("invoke",)),
            )
            for name in names
        )
        return parts, methods

    def _verify(self) -> ProductRuntimeObservation:
        from .native_tools import native_tool_catalog_materials

        if self._closed or self._failed:
            raise _fail()
        graph = self.graph()
        if graph is None:
            raise _fail()
        validate_product_execution_configuration(graph._adapter.config)
        parts, methods = self._assembly()
        if self._components is not None and (
            any(a is not b for a, b in zip(parts, self._components))
            or methods != self._methods
        ):
            raise _fail("product_composition_drift")
        assert graph is not None
        client = graph._adapter._product_client()
        manifest = client._check_product()
        materials = native_tool_catalog_materials(
            graph._tools, model_visible_tools=graph._bound_model.kwargs["tools"]
        )
        if self._artifact is None:
            self._artifact = verify_installed_product_artifact(
                graph._adapter.config.product_adapter_wheel_path,
                expected_digest=manifest.adapter_artifact_digest,
            )
        self._artifact.assert_current()
        report_data = {
            "schema_version": "2.0",
            "runtime": "langgraph",
            "agent_id": manifest.agent_id,
            "runtime_binding_id": manifest.runtime_binding_id,
            "profile_id": "agentguard-langgraph-v2",
            "supported": True,
            "active": True,
            "c0_registration": True,
            "c1_pre_execution_interception": True,
            "c2_correlation": True,
            "c3_atomic_replace_and_seal": True,
            "c4_outcome_receipts": True,
            "events": [
                {
                    "event_type": name,
                    "supported": True,
                    "active": True,
                    "enforcement": _ENFORCEMENT[name],
                    "residual_boundaries": [],
                }
                for name in PRODUCT_EVENT_TYPES
            ],
            "residual_boundaries": [],
        }
        report = LangGraphCapabilityReportV2.model_validate(
            {**report_data, "report_digest": canonical_sha256(report_data)}
        )
        observed = ProductRuntimeObservation(
            runtime="langgraph",
            runtime_version=version("langgraph"),
            plugin_version=version("agentguard-langgraph-adapter"),
            loaded=True,
            enforcement_mode="enforce",
            adapter_artifact_digest=self._artifact.digest,
            host_inventory_digest=materials["host_inventory_digest"],
            tool_inventory_digest=materials["tool_inventory_digest"],
            capability_report=report,
        )
        manifest.make_heartbeat(observed)
        # Same frozen catalog projection as Core, without importing Core into
        # the standalone Adapter installation. LG has no plugin-order digests.
        identity = {
            name: getattr(manifest, name)
            for name in (
                "runtime",
                "runtime_version",
                "plugin_version",
                "profile_id",
                "agent_id",
                "runtime_binding_id",
                "principal_id",
                "adapter_artifact_digest",
                "capability_report_digest",
                "host_inventory_digest",
                "tool_inventory_digest",
            )
        }
        identity.update(
            plugin_inventory_digest=None, plugin_order_inventory_digest=None
        )
        if (
            canonical_sha256(
                {
                    "schema_version": "1.0",
                    "semantics_version": "isolated-product-tools-1",
                    "identity": identity,
                    "execution": materials["execution"],
                }
            )
            != manifest.profile_digest
        ):
            raise _fail("product_profile_drift")
        status = graph._adapter.product_delivery_status()
        if status.breaker_open or status.unknown_action_count:
            raise _fail("product_delivery_unavailable")
        self._components, self._methods, self._client = parts, methods, client
        return observed

    def observe(self) -> ProductRuntimeObservation:
        try:
            return self._verify()
        except Exception:
            self._failed = True
            raise ProductActivationError("observation_drift") from None

    def start(self) -> ActivationAckV1:
        with self._mutex:
            self._verify()
            graph = self.graph()
            assert graph is not None
            graph._adapter.product_action_barrier.assert_ready()
            ack = self._client._start_composed_session(self, observe=self._observer)
            self._started = True
            self.assert_current()
            return ack

    def assert_current(self) -> None:
        if not self._started or self._closed or self._failed:
            raise _fail()
        try:
            self._verify()
            self._client._assert_composed_session(self, self._observer)
        except Exception:
            self._failed = True
            raise _fail("product_composition_drift") from None
        # Temporary heartbeat unavailability/expiry may recover through the
        # same owned session. Identity drift remains sticky in its reader.
        self._client.snapshot_product_ack()
        if self._closed or self._failed:
            raise _fail("product_composition_drift")

    @contextmanager
    def run(self) -> Iterator[None]:
        with self._mutex:
            self.assert_current()
            if self._running:
                raise _fail()
            graph = self.graph()
            assert graph is not None
            graph._adapter.product_action_barrier.assert_ready()
            self._running = True
        try:
            yield
        finally:
            self._running = False

    @contextmanager
    def invocation(
        self, owner: Any, callback: Any, subject: str, postprocess: Any = None
    ) -> Iterator[Any]:
        self.assert_current()
        graph = self.graph()
        if (
            not self._running
            or graph is None
            or owner not in (graph._executor, graph._model_boundary)
        ):
            raise _fail()
        permit = _InvocationPermit()
        with _PERMIT_LOCK:
            _PERMITS[permit] = _Grant(
                self, owner, callback, subject, postprocess, get_ident()
            )
        try:
            yield permit
        finally:
            with _PERMIT_LOCK:
                _PERMITS.pop(permit, None)

    def close(self) -> None:
        self._closed = True
        with _PERMIT_LOCK:
            for permit, grant in tuple(_PERMITS.items()):
                if grant.composition is self:
                    _PERMITS.pop(permit, None)
        if self._client is not None and self._client._product_session_owner is self:
            self._client.close_product_session()


def _create_composition(graph: Any) -> ProductComposition:
    return ProductComposition(_FACTORY_KEY, graph)
