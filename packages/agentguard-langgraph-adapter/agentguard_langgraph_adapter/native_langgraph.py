"""Serial native StateGraph entrypoint for the isolated Product tool inventory.

The public execution fuse remains closed until the complete Product composition
is admitted.  This module has no benchmark, replay-model, or legacy fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from importlib.metadata import version as _installed_version
import json
import re
from threading import Lock
from typing import Any, Callable, TypedDict
from uuid import uuid4

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage, convert_to_messages
from langchain_core.runnables import RunnableBinding, RunnableConfig
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import RetryPolicy
from langsmith import tracing_context
from pydantic import SecretBytes, SecretStr

from .activation_ack import ActivationAckV1, ProductActivationError
from .product_composition import (
    ProductComposition,
    _create_composition,
    invocation_subject,
    tool_subject,
)
from . import execution_template as _execution
from .model_boundary import GuardedModelBoundary, NativeModelOutput
from .native_events import NativeGuardEventBuilder, NativeModelOrigin, native_json
from .native_tools import (
    NativeToolSpec,
    native_tool_inventory_digest,
    prepare_native_tool_call,
)

_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_NATIVE_VERSIONS = {
    "langgraph": "1.2.7",
    "langgraph-prebuilt": "1.1.0",
    "langchain-core": "1.4.8",
}


class NativeRuntimeError(RuntimeError):
    """A bounded runtime failure; original model/tool errors stay private."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _json(value: Any) -> str:
    try:
        return native_json(value)
    except Exception:
        raise NativeRuntimeError("native_payload_invalid") from None


def _copy(value: Any) -> Any:
    return json.loads(_json(value))


def _require_complete_product_composition(graph: Any) -> None:
    if (
        type(graph._composition) is not ProductComposition
        or graph._composition.graph() is not graph
    ):
        raise ProductActivationError("product_execution_unavailable")
    graph._composition.assert_current()


@dataclass(frozen=True, slots=True)
class NativeRunResult:
    """Only the final admitted answer, without live graph or runtime handles."""

    trace_id: str
    blocked: bool
    model_calls: int
    tool_invocations: int
    inventory_digest: str
    error_code: str | None
    _messages_json: str = field(repr=False)

    def messages(self) -> list[dict[str, Any]]:
        return json.loads(self._messages_json)


class _State(TypedDict):
    history: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    messages: list[Any]
    security: dict[str, Any]
    tool_security: dict[str, Any]
    model_origin: NativeModelOrigin | None
    trace_id: str
    model_calls: int
    tool_invocations: int
    seen_call_ids: list[str]
    blocked: bool
    error_code: str | None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_model_argument_key")
        result[key] = value
    return result


def _normalize_model_output(value: Any) -> NativeModelOutput:
    # An AIMessageChunk is also an AIMessage; exact type is intentional.
    if type(value) is not AIMessage or value.model_extra:
        raise NativeRuntimeError("native_model_output_invalid")
    projection = _copy(
        {
            "content": value.content,
            "tool_calls": value.tool_calls,
            "invalid_tool_calls": value.invalid_tool_calls,
        }
    )
    calls = projection["tool_calls"]
    if len(calls) > 1 or projection["invalid_tool_calls"]:
        raise NativeRuntimeError("native_model_calls_invalid")
    if calls:
        call = calls[0]
        if (
            set(call) != {"name", "args", "id", "type"}
            or call["type"] != "tool_call"
            or type(call["args"]) is not dict
            or type(call["name"]) is not str
            or not call["name"]
            or type(call["id"]) is not str
            or not _IDENTITY.fullmatch(call["id"])
        ):
            raise NativeRuntimeError("native_model_calls_invalid")
    additional = _copy(value.additional_kwargs)
    # ChatOpenAI retains these empty response fields on ordinary completions.
    # Nonempty auxiliary content is unsupported and must never be discarded.
    for empty_field in ("refusal", "parsed"):
        if empty_field in additional and additional[empty_field] is None:
            additional.pop(empty_field)
    if additional:
        # Standard providers retain their raw tool-call projection here. It
        # must describe precisely the same call the executor will receive.
        try:
            if set(additional) != {"tool_calls"}:
                raise ValueError
            raw_calls = additional["tool_calls"]
            if type(raw_calls) is not list or len(raw_calls) != len(calls):
                raise ValueError
            for raw, parsed in zip(raw_calls, calls, strict=True):
                if (
                    type(raw) is not dict
                    or set(raw) != {"id", "type", "function"}
                    or raw["type"] != "function"
                    or raw["id"] != parsed["id"]
                    or type(raw["function"]) is not dict
                    or set(raw["function"]) != {"name", "arguments"}
                    or raw["function"]["name"] != parsed["name"]
                    or type(raw["function"]["arguments"]) is not str
                    or _json(
                        json.loads(
                            raw["function"]["arguments"],
                            object_pairs_hook=_unique_json_object,
                        )
                    )
                    != _json(parsed["args"])
                ):
                    raise ValueError
        except Exception:
            raise NativeRuntimeError("native_model_metadata_invalid") from None
    return NativeModelOutput.from_mapping(projection)


class NativeProductGraph:
    """Private compiled StateGraph behind a serial, non-resumable facade."""

    def __init__(
        self,
        *,
        adapter: Any,
        model: BaseChatModel,
        tools: tuple[NativeToolSpec, ...],
        provider: str,
        model_name: str,
        max_model_calls: int = 16,
    ) -> None:
        try:
            if any(
                _installed_version(name) != expected
                for name, expected in _NATIVE_VERSIONS.items()
            ):
                raise ValueError
        except Exception:
            raise NativeRuntimeError("native_version_mismatch") from None
        if (
            type(max_model_calls) is not int
            or not 1 <= max_model_calls <= 64
            or type(provider) is not str
            or not _IDENTITY.fullmatch(provider)
            or type(model_name) is not str
            or not model_name
            or len(model_name) > 256
            or type(tools) is not tuple
        ):
            raise NativeRuntimeError("native_configuration_invalid")
        self._adapter = adapter
        self._model = model
        self._tools = tools
        self._specs = {spec.name: spec for spec in tools}
        self._inventory_digest = native_tool_inventory_digest(tools)
        self._provider = provider
        self._model_name = model_name
        self._max_model_calls = max_model_calls
        self._lock = Lock()
        self._closed = False
        self._composition: ProductComposition | None = None
        self._assert_model_configuration()
        self._model_configuration_digest = self._capture_model_configuration()
        # LangChain 1.4.8 returns a typed, behaviorally identical binding
        # subclass. Obtain that exact SDK type without trusting an override.
        self._sdk_binding_type = type(BaseChatModel.bind(model))
        try:
            self._bound_model: Any = model.bind_tools(
                [spec.tool for spec in tools],
                parallel_tool_calls=False,
            )
        except Exception:
            raise NativeRuntimeError("native_model_binding_invalid") from None
        self._assert_binding()
        self._builder = NativeGuardEventBuilder(adapter)
        self._executor = _execution.GuardedExecutionTemplate(
            adapter,
            event_builder=self._builder,
        )
        self._model_boundary = GuardedModelBoundary(
            adapter,
            event_builder=self._builder,
            executor=self._executor,
        )
        self._tool_node = ToolNode(
            [spec.tool for spec in tools],
            handle_tool_errors=False,
            wrap_tool_call=self._wrap_tool_call,
        )
        graph = StateGraph(_State)
        no_retry = RetryPolicy(max_attempts=1)
        graph.add_node("model", self._model_step, retry_policy=no_retry)
        graph.add_node("tools", self._tool_step, retry_policy=no_retry)
        graph.add_edge(START, "model")
        graph.add_conditional_edges(
            "model",
            self._after_model,
            {"tools": "tools", "end": END},
        )
        graph.add_conditional_edges(
            "tools",
            lambda state: "end" if state["blocked"] else "model",
            {"model": "model", "end": END},
        )
        self._compiled = graph.compile(
            checkpointer=False,
            store=None,
            cache=None,
            interrupt_before=[],
            interrupt_after=[],
        )

    def _assert_model_configuration(self) -> None:
        model: Any = self._model
        if (
            not isinstance(model, BaseChatModel)
            or model.cache is not False
            or model.callbacks not in (None, [])
            or model.verbose is not False
            or getattr(model, "max_retries", 0) != 0
            or getattr(model, "streaming", False) is not False
            or (
                hasattr(model, "model_name")
                and getattr(model, "model_name") != self._model_name
            )
        ):
            raise NativeRuntimeError("native_model_configuration_invalid")
        if (
            hasattr(self, "_model_configuration_digest")
            and self._capture_model_configuration() != self._model_configuration_digest
        ):
            raise NativeRuntimeError("native_model_configuration_drift")

    def _capture_model_configuration(self) -> str:
        """Freeze effective parameters/clients privately, including secret changes.

        Provider models exclude live clients and counters from their Pydantic
        config. Client and callable identities are therefore bound separately.
        Controlled test models likewise mark only their response cursor private.
        """
        try:
            model: Any = self._model
            clients = {}
            for name in (
                "client",
                "async_client",
                "root_client",
                "root_async_client",
                "http_client",
                "http_async_client",
            ):
                client: Any = getattr(model, name, None)
                retries = getattr(client, "max_retries", None)
                if retries is not None and retries != 0:
                    raise ValueError
                api_key = getattr(client, "api_key", None)
                if api_key is not None and type(api_key) is not str:
                    raise ValueError
                clients[name] = {
                    "identity": id(client),
                    "owner_identity": id(getattr(client, "_client", None)),
                    "base_url": (
                        str(client.base_url) if hasattr(client, "base_url") else None
                    ),
                    "max_retries": retries,
                    "api_key_digest": (
                        hashlib.sha256(api_key.encode("utf-8")).hexdigest()
                        if api_key is not None
                        else None
                    ),
                }
            methods = {}
            for name in ("invoke", "generate", "_generate", "bind_tools"):
                bound = getattr(model, name)
                function = getattr(bound, "__func__", bound)
                methods[name] = [id(function), id(getattr(function, "__code__", None))]
            secret_digests = {}
            for name in type(model).model_fields:
                value = getattr(model, name, None)
                if isinstance(value, (SecretStr, SecretBytes)):
                    secret = value.get_secret_value()
                    data = secret.encode("utf-8") if isinstance(secret, str) else secret
                    secret_digests[name] = hashlib.sha256(data).hexdigest()
            wire = json.dumps(
                {
                    "config": model.model_dump(mode="json"),
                    "identifying": model._identifying_params,
                    "clients": clients,
                    "methods": methods,
                    "callbacks_identity": id(model.callbacks),
                    "secrets": secret_digests,
                },
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            return hashlib.sha256(wire.encode("utf-8")).hexdigest()
        except Exception:
            raise NativeRuntimeError("native_model_configuration_invalid") from None

    def _assert_binding(self) -> None:
        self._assert_model_configuration()
        binding = self._bound_model
        if (
            type(binding) not in (RunnableBinding, self._sdk_binding_type)
            or binding.bound is not self._model
            or binding.config
            or binding.config_factories
            or binding.custom_input_type is not None
            or binding.custom_output_type is not None
            or set(binding.kwargs) != {"tools", "parallel_tool_calls"}
            or binding.kwargs["parallel_tool_calls"] is not False
            or _json(binding.kwargs["tools"])
            != _json([convert_to_openai_tool(spec.tool) for spec in self._tools])
        ):
            raise NativeRuntimeError("native_model_binding_invalid")

    def _assert_current(self) -> None:
        if self._closed:
            raise NativeRuntimeError("native_runtime_closed")
        _require_complete_product_composition(self)
        if native_tool_inventory_digest(self._tools) != self._inventory_digest:
            raise NativeRuntimeError("native_inventory_drift")
        self._assert_binding()

    def invoke(
        self,
        *,
        sources: list[dict[str, Any]],
        security: dict[str, Any],
        trace_id: str | None = None,
    ) -> NativeRunResult:
        self._assert_current()
        if not self._lock.acquire(blocking=False):
            raise NativeRuntimeError("native_runtime_busy")
        try:
            self._assert_current()
            trace = trace_id if trace_id is not None else "tr_" + uuid4().hex
            if type(trace) is not str or not _IDENTITY.fullmatch(trace):
                raise NativeRuntimeError("native_trace_invalid")
            if type(sources) is not list or not sources or type(security) is not dict:
                raise NativeRuntimeError("native_input_invalid")
            state: _State = {
                "history": _copy(sources),
                "outputs": [],
                "messages": [],
                "security": _copy(security),
                "tool_security": {},
                "model_origin": None,
                "trace_id": trace,
                "model_calls": 0,
                "tool_invocations": 0,
                "seen_call_ids": [],
                "blocked": False,
                "error_code": None,
            }
            # No external callbacks, streaming, checkpoint, parent interrupts,
            # or caller-supplied RunnableConfig cross this entrypoint.
            assert self._composition is not None
            with self._composition.run(), tracing_context(enabled=False):
                final = self._compiled.invoke(
                    state,
                    config={
                        "max_concurrency": 1,
                        "recursion_limit": self._max_model_calls * 2 + 2,
                        "callbacks": [],
                    },
                )
            return NativeRunResult(
                trace_id=trace,
                blocked=final["blocked"],
                model_calls=final["model_calls"],
                tool_invocations=final["tool_invocations"],
                inventory_digest=self._inventory_digest,
                error_code=final["error_code"],
                _messages_json=_json(final["outputs"]),
            )
        except (NativeRuntimeError, ProductActivationError):
            raise
        except Exception:
            raise NativeRuntimeError("native_runtime_failed") from None
        finally:
            self._lock.release()

    def start(self) -> ActivationAckV1:
        """Verify the complete candidate and acquire this graph's ACK session."""
        if (
            self._closed
            or type(self._composition) is not ProductComposition
            or self._composition.graph() is not self
        ):
            raise ProductActivationError("product_execution_unavailable")
        return self._composition.start()

    def snapshot(self) -> dict[str, Any]:
        """Return bounded state without credentials, sources or provider config."""
        self._assert_current()
        assert self._composition is not None
        ack = self._adapter._product_client().snapshot_product_ack()
        return {
            "ready": True,
            "runtime": "langgraph",
            "inventory_digest": self._inventory_digest,
            "ack_expires_at": ack.expires_at,
        }

    def close(self) -> None:
        """Revoke invocation/session ownership; retain historical delivery transport."""
        self._closed = True
        if (
            type(self._composition) is ProductComposition
            and self._composition.graph() is self
        ):
            self._composition.close()

    def _model_step(self, state: _State) -> dict[str, Any]:
        self._assert_current()
        if state["model_calls"] >= self._max_model_calls:
            return {"blocked": True, "error_code": "native_model_limit"}
        invocations = 0

        def invoke_model(messages: list[dict[str, Any]]) -> Any:
            nonlocal invocations
            if invocations:
                raise NativeRuntimeError("native_model_already_invoked")
            self._assert_current()
            invocations += 1
            return self._bound_model.invoke(
                convert_to_messages(_copy(messages)),
                config={"callbacks": [], "max_concurrency": 1},
            )

        request = dict(
            sources=_copy(state["history"]),
            security=_copy(state["security"]),
            trace_id=state["trace_id"],
            model_call_id="model_" + uuid4().hex,
            provider=self._provider,
            model=self._model_name,
            tool_descriptors=_copy(self._bound_model.kwargs["tools"]),
        )
        assert self._composition is not None
        with self._composition.invocation(
            self._model_boundary,
            invoke_model,
            invocation_subject(request),
            _normalize_model_output,
        ) as permit:
            result = self._model_boundary.invoke(
                **request,
                invoke_model=invoke_model,
                normalize_output=_normalize_model_output,
                _permit=permit,
            )
        self._assert_current()
        update: dict[str, Any] = {"model_calls": state["model_calls"] + invocations}
        if (
            result.blocked
            or result.output is None
            or result.delivery is None
            or result.delivery.status != "recorded"
            or result.invocation_status != "executed"
        ):
            update.update(
                blocked=True,
                error_code=result.error_code or "native_model_boundary_blocked",
            )
            return update
        mapping = result.output.to_mapping()
        # Validate the post-checkpoint projection again before constructing an
        # executable ToolNode message; no model-owned object enters state.
        normalized = _normalize_model_output(AIMessage(**mapping)).to_mapping()
        calls = normalized["tool_calls"]
        if calls and (
            calls[0]["id"] in state["seen_call_ids"]
            or calls[0]["name"] not in self._specs
            or not result.output_source_ref
            or not result.output_policy_audit_id
        ):
            update.update(blocked=True, error_code="native_tool_call_rejected")
            return update
        output = {
            "role": "assistant",
            **normalized,
            "source_type": "model",
            "source_trust": "untrusted",
        }
        # Invalid calls are already rejected, and empty lists carry no message
        # semantics. Keep the context source allowlist small.
        output.pop("invalid_tool_calls")
        origin = None
        if calls:
            output_audit_id = result.output_policy_audit_id
            output_source = result.output_source_ref
            if output_audit_id is None or output_source is None:
                raise NativeRuntimeError("native_model_origin_invalid")
            origin = NativeModelOrigin(output_audit_id, output_source, calls[0]["id"])
        update.update(
            tool_security={
                **_copy(state["security"]),
                "source_type": "model",
                "source_trust": "unknown",
                "visible_source_refs": list(
                    dict.fromkeys(
                        ([result.output_source_ref] if calls else [])
                        + list(result.visible_source_refs)
                    )
                ),
            },
            model_origin=origin,
            # Opaque model reasoning is never retained as next-round context.
            # The approved call remains private to the real ToolNode; only a
            # final answer without calls is returned through the public facade.
            outputs=[] if calls else [_copy(output)],
            messages=[AIMessage(**normalized)],
            seen_call_ids=[*state["seen_call_ids"], *[call["id"] for call in calls]],
        )
        return update

    @staticmethod
    def _after_model(state: _State) -> str:
        if state["blocked"] or not state["messages"]:
            return "end"
        return "tools" if state["messages"][-1].tool_calls else "end"

    def _wrap_tool_call(
        self,
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], Any],
    ) -> ToolMessage:
        self._assert_current()
        call = _copy(request.tool_call)
        spec = self._specs.get(call["name"])
        if spec is None or request.tool is not spec.tool:
            raise NativeRuntimeError("native_tool_call_rejected")
        prepared = prepare_native_tool_call(spec, call["id"], call["args"])
        origin = request.state.get("model_origin")
        if type(origin) is not NativeModelOrigin or origin.call_id != prepared.call_id:
            raise NativeRuntimeError("native_model_origin_invalid")
        source_type = "tool_result"
        source_id = None
        if prepared.category == "memory" and prepared.operation == "read":
            resource = prepared.resources()[0]["target"]
            namespace, key = resource.rsplit("/", 1)
            if key != prepared.arguments()["key"]:
                raise NativeRuntimeError("native_memory_source_invalid")

            def escape(segment: str) -> str:
                return segment.replace("\\", "\\\\").replace("/", "\\/")

            source_type = "memory"
            source_id = f"memory://{escape(namespace)}/{escape(key)}"
        invoked = False

        def invoke_once() -> Any:
            nonlocal invoked
            if invoked:
                raise NativeRuntimeError("native_tool_already_invoked")
            self._assert_current()
            prepared.assert_current()
            invoked = True
            response = execute(
                request.override(
                    tool_call={
                        "name": prepared.name,
                        "id": prepared.call_id,
                        "args": prepared.arguments(),
                        "type": "tool_call",
                    }
                )
            )
            if (
                type(response) is not ToolMessage
                or response.tool_call_id != prepared.call_id
                or response.name != prepared.name
                or response.artifact is not None
                or response.additional_kwargs
                or response.model_extra
                or response.status != "success"
            ):
                raise NativeRuntimeError("native_tool_output_invalid")
            return _copy(response.content)

        security = _copy(request.state["tool_security"])
        trace = request.state["trace_id"]
        assert self._composition is not None
        with self._composition.invocation(
            self._executor, invoke_once, tool_subject(prepared, security, trace, origin)
        ) as permit:
            result = self._executor.execute_action(
                prepared,
                security=security,
                trace_id=trace,
                invoke_once=invoke_once,
                model_origin=origin,
                _permit=permit,
            )
        self._assert_current()
        blocked = bool(
            result.blocked
            or result.runtime_receipt_status != "recorded"
            or not result.executed
            or not invoked
            or result.result is None
        )
        return ToolMessage(
            content="" if blocked else _copy(result.result),
            name=prepared.name,
            tool_call_id=prepared.call_id,
            additional_kwargs={
                "agentguard": {
                    "blocked": blocked,
                    "invoked": invoked,
                    "source_type": source_type,
                    "source_id": source_id,
                }
            },
        )

    def _tool_step(self, state: _State, config: RunnableConfig) -> dict[str, Any]:
        self._assert_current()
        if (
            len(state["messages"]) != 1
            or type(state["messages"][0]) is not AIMessage
            or len(state["messages"][0].tool_calls) != 1
        ):
            raise NativeRuntimeError("native_tool_calls_invalid")
        # Preserve the real graph-injected ToolRuntime. The outer facade owns
        # this config and has already disabled retries/parallelism/checkpoints.
        result = self._tool_node.invoke(state, config=config)
        if type(result) is not dict or set(result) != {"messages"}:
            raise NativeRuntimeError("native_tool_output_invalid")
        messages = result["messages"]
        if len(messages) != 1 or type(messages[0]) is not ToolMessage:
            raise NativeRuntimeError("native_tool_output_invalid")
        message = messages[0]
        gate = message.additional_kwargs["agentguard"]
        update: dict[str, Any] = {
            "tool_invocations": state["tool_invocations"] + int(gate["invoked"]),
        }
        if gate["blocked"]:
            update.update(blocked=True, error_code="native_tool_boundary_blocked")
            return update
        evidence = {
            # This is an evidence carrier, not authenticated user provenance.
            # Context Builder still annotates/isolates its untrusted source;
            # the full model input is evaluated again before every invocation.
            "role": "user",
            "content": (
                _copy(message.content)
                if gate["source_type"] == "memory"
                else _json(
                    {
                        "kind": "tool_result_evidence",
                        "tool_name": message.name,
                        "call_id": message.tool_call_id,
                        "content": _copy(message.content),
                    }
                )
            ),
            "source_type": gate["source_type"],
            "source_trust": "untrusted",
        }
        if gate["source_id"] is not None:
            evidence["source_id"] = gate["source_id"]
        update.update(
            history=[*state["history"], evidence],
            messages=[],
        )
        return update


def build_native_product_graph(
    *,
    adapter: Any,
    model: BaseChatModel,
    tools: tuple[NativeToolSpec, ...],
    provider: str,
    model_name: str,
    max_model_calls: int = 16,
) -> NativeProductGraph:
    """Build a closed native topology; call start() to verify explicit admission."""
    graph = NativeProductGraph(
        adapter=adapter,
        model=model,
        tools=tools,
        provider=provider,
        model_name=model_name,
        max_model_calls=max_model_calls,
    )

    graph._composition = _create_composition(graph)
    return graph
