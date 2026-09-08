"""AgentGuard adapter layer for LangGraph runtimes."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .native_langgraph import (
        NativeProductGraph,
        NativeRunResult,
        NativeRuntimeError,
        build_native_product_graph,
    )
    from .native_tools import (
        NativeToolSpec,
        PreparedNativeToolCall,
        close_isolated_product_tools,
        create_isolated_product_tools,
        native_tool_descriptor,
        native_tool_inventory_digest,
        prepare_native_tool_call,
    )

from .activation_ack import ActivationAckV1, ProductActivationError
from .activation_session import ProductActivationSession
from .product_manifest import ProductActivationManifest, ProductRuntimeObservation
from .product_delivery import (
    ProductReceiptDeliveryResult,
    ProductReceiptTransportResult,
)
from .product_outbox import ProductReceiptOutbox, ProductOutboxStatus
from .product_action_barrier import (
    ProductActionBarrier,
    ProductActionTicket,
    BeginActionResult,
)
from .config import AgentGuardLangGraphConfig
from .context_guard import (
    ContextPlanValidationError,
    PreparedContext,
    REFERENCE_RUNTIME_FACT,
    context_content_digest,
    context_plan_digest,
    validate_and_prepare_context,
)
from .core_client import (
    AgentGuardCoreClient,
    CoreClientError,
    CoreClientProtocol,
    FakeAllowCoreClient,
    FakeAskCoreClient,
    FakeDenyCoreClient,
    UnsupportedApiModeError,
)
from .event_models import (
    AuditEvent,
    PolicyDecision,
    RuntimeGuardEvent,
    RuntimeOutcomeReceipt,
    ToolCallEvent,
    ToolExecutionResult,
)
from .langgraph_adapter import (
    LangGraphAdapter,
    blocked_result,
    create_guarded_tool_node,
)
from .secure_tool_node import GuardedToolNode, SecureToolNode
from .runtime_receipts import (
    ReceiptSubmissionResult,
    build_runtime_outcome,
    build_tool_started_observation,
    build_trace_lifecycle_observation,
    runtime_receipts_enabled,
    runtime_receipts_required,
    runtime_receipt_preflight_error,
    submit_runtime_receipt,
    submit_runtime_receipt_result,
)
from .tool_gateway import GuardedToolGateway
from .tool_compat import (
    BROWSER_TOOLS,
    ToolCompatibilityLayer,
    ToolCompatibilityResult,
    blocked_runtime_policy_result,
    tool_result_with_compatibility,
)

__all__ = [
    "ActivationAckV1",
    "ProductActivationError",
    "ProductActivationSession",
    "ProductActivationManifest",
    "ProductRuntimeObservation",
    "ProductReceiptDeliveryResult",
    "ProductReceiptTransportResult",
    "ProductReceiptOutbox",
    "ProductOutboxStatus",
    "ProductActionBarrier",
    "ProductActionTicket",
    "BeginActionResult",
    "AgentGuardCoreClient",
    "AgentGuardLangGraphConfig",
    "ContextPlanValidationError",
    "PreparedContext",
    "REFERENCE_RUNTIME_FACT",
    "AuditEvent",
    "CoreClientError",
    "CoreClientProtocol",
    "FakeAllowCoreClient",
    "FakeAskCoreClient",
    "FakeDenyCoreClient",
    "UnsupportedApiModeError",
    "GuardedToolNode",
    "GuardedToolGateway",
    "LangGraphAdapter",
    "PolicyDecision",
    "RuntimeGuardEvent",
    "RuntimeOutcomeReceipt",
    "ReceiptSubmissionResult",
    "build_runtime_outcome",
    "build_tool_started_observation",
    "build_trace_lifecycle_observation",
    "runtime_receipts_enabled",
    "runtime_receipts_required",
    "runtime_receipt_preflight_error",
    "submit_runtime_receipt",
    "submit_runtime_receipt_result",
    "SecureToolNode",
    "ToolCallEvent",
    "ToolExecutionResult",
    "BROWSER_TOOLS",
    "blocked_result",
    "blocked_runtime_policy_result",
    "ToolCompatibilityLayer",
    "ToolCompatibilityResult",
    "tool_result_with_compatibility",
    "create_guarded_tool_node",
    "context_content_digest",
    "context_plan_digest",
    "validate_and_prepare_context",
    "NativeProductGraph",
    "NativeRunResult",
    "NativeRuntimeError",
    "build_native_product_graph",
    "NativeToolSpec",
    "PreparedNativeToolCall",
    "close_isolated_product_tools",
    "create_isolated_product_tools",
    "native_tool_descriptor",
    "native_tool_inventory_digest",
    "prepare_native_tool_call",
]


_NATIVE_EXPORTS = {
    **dict.fromkeys(
        (
            "NativeProductGraph",
            "NativeRunResult",
            "NativeRuntimeError",
            "build_native_product_graph",
        ),
        ".native_langgraph",
    ),
    **dict.fromkeys(
        (
            "NativeToolSpec",
            "PreparedNativeToolCall",
            "close_isolated_product_tools",
            "create_isolated_product_tools",
            "native_tool_descriptor",
            "native_tool_inventory_digest",
            "prepare_native_tool_call",
        ),
        ".native_tools",
    ),
}


def __getattr__(name: str) -> Any:
    module = _NATIVE_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        value = getattr(import_module(module, __name__), name)
    except ModuleNotFoundError as error:
        if (error.name or "").split(".")[0] in {
            "langgraph",
            "langchain_core",
            "langsmith",
        }:
            raise ImportError(
                "Native LangGraph requires agentguard-langgraph-adapter[native]."
            ) from None
        raise
    globals()[name] = value
    return value
