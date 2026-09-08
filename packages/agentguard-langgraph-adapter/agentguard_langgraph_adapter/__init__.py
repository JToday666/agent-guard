"""AgentGuard adapter layer for LangGraph runtimes."""

from __future__ import annotations

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
]
