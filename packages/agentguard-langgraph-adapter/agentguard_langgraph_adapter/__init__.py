"""AgentGuard adapter layer for LangGraph runtimes."""

from __future__ import annotations

from .config import AgentGuardLangGraphConfig
from .core_client import (
    AgentGuardCoreClient,
    CoreClientError,
    CoreClientProtocol,
    FakeAllowCoreClient,
    FakeAskCoreClient,
    FakeDenyCoreClient,
)
from .event_models import (
    AuditEvent,
    PolicyDecision,
    RuntimeGuardEvent,
    ToolCallEvent,
    ToolExecutionResult,
)
from .langgraph_adapter import (
    LangGraphAdapter,
    blocked_result,
    create_guarded_tool_node,
)
from .secure_tool_node import GuardedToolNode, SecureToolNode
from .tool_gateway import GuardedToolGateway
from .tool_compat import (
    BROWSER_TOOLS,
    ToolCompatibilityLayer,
    ToolCompatibilityResult,
    blocked_runtime_policy_result,
    tool_result_with_compatibility,
)

__all__ = [
    "AgentGuardCoreClient",
    "AgentGuardLangGraphConfig",
    "AuditEvent",
    "CoreClientError",
    "CoreClientProtocol",
    "FakeAllowCoreClient",
    "FakeAskCoreClient",
    "FakeDenyCoreClient",
    "GuardedToolNode",
    "GuardedToolGateway",
    "LangGraphAdapter",
    "PolicyDecision",
    "RuntimeGuardEvent",
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
]
