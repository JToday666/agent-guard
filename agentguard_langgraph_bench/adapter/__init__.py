"""Compatibility exports for the standalone AgentGuard LangGraph adapter SDK."""

from __future__ import annotations

import sys
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parents[2] / "packages" / "agentguard-langgraph-adapter"
_SDK_ROOT_TEXT = str(_SDK_ROOT)
if _SDK_ROOT.exists() and _SDK_ROOT_TEXT not in sys.path:
    sys.path.insert(0, _SDK_ROOT_TEXT)

from agentguard_langgraph_adapter import (  # noqa: E402
    AgentGuardCoreClient,
    AgentGuardLangGraphConfig,
    AuditEvent,
    CoreClientError,
    CoreClientProtocol,
    FakeAllowCoreClient,
    FakeAskCoreClient,
    FakeDenyCoreClient,
    GuardedToolNode,
    LangGraphAdapter,
    PolicyDecision,
    SecureToolNode,
    ToolCallEvent,
    ToolExecutionResult,
    blocked_result,
    create_guarded_tool_node,
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
    "LangGraphAdapter",
    "PolicyDecision",
    "SecureToolNode",
    "ToolCallEvent",
    "ToolExecutionResult",
    "blocked_result",
    "create_guarded_tool_node",
]
