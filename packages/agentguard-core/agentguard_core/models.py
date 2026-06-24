"""Compatibility facade for AgentGuard Core domain models.

New code should import from ``agentguard_core.events``,
``agentguard_core.decisions``, or ``agentguard_core.policies``. This module
keeps the pre-package public import path stable for existing callers.
"""

from __future__ import annotations

from .decisions import (
    ApprovalIntent,
    ApprovalResolution,
    AuditEvent,
    Decision,
    GuardDecision,
    RuleHit,
    RuleOverrideDecision,
)
from .events import (
    ContextBuildPayload,
    ContextSource,
    DerivedResource,
    GuardEvent,
    GuardEventType,
    GuardPayload,
    MemoryEventPayload,
    MemoryRecord,
    MessageSendPayload,
    ModelCallPayload,
    RawPayloadContract,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    ToolResult,
    ToolResultPayload,
    guard_event_raw_payload_contracts,
)
from .ids import new_id, utc_now_iso
from .policies import PolicyBundle, RuleOverride, ToolProfile, default_tool_profiles

__all__ = [
    "ApprovalIntent",
    "ApprovalResolution",
    "AuditEvent",
    "ContextBuildPayload",
    "ContextSource",
    "Decision",
    "DerivedResource",
    "GuardDecision",
    "GuardEvent",
    "GuardEventType",
    "GuardPayload",
    "MemoryEventPayload",
    "MemoryRecord",
    "MessageSendPayload",
    "ModelCallPayload",
    "PolicyBundle",
    "RawPayloadContract",
    "RuleHit",
    "RuleOverride",
    "RuleOverrideDecision",
    "SecurityContext",
    "ToolCallPayload",
    "ToolDescriptor",
    "ToolProfile",
    "ToolResult",
    "ToolResultPayload",
    "default_tool_profiles",
    "guard_event_raw_payload_contracts",
    "new_id",
    "utc_now_iso",
]
