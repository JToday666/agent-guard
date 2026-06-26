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
    DecisionEffect,
    DecisionEnforcement,
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
from .p2 import (
    ActionCritic,
    ActionCriticReview,
    AuditIntegrityMetadata,
    ConfigAuditEvent,
    ConfigAuditFinding,
    ConfigAuditResult,
    MemoryGuardChange,
    ProvenanceEdge,
    ProvenanceNode,
    evaluate_config_audit,
)
from .policies import PolicyBundle, RuleOverride, ToolProfile, default_tool_profiles

__all__ = [
    "ActionCritic",
    "ActionCriticReview",
    "ApprovalIntent",
    "ApprovalResolution",
    "AuditEvent",
    "AuditIntegrityMetadata",
    "ConfigAuditEvent",
    "ConfigAuditFinding",
    "ConfigAuditResult",
    "ContextBuildPayload",
    "ContextSource",
    "Decision",
    "DecisionEffect",
    "DecisionEnforcement",
    "DerivedResource",
    "GuardDecision",
    "GuardEvent",
    "GuardEventType",
    "GuardPayload",
    "MemoryEventPayload",
    "MemoryGuardChange",
    "MemoryRecord",
    "MessageSendPayload",
    "ModelCallPayload",
    "PolicyBundle",
    "ProvenanceEdge",
    "ProvenanceNode",
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
    "evaluate_config_audit",
    "guard_event_raw_payload_contracts",
    "new_id",
    "utc_now_iso",
]
