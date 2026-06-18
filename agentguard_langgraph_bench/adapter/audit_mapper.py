"""AuditEvent mapping helpers for the LangGraph adapter layer."""

from __future__ import annotations

from .event_models import AuditEvent, PolicyDecision, ToolCallEvent
from .langgraph_adapter import LangGraphAdapter


def build_audit_event(adapter: LangGraphAdapter, event: ToolCallEvent, decision: PolicyDecision) -> AuditEvent:
    return adapter.build_audit_event(event, decision)


__all__ = ["build_audit_event"]
