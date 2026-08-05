"""Stable public facade for AgentGuard Core."""

from agentguard_core import (
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    evaluate,
)

from ._version import __version__

__all__ = [
    "__version__",
    "GuardDecision",
    "GuardEngine",
    "GuardEvent",
    "PolicyBundle",
    "evaluate",
]
