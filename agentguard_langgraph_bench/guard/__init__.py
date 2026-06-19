"""General guard compatibility layer."""

from .config import GuardConfig
from .guard_adapter import GuardAdapter

__all__ = ["GuardAdapter", "GuardConfig"]
