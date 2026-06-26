"""Compatibility facade for event resource derivation helpers."""

from __future__ import annotations

from .events.resources import derive_resources, tool_argument_text

__all__ = ["derive_resources", "tool_argument_text"]
