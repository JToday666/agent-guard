"""Tool manifest generation for OpenClaw-style external agents."""

from __future__ import annotations

from typing import Any


def build_tool_manifest(tool_runtime: Any, base_url: str) -> dict[str, Any]:
    tools = []
    for item in tool_runtime.list_tools().values():
        payload = dict(item)
        payload["endpoint"] = f"{base_url.rstrip('/')}/tools/{payload['name']}"
        tools.append(payload)
    return {"tools": tools}
