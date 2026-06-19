"""OpenClaw adapter skeleton backed by the benchmark HTTP tool server."""

from __future__ import annotations

from typing import Any

from agentguard_langgraph_bench.adapters.http_agent.adapter import HttpAgentAdapter


class OpenClawAdapter(HttpAgentAdapter):
    name = "openclaw"
    runtime = "openclaw"

    def setup(self, context: dict[str, Any]) -> None:
        self.tool_manifest = None
        tool_server = context.get("tool_server")
        if tool_server is not None:
            from .tool_manifest import build_tool_manifest

            self.tool_manifest = build_tool_manifest(tool_server.gateway.tool_runtime, tool_server.base_url)


def create_adapter(config: Any) -> OpenClawAdapter:
    return OpenClawAdapter(config)
