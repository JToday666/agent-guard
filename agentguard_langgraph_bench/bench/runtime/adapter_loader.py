"""Load pluggable benchmark agent adapters."""

from __future__ import annotations

import importlib
from typing import Any

from .agent_protocol import AgentAdapterProtocol


def load_agent_adapter(config: Any) -> AgentAdapterProtocol:
    name = getattr(config, "agent_adapter", "langgraph-demo")

    if name == "langgraph-demo":
        from agentguard_langgraph_bench.adapters.langgraph_demo.adapter import create_adapter

        return create_adapter(config)
    if name == "openclaw":
        from agentguard_langgraph_bench.adapters.openclaw.adapter import create_adapter

        return create_adapter(config)
    if name == "http":
        from agentguard_langgraph_bench.adapters.http_agent.adapter import create_adapter

        return create_adapter(config)
    if name in {"subprocess", "standalone-langgraph-subprocess"}:
        from agentguard_langgraph_bench.adapters.subprocess_agent.adapter import create_adapter

        return create_adapter(config)
    if name == "claude-code":
        from agentguard_langgraph_bench.adapters.claude_code.adapter import create_adapter

        return create_adapter(config)
    if name == "python":
        return load_python_entrypoint(getattr(config, "adapter_entrypoint", ""), config)

    raise ValueError(f"Unknown agent adapter: {name}")


def load_python_entrypoint(entrypoint: str, config: Any) -> AgentAdapterProtocol:
    if not entrypoint or ":" not in entrypoint:
        raise ValueError("--adapter-entrypoint must be module:function")
    module_name, factory_name = entrypoint.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name)
    return factory(config)
