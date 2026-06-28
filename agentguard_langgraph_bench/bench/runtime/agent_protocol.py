"""Protocols shared by benchmark runner and pluggable agent adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from agentguard_langgraph_bench.bench.models import AttackCase


@dataclass(slots=True)
class CaseContext:
    case: AttackCase
    trace_id: str
    runtime: str
    adapter_name: str
    sandbox_dir: Path
    results_dir: Path
    security: dict[str, Any]
    tool_gateway: Any
    tool_runtime: Any
    config: Any
    tool_server: Any = None
    tool_hijacking_context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CaseRunResult:
    case_id: str
    trace_id: str
    runtime: str
    adapter_name: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    behavior_events: list[dict[str, Any]] = field(default_factory=list)
    final_answer: str = ""
    blocked: bool = False
    executed: bool = False
    side_effects: list[dict[str, Any]] = field(default_factory=list)
    raw_state: dict[str, Any] = field(default_factory=dict)
    raw_logs: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


class AgentAdapterProtocol(Protocol):
    name: str
    runtime: str

    def setup(self, context: dict[str, Any]) -> None:
        ...

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        ...

    def teardown(self) -> None:
        ...
