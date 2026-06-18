"""AttackBench datasets, runners, mock tools, and metrics."""

from __future__ import annotations

from typing import Any

__all__ = [
    "BenchConfig",
    "MockToolRegistry",
    "calculate_metrics",
    "load_attack_cases",
    "run_cases",
    "success_for_case",
    "write_results",
]


def __getattr__(name: str) -> Any:
    if name == "BenchConfig":
        from .config import BenchConfig

        return BenchConfig
    if name == "load_attack_cases":
        from .dataset_loader import load_attack_cases

        return load_attack_cases
    if name == "calculate_metrics":
        from .metrics import calculate_metrics

        return calculate_metrics
    if name == "MockToolRegistry":
        from .tools import MockToolRegistry

        return MockToolRegistry
    if name in {"run_cases", "success_for_case", "write_results"}:
        from .runner import run_cases, success_for_case, write_results

        return {"run_cases": run_cases, "success_for_case": success_for_case, "write_results": write_results}[name]
    raise AttributeError(name)
