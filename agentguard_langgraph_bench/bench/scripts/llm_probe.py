"""Minimal LLM connectivity and prompt-size probe for benchmark planning."""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

from langchain_core.tools import tool

from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.demo_agent.graph import (
    _build_llm,
    _invoke_llm_with_diagnostics,
)


def _probe_case() -> AttackCase:
    return AttackCase.model_validate(
        {
            "case_id": "LLM-PROBE",
            "attack_type": "benign",
            "is_malicious": False,
            "runtime_targets": ["langgraph"],
            "input": {"source_type": "probe", "source_trust": "trusted", "payload": "LLM probe"},
            "target_behavior": {"tool": "call_api", "operation": "probe", "resource": "llm"},
            "expected_decision": "allow",
            "success_condition": {"type": "tool_executed", "tool": "call_api", "resource": "llm"},
        }
    )


@tool
def echo(value: str) -> str:
    """Return the provided value without side effects."""

    return value


def _run_once(llm: Any, messages: list[tuple[str, str]], *, config: BenchConfig, name: str, tool_calling: bool) -> dict[str, Any]:
    case = _probe_case()
    bound = llm.bind_tools([echo]) if tool_calling else llm
    started = time.monotonic()
    try:
        message, diagnostics = _invoke_llm_with_diagnostics(
            bound,
            messages,
            case=case,
            round_index=1,
            config=config,
            tool_schema_count=1 if tool_calling else 0,
            observation_count=0,
        )
        return {
            "name": name,
            "success": True,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "outcome": diagnostics.get("outcome"),
            "prompt_chars": diagnostics.get("prompt_chars"),
            "tool_call_count": len(getattr(message, "tool_calls", None) or []),
        }
    except Exception as exc:
        diagnostics = getattr(exc, "diagnostics", {}) if hasattr(exc, "diagnostics") else {}
        return {
            "name": name,
            "success": False,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "outcome": diagnostics.get("outcome") or "unknown_error",
            "error_type": diagnostics.get("error_type") or type(exc).__name__,
            "root_error_type": diagnostics.get("root_error_type"),
            "error_message": diagnostics.get("error_message") or str(exc)[:1000],
            "prompt_chars": diagnostics.get("prompt_chars"),
            "http_status": diagnostics.get("http_status"),
        }


def run_probe(config: BenchConfig, *, runs: int) -> dict[str, Any]:
    llm = _build_llm(config)
    tests: list[dict[str, Any]] = []
    scenarios = [
        ("short_text", [("system", "Reply briefly."), ("user", "Reply with exactly OK.")], False),
        ("tool_calling", [("system", "Use the bound echo tool."), ("user", "Call echo with value OK.")], True),
        ("prompt_4kb", [("system", "Reply briefly."), ("user", "A" * 4096)], False),
        ("prompt_16kb", [("system", "Reply briefly."), ("user", "B" * 16384)], False),
        ("prompt_32kb", [("system", "Reply briefly."), ("user", "C" * 32768)], False),
    ]
    for run_index in range(1, max(1, runs) + 1):
        for name, messages, tool_calling in scenarios:
            item = _run_once(llm, messages, config=config, name=name, tool_calling=tool_calling)
            item["run_index"] = run_index
            tests.append(item)
    return {
        "provider": config.llm_provider,
        "model": config.llm_model,
        "request_timeout": config.llm_request_timeout,
        "max_retries": config.llm_max_retries,
        "runs": runs,
        "tests": tests,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe configured AgentGuard benchmark LLM endpoint")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--request-timeout", type=float, default=None)
    parser.add_argument("--max-retries", type=int, default=None)
    parser.add_argument("--runs", type=int, default=3)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = BenchConfig.from_values(
        llm_enabled=True,
        llm_provider=args.provider,
        llm_model=args.model,
        llm_base_url=args.base_url,
        llm_api_key=args.api_key,
        llm_request_timeout=args.request_timeout,
        llm_max_retries=args.max_retries,
    )
    print(json.dumps(run_probe(config, runs=args.runs), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
