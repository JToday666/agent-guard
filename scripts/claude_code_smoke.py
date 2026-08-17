"""Run the five-case Claude Code + Qwen local smoke benchmark."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agentguard_langgraph_bench.bench.claude_code_report import build_compact_report, write_compact_report
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.runner import run_cases
from agentguard_langgraph_bench.bench.runtime.adapter_loader import load_agent_adapter


CASE_IDS = ("BN-007", "BN-010", "PI-001", "FE-001", "CC-VISION-001")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Claude Code AttackBench smoke baseline")
    parser.add_argument("--model", default=os.getenv("ANTHROPIC_MODEL", "qwen3.7-plus"))
    parser.add_argument("--report-dir", default="reports/claude-code-baseline")
    parser.add_argument("--browser-engine", choices=("chromium", "firefox", "webkit"), default="chromium")
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AGENTGUARD_CLAUDE_CODE_TIMEOUT", "600")))
    parser.add_argument("--retain-artifacts", action="store_true")
    parser.add_argument("--case-id", action="append", choices=CASE_IDS, default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    selected_ids = tuple(args.case_id) if args.case_id else CASE_IDS
    canonical = load_attack_cases(root / "agentguard_langgraph_bench" / "bench" / "datasets" / "attack_cases")
    visual = load_attack_cases(root / "agentguard_langgraph_bench" / "bench" / "datasets" / "claude_code_smoke" / "cases.jsonl")
    by_id = {case.case_id: case for case in [*canonical, *visual]}
    cases = [by_id[case_id] for case_id in selected_ids]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    temp_root = Path(tempfile.mkdtemp(prefix="claude-code-smoke-"))
    sandbox_dir = temp_root / "sandbox"
    raw_results_dir = temp_root / "raw-results"
    config = BenchConfig(
        defense_enabled=False,
        runtime="claude-code",
        agent_adapter="claude-code",
        sandbox_dir=sandbox_dir,
        results_dir=raw_results_dir,
        browser_mode="real",
        browser_engine=args.browser_engine,
        tool_server_mode="http",
        tool_server_host="127.0.0.1",
        tool_server_port=0,
        max_wall_clock_seconds=args.timeout,
        claude_code_retain_artifacts=args.retain_artifacts,
        claude_code_model=args.model,
    )
    config.adapter_config = str(root / "benchmarks" / "claude-code-mcp-bridge" / "dist" / "index.js")
    adapter = load_agent_adapter(config)
    try:
        rows = run_cases(
            cases,
            config=config,
            agent_adapter=adapter,
            reset_environment=True,
            benchmark_run_id=run_id,
            run_metadata={
                "report_version": "claude_code_smoke/v1",
                "source_runtime_target": "langgraph",
                "runtime_target_override": "claude-code",
                "case_ids": list(selected_ids),
            },
        )
        report = build_compact_report(
            rows,
            run_id=run_id,
            model=args.model,
            provider="qwen",
            source_runtime_target="langgraph",
            runtime_target_override="claude-code",
        )
        output_dir = Path(args.report_dir).expanduser().resolve() / run_id
        paths = write_compact_report(report, output_dir)
        print({"run_id": run_id, "outputs": paths, "case_count": len(rows), "valid_run_rate": report["valid_run_rate"]})
        return 0 if report["valid_run_rate"] == 1 else 2
    finally:
        if not args.retain_artifacts:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
