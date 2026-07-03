"""Static preflight checks for expensive autonomous benchmark runs."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard_langgraph_bench.adapters.metadata import (
    forbidden_agent_visible_metadata_keys,
    safe_agent_metadata,
)

from .config import BENCH_ROOT, DEFAULT_DATASET_DIR, DEFAULT_SANDBOX_DIR, REPO_ROOT, ensure_sandbox
from .dataset_loader import load_attack_cases


FORBIDDEN_AGENT_VISIBLE_MARKERS = (
    "attack_success",
    "hidden goal",
    "red team",
)


@dataclass(slots=True)
class PreflightReport:
    ok: bool = True
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    checked: dict[str, Any] = field(default_factory=dict)

    def error(self, code: str, message: str, **extra: Any) -> None:
        self.ok = False
        self.errors.append({"code": code, "message": message, **extra})

    def warning(self, code: str, message: str, **extra: Any) -> None:
        self.warnings.append({"code": code, "message": message, **extra})

    def model_dump(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "checked": self.checked,
        }


def run_preflight(
    *,
    dataset: str | Path = DEFAULT_DATASET_DIR,
    sandbox_dir: str | Path = DEFAULT_SANDBOX_DIR,
    check_fixtures: bool = False,
    check_browser_artifacts: bool = False,
    check_tool_manifest: bool = False,
    check_langgraph_runtime: bool = False,
    check_real_browser_runtime: bool = False,
    browser_engine: str = "chromium",
    check_prompt_contamination: bool = True,
) -> PreflightReport:
    report = PreflightReport()
    sandbox_path = Path(sandbox_dir)
    cases = load_attack_cases(dataset)
    report.checked["case_count"] = len(cases)
    report.checked["dataset"] = str(dataset)
    report.checked["sandbox_dir"] = str(sandbox_path)

    if check_fixtures or check_tool_manifest or check_browser_artifacts:
        ensure_sandbox(sandbox_path)
    if check_fixtures:
        _check_fixture_paths(cases, sandbox_path, report)
    if check_browser_artifacts:
        _check_browser_sources(cases, report)
    if check_tool_manifest:
        _check_tool_catalogs(cases, sandbox_path, report)
    if check_langgraph_runtime:
        _check_langgraph_runtime(report)
    if check_real_browser_runtime:
        _check_real_browser_runtime(report, browser_engine=browser_engine)
    if check_prompt_contamination:
        _check_prompt_contamination(cases, report)
        _check_agent_visible_metadata(cases, report)
    return report


def _check_fixture_paths(cases: list[Any], sandbox_dir: Path, report: PreflightReport) -> None:
    checked = 0
    for case in cases:
        for path in _fixture_paths_for_case(case):
            checked += 1
            if _fixture_path_exists(path, sandbox_dir):
                continue
            report.error(
                "missing_fixture_path",
                f"{case.case_id} references missing fixture path {path}",
                case_id=case.case_id,
                path=path,
            )
    report.checked["fixture_path_references"] = checked


def _fixture_paths_for_case(case: Any) -> list[str]:
    paths: list[str] = []
    metadata = dict(getattr(case, "metadata", {}) or {})
    for item in metadata.get("fixture_files") or []:
        _append_path(paths, item)
    for item in metadata.get("real_benchmark_resources") or []:
        _append_path(paths, item)
    agent_files = metadata.get("agent_files") if isinstance(metadata.get("agent_files"), dict) else {}
    for item in agent_files.values():
        _append_path(paths, item)
    for step in getattr(case, "tool_plan", []) or []:
        if getattr(step, "tool", "") == "read_file":
            _append_path(paths, step.arguments.get("path") or step.arguments.get("file_path"))
    return list(dict.fromkeys(paths))


def _append_path(paths: list[str], value: Any) -> None:
    if not isinstance(value, str):
        return
    value = value.strip()
    if value:
        paths.append(value)


def _fixture_path_exists(path: str, sandbox_dir: Path) -> bool:
    if _is_local_service_url(path) or _is_side_effect_output_reference(path):
        return True
    normalized = _normalize_fixture_path(path)
    repo_candidate = _repo_relative_candidate(normalized)
    if repo_candidate is not None and repo_candidate.exists():
        return True
    if normalized.startswith("files/"):
        candidates = [sandbox_dir / normalized]
    elif normalized.startswith(("mcp/", "api/", "rag/", "memory/", "browser/", "web_state/", "outbox/")):
        candidates = [sandbox_dir / normalized]
    else:
        candidates = [sandbox_dir / "files" / normalized, sandbox_dir / normalized]
    return any(candidate.exists() for candidate in candidates) or _is_known_synthetic_fixture(path)


def _normalize_fixture_path(path: str) -> str:
    normalized = path.strip()
    if normalized.startswith("read_file:"):
        normalized = normalized.removeprefix("read_file:")
    return normalized.lstrip("/").removeprefix("sandbox/")


def _repo_relative_candidate(normalized: str) -> Path | None:
    if normalized.startswith("agentguard_langgraph_bench/"):
        return REPO_ROOT / normalized
    if normalized.startswith("datasets/"):
        return BENCH_ROOT / normalized
    if "Browser-art_" in normalized:
        marker_index = normalized.find("Browser-art_")
        return BENCH_ROOT / "datasets" / "instrumentation" / normalized[marker_index:]
    return None


def _is_local_service_url(path: str) -> bool:
    return path.startswith(("http://127.0.0.1:", "http://localhost:"))


def _is_side_effect_output_reference(path: str) -> bool:
    normalized = path.strip().lstrip("/").removeprefix("sandbox/")
    if not normalized:
        return False
    if normalized.startswith(("api/downloads/", "downloads/")):
        return True
    if normalized.endswith(".jsonl") and normalized.startswith(
        ("api/", "outbox/", "identity/", "social/", "ads/", "platform/", "browser/", "web_state/", "records/", "memory/", "rag/", "mcp/")
    ):
        return True
    return False


def _is_known_synthetic_fixture(path: str) -> bool:
    normalized = path.lstrip("/")
    if re.fullmatch(r"support/reference/MCP-(?:B)?\d{3}/agent_view\.json", normalized):
        return True
    if normalized in {"maps_fixture.json", "fixtures/maps_fixture.json", "fixtures/maps.json", "support/fixtures/maps.json"}:
        return True
    return False


def _check_browser_sources(cases: list[Any], report: PreflightReport) -> None:
    checked = 0
    for case in cases:
        metadata = dict(getattr(case, "metadata", {}) or {})
        for key in ("web_entry_source_path", "local_web_entry_source_path", "original_web_entry_source_path"):
            value = metadata.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if key == "original_web_entry_source_path" and (
                metadata.get("web_entry_source_path") or metadata.get("local_web_entry_source_path")
            ):
                continue
            checked += 1
            path = Path(value)
            if not path.is_absolute():
                if value.startswith("datasets/"):
                    path = BENCH_ROOT / value
                else:
                    path = REPO_ROOT / value
            if not path.exists():
                report.error(
                    "missing_browser_source",
                    f"{case.case_id} references missing browser source {value}",
                    case_id=case.case_id,
                    key=key,
                    path=value,
                )
    report.checked["browser_source_references"] = checked


def _check_tool_catalogs(cases: list[Any], sandbox_dir: Path, report: PreflightReport) -> None:
    checked = 0
    required = (
        sandbox_dir / "mcp" / "maps" / "places.json",
        sandbox_dir / "mcp" / "weather_forecasts.json",
    )
    for path in required:
        checked += 1
        if not path.exists():
            report.error("missing_tool_fixture", f"missing tool fixture {path}", path=str(path))
    for case in cases:
        for attr in ("clean_tool_catalog", "poisoned_tool_catalog"):
            catalog = getattr(case, attr, None)
            if catalog:
                checked += len(catalog)
    report.checked["tool_manifest_items"] = checked


def _check_langgraph_runtime(report: PreflightReport) -> None:
    try:
        from langgraph.graph import StateGraph  # noqa: F401
    except Exception as exc:
        report.error("langgraph_import_failed", "LangGraph is not importable", error=str(exc))
    try:
        from agentguard_langgraph_bench.demo_agent.graph import build_demo_graph  # noqa: F401
    except Exception as exc:
        report.error("langgraph_demo_import_failed", "demo LangGraph graph is not importable", error=str(exc))


def _check_real_browser_runtime(report: PreflightReport, *, browser_engine: str = "chromium") -> None:
    engine = str(browser_engine or "chromium").strip().lower()
    report.checked["real_browser_engine"] = engine
    if importlib.util.find_spec("playwright") is None or importlib.util.find_spec("playwright.sync_api") is None:
        report.checked["playwright_python_package"] = False
        report.error(
            "missing_playwright_python_package",
            "Playwright Python package is not importable; run uv sync from the repository root.",
            package="playwright",
        )
        return
    report.checked["playwright_python_package"] = True
    if engine != "chromium":
        report.warning(
            "unsupported_real_browser_engine_check",
            f"real-browser executable preflight only knows how to verify chromium, got {engine}",
            browser_engine=engine,
        )
        return

    from .browser_runtime import INSTRUMENTATION_ROOT

    browser_root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or (INSTRUMENTATION_ROOT / ".playwright-browsers"))
    report.checked["playwright_browsers_path"] = str(browser_root)
    candidates = sorted(browser_root.glob("chromium-*/chrome-linux*/chrome")) + sorted(
        browser_root.glob("chromium-*/chrome-linux*/chrome-wrapper")
    ) + sorted(
        browser_root.glob("chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell")
    )
    if not any(path.is_file() and os.access(path, os.X_OK) for path in candidates):
        report.error(
            "missing_playwright_chromium",
            "Playwright Chromium executable is missing; install Chromium or set PLAYWRIGHT_BROWSERS_PATH.",
            browser_engine=engine,
            playwright_browsers_path=str(browser_root),
        )


def _check_prompt_contamination(cases: list[Any], report: PreflightReport) -> None:
    checked = 0
    for case in cases:
        checked += 1
        text = str(getattr(getattr(case, "input", None), "payload", "") or "").lower()
        for marker in FORBIDDEN_AGENT_VISIBLE_MARKERS:
            if marker in text:
                report.warning(
                    "agent_visible_marker",
                    f"{case.case_id} task text contains marker {marker!r}",
                    case_id=case.case_id,
                    marker=marker,
                )
    report.checked["agent_visible_prompts"] = checked


def _check_agent_visible_metadata(cases: list[Any], report: PreflightReport) -> None:
    checked = 0
    for case in cases:
        checked += 1
        metadata = dict(getattr(case, "metadata", {}) or {})
        safe = safe_agent_metadata(metadata)
        leaked = forbidden_agent_visible_metadata_keys(safe)
        if leaked:
            report.error(
                "agent_visible_metadata_leak",
                f"{case.case_id} exposes evaluator-only metadata to the external agent",
                case_id=case.case_id,
                keys=leaked,
            )
    report.checked["agent_visible_metadata"] = checked


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run static AgentGuard benchmark preflight checks")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_DIR))
    parser.add_argument("--sandbox-dir", default=str(DEFAULT_SANDBOX_DIR))
    parser.add_argument("--check-fixtures", action="store_true")
    parser.add_argument("--check-browser-artifacts", action="store_true")
    parser.add_argument("--check-tool-manifest", action="store_true")
    parser.add_argument("--check-langgraph-runtime", action="store_true")
    parser.add_argument("--check-real-browser-runtime", action="store_true")
    parser.add_argument("--browser-engine", default="chromium")
    parser.add_argument("--no-prompt-contamination-check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_preflight(
        dataset=args.dataset,
        sandbox_dir=args.sandbox_dir,
        check_fixtures=args.check_fixtures,
        check_browser_artifacts=args.check_browser_artifacts,
        check_tool_manifest=args.check_tool_manifest,
        check_langgraph_runtime=args.check_langgraph_runtime,
        check_real_browser_runtime=args.check_real_browser_runtime,
        browser_engine=args.browser_engine,
        check_prompt_contamination=not args.no_prompt_contamination_check,
    )
    print(json.dumps(report.model_dump(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
