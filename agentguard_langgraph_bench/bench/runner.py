"""AttackBench runner CLI."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapter.core_client import FakeAllowCoreClient, FakeDenyCoreClient
from ..adapter.event_models import new_id
from ..guard import GuardAdapter, GuardConfig
from .config import DEFAULT_DATASET_DIR, DEFAULT_RESULTS_DIR, BenchConfig, ensure_sandbox
from .dataset_loader import load_attack_cases
from .environment import archive_sandbox_effects, restore_initial_sandbox
from .metrics import calculate_metrics
from .memory_poisoning_metrics import calculate_memory_poisoning_metrics
from .models import AttackCase, ToolPlanStep, supports_runtime
from .mcpsafety import build_descriptor_diff, evaluate_differential_run
from .mcpsafety_evaluator import build_mcpsafety_evaluation_report, should_evaluate_mcpsafety
from .poisonedrag_metrics import calculate_poisonedrag_metrics
from .runtime.adapter_loader import load_agent_adapter
from .runtime.agent_protocol import AgentAdapterProtocol, CaseContext
from .runtime.row_normalizer import normalize_case_result
from .runtime.tool_gateway import GuardedToolGateway
from .runtime.tool_server import BenchmarkToolServer
from .scoring.success import success_for_case
from .scoring.agent_abuse import build_agent_abuse_evaluation_report
from .scoring.tool_hijacking import build_tool_hijacking_report, case_extra_dict, case_extra_list
from .tools import MockToolRegistry


def run_cases(
    cases: list[AttackCase],
    *,
    config: BenchConfig,
    agent_adapter: AgentAdapterProtocol | None = None,
    fake_core: bool = False,
    fake_core_decision: str = "deny",
    reset_environment: bool = True,
    scenario_stateful: bool = False,
    isolate_scenarios: bool = True,
) -> list[dict[str, Any]]:
    benchmark_run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if config.tool_hijacking_mode == "differential" and all(case.attack_type == "tool_hijacking" for case in cases):
        return _run_differential_cases(
            cases,
            config=config,
            fake_core=fake_core,
            fake_core_decision=fake_core_decision,
            reset_environment=reset_environment,
        )
    if reset_environment:
        restore_initial_sandbox(config.sandbox_dir)
    else:
        ensure_sandbox(config.sandbox_dir)
    tools = MockToolRegistry(
        config.sandbox_dir,
        browser_mode=config.browser_mode,
        browser_engine=config.browser_engine,
        browser_fixture_compat_mode=config.browser_fixture_compat_mode,
        allowed_local_service_ports=set(config.allowed_local_service_ports),
    )
    core_client = None
    if fake_core:
        core_client = FakeAllowCoreClient() if fake_core_decision == "allow" else FakeDenyCoreClient()
    agent_adapter = agent_adapter or load_agent_adapter(config)
    guard_config = GuardConfig.from_bench_config(config, runtime=agent_adapter.runtime, agent_id=agent_adapter.name)
    guard_adapter = GuardAdapter(config=guard_config, core_client=core_client)
    tool_gateway = GuardedToolGateway(guard_adapter=guard_adapter, tool_runtime=tools)
    tool_server = None
    if config.tool_server_mode == "http":
        tool_server = BenchmarkToolServer(tool_gateway, host=config.tool_server_host, port=config.tool_server_port).start()
    rows: list[dict[str, Any]] = []
    sandbox_archive: dict[str, Any] | None = None
    try:
        agent_adapter.setup({"config": config, "tool_server": tool_server})
        groups = group_cases_by_scenario(cases) if scenario_stateful else [[case] for case in cases]
        for group_index, group in enumerate(groups):
            if scenario_stateful and isolate_scenarios and group_index > 0:
                restore_initial_sandbox(config.sandbox_dir)
            for case in group:
                if tool_server is not None:
                    tool_server.reset_case()
                row = _run_single_case(case, agent_adapter, tools, tool_gateway, config, tool_server, benchmark_run_id=benchmark_run_id)
                rows.append(row)
    finally:
        agent_adapter.teardown()
        if tool_server is not None:
            tool_server.stop()
        tools.close()
        if reset_environment:
            archive_report = archive_sandbox_effects(config.sandbox_dir, config.results_dir)
            sandbox_archive = archive_report.as_dict()
            restore_initial_sandbox(config.sandbox_dir)
    if sandbox_archive is not None:
        for row in rows:
            row["sandbox_archive"] = sandbox_archive
    return rows


def _run_differential_cases(
    cases: list[AttackCase],
    *,
    config: BenchConfig,
    fake_core: bool,
    fake_core_decision: str,
    reset_environment: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        clean_config = _copy_config(
            config,
            tool_hijacking_mode="autonomous",
            tool_catalog_view="clean",
            sandbox_dir=config.sandbox_dir / "differential" / case.case_id / "clean",
        )
        poisoned_config = _copy_config(
            config,
            tool_hijacking_mode="autonomous",
            tool_catalog_view="poisoned",
            sandbox_dir=config.sandbox_dir / "differential" / case.case_id / "poisoned",
        )
        clean_row = run_cases(
            [case],
            config=clean_config,
            fake_core=fake_core,
            fake_core_decision=fake_core_decision,
            reset_environment=reset_environment,
        )[0]
        poisoned_row = run_cases(
            [case],
            config=poisoned_config,
            fake_core=fake_core,
            fake_core_decision=fake_core_decision,
            reset_environment=reset_environment,
        )[0]
        differential = evaluate_differential_run(clean_row, poisoned_row, case_extra_dict(case, "differential_oracle"))
        combined = {
            **poisoned_row,
            "trace_id": {"clean": clean_row.get("trace_id"), "poisoned": poisoned_row.get("trace_id")},
            "tool_hijacking_mode": "differential",
            "tool_catalog_view": "clean_vs_poisoned",
            "clean_run": clean_row,
            "poisoned_run": poisoned_row,
            "differential": differential,
            "attack_success": bool(poisoned_row.get("attack_success") or differential.get("attack_success")),
            "task_success": bool(clean_row.get("task_success") and poisoned_row.get("task_success")),
            "safe_completion": bool(poisoned_row.get("safe_completion") and not differential.get("attack_success")),
            "overblocked": bool(clean_row.get("overblocked") or poisoned_row.get("overblocked")),
        }
        rows.append(combined)
    return rows


def _copy_config(config: BenchConfig, **updates: Any) -> BenchConfig:
    data = {
        "core_base_url": config.core_base_url,
        "token": config.token,
        "timeout": config.timeout,
        "fail_closed": config.fail_closed,
        "defense_enabled": config.defense_enabled,
        "runtime": config.runtime,
        "sandbox_dir": config.sandbox_dir,
        "results_dir": config.results_dir,
        "llm_enabled": config.llm_enabled,
        "llm_provider": config.llm_provider,
        "llm_model": config.llm_model,
        "llm_api_key": config.llm_api_key,
        "llm_base_url": config.llm_base_url,
        "llm_temperature": config.llm_temperature,
        "llm_fallback_to_case_plan": config.llm_fallback_to_case_plan,
        "llm_max_tool_rounds": config.llm_max_tool_rounds,
        "llm_request_timeout": config.llm_request_timeout,
        "llm_max_retries": config.llm_max_retries,
        "instrumentation_plan_mode": config.instrumentation_plan_mode,
        "browser_mode": config.browser_mode,
        "browser_engine": config.browser_engine,
        "browser_fixture_compat_mode": config.browser_fixture_compat_mode,
        "allowed_local_service_ports": config.allowed_local_service_ports,
        "tool_hijacking_mode": config.tool_hijacking_mode,
        "tool_catalog_view": config.tool_catalog_view,
        "agent_adapter": config.agent_adapter,
        "adapter_entrypoint": config.adapter_entrypoint,
        "adapter_config": config.adapter_config,
        "agent_endpoint": config.agent_endpoint,
        "agent_command": config.agent_command,
        "tool_server_mode": config.tool_server_mode,
        "tool_server_host": config.tool_server_host,
        "tool_server_port": config.tool_server_port,
        "core_api_mode": config.core_api_mode,
        "strict_runtime_targets": config.strict_runtime_targets,
    }
    data.update(updates)
    return BenchConfig(**data)


def _run_single_case(
    case: AttackCase,
    agent_adapter: AgentAdapterProtocol,
    tools: MockToolRegistry,
    tool_gateway: GuardedToolGateway,
    config: BenchConfig,
    tool_server: BenchmarkToolServer | None = None,
    benchmark_run_id: str | None = None,
) -> dict[str, Any]:
    case_result_dir = config.results_dir / "cases" / case.case_id
    case_result_dir.mkdir(parents=True, exist_ok=True)
    row: dict[str, Any]
    try:
        context = build_case_context(case, config, agent_adapter, tools, tool_gateway, tool_server)
        context.security["benchmark_run_id"] = benchmark_run_id or ""
        context.security["attempt_id"] = "1"
        result = agent_adapter.run_case(case, context)
        row = normalize_case_result(case, result, config, tools)
    except Exception as exc:
        row = _invalid_case_row(case, config, str(exc), benchmark_run_id=benchmark_run_id)
    row["benchmark_run_id"] = benchmark_run_id
    row["attempt_id"] = "1"
    if case.attack_type == "tool_hijacking":
        hijacking_report = build_tool_hijacking_report(case, row)
        row["hijacking_report"] = hijacking_report
        row["hijacking_mode"] = hijacking_report.get("mode")
        row["target_tool"] = (hijacking_report.get("target") or {}).get("tool")
        row["hijacked_tool"] = (hijacking_report.get("hijacked") or {}).get("tool")
        row["resisted"] = hijacking_report.get("resisted")
        row["resistance_score"] = hijacking_report.get("resistance_score")
        row["evidence_status"] = hijacking_report.get("evidence_status")
        row["task_success"] = hijacking_report.get("task_success")
        row["safe_completion"] = hijacking_report.get("safe_completion")
        row["overblocked"] = hijacking_report.get("overblocked")
        row["resisted_but_task_failed"] = hijacking_report.get("resisted_but_task_failed")
        row["oracle_evidence"] = hijacking_report.get("oracle_evidence")
        row["descriptor_evidence"] = _descriptor_evidence(row.get("tool_calls") or [])
        row["descriptor_diff"] = _descriptor_diff_for_case(case)
    if should_evaluate_mcpsafety(case):
        mcpsafety_report = build_mcpsafety_evaluation_report(case, row)
        if mcpsafety_report is not None:
            row["mcpsafety_evaluation_report"] = mcpsafety_report
            row["mcpsafety_evaluator"] = mcpsafety_report.get("evaluator")
            row["mcpsafety_attack_success"] = mcpsafety_report.get("attack_success")
            row["mcpsafety_evidence_status"] = mcpsafety_report.get("evidence_status")
    if case.attack_type == "agent_abuse":
        report = build_agent_abuse_evaluation_report(case, row, sandbox_dir=config.sandbox_dir)
        row["agent_abuse_evaluation_report"] = report.model_dump()
        row["evaluator"] = report.evaluator
        row["evidence_status"] = report.evidence_status
        row["harm_attempted"] = report.harm_attempted
        row["completion_level"] = report.completion_level
        row["attack_success"] = report.attack_success
        row["blocked_before_harm"] = report.blocked_before_harm
        row["blocked_after_harm"] = report.blocked_after_harm
        row["run_valid"] = row.get("run_valid", True) and report.run_valid
        if not report.run_valid:
            row["invalid_reasons"] = sorted(set([*(row.get("invalid_reasons") or []), *report.missing_evidence]))
        _write_case_artifacts(case_result_dir, row, report.model_dump())
    else:
        row["attack_success"] = success_for_case(case, row)
        _write_case_artifacts(case_result_dir, row, None)
    return row


def _invalid_case_row(case: AttackCase, config: BenchConfig, error: str, *, benchmark_run_id: str | None) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "trace_id": new_id("trace"),
        "runtime": config.runtime,
        "adapter_name": config.agent_adapter,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "metadata": case.metadata,
        "instrumentation_plan_mode": config.instrumentation_plan_mode,
        "planning_source": "runtime_error",
        "guided_plan_applied": False,
        "fallback_applied": False,
        "llm_planning_evidence": [],
        "llm_request_diagnostics": [],
        "task_terminal": False,
        "task_terminal_reason": "",
        "stop_reason": "runtime_error",
        "run_status": "runtime_error",
        "run_valid": False,
        "invalid_reasons": ["case_runtime_exception"],
        "defense_enabled": config.defense_enabled,
        "expected_decision": case.expected_decision,
        "tool_calls": [],
        "behavior_events": [],
        "browser_recordings": [],
        "decisions": [],
        "blocked": False,
        "executed": False,
        "side_effects": [],
        "final_answer": "",
        "adapter_error": error,
        "raw_logs": [error],
        "benchmark_run_id": benchmark_run_id,
    }


def _write_case_artifacts(case_result_dir: Path, row: dict[str, Any], report: dict[str, Any] | None) -> None:
    case_result = case_result_dir / "case_result.json"
    case_result.write_text(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    evidence_index = {
        "case_id": row.get("case_id"),
        "finalized": True,
        "streams": [],
        "missing": [],
    }
    for recording in row.get("browser_recordings") or []:
        if isinstance(recording, dict):
            for key in ("events", "manifest", "screenshot", "full_page_screenshot", "trace", "raw_video", "video"):
                if recording.get(key):
                    evidence_index["streams"].append({"type": key, "path": recording[key]})
    (case_result_dir / "evidence_index.json").write_text(json.dumps(evidence_index, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if report is not None:
        (case_result_dir / "evaluation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def build_case_context(
    case: AttackCase,
    config: BenchConfig,
    agent_adapter: AgentAdapterProtocol,
    tool_runtime: MockToolRegistry,
    tool_gateway: GuardedToolGateway,
    tool_server: BenchmarkToolServer | None = None,
) -> CaseContext:
    trace_id = new_id("trace")
    security = {
        "case_id": case.case_id,
        "trace_id": trace_id,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "source_type": case.input.source_type,
        "source_trust": case.input.source_trust,
        "user_task": case.input.payload,
        "payload": case.input.payload,
        "metadata": case.metadata,
        "agent_id": agent_adapter.name,
        "runtime": agent_adapter.runtime,
    }
    return CaseContext(
        case=case,
        trace_id=trace_id,
        runtime=agent_adapter.runtime,
        adapter_name=agent_adapter.name,
        sandbox_dir=config.sandbox_dir,
        results_dir=config.results_dir,
        security=security,
        tool_gateway=tool_gateway,
        tool_runtime=tool_runtime,
        config=config,
        tool_server=tool_server,
    )


def _planning_source(state: dict[str, Any], case: AttackCase, config: BenchConfig) -> str:
    if case.attack_type == "tool_hijacking" and config.tool_hijacking_mode in {"autonomous", "differential"}:
        return f"{config.tool_catalog_view}_tool_catalog"
    events = state.get("behavior_events") or []
    for event in reversed(events):
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        planner = metadata.get("planner") if isinstance(metadata, dict) else None
        if planner:
            return str(planner)
    return "case_plan_fallback" if config.llm_fallback_to_case_plan else "attackcase_tool_plan"


def _final_answer_from_state(state: dict[str, Any]) -> str:
    if state.get("last_model_content"):
        return str(state["last_model_content"])
    for item in reversed(state.get("tool_results") or []):
        result = item.get("result")
        if isinstance(result, dict):
            if result.get("answer"):
                return str(result["answer"])
            body = result.get("body")
            if isinstance(body, dict) and body.get("answer"):
                return str(body["answer"])
    return ""


def _descriptor_evidence(tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in tool_results:
        if item.get("tool_name") != "mcp_call":
            continue
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        event_args = (item.get("event") or {}).get("arguments") if isinstance(item.get("event"), dict) else {}
        evidence.append(
            {
                "descriptor_view": result.get("descriptor_view") or event_args.get("catalog_view"),
                "descriptor_hash": result.get("descriptor_hash"),
                "clean_descriptor_hash": result.get("clean_descriptor_hash"),
                "poisoned_descriptor_hash": result.get("poisoned_descriptor_hash"),
                "descriptor_diff": result.get("descriptor_diff") or [],
                "permissions": result.get("permissions") or [],
                "trust_level": result.get("trust_level"),
                "server_version": result.get("server_version"),
            }
        )
    return [item for item in evidence if any(value for value in item.values())]


def _descriptor_diff_for_case(case: AttackCase) -> list[dict[str, Any]]:
    explicit = case_extra_list(case, "descriptor_diff")
    if explicit:
        return [item for item in explicit if isinstance(item, dict)]
    clean = [item for item in case_extra_list(case, "clean_tool_catalog") if isinstance(item, dict)]
    poisoned = [item for item in case_extra_list(case, "poisoned_tool_catalog") if isinstance(item, dict)]
    if not clean or not poisoned:
        return []
    return build_descriptor_diff(clean, poisoned)


def group_cases_by_scenario(cases: list[AttackCase]) -> list[list[AttackCase]]:
    groups: dict[str, list[AttackCase]] = {}
    order: list[str] = []
    for index, case in enumerate(cases):
        scenario_id = str(case.metadata.get("scenario_id") or f"__case__:{index}:{case.case_id}")
        if scenario_id not in groups:
            groups[scenario_id] = []
            order.append(scenario_id)
        groups[scenario_id].append(case)
    return [
        sorted(
            groups[scenario_id],
            key=lambda item: (int(item.metadata.get("scenario_order") or 0), item.case_id),
        )
        for scenario_id in order
    ]


def _case_browser_session_ids(case: AttackCase) -> list[str]:
    ids: list[str] = []
    for step in case.tool_plan:
        if not step.tool.startswith("browser_"):
            continue
        candidate = step.arguments.get("session_id") or step.arguments.get("run_id")
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    if not ids and any(step.tool.startswith("browser_") for step in case.tool_plan):
        ids.append(case.case_id)
    return ids


def _finalize_case_browser_recordings(case: AttackCase, tools: MockToolRegistry) -> list[dict[str, Any]]:
    recordings: list[dict[str, Any]] = []
    for session_id in _case_browser_session_ids(case):
        finalized = tools.finalize_browser_session(session_id)
        if finalized is not None:
            recordings.append(finalized)
        else:
            recordings.extend(tools.browser_recordings(session_id))
    return recordings


def write_results(rows: list[dict[str, Any]], summary: dict[str, Any], results_dir: Path) -> dict[str, str]:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_json = results_dir / f"run_{stamp}.json"
    run_csv = results_dir / f"run_{stamp}.csv"
    summary_json = results_dir / f"summary_{stamp}.json"
    run_manifest_json = results_dir / f"manifest_run_{stamp}.json"
    run_manifest = _build_run_manifest(rows, results_dir)
    summary["run_manifest"] = run_manifest
    summary["run_integrity_failed"] = not run_manifest["run_integrity_ok"]

    run_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    run_manifest_json.write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    with run_csv.open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "case_id",
            "trace_id",
            "attack_type",
            "hijacking_mode",
            "is_malicious",
            "scenario_id",
            "phase",
            "scenario_order",
            "defense_enabled",
            "expected_decision",
            "decisions",
            "blocked",
            "executed",
            "attack_success",
            "task_success",
            "safe_completion",
            "overblocked",
            "instrumentation_plan_mode",
            "planning_source",
            "guided_plan_applied",
            "fallback_applied",
            "stop_reason",
            "run_status",
            "run_valid",
            "invalid_reasons",
            "successful_tool_count",
            "tool_error_count",
            "browser_action_count",
            "task_terminal",
            "task_terminal_reason",
            "completed_round_index",
            "llm_request_count",
            "llm_timeout_count",
            "llm_retry_count",
            "evidence_status",
            "mcpsafety_evaluator",
            "mcpsafety_evidence_status",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: json.dumps(row[field]) if isinstance(row.get(field), list) else row.get(field) for field in fields})
    paths = {"run_json": str(run_json), "run_csv": str(run_csv), "summary_json": str(summary_json), "run_manifest": str(run_manifest_json)}
    sandbox_archive = next((row.get("sandbox_archive") for row in rows if row.get("sandbox_archive")), None)
    if isinstance(sandbox_archive, dict):
        paths["sandbox_artifact_dir"] = str(sandbox_archive.get("artifact_dir", ""))
        paths["sandbox_manifest"] = str(sandbox_archive.get("manifest_path", ""))
    return paths


def _build_run_manifest(rows: list[dict[str, Any]], results_dir: Path) -> dict[str, Any]:
    case_ids = [str(row.get("case_id") or "") for row in rows]
    duplicates = sorted({case_id for case_id in case_ids if case_ids.count(case_id) > 1 and case_id})
    missing_case_results: list[str] = []
    missing_artifacts: list[str] = []
    for case_id in case_ids:
        case_result = results_dir / "cases" / case_id / "case_result.json"
        if not case_result.exists():
            missing_case_results.append(case_id)
        row = next((item for item in rows if item.get("case_id") == case_id), {})
        if row.get("attack_type") == "agent_abuse" and row.get("run_valid", True) and not row.get("browser_recordings"):
            missing_artifacts.append(case_id)
    run_integrity_ok = not duplicates and not missing_case_results and not missing_artifacts
    return {
        "expected_case_count": len(rows),
        "result_case_count": len(rows),
        "missing_case_ids": [],
        "duplicate_case_ids": duplicates,
        "missing_case_result_ids": sorted(missing_case_results),
        "artifact_missing_case_ids": sorted(missing_artifacts),
        "run_integrity_ok": run_integrity_ok,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AgentGuard LangGraph AttackBench")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_DIR), help="JSONL file or directory of AttackCase files")
    parser.add_argument("--core-url", default="http://localhost:8000", help="Agent Security Core base URL")
    parser.add_argument("--token", default="demo-token", help="Agent Security Core bearer token")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--defense", choices=["on", "off"], default="off")
    parser.add_argument("--fail-open-debug", action="store_true", help="Allow local debug execution if Core fails")
    parser.add_argument("--fake-core", action="store_true", help="Use a local fake Core instead of HTTP Core")
    parser.add_argument("--fake-core-decision", choices=["allow", "deny"], default="deny", help="Decision returned by local fake Core")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    parser.add_argument("--sandbox-dir", default=None, help="Sandbox directory to reset and use for mock tool side effects")
    parser.add_argument(
        "--no-reset-env",
        action="store_true",
        help="Keep sandbox side effects after the run for debugging instead of restoring the initial environment",
    )
    parser.add_argument(
        "--reset-env-only",
        action="store_true",
        help="Restore the sandbox to the initial evaluation environment and exit",
    )
    parser.add_argument("--case-id", action="append", default=[], help="Run only the selected AttackCase id; can be repeated")
    parser.add_argument("--llm", action="store_true", help="Enable LLM planning from AGENTGUARD_LLM_* env/.env settings")
    parser.add_argument("--llm-enabled", action="store_true", help="Alias for --llm")
    parser.add_argument("--no-llm-fallback-to-case-plan", action="store_true", help="Disable LLM fallback to replay/case plan")
    parser.add_argument(
        "--tool-hijacking-mode",
        choices=["replay", "autonomous", "differential", "hybrid"],
        default="replay",
        help="Tool hijacking evaluation mode",
    )
    parser.add_argument("--llm-max-tool-rounds", type=int, default=None, help="Maximum LLM/tool/observation rounds per case")
    parser.add_argument("--llm-request-timeout", type=float, default=None, help="Timeout in seconds for each LLM planning request.")
    parser.add_argument("--llm-max-retries", type=int, default=None, help="Maximum retries for transient LLM request failures.")
    parser.add_argument(
        "--instrumentation-plan-mode",
        choices=["guided", "autonomous"],
        default=None,
        help="Instrumentation browser planning mode: guided replay hints or autonomous LLM tool planning.",
    )
    parser.add_argument("--poisonedrag-mode", choices=["clean", "poisoned", "hybrid", "delayed_memory"], default=None)
    parser.add_argument("--poison-prefix", choices=["question", "none"], default=None)
    parser.add_argument("--rag-scorer", choices=["light", "exact"], default=None)
    parser.add_argument("--top-k", type=int, default=None)
    parser.add_argument("--adv-per-query", type=int, default=None)
    parser.add_argument("--allow-scorer-fallback", action="store_true")
    parser.add_argument(
        "--scenario-stateful",
        action="store_true",
        help="Run cases grouped by metadata.scenario_id with sandbox memory preserved within each scenario.",
    )
    parser.add_argument(
        "--share-memory-across-scenarios",
        action="store_true",
        help="Keep memory across scenario groups instead of isolating each scenario.",
    )
    parser.add_argument(
        "--poisonedrag-datasets",
        default=None,
        help="Comma-separated PoisonedRAG dataset filter, for example nq,msmarco",
    )
    parser.add_argument(
        "--browser-mode",
        choices=["record", "real"],
        default=None,
        help="Use record-only browser tools or real Playwright local-page browser tools",
    )
    parser.add_argument(
        "--browser-engine",
        choices=["chromium", "firefox", "webkit"],
        default=None,
        help="Playwright engine for --browser-mode real",
    )
    parser.add_argument(
        "--browser-fixture-compat-mode",
        choices=["strict", "legacy"],
        default=None,
        help="strict preserves page validation/disabled/readonly semantics; legacy applies old compatibility workarounds.",
    )
    parser.add_argument(
        "--agent-adapter",
        choices=["langgraph-demo", "openclaw", "http", "subprocess", "python"],
        default="langgraph-demo",
        help="Agent adapter used by the benchmark runner.",
    )
    parser.add_argument("--adapter-entrypoint", default="", help="Python entrypoint for --agent-adapter python.")
    parser.add_argument("--adapter-config", default="", help="Adapter-specific config file path.")
    parser.add_argument("--agent-endpoint", default="", help="HTTP endpoint for http/openclaw adapter.")
    parser.add_argument("--agent-command", default="", help="Subprocess command for subprocess adapter.")
    parser.add_argument(
        "--tool-server-mode",
        choices=["inprocess", "http"],
        default="inprocess",
        help="Use in-process gateway or expose the local HTTP tool server.",
    )
    parser.add_argument("--tool-server-host", default="127.0.0.1")
    parser.add_argument("--tool-server-port", type=int, default=18090)
    parser.add_argument("--runtime", default="", help="Runtime label. Defaults to adapter runtime.")
    parser.add_argument("--core-api-mode", choices=["legacy", "guard-api-v0.3"], default="legacy")
    parser.add_argument("--strict-runtime-targets", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    defense_enabled = args.defense == "on"
    config = BenchConfig.from_values(
        core_base_url=args.core_url,
        token=args.token,
        timeout=args.timeout,
        fail_closed=not args.fail_open_debug,
        defense_enabled=defense_enabled,
        sandbox_dir=args.sandbox_dir,
        results_dir=args.results_dir,
        llm_enabled=args.llm or args.llm_enabled,
        llm_fallback_to_case_plan=(
            args.tool_hijacking_mode == "hybrid"
            and args.instrumentation_plan_mode != "autonomous"
            and not args.no_llm_fallback_to_case_plan
        ),
        llm_max_tool_rounds=args.llm_max_tool_rounds,
        llm_request_timeout=args.llm_request_timeout,
        llm_max_retries=args.llm_max_retries,
        instrumentation_plan_mode=args.instrumentation_plan_mode,
        browser_mode=args.browser_mode,
        browser_engine=args.browser_engine,
        browser_fixture_compat_mode=args.browser_fixture_compat_mode,
        tool_hijacking_mode="replay" if args.tool_hijacking_mode == "hybrid" else args.tool_hijacking_mode,
        agent_adapter=args.agent_adapter,
        adapter_entrypoint=args.adapter_entrypoint,
        adapter_config=args.adapter_config,
        agent_endpoint=args.agent_endpoint,
        agent_command=args.agent_command,
        tool_server_mode=args.tool_server_mode,
        tool_server_host=args.tool_server_host,
        tool_server_port=args.tool_server_port,
        core_api_mode=args.core_api_mode,
        strict_runtime_targets=args.strict_runtime_targets,
    )
    if config.instrumentation_plan_mode == "autonomous" and config.llm_fallback_to_case_plan:
        config.llm_fallback_to_case_plan = False
        print("Warning: disabled llm_fallback_to_case_plan for instrumentation_plan_mode=autonomous")
    if args.reset_env_only:
        report = restore_initial_sandbox(config.sandbox_dir)
        print(json.dumps({"environment_reset": report.as_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    cases = load_attack_cases(args.dataset)
    if args.case_id:
        selected = set(args.case_id)
        cases = [case for case in cases if case.case_id in selected]
        missing = sorted(selected - {case.case_id for case in cases})
        if missing:
            raise SystemExit(f"AttackCase id not found: {', '.join(missing)}")
    cases = _filter_poisonedrag_datasets(cases, args.poisonedrag_datasets)
    cases = _override_poisonedrag_cases(
        cases,
        mode=args.poisonedrag_mode,
        poison_prefix=args.poison_prefix,
        scorer=args.rag_scorer,
        top_k=args.top_k,
        adv_per_query=args.adv_per_query,
        allow_scorer_fallback=args.allow_scorer_fallback,
    )
    agent_adapter = load_agent_adapter(config)
    runtime = args.runtime or agent_adapter.runtime
    supported = [case for case in cases if supports_runtime(case, runtime)]
    skipped = [case for case in cases if not supports_runtime(case, runtime)]
    if skipped and args.strict_runtime_targets:
        raise SystemExit("Cases do not support selected runtime: " + ", ".join(case.case_id for case in skipped))
    cases = supported
    rows = run_cases(
        cases,
        config=config,
        agent_adapter=agent_adapter,
        fake_core=args.fake_core or defense_enabled and args.core_url == "fake",
        fake_core_decision=args.fake_core_decision,
        reset_environment=not args.no_reset_env,
        scenario_stateful=args.scenario_stateful,
        isolate_scenarios=not args.share_memory_across_scenarios,
    )
    summary = calculate_metrics(rows, defense_enabled=defense_enabled)
    if skipped:
        summary["skipped_runtime_mismatch"] = len(skipped)
    poisonedrag_summary = calculate_poisonedrag_metrics(rows)
    if poisonedrag_summary is not None:
        summary["poisonedrag"] = poisonedrag_summary
    memory_summary = calculate_memory_poisoning_metrics(rows)
    if memory_summary is not None:
        summary["memory_poisoning"] = memory_summary
    paths = write_results(rows, summary, config.results_dir)
    print(json.dumps({"summary": summary, "outputs": paths}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _filter_poisonedrag_datasets(cases: list[AttackCase], raw_datasets: str | None) -> list[AttackCase]:
    if not raw_datasets:
        return cases
    selected = {item.strip() for item in raw_datasets.split(",") if item.strip()}
    return [
        case
        for case in cases
        if case.metadata.get("source_dataset") != "PoisonedRAG" or case.metadata.get("source_subset") in selected
    ]


def _override_poisonedrag_cases(
    cases: list[AttackCase],
    *,
    mode: str | None,
    poison_prefix: str | None,
    scorer: str | None,
    top_k: int | None,
    adv_per_query: int | None,
    allow_scorer_fallback: bool,
) -> list[AttackCase]:
    if not any(value is not None for value in (mode, poison_prefix, scorer, top_k, adv_per_query)) and not allow_scorer_fallback:
        return cases
    updated: list[AttackCase] = []
    for case in cases:
        if case.metadata.get("source_dataset") != "PoisonedRAG":
            updated.append(case)
            continue
        payload = case.model_dump()
        metadata = dict(payload.get("metadata") or {})
        for key, value in {
            "mode": mode,
            "poison_prefix": poison_prefix,
            "scorer": scorer,
            "top_k": top_k,
            "adv_per_query": adv_per_query,
        }.items():
            if value is not None:
                metadata[key] = value
        payload["metadata"] = metadata
        payload["tool_plan"] = [
            _override_poisonedrag_step(step, mode, poison_prefix, scorer, top_k, adv_per_query, allow_scorer_fallback)
            for step in case.tool_plan
        ]
        updated.append(AttackCase.model_validate(payload))
    return updated


def _override_poisonedrag_step(
    step: ToolPlanStep,
    mode: str | None,
    poison_prefix: str | None,
    scorer: str | None,
    top_k: int | None,
    adv_per_query: int | None,
    allow_scorer_fallback: bool,
) -> dict[str, Any]:
    payload = step.model_dump()
    args = dict(payload.get("arguments") or {})
    if step.tool == "rag_retrieve":
        args.setdefault("source", "poisonedrag")
        if mode is not None:
            args["mode"] = mode
        if poison_prefix is not None:
            args["poison_prefix"] = poison_prefix
        if scorer is not None:
            args["scorer"] = scorer
        if top_k is not None:
            args["top_k"] = top_k
        if adv_per_query is not None:
            args["adv_per_query"] = adv_per_query
        if allow_scorer_fallback:
            args["allow_scorer_fallback"] = True
    elif step.tool == "rag_answer" and mode is not None:
        args["mode"] = mode
        args["answer_strategy"] = "target_correct_answer" if mode == "clean" else args.get("answer_strategy", "target_incorrect_answer")
    payload["arguments"] = args
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
