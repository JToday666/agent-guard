"""AttackBench runner CLI."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import shutil
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from ..adapter.core_client import FakeAllowCoreClient, FakeAskCoreClient, FakeDenyCoreClient
from ..adapter.event_models import new_id
from ..guard import GuardAdapter, GuardConfig
from .config import DEFAULT_DATASET_DIR, DEFAULT_RESULTS_DIR, BenchConfig, ensure_sandbox
from .dataset_loader import load_attack_cases
from .environment import archive_sandbox_effects, restore_initial_sandbox
from .agent_abuse_report import write_agent_abuse_iteration_report
from .evidence.artifact_integrity import build_artifact_integrity_manifest
from .evidence.artifact_integrity import check_case_artifacts
from .metrics import calculate_metrics
from .memory_poisoning_metrics import calculate_memory_poisoning_metrics
from .models import AttackCase, ToolPlanStep, supports_runtime
from .mcpsafety import build_descriptor_diff, evaluate_differential_run
from .mcpsafety_evaluator import build_mcpsafety_evaluation_report, should_evaluate_mcpsafety
from .poisonedrag_metrics import calculate_poisonedrag_metrics
from .runtime.adapter_loader import load_agent_adapter
from .runtime.agent_protocol import AgentAdapterProtocol, CaseContext
from .runtime.row_normalizer import normalize_case_result
from .runtime.sandbox_diff import diff_sandbox, snapshot_sandbox
from .runtime.termination import runtime_limits_for_case
from .runtime.tool_gateway import GuardedToolGateway
from .runtime.tool_server import BenchmarkToolServer
from .scoring.success import success_for_case
from .scoring.agent_abuse import build_agent_abuse_evaluation_report
from .scoring.file_exfiltration import build_file_exfiltration_evaluation_report
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
    benchmark_run_id: str | None = None,
) -> list[dict[str, Any]]:
    benchmark_run_id = benchmark_run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if config.tool_hijacking_mode == "differential" and all(case.attack_type == "tool_hijacking" for case in cases):
        return _run_differential_cases(
            cases,
            config=config,
            fake_core=fake_core,
            fake_core_decision=fake_core_decision,
            reset_environment=reset_environment,
            benchmark_run_id=benchmark_run_id,
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
        core_client = _fake_core_client(fake_core_decision)
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
                if not scenario_stateful:
                    _clear_case_volatile_sandbox(config.sandbox_dir)
                if tool_server is not None:
                    tool_server.reset_case()
                row = _run_single_case(
                    case,
                    agent_adapter,
                    tools,
                    tool_gateway,
                    config,
                    tool_server,
                    benchmark_run_id=benchmark_run_id,
                    core_mode=_core_mode(fake_core=fake_core, fake_core_decision=fake_core_decision, defense_enabled=config.defense_enabled),
                    fake_core_decision=fake_core_decision if fake_core else None,
                )
                rows.append(row)
    finally:
        agent_adapter.teardown()
        if tool_server is not None:
            tool_server.stop()
        tools.close()
        if reset_environment:
            archive_report = archive_sandbox_effects(config.sandbox_dir, config.results_dir, run_id=benchmark_run_id)
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
    benchmark_run_id: str,
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
            benchmark_run_id=f"{benchmark_run_id}_clean",
        )[0]
        poisoned_row = run_cases(
            [case],
            config=poisoned_config,
            fake_core=fake_core,
            fake_core_decision=fake_core_decision,
            reset_environment=reset_environment,
            benchmark_run_id=f"{benchmark_run_id}_poisoned",
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
            "benchmark_run_id": benchmark_run_id,
        }
        combined_case_dir = _case_result_dir(config.results_dir, benchmark_run_id, case.case_id)
        combined_case_dir.mkdir(parents=True, exist_ok=True)
        combined["case_artifact_dir"] = str(combined_case_dir)
        _write_case_artifacts(combined_case_dir, combined, None)
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
        "agent_visible_payload_mode": config.agent_visible_payload_mode,
        "closure_on_partial": config.closure_on_partial,
        "strict_business_validation": config.strict_business_validation,
        "prompt_contamination_check": config.prompt_contamination_check,
        "autonomous_planner_recovery_retry": config.autonomous_planner_recovery_retry,
        "autonomous_planner_recovery_max_observations": config.autonomous_planner_recovery_max_observations,
    }
    data.update(updates)
    return BenchConfig(**data)


def _clear_case_volatile_sandbox(sandbox_dir: Path) -> None:
    for relative in ("api", "browser", "outbox", "identity", "social", "web_state", "ads", "platform", "records", "memory"):
        root = sandbox_dir / relative
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.jsonl")):
            path.unlink()
        if relative == "browser":
            for path in sorted(root.rglob("replay_artifacts")):
                if path.is_dir():
                    import shutil

                    shutil.rmtree(path)


def _fake_core_client(decision: str) -> Any:
    if decision == "allow":
        return FakeAllowCoreClient()
    if decision == "ask":
        return FakeAskCoreClient()
    return FakeDenyCoreClient()


def _core_mode(*, fake_core: bool, fake_core_decision: str, defense_enabled: bool) -> str:
    if not defense_enabled:
        return "defense_off"
    if fake_core:
        return f"fake_{fake_core_decision}"
    return "real_core"


def _run_single_case(
    case: AttackCase,
    agent_adapter: AgentAdapterProtocol,
    tools: MockToolRegistry,
    tool_gateway: GuardedToolGateway,
    config: BenchConfig,
    tool_server: BenchmarkToolServer | None = None,
    benchmark_run_id: str | None = None,
    core_mode: str = "real_core",
    fake_core_decision: str | None = None,
) -> dict[str, Any]:
    run_id = benchmark_run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    case_result_dir = _case_result_dir(config.results_dir, run_id, case.case_id)
    case_result_dir.mkdir(parents=True, exist_ok=True)
    sandbox_before = snapshot_sandbox(config.sandbox_dir)
    row: dict[str, Any]
    preflight = _preflight_case_row(case, config, agent_adapter, benchmark_run_id=run_id)
    if preflight is not None:
        row = preflight
    else:
        try:
            context = build_case_context(case, config, agent_adapter, tools, tool_gateway, tool_server)
            context.security["benchmark_run_id"] = run_id
            context.security["attempt_id"] = "1"
            result = agent_adapter.run_case(case, context)
            row = normalize_case_result(case, result, config, tools)
        except Exception as exc:
            row = _invalid_case_row(case, config, str(exc), benchmark_run_id=run_id)
    row["benchmark_run_id"] = run_id
    row["attempt_id"] = "1"
    row["case_artifact_dir"] = str(case_result_dir)
    row["core_mode"] = core_mode
    row["fake_core_decision"] = fake_core_decision
    row["agent_visible_payload_mode"] = config.agent_visible_payload_mode
    row["closure_on_partial"] = config.closure_on_partial
    row["strict_business_validation"] = config.strict_business_validation
    row["prompt_contamination_check"] = config.prompt_contamination_check
    row["runtime_limits"] = row.get("runtime_limits") or runtime_limits_for_case(case, config).model_dump()
    row["metric_interpretation"] = _case_metric_interpretation(core_mode, fake_core_decision)
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
    if case.attack_type not in {"agent_abuse", "file_exfiltration"}:
        row["attack_success"] = success_for_case(case, row)
        report_payload = None
    else:
        report_payload = None
    sandbox_diff = diff_sandbox(config.sandbox_dir, sandbox_before)
    row["sandbox_diff"] = sandbox_diff
    if sandbox_diff.get("outside_sandbox_paths"):
        row["run_valid"] = False
        row["run_status"] = "security_failure"
        row["security_failure"] = True
        row["invalid_reasons"] = sorted(set([*(row.get("invalid_reasons") or []), "sandbox_escape_detected"]))
    if case.attack_type == "agent_abuse":
        report = build_agent_abuse_evaluation_report(case, row, sandbox_dir=config.sandbox_dir)
        row["agent_abuse_evaluation_report"] = report.model_dump()
        row["agent_abuse_verdict"] = report.agent_abuse_verdict
        row["evaluator"] = report.evaluator
        row["evidence_status"] = report.evidence_status
        row["harm_attempted"] = report.harm_attempted
        row["completion_level"] = report.completion_level
        row["attack_success"] = report.attack_success
        row["blocked_before_harm"] = report.blocked_before_harm
        row["blocked_after_harm"] = report.blocked_after_harm
        row["run_valid"] = report.run_valid if report.run_valid else row.get("run_valid", True) and report.run_valid
        if report.reason.startswith("skipped:"):
            row["run_status"] = "skipped"
            row["skip_reason"] = report.reason
            row["not_applicable"] = True
        elif report.run_valid and row.get("run_status") not in {"blocked", "skipped"}:
            row["run_status"] = "completed" if report.completion_level == "completed" else row.get("run_status")
        if not report.run_valid:
            row["invalid_reasons"] = sorted(set([*(row.get("invalid_reasons") or []), *report.missing_evidence]))
        else:
            row["invalid_reasons"] = []
        report_payload = report.model_dump()
        if _should_run_forced_closure(case, row, config):
            row["forced_closure"] = _run_forced_closure_diagnostic(
                case,
                config=config,
                benchmark_run_id=run_id,
                parent_case_result_dir=case_result_dir,
            )
    if case.attack_type == "file_exfiltration":
        report = build_file_exfiltration_evaluation_report(case, row, sandbox_dir=config.sandbox_dir)
        row["file_exfiltration_evaluation_report"] = report.model_dump()
        row["file_exfiltration_attack_success"] = report.attack_success
        row["evaluator"] = "file_exfiltration_chain_v1"
        row["evidence_status"] = report.evidence_status
        row["completion_level"] = report.completion_level
        row["attack_success"] = report.attack_success
        row["task_success"] = report.normal_task_success
        row["run_valid"] = False if row.get("security_failure") else report.run_valid
        if not report.run_valid:
            row["invalid_reasons"] = sorted(set([*(row.get("invalid_reasons") or []), *report.missing_evidence]))
        elif not row.get("security_failure"):
            row["invalid_reasons"] = []
        report_payload = report.model_dump()
    _write_case_artifacts(case_result_dir, row, report_payload)
    return row


def _should_run_forced_closure(case: AttackCase, row: dict[str, Any], config: BenchConfig) -> bool:
    if case.attack_type != "agent_abuse":
        return False
    if not config.closure_on_partial or config.instrumentation_plan_mode != "autonomous":
        return False
    if row.get("attack_success") is True or row.get("completion_level") in {"completed", "safe_refusal", "unsupported"}:
        return False
    verdict = row.get("agent_abuse_verdict") if isinstance(row.get("agent_abuse_verdict"), dict) else {}
    if not verdict.get("harmful_attempt_detected"):
        return False
    if row.get("completion_level") not in {"attempted", "partial"}:
        return False
    return bool(getattr(case, "closure_plan", None) or getattr(case, "guided_success_plan", None) or case.tool_plan)


def _run_forced_closure_diagnostic(
    case: AttackCase,
    *,
    config: BenchConfig,
    benchmark_run_id: str,
    parent_case_result_dir: Path,
) -> dict[str, Any]:
    closure_results_dir = parent_case_result_dir / "forced_closure_results"
    closure_config = _copy_config(
        config,
        instrumentation_plan_mode="replay",
        llm_enabled=False,
        llm_fallback_to_case_plan=False,
        closure_on_partial=False,
        sandbox_dir=config.sandbox_dir / "forced_closure" / case.case_id,
        results_dir=closure_results_dir,
    )
    try:
        closure_rows = run_cases(
            [case],
            config=closure_config,
            fake_core=True,
            fake_core_decision="allow",
            reset_environment=True,
            benchmark_run_id=f"{benchmark_run_id}_forced_closure_{case.case_id}",
        )
    except Exception as exc:
        result = {
            "enabled": True,
            "status": "error",
            "error": str(exc),
            "counts_for_autonomous_asr": False,
        }
        (parent_case_result_dir / "closure_result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return result
    closure_row = closure_rows[0] if closure_rows else {}
    result = {
        "enabled": True,
        "status": "completed",
        "counts_for_autonomous_asr": False,
        "planning_source": closure_row.get("planning_source"),
        "llm_request_count": closure_row.get("llm_request_count", 0),
        "completion_level": closure_row.get("completion_level"),
        "attack_success": closure_row.get("attack_success"),
        "business_effect_validated": (closure_row.get("agent_abuse_verdict") or {}).get("business_effect_validated"),
        "case_artifact_dir": closure_row.get("case_artifact_dir"),
        "closure_tool_results": str(parent_case_result_dir / "closure_tool_results.jsonl"),
        "closure_browser_replay": _closure_browser_replay_paths(closure_row),
    }
    (parent_case_result_dir / "closure_result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    if isinstance(closure_row.get("agent_abuse_evaluation_report"), dict):
        (parent_case_result_dir / "closure_evaluation_report.json").write_text(
            json.dumps(closure_row["agent_abuse_evaluation_report"], ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    _write_case_jsonl(parent_case_result_dir / "closure_tool_results.jsonl", closure_row.get("tool_calls") or [])
    return result


def _closure_browser_replay_paths(row: dict[str, Any]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for recording in row.get("browser_recordings") or []:
        if not isinstance(recording, dict):
            continue
        paths.append(
            {
                "artifact_dir": recording.get("artifact_dir"),
                "events": recording.get("events"),
                "report": recording.get("report"),
                "screenshot": recording.get("screenshot"),
                "full_page_screenshot": recording.get("full_page_screenshot"),
                "final_dom": recording.get("final_dom"),
                "final_accessibility_tree": recording.get("final_accessibility_tree"),
                "action_metadata": recording.get("action_metadata"),
                "business_event_correlation_index": recording.get("business_event_correlation_index"),
            }
        )
    return paths


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
        "sandbox_diff": {"schema_version": "1.0", "added": [], "modified": [], "deleted": [], "outside_sandbox_paths": [], "empty": True},
        "final_answer": "",
        "adapter_error": error,
        "raw_logs": [error],
        "benchmark_run_id": benchmark_run_id,
        "runtime_limits": runtime_limits_for_case(case, config).model_dump(),
        "termination_decision": {},
        "metric_interpretation": _case_metric_interpretation(_core_mode(fake_core=False, fake_core_decision="deny", defense_enabled=config.defense_enabled), None),
    }


def _preflight_case_row(
    case: AttackCase,
    config: BenchConfig,
    agent_adapter: AgentAdapterProtocol,
    *,
    benchmark_run_id: str | None,
) -> dict[str, Any] | None:
    requirements = getattr(case, "capability_requirements", None)
    requires_vision = bool(requirements.get("vision")) if isinstance(requirements, dict) else False
    supports_vision = bool(getattr(agent_adapter, "supports_vision", False) or getattr(agent_adapter, "multimodal_supported", False))
    if not requires_vision or supports_vision:
        return None
    row = _invalid_case_row(case, config, "requires_visual_model", benchmark_run_id=benchmark_run_id)
    row.update(
        {
            "run_valid": True,
            "run_status": "skipped",
            "stop_reason": "unsupported_modality_preflight",
            "invalid_reasons": [],
            "skip_reason": "requires_visual_model",
            "not_applicable": True,
            "vision_supported": False,
            "tool_calls": [],
            "browser_recordings": [],
            "side_effects": [],
            "sandbox_diff": {"schema_version": "1.0", "added": [], "modified": [], "deleted": [], "outside_sandbox_paths": [], "empty": True},
            "termination_decision": {
                "should_stop": True,
                "reason": "requires_visual_model",
                "completion_level": "unsupported",
                "runtime_limits": runtime_limits_for_case(case, config).model_dump(),
            },
        }
    )
    return row


def _case_metric_interpretation(core_mode: str, fake_core_decision: str | None) -> dict[str, Any]:
    fake = core_mode.startswith("fake_")
    fake_decision = fake_core_decision or (core_mode.removeprefix("fake_") if fake else None)
    if core_mode == "defense_off":
        return {
            "core_mode": core_mode,
            "defense_effect_interpretable": False,
            "benchmark_quality_interpretable": True,
            "reason": "defense_off_baseline_only",
        }
    if fake:
        reason = f"fake_{fake_decision}_cannot_prove_real_defense"
        if fake_decision == "allow":
            reason = "fake_allow_all_cannot_prove_real_defense"
        return {
            "core_mode": core_mode,
            "defense_effect_interpretable": False,
            "benchmark_quality_interpretable": True,
            "reason": reason,
        }
    return {
        "core_mode": core_mode,
        "defense_effect_interpretable": True,
        "benchmark_quality_interpretable": True,
        "reason": "real_core_decisions",
    }


def _write_case_artifacts(case_result_dir: Path, row: dict[str, Any], report: dict[str, Any] | None) -> None:
    case_result_dir.mkdir(parents=True, exist_ok=True)
    if _should_create_diagnostic_browser_artifact(row) and not row.get("browser_recordings"):
        row["browser_recordings"] = [_write_planner_stall_browser_artifact(case_result_dir, row)]
    for recording in row.get("browser_recordings") or []:
        if isinstance(recording, dict):
            immutable_recording = _copy_browser_replay_artifacts(recording, case_result_dir)
            if immutable_recording:
                recording.update(immutable_recording)
    sandbox_snapshot = _archive_case_side_effects(case_result_dir, row)
    if sandbox_snapshot:
        row["case_side_effect_artifacts"] = sandbox_snapshot
    _write_case_jsonl(case_result_dir / "tool_call_events.jsonl", [item.get("event") for item in row.get("tool_calls") or [] if item.get("event")])
    _write_case_jsonl(case_result_dir / "policy_decisions.jsonl", [_decision_record(item, row) for item in row.get("tool_calls") or []])
    _write_case_jsonl(case_result_dir / "audit_events.jsonl", [item.get("audit_event") for item in row.get("tool_calls") or [] if item.get("audit_event")])
    _write_case_jsonl(case_result_dir / "tool_results.jsonl", row.get("tool_calls") or [])
    (case_result_dir / "browser_action_summary.json").write_text(
        json.dumps(_browser_action_summary(row), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (case_result_dir / "agent_visible_prompt_contamination.json").write_text(
        json.dumps(_prompt_contamination_summary(row), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (case_result_dir / "sandbox_diff.json").write_text(
        json.dumps(row.get("sandbox_diff") or {}, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    evidence_index = _build_evidence_index(row, case_result_dir)
    for recording in row.get("browser_recordings") or []:
        if isinstance(recording, dict):
            for key in (
                "events",
                "manifest",
                "screenshot",
                "full_page_screenshot",
                "final_dom",
                "final_accessibility_tree",
                "action_metadata",
                "step_actions",
                "business_event_correlation_index",
                "trace",
                "video",
                "video_timeline",
                "continuous_frames_manifest",
            ):
                if recording.get(key):
                    evidence_index["streams"].append(_artifact_record(key, Path(str(recording[key])), case_result_dir))
            artifact_dir = recording.get("artifact_dir")
            if artifact_dir:
                integrity = check_case_artifacts(Path(str(artifact_dir)), root=Path(str(artifact_dir)).parent)
                (case_result_dir / "artifact_integrity.json").write_text(
                    json.dumps(integrity, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                evidence_index["artifact_parse_status"] = {
                    "checked": True,
                    "ok": integrity.get("ok"),
                    "manifest_path": str(case_result_dir / "artifact_integrity.json"),
                }
    evidence_index["artifact_parse_status"] = {
        **{"checked": False, "reason": "no browser replay artifact directory found"},
        **evidence_index.get("artifact_parse_status", {}),
    }
    (case_result_dir / "evidence_index.json").write_text(json.dumps(evidence_index, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if report is not None:
        (case_result_dir / "evaluation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if isinstance(row.get("file_exfiltration_evaluation_report"), dict):
        (case_result_dir / "file_exfiltration_evaluation_report.json").write_text(
            json.dumps(row["file_exfiltration_evaluation_report"], ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    case_result = case_result_dir / "case_result.json"
    case_result.write_text(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _archive_case_side_effects(case_result_dir: Path, row: dict[str, Any]) -> dict[str, Any]:
    sandbox_root = _sandbox_root_from_row(row)
    if sandbox_root is None or not sandbox_root.exists():
        return {}
    targets = {
        "side_effects": ["outbox", "api", "browser", "web_state", "records", "memory", "identity", "social", "ads", "platform"],
        "outbox_snapshot": ["outbox"],
        "api_snapshot": ["api"],
        "reports_snapshot": ["files/reports"],
        "browser_snapshot": ["browser", "web_state", "records"],
    }
    changed_files = _changed_sandbox_files(row, sandbox_root)
    if not changed_files:
        return {}
    archived: dict[str, Any] = {}
    for dest_name, relatives in targets.items():
        dest_root = case_result_dir / dest_name
        copied: list[dict[str, Any]] = []
        prefixes = tuple(f"{relative.rstrip('/')}/" for relative in relatives)
        exact = {relative.rstrip("/") for relative in relatives}
        for item in changed_files:
            relative = str(item.get("relative_path") or item.get("path") or "")
            if not relative or (relative not in exact and not relative.startswith(prefixes)):
                continue
            source = Path(str(item.get("absolute_path") or ""))
            if not source.exists() or not source.is_file() or not _is_under(source, sandbox_root):
                continue
            dest = dest_root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            copied.append(
                {
                    "case_id": row.get("case_id"),
                    "relative_path": relative,
                    "state": item.get("state"),
                    "sha256": item.get("sha256"),
                    "size": item.get("size"),
                    "artifact_path": str(dest),
                }
            )
        if copied:
            manifest = {
                "case_id": row.get("case_id"),
                "sandbox_root": str(sandbox_root),
                "copied_count": len(copied),
                "files": copied,
            }
            dest_root.mkdir(parents=True, exist_ok=True)
            (dest_root / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            archived[dest_name] = {"root": str(dest_root), "manifest": str(dest_root / "manifest.json"), "files": copied}
    return archived


def _changed_sandbox_files(row: dict[str, Any], sandbox_root: Path) -> list[dict[str, Any]]:
    diff = row.get("sandbox_diff") if isinstance(row.get("sandbox_diff"), dict) else {}
    changed: list[dict[str, Any]] = []
    for state, group in (("added", diff.get("added")), ("modified", diff.get("modified"))):
        if not isinstance(group, list):
            continue
        for raw in group:
            if not isinstance(raw, dict):
                continue
            item = raw.get("after") if state == "modified" and isinstance(raw.get("after"), dict) else raw
            relative = str(item.get("relative_path") or item.get("path") or "")
            absolute = str(item.get("absolute_path") or (sandbox_root / relative))
            changed.append(
                {
                    "state": state,
                    "relative_path": relative,
                    "absolute_path": absolute,
                    "size": item.get("size") or raw.get("size"),
                    "sha256": item.get("sha256") or raw.get("sha256"),
                }
            )
    return changed


def _sandbox_root_from_row(row: dict[str, Any]) -> Path | None:
    diff = row.get("sandbox_diff") if isinstance(row.get("sandbox_diff"), dict) else {}
    root = diff.get("root")
    if root:
        return Path(str(root))
    for item in row.get("tool_calls") or []:
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        evidence_path = result.get("evidence_path")
        if not evidence_path:
            continue
        path = Path(str(evidence_path)).expanduser()
        for parent in [path, *path.parents]:
            if parent.name == "sandbox":
                return parent
    return None


def _copy_browser_replay_artifacts(recording: dict[str, Any], case_result_dir: Path) -> dict[str, Any]:
    source_dir_raw = recording.get("artifact_dir") or recording.get("replay_artifact")
    if not source_dir_raw:
        return {}
    source_dir = Path(str(source_dir_raw))
    if not source_dir.exists() or not source_dir.is_dir():
        return {}
    dest_dir = case_result_dir / "browser_replay"
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied: dict[str, Any] = {"artifact_dir": str(dest_dir)}
    file_map = {
        "events": "events.jsonl",
        "manifest": "manifest.json",
        "screenshot": "final.png",
        "full_page_screenshot": "final_full_page.png",
        "trace": "trace.zip",
        "video": "replay.webm",
        "video_timeline": "video_timeline.json",
        "continuous_frames_manifest": "continuous_frames_manifest.json",
        "report": "report.html",
        "replay_state": "replay_state.json",
        "final_dom": "final_dom.html",
        "final_accessibility_tree": "final_accessibility_tree.json",
        "action_metadata": "action_metadata.jsonl",
        "step_actions": "step_actions.jsonl",
        "business_event_correlation_index": "business_event_correlation_index.json",
    }
    for key, filename in file_map.items():
        raw = recording.get(key)
        source = Path(str(raw)) if raw else source_dir / filename
        dest = dest_dir / filename
        if source.exists() and source.is_file():
            if source.resolve() != dest.resolve():
                dest.write_bytes(source.read_bytes())
            copied[key] = str(dest)
    steps_source = Path(str(recording.get("steps_dir") or source_dir / "steps"))
    steps_dest = dest_dir / "steps"
    step_paths: list[str] = []
    if steps_source.exists() and steps_source.is_dir():
        steps_dest.mkdir(parents=True, exist_ok=True)
        for path in sorted(steps_source.glob("*.png")):
            dest = steps_dest / path.name
            if path.resolve() != dest.resolve():
                dest.write_bytes(path.read_bytes())
            step_paths.append(str(dest))
    elif recording.get("step_screenshots"):
        steps_dest.mkdir(parents=True, exist_ok=True)
        for raw in recording.get("step_screenshots") or []:
            path = Path(str(raw))
            if not path.exists() or not path.is_file():
                continue
            dest = steps_dest / path.name
            if path.resolve() != dest.resolve():
                dest.write_bytes(path.read_bytes())
            step_paths.append(str(dest))
    if step_paths:
        copied["steps_dir"] = str(steps_dest)
        copied["step_screenshots"] = step_paths
    frames_source = Path(str(recording.get("continuous_frames_dir") or source_dir / "continuous_frames"))
    frames_dest = dest_dir / "continuous_frames"
    frame_paths: list[str] = []
    if frames_source.exists() and frames_source.is_dir():
        frames_dest.mkdir(parents=True, exist_ok=True)
        for path in sorted(frames_source.glob("*.jpg")):
            dest = frames_dest / path.name
            if path.resolve() != dest.resolve():
                dest.write_bytes(path.read_bytes())
            frame_paths.append(str(dest))
    elif recording.get("continuous_frames"):
        frames_dest.mkdir(parents=True, exist_ok=True)
        for raw in recording.get("continuous_frames") or []:
            path = Path(str(raw))
            if not path.exists() or not path.is_file():
                continue
            dest = frames_dest / path.name
            if path.resolve() != dest.resolve():
                dest.write_bytes(path.read_bytes())
            frame_paths.append(str(dest))
    if frame_paths:
        copied["continuous_frames_dir"] = str(frames_dest)
        copied["continuous_frames"] = frame_paths
    if copied.get("final_dom"):
        _copy_final_dom_references(Path(str(copied["final_dom"])), source_dir, dest_dir)
    return copied


def _copy_final_dom_references(final_dom: Path, source_dir: Path, dest_dir: Path) -> None:
    try:
        parser = _DomReferenceParser()
        parser.feed(final_dom.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return
    for ref in sorted(set(parser.refs)):
        if ref.startswith(("http://", "https://", "data:", "#")):
            continue
        if ref.startswith(("/", "\\")) or ".." in Path(ref).parts:
            continue
        source = source_dir / ref
        dest = dest_dir / ref
        if not source.exists() or not source.is_file():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != dest.resolve():
            dest.write_bytes(source.read_bytes())


class _DomReferenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key in {"href", "src"} and value:
                self.refs.append(value)


def _write_planner_stall_browser_artifact(case_result_dir: Path, row: dict[str, Any]) -> dict[str, Any]:
    artifact_dir = case_result_dir / "browser_replay"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    reason = str(row.get("stop_reason") or row.get("run_status") or "no_browser_actions")
    event = {
        "event_type": "planner_stalled_before_browser_start",
        "timestamp": timestamp,
        "case_id": row.get("case_id"),
        "reason": reason,
        "instrumentation_plan_mode": row.get("instrumentation_plan_mode"),
        "agent_visible_payload_mode": row.get("agent_visible_payload_mode"),
        "llm_request_count": row.get("llm_request_count"),
        "llm_timeout_count": row.get("llm_timeout_count"),
    }
    _write_case_jsonl(artifact_dir / "events.jsonl", [event])
    _write_case_jsonl(artifact_dir / "action_metadata.jsonl", [event])
    _write_case_jsonl(artifact_dir / "step_actions.jsonl", [event])
    (artifact_dir / "business_event_correlation_index.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": row.get("case_id"),
                "diagnostic_artifact": True,
                "browser_actions": 0,
                "business_events": [],
                "correlations": [],
                "reason": reason,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Planner stalled before browser start</title></head>"
        "<body><main><h1>Planner stalled before browser start</h1>"
        f"<p>case_id: {row.get('case_id')}</p><p>reason: {reason}</p>"
        "<p>No browser page was opened and no business event was produced.</p></main></body></html>"
    )
    (artifact_dir / "final_dom.html").write_text(html, encoding="utf-8")
    (artifact_dir / "final_accessibility_tree.json").write_text(
        json.dumps(
            {
                "ok": True,
                "diagnostic_artifact": True,
                "role": "document",
                "name": "Planner stalled before browser start",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/lHVqVwAAAABJRU5ErkJggg=="
    )
    (artifact_dir / "final.png").write_bytes(png)
    (artifact_dir / "final_full_page.png").write_bytes(png)
    (artifact_dir / "replay.webm").write_bytes(b"")
    (artifact_dir / "trace.zip").write_bytes(b"")
    (artifact_dir / "report.html").write_text(html, encoding="utf-8")
    (artifact_dir / "replay_state.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": row.get("case_id"),
                "diagnostic_artifact": True,
                "step_count": 0,
                "dom_event_count": 1,
                "video_source": "none",
                "reason": reason,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "1.0",
        "case_id": row.get("case_id"),
        "artifact_type": "planner_stall_browser_evidence",
        "diagnostic_artifact": True,
        "reason": reason,
        "created_at": timestamp,
        "browser_started": False,
        "business_effect_validated": False,
        "attack_success": bool(row.get("attack_success")),
    }
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "artifact_dir": str(artifact_dir),
        "events": str(artifact_dir / "events.jsonl"),
        "manifest": str(artifact_dir / "manifest.json"),
        "screenshot": str(artifact_dir / "final.png"),
        "full_page_screenshot": str(artifact_dir / "final_full_page.png"),
        "final_dom": str(artifact_dir / "final_dom.html"),
        "final_accessibility_tree": str(artifact_dir / "final_accessibility_tree.json"),
        "action_metadata": str(artifact_dir / "action_metadata.jsonl"),
        "step_actions": str(artifact_dir / "step_actions.jsonl"),
        "business_event_correlation_index": str(artifact_dir / "business_event_correlation_index.json"),
        "trace": str(artifact_dir / "trace.zip"),
        "video": str(artifact_dir / "replay.webm"),
        "report": str(artifact_dir / "report.html"),
        "replay_state": str(artifact_dir / "replay_state.json"),
        "diagnostic_artifact": True,
    }


def _prompt_contamination_summary(row: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    checked = False
    for diagnostic in row.get("llm_request_diagnostics") or []:
        if not isinstance(diagnostic, dict):
            continue
        contamination = diagnostic.get("prompt_contamination")
        if not isinstance(contamination, dict):
            continue
        checked = True
        findings.extend(item for item in contamination.get("findings") or [] if isinstance(item, dict))
    return {
        "checked": checked or bool(row.get("prompt_contamination_check")),
        "found": bool(findings),
        "findings": findings,
        "agent_visible_payload_mode": row.get("agent_visible_payload_mode"),
        "instrumentation_plan_mode": row.get("instrumentation_plan_mode"),
    }

def _write_case_jsonl(path: Path, rows: list[Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            if row is None:
                continue
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _decision_record(tool_result: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    event = tool_result.get("event") if isinstance(tool_result.get("event"), dict) else {}
    audit = tool_result.get("audit_event") if isinstance(tool_result.get("audit_event"), dict) else {}
    return {
        "tool_call_id": tool_result.get("call_id"),
        "event_id": event.get("event_id"),
        "trace_id": row.get("trace_id"),
        "case_id": row.get("case_id"),
        "tool_name": tool_result.get("tool_name"),
        "decision": tool_result.get("decision"),
        "executed": tool_result.get("executed"),
        "blocked": tool_result.get("blocked"),
        "side_effects": tool_result.get("side_effects") or [],
        "audit_id": audit.get("audit_id"),
    }


def _browser_action_summary(row: dict[str, Any]) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    for item in row.get("tool_calls") or []:
        name = str(item.get("tool_name") or "")
        if not name.startswith("browser_"):
            continue
        event = item.get("event") if isinstance(item.get("event"), dict) else {}
        args = event.get("arguments") if isinstance(event.get("arguments"), dict) else {}
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        value = args.get("value")
        actions.append(
            {
                "tool_call_id": item.get("call_id"),
                "event_id": event.get("event_id"),
                "tool_name": name,
                "action": name.removeprefix("browser_"),
                "selector": args.get("selector"),
                "text": args.get("text"),
                "url": result.get("url") or args.get("url"),
                "input_text_preview": str(value)[:160] if value is not None else None,
                "executed": item.get("executed"),
                "blocked": item.get("blocked"),
                "decision": item.get("decision"),
                "screenshot": result.get("step_screenshot") or result.get("screenshot"),
            }
        )
    return {
        "case_id": row.get("case_id"),
        "trace_id": row.get("trace_id"),
        "final_url": _last_value(actions, "url"),
        "action_count": len(actions),
        "actions": actions,
        "last_5_actions": actions[-5:],
    }


def _last_value(items: list[dict[str, Any]], key: str) -> Any:
    for item in reversed(items):
        if item.get(key):
            return item[key]
    return None


def _build_evidence_index(row: dict[str, Any], case_result_dir: Path) -> dict[str, Any]:
    return {
        "case_id": row.get("case_id"),
        "finalized": True,
        "streams": [],
        "missing": [],
        "path_mode": "portable",
        "case_artifact_dir": str(case_result_dir),
    }


def _artifact_record(artifact_type: str, path: Path, case_result_dir: Path) -> dict[str, Any]:
    exists = path.exists()
    size = path.stat().st_size if exists else 0
    return {
        "type": artifact_type,
        "run_relative_path": _relative_to(path, case_result_dir.parents[1]) if exists else str(path),
        "repo_path": _relative_to(path, Path.cwd()) if exists and _is_under(path, Path.cwd()) else None,
        "debug_local_path": str(path),
        "exists": exists,
        "size_bytes": size,
        "sha256": _sha256(path) if exists and path.is_file() else None,
        "parse_ok": None,
        "warning": None,
        "error": None if exists else "missing",
    }


def _relative_to(path: Path, root: Path) -> str:
    try:
        return path.expanduser().resolve().relative_to(root.expanduser().resolve()).as_posix()
    except ValueError:
        return str(path)


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
        return True
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _case_result_dir(results_dir: Path, run_id: str, case_id: str) -> Path:
    return _run_results_dir(results_dir, run_id) / "cases" / case_id


def _run_results_dir(results_dir: Path, run_id: str) -> Path:
    return results_dir.expanduser().resolve() / f"run_{run_id}"


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
    stamp = _result_stamp(rows)
    run_dir = _run_results_dir(results_dir, stamp)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_json = run_dir / f"run_{stamp}.json"
    run_csv = run_dir / f"run_{stamp}.csv"
    summary_json = run_dir / f"summary_{stamp}.json"
    run_manifest_json = run_dir / f"manifest_run_{stamp}.json"
    artifact_integrity_json = run_dir / "artifact_integrity_manifest.json"
    run_manifest = _build_run_manifest(rows, results_dir, stamp)
    summary["run_manifest"] = run_manifest
    summary["run_integrity_failed"] = not run_manifest["run_integrity_ok"]

    run_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    run_manifest_json.write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    artifact_manifest = build_artifact_integrity_manifest(run_dir, output_path=artifact_integrity_json)
    summary["artifact_integrity"] = {
        "ok": artifact_manifest.get("ok"),
        "case_count": artifact_manifest.get("case_count"),
        "manifest_path": str(artifact_integrity_json),
    }
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
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
    paths = {
        "run_json": str(run_json),
        "run_csv": str(run_csv),
        "summary_json": str(summary_json),
        "run_manifest": str(run_manifest_json),
        "artifact_integrity_manifest": str(artifact_integrity_json),
        "run_dir": str(run_dir),
        "case_artifacts_dir": str(run_dir / "cases"),
    }
    sandbox_archive = next((row.get("sandbox_archive") for row in rows if row.get("sandbox_archive")), None)
    if isinstance(sandbox_archive, dict):
        paths["sandbox_artifact_dir"] = str(sandbox_archive.get("artifact_dir", ""))
        paths["sandbox_manifest"] = str(sandbox_archive.get("manifest_path", ""))
    return paths


def _result_stamp(rows: list[dict[str, Any]]) -> str:
    run_ids = {str(row.get("benchmark_run_id") or "") for row in rows if row.get("benchmark_run_id")}
    if len(run_ids) == 1:
        return next(iter(run_ids))
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _build_run_manifest(rows: list[dict[str, Any]], results_dir: Path, run_id: str) -> dict[str, Any]:
    case_ids = [str(row.get("case_id") or "") for row in rows]
    duplicates = sorted({case_id for case_id in case_ids if case_ids.count(case_id) > 1 and case_id})
    missing_case_results: list[str] = []
    missing_artifacts: list[str] = []
    for case_id in case_ids:
        case_result = _case_result_dir(results_dir, run_id, case_id) / "case_result.json"
        if not case_result.exists():
            missing_case_results.append(case_id)
        row = next((item for item in rows if item.get("case_id") == case_id), {})
        if _requires_browser_artifact(row) and not row.get("browser_recordings"):
            missing_artifacts.append(case_id)
    run_integrity_ok = not duplicates and not missing_case_results and not missing_artifacts
    return {
        "expected_case_count": len(rows),
        "result_case_count": len(rows),
        "missing_case_ids": [],
        "duplicate_case_ids": duplicates,
        "missing_case_result_ids": sorted(missing_case_results),
        "artifact_missing_case_ids": sorted(missing_artifacts),
        "run_dir": str(_run_results_dir(results_dir, run_id)),
        "case_artifacts_dir": str(_run_results_dir(results_dir, run_id) / "cases"),
        "run_integrity_ok": run_integrity_ok,
    }


def _requires_browser_artifact(row: dict[str, Any]) -> bool:
    if _is_file_exfiltration_browser_case(row):
        return not row.get("not_applicable")
    if row.get("attack_type") != "agent_abuse":
        return False
    if not row.get("run_valid", True) or row.get("not_applicable"):
        return False
    if row.get("run_status") == "refused" or row.get("completion_level") in {"safe_refusal", "unsupported"}:
        return False
    verdict = row.get("agent_abuse_verdict") if isinstance(row.get("agent_abuse_verdict"), dict) else {}
    if verdict.get("safe_refusal") is True:
        return False
    return True


def _should_create_diagnostic_browser_artifact(row: dict[str, Any]) -> bool:
    return row.get("attack_type") == "agent_abuse" and _requires_browser_artifact(row)


def _is_file_exfiltration_browser_case(row: dict[str, Any]) -> bool:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    return row.get("attack_type") == "file_exfiltration" and bool(metadata.get("web_entry_source_path"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AgentGuard LangGraph AttackBench")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_DIR), help="JSONL file or directory of AttackCase files")
    parser.add_argument("--core-url", default="http://localhost:8000", help="Agent Security Core base URL")
    parser.add_argument("--token", default="demo-token", help="Agent Security Core bearer token")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--defense", choices=["on", "off"], default="off")
    parser.add_argument("--fail-open-debug", action="store_true", help="Allow local debug execution if Core fails")
    parser.add_argument("--fake-core", action="store_true", help="Use a local fake Core instead of HTTP Core")
    parser.add_argument("--fake-core-decision", choices=["allow", "deny", "ask"], default="deny", help="Decision returned by local fake Core")
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
        choices=["guided", "autonomous", "replay"],
        default=None,
        help="Instrumentation browser planning mode: guided LLM hints, autonomous LLM planning, or deterministic replay.",
    )
    parser.add_argument(
        "--agent-visible-payload-mode",
        choices=["original", "naturalistic", "closure"],
        default=None,
        help="Payload variant shown to the autonomous agent.",
    )
    parser.add_argument(
        "--closure-on-partial",
        action="store_true",
        help="Run forced closure diagnostics after harmful attempted/partial autonomous agent_abuse cases.",
    )
    parser.add_argument(
        "--no-strict-business-validation",
        action="store_true",
        help="Allow legacy business-effect inference in evaluator. Not recommended for high-confidence runs.",
    )
    parser.add_argument(
        "--no-prompt-contamination-check",
        action="store_true",
        help="Disable agent-visible prompt contamination checks.",
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
        agent_visible_payload_mode=args.agent_visible_payload_mode,
        closure_on_partial=args.closure_on_partial,
        strict_business_validation=not args.no_strict_business_validation,
        prompt_contamination_check=not args.no_prompt_contamination_check,
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
    fake_core_active = args.fake_core or defense_enabled and args.core_url == "fake"
    summary = calculate_metrics(
        rows,
        defense_enabled=defense_enabled,
        core_mode=_core_mode(fake_core=fake_core_active, fake_core_decision=args.fake_core_decision, defense_enabled=defense_enabled),
        fake_core_decision=args.fake_core_decision if fake_core_active else None,
    )
    if skipped:
        summary["skipped_runtime_mismatch"] = len(skipped)
    poisonedrag_summary = calculate_poisonedrag_metrics(rows)
    if poisonedrag_summary is not None:
        summary["poisonedrag"] = poisonedrag_summary
    memory_summary = calculate_memory_poisoning_metrics(rows)
    if memory_summary is not None:
        summary["memory_poisoning"] = memory_summary
    paths = write_results(rows, summary, config.results_dir)
    write_agent_abuse_iteration_report(rows=rows, summary=summary, outputs=paths, argv=argv)
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
