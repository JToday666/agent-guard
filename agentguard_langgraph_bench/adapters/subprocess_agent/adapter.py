"""Subprocess adapter for external agents that use the benchmark tool server."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from agentguard_langgraph_bench.adapters.metadata import safe_agent_metadata as _safe_agent_metadata
from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.scoring.tool_hijacking import case_extra_list
from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext, CaseRunResult


class SubprocessAgentAdapter:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.runtime = str(getattr(config, "runtime", "") or "subprocess")
        configured_name = str(getattr(config, "agent_adapter", "") or "").strip()
        self.name = configured_name or "subprocess"

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        if context.tool_server is None:
            return _error(case, context, "Subprocess adapter requires --tool-server-mode http.")
        command = _agent_command(self.config)
        if not command:
            return _error(case, context, "--agent-command is required for subprocess adapter.")
        if hasattr(context.tool_server, "set_case_context"):
            context.tool_server.set_case_context(case, context)

        input_path = context.results_dir / f"{context.trace_id}_subprocess_input.json"
        output_path = context.results_dir / f"{context.trace_id}_subprocess_output.json"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text(
            json.dumps(_agent_payload(case, context, context.tool_server.base_url), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        argv = [
            part.format(input_json=str(input_path), output_json=str(output_path))
            for part in shlex.split(command)
        ]
        timeout_seconds = _subprocess_timeout(self.config)
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - user-provided benchmark adapter command
                argv,
                cwd=Path.cwd(),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            response = _read_output(output_path)
            error = None if completed.returncode == 0 else completed.stderr or f"subprocess exited {completed.returncode}"
        except subprocess.TimeoutExpired as exc:
            response = _timeout_response(case, context, input_path, output_path, timeout_seconds, started, exc)
            completed = None
            error = response["raw_state"]["adapter_error"]
        except Exception as exc:
            response = {}
            completed = None
            error = str(exc)
        tool_calls = context.tool_server.events()
        response_raw_state = response.get("raw_state") if isinstance(response.get("raw_state"), dict) else {}
        response_behavior_events = response.get("behavior_events") if isinstance(response.get("behavior_events"), list) else []
        return CaseRunResult(
            case_id=case.case_id,
            trace_id=context.trace_id,
            runtime=str(response.get("runtime") or context.runtime),
            adapter_name=str(response.get("adapter_name") or self.name),
            tool_calls=tool_calls,
            behavior_events=response_behavior_events,
            final_answer=str(response.get("final_answer") or ""),
            raw_logs=[
                {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}
            ]
            if completed is not None
            else [],
            raw_state={
                **response_raw_state,
                "agent_response": response,
                "input_json": str(input_path),
                "output_json": str(output_path),
            },
            blocked=any(item.get("blocked") and not item.get("runtime_policy_blocked") for item in tool_calls),
            executed=any(item.get("executed") for item in tool_calls),
            error=error,
        )

    def teardown(self) -> None:
        return None


def create_adapter(config: Any) -> SubprocessAgentAdapter:
    return SubprocessAgentAdapter(config)


def _agent_command(config: Any) -> str:
    command = str(getattr(config, "agent_command", "") or "").strip()
    if command:
        return command
    return ""


def _subprocess_timeout(config: Any) -> float:
    explicit = getattr(config, "subprocess_timeout", None)
    if explicit is not None:
        return float(explicit)
    core_timeout = float(getattr(config, "timeout", 5.0) or 5.0)
    wall_clock_timeout = float(getattr(config, "max_wall_clock_seconds", 0.0) or 0.0)
    if wall_clock_timeout > 0:
        return max(core_timeout, wall_clock_timeout + 60.0)
    llm_timeout = float(getattr(config, "llm_request_timeout", 0.0) or 0.0)
    max_rounds = int(getattr(config, "llm_max_tool_rounds", 0) or 0)
    if llm_timeout <= 0 or max_rounds <= 0:
        return core_timeout
    # External agents own the LLM loop and tool calls; give the subprocess the
    # same planning budget plus room for browser/tool execution and JSON I/O.
    return max(core_timeout, llm_timeout * max_rounds + 30.0)


def _agent_payload(case: AttackCase, context: CaseContext, tool_server_url: str) -> dict[str, Any]:
    runtime_policy = _runtime_policy(case)
    mcp_tool_catalog = _agent_visible_mcp_tool_catalog(case, context)
    mcp_catalog_view = _mcp_catalog_view(context)
    return {
        "case_id": case.case_id,
        "trace_id": context.trace_id,
        "input": case.input.model_dump(),
        "metadata": _safe_agent_metadata(case.metadata),
        "mcp_catalog_view": mcp_catalog_view,
        "mcp_tool_catalog": mcp_tool_catalog,
        "runtime_policy": runtime_policy,
        "runtime": context.runtime,
        "adapter_name": context.adapter_name,
        "run_config": {
            "llm_provider": getattr(context.config, "llm_provider", None),
            "llm_model": getattr(context.config, "llm_model", None),
            "llm_request_timeout": getattr(context.config, "llm_request_timeout", None),
            "llm_max_retries": getattr(context.config, "llm_max_retries", None),
            "max_tool_rounds": getattr(context.config, "llm_max_tool_rounds", None),
            "max_wall_clock_seconds": getattr(context.config, "max_wall_clock_seconds", None),
            "langgraph_recursion_limit": getattr(context.config, "langgraph_recursion_limit", None),
            "browser_mode": getattr(context.config, "browser_mode", None),
            "browser_action_timeout": getattr(context.config, "browser_action_timeout", None),
            "instrumentation_plan_mode": getattr(context.config, "instrumentation_plan_mode", None),
            "llm_fallback_to_case_plan": getattr(context.config, "llm_fallback_to_case_plan", None),
            "langgraph_graph_module": getattr(context.config, "langgraph_graph_module", None),
            "langgraph_graph_object": getattr(context.config, "langgraph_graph_object", None),
        },
        "tool_manifest_url": f"{tool_server_url}/tools?case_id={case.case_id}&trace_id={context.trace_id}",
        "tool_invocation_base_url": f"{tool_server_url}/tools",
    }


def _mcp_catalog_view(context: CaseContext) -> str:
    view = str(getattr(context.config, "tool_catalog_view", "") or "").strip()
    return view if view in {"clean", "poisoned"} else "poisoned"


def _agent_visible_mcp_tool_catalog(case: AttackCase, context: CaseContext) -> list[dict[str, Any]]:
    if case.attack_type != "tool_hijacking":
        return []
    view = _mcp_catalog_view(context)
    catalog = case_extra_list(case, f"{view}_tool_catalog")
    if not catalog and view == "poisoned":
        catalog = case_extra_list(case, "clean_tool_catalog")
    if not catalog and view == "clean":
        catalog = case_extra_list(case, "poisoned_tool_catalog")
    return [_public_mcp_descriptor(item) for item in catalog if isinstance(item, dict)]


def _public_mcp_descriptor(item: dict[str, Any]) -> dict[str, Any]:
    allowed = ("server", "server_name", "tool", "tool_name", "name", "title", "description", "input_schema", "permissions", "trust_level", "version")
    return {key: item[key] for key in allowed if key in item}


def _timeout_response(
    case: AttackCase,
    context: CaseContext,
    input_path: Path,
    output_path: Path,
    timeout_seconds: float,
    started: float,
    exc: subprocess.TimeoutExpired,
) -> dict[str, Any]:
    elapsed = max(0.0, time.monotonic() - started)
    message = f"subprocess timed out after {timeout_seconds:.1f} seconds"
    stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
    stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    diagnostics = {
        "ok": False,
        "outcome": "adapter_timeout",
        "error_type": "TimeoutExpired",
        "error": message,
        "timeout_seconds": timeout_seconds,
        "elapsed_seconds": elapsed,
        "provider": getattr(context.config, "llm_provider", None),
        "model": getattr(context.config, "llm_model", None),
        "llm_request_timeout": getattr(context.config, "llm_request_timeout", None),
        "max_tool_rounds": getattr(context.config, "llm_max_tool_rounds", None),
        "max_wall_clock_seconds": getattr(context.config, "max_wall_clock_seconds", None),
        "langgraph_recursion_limit": getattr(context.config, "langgraph_recursion_limit", None),
    }
    raw_state = {
        "case_id": case.case_id,
        "trace_id": context.trace_id,
        "instrumentation_plan_mode": getattr(context.config, "instrumentation_plan_mode", "autonomous"),
        "planning_source": "llm_autonomous",
        "guided_plan_applied": False,
        "fallback_applied": False,
        "stop_reason": "adapter_timeout",
        "adapter_error": message,
        "runtime_limits": {
            "max_tool_rounds": getattr(context.config, "llm_max_tool_rounds", None),
            "max_wall_clock_seconds": getattr(context.config, "max_wall_clock_seconds", None),
        },
        "llm_planning_evidence": [
            {
                "planning_source": "llm_autonomous",
                "guided_plan_applied": False,
                "fallback_applied": False,
                "diagnostics": diagnostics,
            }
        ],
        "langgraph_graph_module": getattr(context.config, "langgraph_graph_module", None)
        or "external:configured-subprocess",
        "langgraph_graph_object": getattr(context.config, "langgraph_graph_object", None) or "build_graph",
        "langgraph_recursion_limit": getattr(context.config, "langgraph_recursion_limit", None),
        "runtime_config": {
            "llm_provider": getattr(context.config, "llm_provider", None),
            "llm_model": getattr(context.config, "llm_model", None),
            "llm_request_timeout": getattr(context.config, "llm_request_timeout", None),
            "max_tool_rounds": getattr(context.config, "llm_max_tool_rounds", None),
            "max_wall_clock_seconds": getattr(context.config, "max_wall_clock_seconds", None),
            "langgraph_recursion_limit": getattr(context.config, "langgraph_recursion_limit", None),
        },
        "input_json": str(input_path),
        "output_json": str(output_path),
    }
    return {
        "runtime": "langgraph",
        "adapter_name": context.adapter_name,
        "final_answer": "",
        "behavior_events": [],
        "raw_logs": [{"stdout": stdout, "stderr": stderr, "returncode": None}],
        "raw_state": raw_state,
    }


def _runtime_policy(case: AttackCase) -> dict[str, Any]:
    metadata = dict(case.metadata or {})
    explicit_browser_plan = any(step.tool.startswith("browser_") for step in case.tool_plan)
    browser_available = explicit_browser_plan or bool(
        metadata.get("web_entry_source_path")
        or metadata.get("local_web_entry_source_path")
        or metadata.get("original_web_entry_source_path")
    )
    if not browser_available and not _is_memory_reference_case(case, metadata):
        browser_available = bool(
            metadata.get("entry_url")
            or metadata.get("local_service_page_url")
            or metadata.get("web_entry_url")
        )
    return {
        "browser_available": browser_available,
        "mcp_available": any(step.tool == "mcp_call" for step in case.tool_plan) or case.attack_type == "tool_hijacking",
        "rag_available": any(step.tool.startswith("rag_") for step in case.tool_plan) or case.metadata.get("source_dataset") == "PoisonedRAG",
        "memory_available": any(step.tool.startswith("memory_") for step in case.tool_plan) or case.attack_type == "memory_poisoning",
    }


def _is_memory_reference_case(case: AttackCase, metadata: dict[str, Any]) -> bool:
    source_group = str(metadata.get("source_group") or "").lower()
    phase = str(metadata.get("phase") or "").lower()
    return (
        case.attack_type == "memory_poisoning"
        or source_group.startswith("memory_poisoning")
        or phase in {"poison_seed", "trigger_query", "conflict_probe", "clean_control", "benign_seed"}
    )


def _read_output(output_path: Path) -> dict[str, Any]:
    if not output_path.exists():
        return {}
    try:
        parsed = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _error(case: AttackCase, context: CaseContext, error: str) -> CaseRunResult:
    return CaseRunResult(
        case_id=case.case_id,
        trace_id=context.trace_id,
        runtime=context.runtime,
        adapter_name="subprocess",
        error=error,
    )
