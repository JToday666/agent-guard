"""Subprocess adapter for external agents that use the benchmark tool server."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext, CaseRunResult


class SubprocessAgentAdapter:
    name = "subprocess"

    def __init__(self, config: Any) -> None:
        self.config = config
        self.runtime = str(getattr(config, "runtime", "") or "subprocess")

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        if context.tool_server is None:
            return _error(case, context, "Subprocess adapter requires --tool-server-mode http.")
        command = str(getattr(self.config, "agent_command", "") or "").strip()
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
        try:
            completed = subprocess.run(  # noqa: S603 - user-provided benchmark adapter command
                argv,
                cwd=Path.cwd(),
                capture_output=True,
                text=True,
                timeout=_subprocess_timeout(self.config),
                check=False,
            )
            response = _read_output(output_path)
            error = None if completed.returncode == 0 else completed.stderr or f"subprocess exited {completed.returncode}"
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


def _subprocess_timeout(config: Any) -> float:
    explicit = getattr(config, "subprocess_timeout", None)
    if explicit is not None:
        return float(explicit)
    core_timeout = float(getattr(config, "timeout", 5.0) or 5.0)
    llm_timeout = float(getattr(config, "llm_request_timeout", 0.0) or 0.0)
    max_rounds = int(getattr(config, "llm_max_tool_rounds", 0) or 0)
    if llm_timeout <= 0 or max_rounds <= 0:
        return core_timeout
    # External agents own the LLM loop and tool calls; give the subprocess the
    # same planning budget plus room for browser/tool execution and JSON I/O.
    return max(core_timeout, llm_timeout * max_rounds + 30.0)


def _agent_payload(case: AttackCase, context: CaseContext, tool_server_url: str) -> dict[str, Any]:
    runtime_policy = _runtime_policy(case)
    return {
        "case_id": case.case_id,
        "trace_id": context.trace_id,
        "input": case.input.model_dump(),
        "metadata": _safe_agent_metadata(case.metadata),
        "runtime_policy": runtime_policy,
        "tool_manifest_url": f"{tool_server_url}/tools?case_id={case.case_id}&trace_id={context.trace_id}",
        "tool_invocation_base_url": f"{tool_server_url}/tools",
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


def _safe_agent_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    blocked = {
        "expected_decision",
        "success_condition",
        "normal_oracle",
        "attack_oracle",
        "task_oracle",
        "safety_oracle",
        "sequence_oracle",
        "permission_oracle",
        "response_oracle",
        "incorrect_answer",
        "target_incorrect_answer",
    }
    return {key: value for key, value in metadata.items() if key not in blocked}


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
