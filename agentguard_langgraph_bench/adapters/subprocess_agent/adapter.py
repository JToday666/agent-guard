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
    runtime = "subprocess"

    def __init__(self, config: Any) -> None:
        self.config = config

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        if context.tool_server is None:
            return _error(case, context, "Subprocess adapter requires --tool-server-mode http.")
        command = str(getattr(self.config, "agent_command", "") or "").strip()
        if not command:
            return _error(case, context, "--agent-command is required for subprocess adapter.")

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
                timeout=float(getattr(self.config, "timeout", 5.0)),
                check=False,
            )
            response = _read_output(output_path)
            error = None if completed.returncode == 0 else completed.stderr or f"subprocess exited {completed.returncode}"
        except Exception as exc:
            response = {}
            completed = None
            error = str(exc)
        tool_calls = context.tool_server.events()
        return CaseRunResult(
            case_id=case.case_id,
            trace_id=context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=tool_calls,
            final_answer=str(response.get("final_answer") or ""),
            raw_logs=[
                {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}
            ]
            if completed is not None
            else [],
            raw_state={"agent_response": response, "input_json": str(input_path), "output_json": str(output_path)},
            blocked=any(item.get("blocked") for item in tool_calls),
            executed=any(item.get("executed") for item in tool_calls),
            error=error,
        )

    def teardown(self) -> None:
        return None


def create_adapter(config: Any) -> SubprocessAgentAdapter:
    return SubprocessAgentAdapter(config)


def _agent_payload(case: AttackCase, context: CaseContext, tool_server_url: str) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "trace_id": context.trace_id,
        "input": case.input.model_dump(),
        "metadata": _safe_agent_metadata(case.metadata),
        "tool_manifest_url": f"{tool_server_url}/tools",
        "tool_invocation_base_url": f"{tool_server_url}/tools",
    }


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
        runtime="subprocess",
        adapter_name="subprocess",
        error=error,
    )
