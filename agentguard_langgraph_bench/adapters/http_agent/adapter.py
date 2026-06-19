"""Adapter for external HTTP agents that use the benchmark tool server."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext, CaseRunResult


class HttpAgentAdapter:
    name = "http"
    runtime = "http"

    def __init__(self, config: Any) -> None:
        self.config = config

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        if context.tool_server is None:
            return CaseRunResult(
                case_id=case.case_id,
                trace_id=context.trace_id,
                runtime=self.runtime,
                adapter_name=self.name,
                error="HTTP agent adapter requires --tool-server-mode http.",
            )
        endpoint = getattr(self.config, "agent_endpoint", "")
        response: dict[str, Any] = {}
        error: str | None = None
        if endpoint:
            payload = _agent_payload(case, context, context.tool_server.base_url)
            try:
                response = _post_json(endpoint, payload, timeout=float(getattr(self.config, "timeout", 5.0)))
            except Exception as exc:
                error = str(exc)
        tool_calls = context.tool_server.events()
        return CaseRunResult(
            case_id=case.case_id,
            trace_id=context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=tool_calls,
            final_answer=str(response.get("final_answer") or ""),
            raw_logs=list(response.get("logs") or []) if isinstance(response.get("logs"), list) else [],
            raw_state={"agent_response": response},
            blocked=any(item.get("blocked") for item in tool_calls),
            executed=any(item.get("executed") for item in tool_calls),
            error=error,
        )

    def teardown(self) -> None:
        return None


def create_adapter(config: Any) -> HttpAgentAdapter:
    return HttpAgentAdapter(config)


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


def _post_json(endpoint: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(endpoint, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - user-provided local benchmark agent endpoint
            parsed = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise RuntimeError(f"HTTP agent request failed: {exc}") from exc
    return parsed if isinstance(parsed, dict) else {"response": parsed}
