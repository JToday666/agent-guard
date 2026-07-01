from __future__ import annotations

import json
from urllib.request import Request, urlopen

from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext
from agentguard_langgraph_bench.bench.runtime.tool_server import BenchmarkToolServer


class _Runtime:
    def list_tools(self) -> dict[str, dict]:
        return {
            "read_file": {"name": "read_file", "input_schema": {"type": "object"}},
            "browser_start": {"name": "browser_start", "input_schema": {"type": "object"}},
        }


class _Gateway:
    tool_runtime = _Runtime()

    def invoke_tool(self, **kwargs):
        raise AssertionError("runtime policy should block before gateway execution")


def _case(tool_plan: list[dict], metadata: dict | None = None) -> AttackCase:
    return AttackCase.model_validate(
        {
            "case_id": "BN-001",
            "attack_type": "benign",
            "is_malicious": False,
            "input": {"source_type": "dataset", "source_trust": "trusted", "payload": "Do the local task."},
            "target_behavior": {"tool": "read_file", "operation": "read"},
            "expected_decision": "allow",
            "success_condition": {"type": "tool", "tool": "read_file"},
            "tool_plan": tool_plan,
            "metadata": metadata or {},
        }
    )


def _context(case: AttackCase) -> CaseContext:
    return CaseContext(
        case=case,
        trace_id="trace-test",
        runtime="langgraph",
        adapter_name="subprocess",
        sandbox_dir=__import__("pathlib").Path("."),
        results_dir=__import__("pathlib").Path("."),
        security={"case_id": case.case_id, "metadata": case.metadata},
        tool_gateway=None,
        tool_runtime=None,
        config=None,
    )


def test_get_tools_hides_browser_tools_for_non_browser_case() -> None:
    case = _case([{"tool": "read_file", "arguments": {"path": "public.txt"}}])
    server = BenchmarkToolServer(_Gateway(), port=0).start()
    try:
        server.set_case_context(case, _context(case))
        payload = json.loads(urlopen(f"{server.base_url}/tools", timeout=2).read().decode("utf-8"))
    finally:
        server.stop()

    assert [item["name"] for item in payload["tools"]] == ["read_file"]
    assert payload["runtime_policy"]["browser_available"] is False


def test_get_tools_exposes_browser_tools_for_browser_case() -> None:
    case = _case(
        [{"tool": "browser_start", "arguments": {"url": "http://127.0.0.1:18080/local-instrumentation/index.html"}}],
        metadata={"web_entry_source_path": "bench/datasets/instrumentation/client_workflows/PI-005/index.html"},
    )
    server = BenchmarkToolServer(_Gateway(), port=0).start()
    try:
        server.set_case_context(case, _context(case))
        payload = json.loads(urlopen(f"{server.base_url}/tools", timeout=2).read().decode("utf-8"))
    finally:
        server.stop()

    names = {item["name"] for item in payload["tools"]}
    assert "browser_start" in names
    browser_start = next(item for item in payload["tools"] if item["name"] == "browser_start")
    assert browser_start["accepted_aliases"]["session_id"] == "run_id"


def test_post_browser_tool_is_blocked_for_non_browser_case() -> None:
    case = _case([{"tool": "read_file", "arguments": {"path": "public.txt"}}])
    server = BenchmarkToolServer(_Gateway(), port=0).start()
    try:
        server.set_case_context(case, _context(case))
        request = Request(
            f"{server.base_url}/tools/browser_start",
            data=json.dumps({"arguments": {"url": "http://127.0.0.1:18080/x"}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        payload = json.loads(urlopen(request, timeout=2).read().decode("utf-8"))
    finally:
        server.stop()

    assert payload["status"] == "blocked_by_runtime_policy"
    assert payload["runtime_policy_blocked"] is True
    assert server.events()[0]["tool_name"] == "browser_start"
