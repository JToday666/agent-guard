from __future__ import annotations

from agentguard_langgraph_bench.bench.config import BenchConfig, ensure_sandbox
from agentguard_langgraph_bench.bench.runtime.tool_gateway import GuardedToolGateway
from agentguard_langgraph_bench.bench.tools import MockToolRegistry
from agentguard_langgraph_bench.guard import GuardAdapter, GuardConfig


class RecordingAllowCore:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.audit_events: list[dict] = []

    def evaluate_tool_call(self, event: dict) -> dict:
        self.events.append(event)
        return {
            "decision_id": "dec_allow",
            "decision": "allow",
            "risk_score": 0,
            "severity": "low",
            "rule_hits": [],
            "reason": "allow for compatibility test",
            "latency_ms": 0,
        }

    def submit_audit_event(self, event: dict) -> dict:
        self.audit_events.append(event)
        return {"ok": True}


def test_gateway_core_receives_normalized_arguments_and_audit_preserves_raw(tmp_path) -> None:
    ensure_sandbox(tmp_path)
    (tmp_path / "files" / "docs" / "public.txt").write_text("hello", encoding="utf-8")
    core = RecordingAllowCore()
    bench_config = BenchConfig(defense_enabled=True, sandbox_dir=tmp_path)
    guard = GuardAdapter(GuardConfig.from_bench_config(bench_config, runtime="langgraph", agent_id="subprocess"), core_client=core)
    gateway = GuardedToolGateway(guard_adapter=guard, tool_runtime=MockToolRegistry(tmp_path))

    result = gateway.invoke_tool(
        tool_name="read_file",
        arguments={"path": "docs/public.txt"},
        raw_arguments={"file_path": "/docs/public.txt"},
        compatibility={
            "raw_arguments": {"file_path": "/docs/public.txt"},
            "normalized_arguments": {"path": "docs/public.txt"},
            "repairs": ["read_file.file_path_to_path"],
        },
        security={"case_id": "BN-001", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_compat",
        call_id="call_compat",
    )

    assert result.executed is True
    assert core.events[0]["arguments"] == {"path": "docs/public.txt"}
    assert core.events[0]["metadata"]["compatibility"]["raw_arguments"] == {"file_path": "/docs/public.txt"}
    assert result.event["metadata"]["compatibility"]["repairs"] == ["read_file.file_path_to_path"]
    assert core.audit_events == []
    assert result.audit_event is None
