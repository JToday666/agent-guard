from pathlib import Path

from agentguard_langgraph_bench.adapter import LangGraphAdapter
from agentguard_langgraph_bench.bench.config import BenchConfig, ensure_sandbox
from agentguard_langgraph_bench.adapter.secure_tool_node import SecureToolNode
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


class StaticDecisionCore:
    def __init__(self, decision):
        self.decision = decision
        self.audit_events = []

    def evaluate_tool_call(self, event):
        return {
            "decision_id": f"dec_{self.decision}",
            "decision": self.decision,
            "risk_score": 0 if self.decision == "allow" else 80,
            "severity": "low" if self.decision == "allow" else "high",
            "rule_hits": [],
            "reason": f"static {self.decision}",
            "safe_message": "blocked" if self.decision != "allow" else None,
            "approval": None,
            "latency_ms": 0,
        }

    def submit_audit_event(self, event):
        self.audit_events.append(event)
        return {"ok": True}


class FailingCore:
    def evaluate_tool_call(self, event):
        raise RuntimeError("core down")

    def submit_audit_event(self, event):
        return {"ok": True}


def make_node(tmp_path: Path, decision: str):
    ensure_sandbox(tmp_path)
    (tmp_path / "files" / "docs" / "public.txt").write_text("hello", encoding="utf-8")
    core = StaticDecisionCore(decision)
    adapter = LangGraphAdapter(BenchConfig(defense_enabled=True, sandbox_dir=tmp_path), core_client=core)
    return SecureToolNode(adapter=adapter, tool_registry=MockToolRegistry(tmp_path)), core


def test_policy_allow_executes_tool(tmp_path):
    node, core = make_node(tmp_path, "allow")

    result = node.invoke_tool(
        tool_name="read_file",
        arguments={"path": "/docs/public.txt"},
        security={"case_id": "BN-001", "attack_type": "benign", "is_malicious": False, "user_task": "read"},
        trace_id="trace_allow",
    )

    assert result.executed is True
    assert result.blocked is False
    assert result.result == "hello"
    assert core.audit_events


def test_policy_deny_does_not_execute_tool(tmp_path):
    node, _ = make_node(tmp_path, "deny")

    result = node.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/blocked.txt", "content": "nope"},
        security={"case_id": "PI-001", "attack_type": "prompt_injection", "is_malicious": True},
        trace_id="trace_deny",
    )

    assert result.executed is False
    assert result.blocked is True
    assert not (tmp_path / "files" / "reports" / "blocked.txt").exists()


def test_policy_ask_does_not_directly_execute_tool(tmp_path):
    node, _ = make_node(tmp_path, "ask")

    result = node.invoke_tool(
        tool_name="send_email",
        arguments={"to": "user@example.com", "subject": "hello", "body": "body"},
        security={"case_id": "BN-003", "attack_type": "benign", "is_malicious": False},
        trace_id="trace_ask",
    )

    assert result.executed is False
    assert result.blocked is True
    assert not (tmp_path / "outbox" / "emails.jsonl").exists()


def test_core_failure_fail_closed_blocks_tool(tmp_path):
    ensure_sandbox(tmp_path)
    adapter = LangGraphAdapter(
        BenchConfig(defense_enabled=True, fail_closed=True, sandbox_dir=tmp_path),
        core_client=FailingCore(),
    )
    node = SecureToolNode(adapter=adapter, tool_registry=MockToolRegistry(tmp_path))

    result = node.invoke_tool(
        tool_name="write_file",
        arguments={"path": "/reports/failclosed.txt", "content": "nope"},
        security={"case_id": "PI-001", "attack_type": "prompt_injection", "is_malicious": True},
        trace_id="trace_fail_closed",
    )

    assert result.executed is False
    assert result.decision == "deny"
    assert not (tmp_path / "files" / "reports" / "failclosed.txt").exists()
