from agentguard_langgraph_bench.adapter import LangGraphAdapter
from agentguard_langgraph_bench.bench.config import BenchConfig


def test_audit_event_contains_dashboard_fields():
    adapter = LangGraphAdapter.with_fake_deny_core(BenchConfig(defense_enabled=True))
    event, decision = adapter.evaluate_before_tool(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        security={
            "case_id": "PI-001",
            "attack_type": "prompt_injection",
            "is_malicious": True,
            "source_type": "email",
            "source_trust": "untrusted",
            "user_task": "summarize inbox",
        },
        trace_id="trace_test",
        call_id="call_test",
    )
    audit = adapter.build_audit_event(event, decision)

    assert audit.schema_version == "0.4"
    assert audit.record_type == "policy_evaluation"
    assert audit.stage == "before_tool_call"
    assert audit.event_type == "tool_call_proposed"
    assert audit.decision == "deny"
    assert audit.blocked is True
    assert audit.resource_targets == ["/private/token.txt"]
    assert audit.rule_hits == ["FAKE_CORE_ALWAYS_DENY"]
    assert audit.links["event_id"] == event.event_id
    assert audit.links["decision_id"] == decision.decision_id
