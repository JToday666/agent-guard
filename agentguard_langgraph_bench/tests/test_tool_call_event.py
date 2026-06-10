from agentguard_langgraph_bench.adapter import LangGraphAdapter
from agentguard_langgraph_bench.config import BenchConfig


def test_tool_call_event_schema_uses_final_contract():
    adapter = LangGraphAdapter.with_fake_deny_core(BenchConfig(defense_enabled=True))
    event = adapter.build_tool_call_event(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        security={
            "case_id": "PI-001",
            "attack_type": "indirect_prompt_injection",
            "is_malicious": True,
            "source_type": "email",
            "source_trust": "untrusted",
            "user_task": "summarize inbox",
        },
        trace_id="trace_test",
        call_id="call_test",
    )

    assert event.schema_version == "0.3"
    assert event.event_type == "tool_call_proposed"
    assert event.runtime == "langgraph"
    assert event.pre_execution is True
    assert event.tool.name == "read_file"
    assert event.derived_resources[0].target == "/private/token.txt"
    assert event.derived_resources[0].data_classification == "secret"


def test_tool_call_event_carries_mcpsafety_hijacking_metadata():
    adapter = LangGraphAdapter.with_fake_deny_core(BenchConfig(defense_enabled=True))
    hijacking = {
        "mode": "gateway_hijacking",
        "target_server": "yfinance",
        "target_tool": "get_historical_stock_prices",
        "required_dependency": "get_yahoo_finance_news",
        "dependency_type": "function_dependency",
        "source_evaluator": "check_dependency",
    }

    event = adapter.build_tool_call_event(
        tool_name="mcp_call",
        arguments={
            "server": "yfinance",
            "tool": "get_historical_stock_prices",
            "arguments": {"ticker": "GOOGL"},
            "hijacking": hijacking,
        },
        security={
            "case_id": "MCP-009",
            "attack_type": "tool_hijack",
            "is_malicious": True,
            "metadata": {"source_dataset": "MCPSafety"},
        },
        trace_id="trace_mcp",
        call_id="call_mcp",
    )

    assert event.derived_resources[0].target == "yfinance.get_historical_stock_prices"
    assert event.metadata["hijacking_mode"] == "gateway_hijacking"
    assert event.metadata["target_tool"] == "get_historical_stock_prices"
    assert event.metadata["required_dependency"] == "get_yahoo_finance_news"
    assert event.metadata["mcpsafety_evaluator"] == "check_dependency"
    assert event.security_context.metadata["required_dependency"] == "get_yahoo_finance_news"
