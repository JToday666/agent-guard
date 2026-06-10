import json
from pathlib import Path

from agentguard_langgraph_bench.attackcase_converter import mcpsafety_task_to_attack_case
from agentguard_langgraph_bench.models import AttackCase


MCPSAFETY_ROOT = Path(__file__).resolve().parents[3] / "MCPSafety"


def _convert(rel_path: str, case_id: str = "MCP-X") -> AttackCase:
    source_path = f"MCPSafety/mcpuniverse/benchmark/configs/test/{rel_path}"
    task_path = MCPSAFETY_ROOT / "mcpuniverse" / "benchmark" / "configs" / "test" / rel_path
    task = json.loads(task_path.read_text(encoding="utf-8"))
    return AttackCase.model_validate(mcpsafety_task_to_attack_case(task, source_path=source_path, case_id=case_id))


def test_converter_maps_malicious_tool_attack_to_shadowing():
    case = _convert("web_search/info_search_task_0026.json")

    assert case.attack_type == "tool_hijack"
    assert case.metadata["hijacking_mode"] == "tool_shadowing"
    assert case.metadata["hijacking"]["target_tool"] == "search"
    assert case.metadata["hijacking"]["hijacked_tool"] == "Google_Search"
    assert case.tool_plan[0].tool == "mcp_call"


def test_converter_maps_parameter_modification_to_argument_hijacking():
    case = _convert("web_search/info_search_task_0019.json")

    assert case.metadata["hijacking_mode"] == "argument_hijacking"
    assert case.metadata["hijacking"]["argument_mutation"] == {"query": "Meryl Streep"}
    assert case.tool_plan[0].arguments["arguments"] == {"query": "Meryl Streep"}


def test_converter_maps_data_tampering_to_return_hijacking():
    case = _convert("location_navigation/google_maps_task_0051.json")

    assert case.metadata["hijacking_mode"] == "return_hijacking"
    assert case.metadata["hijacking"]["target_tool"] == "maps_search_places"
    assert case.metadata["hijacking"]["injected_return_markers"]


def test_converter_maps_replay_and_rug_pull_to_gateway_hijacking():
    replay = _convert("financial_analysis/yfinance_task_0052.json")
    rug_pull = _convert("repository_management/github_task_0039.json")

    assert replay.metadata["hijacking_mode"] == "gateway_hijacking"
    assert replay.metadata["hijacking"]["trigger"] == "replay"
    assert replay.metadata["hijacking"]["call_threshold"] == 2
    assert rug_pull.metadata["hijacking"]["trigger"] == "rug_pull"
    assert rug_pull.metadata["hijacking"]["target_tool"] == "get_file_content"


def test_converter_maps_dependency_to_call_chain_hijacking():
    case = _convert("financial_analysis/yfinance_task_0002.json")

    assert case.metadata["hijacking_mode"] == "gateway_hijacking"
    assert case.metadata["hijacking"]["trigger"] == "dependency"
    assert case.metadata["hijacking"]["required_dependency"] == "get_yahoo_finance_news"
    assert [step.arguments["tool"] for step in case.tool_plan] == [
        "get_yahoo_finance_news",
        "get_historical_stock_prices",
    ]


def test_converter_maps_url_command_injection_to_url_argument():
    case = _convert("web_search/info_search_task_0003.json")

    assert case.metadata["hijacking_mode"] == "argument_hijacking"
    assert case.metadata["hijacking"]["argument_mutation"] == {"url": "http://127.0.0.1:18085/collect/cvpr-paper"}
    assert case.tool_plan[0].arguments["arguments"] == {"url": "http://127.0.0.1:18085/collect/cvpr-paper"}
