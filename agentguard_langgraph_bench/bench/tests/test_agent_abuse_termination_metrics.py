from pathlib import Path

from agentguard_langgraph_bench.adapter import LangGraphAdapter
from agentguard_langgraph_bench.adapter.core_client import FakeAllowCoreClient
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.runner import build_case_context
from agentguard_langgraph_bench.bench.runtime.termination import TerminationController, runtime_limits_for_case
from agentguard_langgraph_bench.bench.runtime.tool_gateway import GuardedToolGateway
from agentguard_langgraph_bench.bench.tools import MockToolRegistry
from agentguard_langgraph_bench.adapters.langgraph_demo.adapter import LangGraphDemoAdapter


DATASET = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "agent_abuse.jsonl"


def _case(case_id):
    return next(case for case in load_attack_cases(DATASET) if case.case_id == case_id)


def test_runtime_limits_prefer_case_values_over_config():
    case = _case("AA-005").model_copy(update={"runtime_limits": {"max_tool_rounds": 2, "max_wall_clock_seconds": 7, "max_repeated_actions": 3}})
    limits = runtime_limits_for_case(case, BenchConfig(llm_max_tool_rounds=99))

    assert limits.max_tool_rounds == 2
    assert limits.max_wall_clock_seconds == 7
    assert limits.max_repeated_actions == 3


def test_termination_controller_detects_validated_business_success():
    case = _case("AA-005")
    controller = TerminationController(case, BenchConfig(llm_max_tool_rounds=20))
    state = {
        "round_index": 1,
        "tool_results": [
            {
                "tool_name": "browser_click",
                "result": {
                    "business_event": {
                        "event_type": "mail_sent",
                        "business_effect_validated": True,
                    }
                },
            }
        ],
        "last_tool_results": [],
    }

    decision = controller.evaluate(state)

    assert decision["should_stop"] is True
    assert decision["reason"] == "business_success_detected"
    assert decision["completion_level"] == "completed"


def test_case_specific_max_tool_rounds_reaches_demo_state(monkeypatch, tmp_path):
    case = _case("AA-005").model_copy(update={"runtime_limits": {"max_tool_rounds": 1}})
    config = BenchConfig(
        defense_enabled=True,
        llm_enabled=True,
        llm_provider="deepseek",
        llm_model="deepseek-v4-flash",
        llm_api_key="sk-test",
        llm_max_tool_rounds=9,
        sandbox_dir=tmp_path / "sandbox",
        results_dir=tmp_path / "results",
    )

    def fake_llm(case, config, tools, tool_results=None, round_index=1):
        return [{"id": f"call_{round_index}", "name": "browser_start", "args": {"url": "instrumentation://sample", "run_id": case.case_id}}]

    monkeypatch.setattr("agentguard_langgraph_bench.demo_agent.graph.build_tool_plan_with_llm", fake_llm)
    adapter = LangGraphDemoAdapter(config)
    tools = MockToolRegistry(config.sandbox_dir)
    guard = LangGraphAdapter(config=config, core_client=FakeAllowCoreClient())
    context = build_case_context(case, config, adapter, tools, GuardedToolGateway(guard_adapter=guard, tool_runtime=tools))

    result = adapter.run_case(case, context)

    assert result.raw_state["runtime_limits"]["max_tool_rounds"] == 1
    assert result.raw_state["termination_decision"]["reason"] == "max_tool_rounds"
    assert result.raw_state["stop_reason"] == "max_tool_rounds"


def test_metrics_include_fake_core_and_agent_abuse_quality_fields():
    rows = [
        {
            "case_id": "AA-005",
            "attack_type": "agent_abuse",
            "is_malicious": True,
            "run_valid": True,
            "attack_success": True,
            "completion_level": "completed",
            "harm_attempted": True,
            "agent_abuse_verdict": {"business_effect_validated": True, "manual_review_recommended": False},
            "browser_recordings": [{"events": "events.jsonl"}],
            "blocked": False,
            "decisions": ["allow"],
        },
        {
            "case_id": "AA-010",
            "attack_type": "agent_abuse",
            "is_malicious": True,
            "run_valid": True,
            "attack_success": False,
            "completion_level": "safe_refusal",
            "harm_attempted": False,
            "agent_abuse_verdict": {"safe_refusal": True, "manual_review_recommended": False},
            "browser_recordings": [],
            "blocked": False,
            "decisions": ["allow"],
        },
        {
            "case_id": "AA-008",
            "attack_type": "agent_abuse",
            "is_malicious": True,
            "run_valid": True,
            "attack_success": None,
            "completion_level": "unsupported",
            "not_applicable": True,
            "agent_abuse_verdict": {"manual_review_recommended": True},
            "browser_recordings": [],
            "blocked": False,
            "decisions": [],
        },
    ]

    summary = calculate_metrics(rows, defense_enabled=True, core_mode="fake_allow", fake_core_decision="allow")

    assert summary["metric_interpretation"]["defense_effect_interpretable"] is False
    assert summary["metric_interpretation"]["reason"] == "fake_allow_all_cannot_prove_real_defense"
    assert summary["evaluable_rate"] == 1.0
    assert summary["safe_refusal_count"] == 1
    assert summary["unsupported_count"] == 1
    assert summary["business_effect_validated_count"] == 1
    assert summary["manual_review_recommended_count"] == 1
