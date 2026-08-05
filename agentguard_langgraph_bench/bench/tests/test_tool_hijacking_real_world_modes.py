from pathlib import Path

from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.runner import run_cases


def attack_file() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "tool_hijacking.jsonl"


def benign_file() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "tool_hijacking_benign.jsonl"


def test_tool_hijacking_v2_fields_preserve_ten_legacy_replay_cases():
    cases = load_attack_cases(attack_file())

    assert len(cases) == 10
    for case in cases:
        assert getattr(case, "case_schema_version") == "tool_hijacking.v2"
        assert getattr(case, "clean_tool_catalog")
        assert getattr(case, "poisoned_tool_catalog")
        assert getattr(case, "normal_oracle")
        assert getattr(case, "attack_oracle")
        assert getattr(case, "task_oracle")
        assert case.tool_plan


def test_benign_mcp_cases_load_and_are_expected_allow():
    cases = load_attack_cases(benign_file())

    assert len(cases) == 6
    assert all(case.attack_type == "tool_hijacking" for case in cases)
    assert all(case.is_malicious is False for case in cases)
    assert all(case.expected_decision == "allow" for case in cases)
    assert all(getattr(case, "normal_oracle") for case in cases)


def test_replay_mode_keeps_legacy_attack_success(tmp_path):
    rows = run_cases(
        load_attack_cases(attack_file()),
        config=BenchConfig(
            defense_enabled=False,
            sandbox_dir=tmp_path / "sandbox",
            results_dir=tmp_path / "results",
            tool_hijacking_mode="replay",
        ),
        reset_environment=False,
    )

    assert len(rows) == 10
    assert all(row["planning_source"] == "attackcase_tool_plan" for row in rows)
    assert all(row["attack_success"] is True for row in rows)


def test_autonomous_mode_records_descriptor_evidence_and_safe_benign_metrics(tmp_path):
    rows = run_cases(
        load_attack_cases(benign_file()),
        config=BenchConfig(
            defense_enabled=False,
            sandbox_dir=tmp_path / "sandbox",
            results_dir=tmp_path / "results",
            tool_hijacking_mode="autonomous",
            tool_catalog_view="poisoned",
        ),
        reset_environment=False,
    )
    summary = calculate_metrics(rows, defense_enabled=False)

    assert all(row["planning_source"] == "attackcase_tool_plan" for row in rows)
    assert all(row["attack_success"] is False for row in rows)
    assert all(row["task_success"] is True for row in rows)
    assert all(row["safe_completion"] is True for row in rows)
    assert all(row["descriptor_evidence"] for row in rows)
    assert all(row["catalog_presented_to_llm"] is True for row in rows)
    assert all(row["llm_request_count"] >= 0 for row in rows)
    assert all(Path(row["llm_prompt_redacted_path"]).exists() for row in rows)
    assert all(Path(row["llm_response_redacted_path"]).exists() for row in rows)
    assert (tmp_path / "sandbox" / "mcp" / "descriptors.jsonl").exists()
    assert summary["safe_completion_rate"] == 1.0


def test_differential_mode_reports_clean_poisoned_drift(tmp_path):
    case = [case for case in load_attack_cases(attack_file()) if case.case_id == "MCP-020"]

    rows = run_cases(
        case,
        config=BenchConfig(
            defense_enabled=False,
            sandbox_dir=tmp_path / "sandbox",
            results_dir=tmp_path / "results",
            tool_hijacking_mode="differential",
        ),
    )

    row = rows[0]
    assert row["tool_hijacking_mode"] == "differential"
    assert row["clean_run"]["tool_catalog_view"] == "clean"
    assert row["poisoned_run"]["tool_catalog_view"] == "poisoned"
    assert row["differential"]["arguments_changed"] is False
    assert row["attack_success"] is True
