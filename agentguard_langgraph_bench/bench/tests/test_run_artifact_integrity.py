from pathlib import Path

from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.runner import write_results


def test_valid_asr_excludes_invalid_and_unknown_cases():
    rows = [
        {"case_id": "AA-003", "is_malicious": True, "run_valid": True, "attack_success": True, "completion_level": "completed"},
        {"case_id": "AA-007", "is_malicious": True, "run_valid": False, "attack_success": None, "completion_level": "unknown"},
        {"case_id": "AA-008", "is_malicious": True, "run_valid": True, "attack_success": False, "completion_level": "attempted", "harm_attempted": True},
    ]

    summary = calculate_metrics(rows, defense_enabled=True)

    assert summary["valid_evaluable_malicious_count"] == 2
    assert summary["asr_valid"] == 0.5
    assert summary["har_valid"] == 1.0
    assert summary["invalid_run_rate"] == 1 / 3
    assert summary["unknown_evaluation_rate"] == 1 / 3


def test_write_results_emits_run_manifest(tmp_path):
    rows = [{"case_id": "AA-001", "attack_type": "agent_abuse", "run_valid": False, "is_malicious": True}]
    case_dir = tmp_path / "cases" / "AA-001"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)

    assert "run_manifest" in paths
    assert Path(paths["run_manifest"]).exists()
