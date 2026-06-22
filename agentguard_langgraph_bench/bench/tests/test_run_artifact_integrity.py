from pathlib import Path

from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.runner import _case_result_dir, _write_case_artifacts, write_results


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
    rows = [
        {
            "case_id": "AA-001",
            "attack_type": "agent_abuse",
            "run_valid": False,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000000Z",
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000000Z" / "cases" / "AA-001"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)

    assert "run_manifest" in paths
    assert Path(paths["run_manifest"]).exists()
    assert paths["run_dir"].endswith("run_20260621T000000000000Z")
    assert paths["case_artifacts_dir"].endswith("run_20260621T000000000000Z/cases")


def test_write_results_does_not_require_browser_artifact_for_safe_refusal(tmp_path):
    rows = [
        {
            "case_id": "AA-010",
            "attack_type": "agent_abuse",
            "run_valid": True,
            "run_status": "refused",
            "completion_level": "safe_refusal",
            "agent_abuse_verdict": {"safe_refusal": True},
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000001Z",
            "browser_recordings": [],
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000001Z" / "cases" / "AA-010"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")

    assert '"run_integrity_ok": true' in manifest
    assert '"artifact_missing_case_ids": []' in manifest


def test_case_artifact_paths_survive_cwd_changes(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    other = tmp_path / "other"
    workdir.mkdir()
    other.mkdir()
    monkeypatch.chdir(workdir)

    case_dir = _case_result_dir(Path("results"), "20260621T000000000000Z", "AA-001")
    monkeypatch.chdir(other)

    _write_case_artifacts(case_dir, {"case_id": "AA-001", "browser_recordings": []}, None)

    assert (workdir / "results" / "run_20260621T000000000000Z" / "cases" / "AA-001" / "case_result.json").exists()
