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


def test_write_case_artifacts_creates_diagnostic_browser_replay_for_autonomous_planner_stall(tmp_path):
    row = {
        "case_id": "AA-009",
        "attack_type": "agent_abuse",
        "run_valid": True,
        "run_status": "llm_planning_error",
        "stop_reason": "llm_planning_error",
        "completion_level": "none",
        "agent_abuse_verdict": {"safe_refusal": False},
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000002Z",
        "instrumentation_plan_mode": "autonomous",
        "agent_visible_payload_mode": "original",
        "llm_request_count": 1,
        "llm_timeout_count": 1,
        "browser_recordings": [],
    }
    case_dir = tmp_path / "run_20260621T000000000002Z" / "cases" / "AA-009"

    _write_case_artifacts(case_dir, row, {"case_id": "AA-009"})
    paths = write_results([row], {}, tmp_path)

    assert (case_dir / "browser_replay" / "manifest.json").exists()
    assert row["browser_recordings"][0]["diagnostic_artifact"] is True
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")
    assert '"run_integrity_ok": true' in manifest
    assert '"artifact_missing_case_ids": []' in manifest
    integrity = Path(paths["artifact_integrity_manifest"]).read_text(encoding="utf-8")
    assert '"ok": true' in integrity
    assert '"diagnostic_artifact": true' in integrity


def test_file_exfiltration_browser_case_missing_replay_is_reported_not_masked(tmp_path):
    row = {
        "case_id": "FE-001",
        "attack_type": "file_exfiltration",
        "run_valid": False,
        "run_status": "llm_planning_error",
        "completion_level": "invalid",
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000003Z",
        "metadata": {"web_entry_source_path": "agentguard_langgraph_bench/bench/datasets/instrumentation/FE_001_booking_business/booking_business_taxi.html"},
        "browser_recordings": [],
    }
    case_dir = tmp_path / "run_20260621T000000000003Z" / "cases" / "FE-001"

    _write_case_artifacts(case_dir, row, {"case_id": "FE-001"})
    paths = write_results([row], {}, tmp_path)
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")

    assert not (case_dir / "browser_replay" / "manifest.json").exists()
    assert '"run_integrity_ok": false' in manifest
    assert '"artifact_missing_case_ids": [' in manifest
    assert '"FE-001"' in manifest


def test_case_side_effect_archive_uses_only_current_sandbox_diff(tmp_path):
    sandbox = tmp_path / "sandbox"
    inherited = sandbox / "files" / "reports" / "old_case_report.json"
    current = sandbox / "files" / "reports" / "current_case_report.json"
    api = sandbox / "api" / "exfiltration_collector.jsonl"
    inherited.parent.mkdir(parents=True, exist_ok=True)
    api.parent.mkdir(parents=True, exist_ok=True)
    inherited.write_text("old", encoding="utf-8")
    current.write_text("current", encoding="utf-8")
    api.write_text('{"case_id":"FE-009"}\n', encoding="utf-8")
    row = {
        "case_id": "FE-009",
        "attack_type": "file_exfiltration",
        "sandbox_diff": {
            "root": str(sandbox),
            "added": [
                {
                    "relative_path": "files/reports/current_case_report.json",
                    "absolute_path": str(current),
                    "size": current.stat().st_size,
                    "sha256": "current-sha",
                },
                {
                    "relative_path": "api/exfiltration_collector.jsonl",
                    "absolute_path": str(api),
                    "size": api.stat().st_size,
                    "sha256": "api-sha",
                },
            ],
            "modified": [],
        },
        "browser_recordings": [],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    assert (case_dir / "reports_snapshot" / "files" / "reports" / "current_case_report.json").exists()
    assert not (case_dir / "reports_snapshot" / "files" / "reports" / "old_case_report.json").exists()
    manifest = (case_dir / "reports_snapshot" / "manifest.json").read_text(encoding="utf-8")
    assert "current_case_report.json" in manifest
    assert "old_case_report.json" not in manifest
    assert (case_dir / "api_snapshot" / "api" / "exfiltration_collector.jsonl").exists()


def test_write_case_artifacts_copies_relative_final_dom_references(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
    ):
        (source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (source / "final_dom.html").write_text('<html><head><link href="styles.css"></head><body></body></html>', encoding="utf-8")
    (source / "styles.css").write_text("body{color:#111}", encoding="utf-8")
    row = {
        "case_id": "AA-010",
        "browser_recordings": [
            {
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "final_dom": str(source / "final_dom.html"),
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    assert (case_dir / "browser_replay" / "styles.css").exists()


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
