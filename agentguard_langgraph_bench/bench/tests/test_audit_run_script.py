from __future__ import annotations

import json
from pathlib import Path

from agentguard_langgraph_bench.bench.scripts.audit_run import audit_run, main, render_markdown


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def _minimal_run(tmp_path: Path, *, invalid: bool = False) -> Path:
    run_dir = tmp_path / "run_20260629T000000Z"
    rows = [
        {
            "case_run_key": "AA-001",
            "case_id": "AA-001",
            "attack_type": "agent_abuse",
            "run_valid": True,
            "run_status": "completed",
            "stop_reason": "task_terminal",
            "invalid_reasons": [],
            "evidence_status": "supported",
            "llm_request_count": 1,
            "browser_action_count": 2,
            "fatal_tool_error_count": 0,
            "tool_calls": [{"tool_name": "browser_start"}],
            "final_answer": "done",
        },
        {
            "case_run_key": "AA-002",
            "case_id": "AA-002",
            "attack_type": "agent_abuse",
            "run_valid": not invalid,
            "run_status": "fatal_tool_exception" if invalid else "completed",
            "stop_reason": "tool_error" if invalid else "task_terminal",
            "invalid_reasons": ["fatal_tool_exception"] if invalid else [],
            "evidence_status": "invalid" if invalid else "supported",
            "llm_request_count": 1,
            "browser_action_count": 0,
            "fatal_tool_error_count": 1 if invalid else 0,
            "tool_calls": [{"tool_name": "browser_start"}],
            "final_answer": "failed" if invalid else "done",
        },
    ]
    _write_json(
        run_dir / "summary_20260629T000000Z.json",
        {
            "case_count": 2,
            "invalid_case_count": 1 if invalid else 0,
            "run_valid_rate": 0.5 if invalid else 1,
            "invalid_run_rate": 0.5 if invalid else 0,
            "metrics_reliable": not invalid,
            "run_quality_pass": not invalid,
            "benchmark_quality_interpretable": not invalid,
            "evidence_complete_rate": 0.5 if invalid else 1,
            "artifact_coverage_rate": 1,
        },
    )
    _write_json(run_dir / "run_20260629T000000Z.json", rows)
    (run_dir / "run_20260629T000000Z.csv").write_text(
        "case_run_key,run_valid\nAA-001,true\nAA-002,{}\n".format("false" if invalid else "true"),
        encoding="utf-8",
    )
    _write_json(
        run_dir / "manifest_run_20260629T000000Z.json",
        {
            "run_integrity_ok": True,
            "expected_case_count": 2,
            "missing_case_ids": [],
            "missing_case_result_ids": [],
            "artifact_missing_case_ids": [],
        },
    )
    _write_json(run_dir / "artifact_integrity_manifest.json", {"ok": True, "case_count": 1, "cases": {}})
    for row in rows:
        case_dir = run_dir / "cases" / row["case_run_key"]
        _write_json(case_dir / "case_result.json", {**row, "case_artifact_dir": str(case_dir)})
        _write_json(case_dir / "evidence_index.json", {"case_id": row["case_id"], "integrity": {"jsonl_parse_ok": True}})
        _write_json(case_dir / "browser_action_summary.json", {"case_id": row["case_id"], "action_count": row["browser_action_count"]})
        _write_jsonl(
            case_dir / "tool_results.jsonl",
            [{"tool_name": "browser_start", "status": "error" if invalid and row["case_id"] == "AA-002" else "executed"}],
        )
    _write_json(
        run_dir / "cases" / "AA-001" / "browser_replay" / "manifest.json",
        {
            "ok": True,
            "browser_started": True,
            "real_browser_artifact": True,
            "diagnostic_artifact": False,
        },
    )
    _write_json(
        run_dir / "cases" / "AA-001" / "browser_replay" / "replay_state.json",
        {"ok": True, "real_browser_artifact": True, "diagnostic_artifact": False},
    )
    return run_dir


def test_audit_run_reports_invalid_cases_and_cross_checks(tmp_path: Path) -> None:
    run_dir = _minimal_run(tmp_path, invalid=True)

    report = audit_run(run_dir)

    assert report["summary_metrics"]["invalid_case_count"] == 1
    assert report["quality_gate"]["structured_all_valid"] is False
    assert report["invalid_cases"][0]["case_run_key"] == "AA-002"
    assert report["case_cross_checks"]["missing_case_results"] == []
    assert report["browser_artifacts"]["real_browser_artifact_case_count"] == 1
    assert report["manual_decision"]["allowed_to_proceed"] == "manual_review_required"


def test_audit_run_require_all_valid_exit_code(tmp_path: Path) -> None:
    run_dir = _minimal_run(tmp_path, invalid=False)

    assert main(["--run-dir", str(run_dir), "--require-all-valid", "--output", str(tmp_path / "report.json")]) == 0


def test_audit_run_markdown_keeps_manual_gate(tmp_path: Path) -> None:
    run_dir = _minimal_run(tmp_path, invalid=False)
    report = audit_run(run_dir)

    markdown = render_markdown(report)

    assert "allowed_to_proceed: `manual_review_required`" in markdown
    assert "| AA-001 | `True` | supported" in markdown
