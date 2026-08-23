from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.e2e


def test_core_rule_matrix_outputs_summary_and_case_details(tmp_path: Path) -> None:
    output_dir = tmp_path / "matrix"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/core-rule-matrix.py",
            "--dataset",
            "tests/fixtures/core_rule_matrix.jsonl",
            "--output-dir",
            str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    stdout = json.loads(completed.stdout)
    report = json.loads(
        (output_dir / "core-rule-matrix-report.json").read_text(encoding="utf-8")
    )
    markdown = (output_dir / "core-rule-matrix-report.md").read_text(encoding="utf-8")

    assert stdout["ok"] is True
    assert stdout["case_count"] == 60
    assert report["summary"]["case_count"] == 60
    assert report["summary"]["fpr"] == 0.0
    assert report["summary"]["fnr"] == 0.0
    assert report["matrix_coverage"]["rule_count"] == 15
    assert report["matrix_coverage"]["quadrants_per_rule"] == 4
    assert report["matrix_coverage"]["expected_case_count"] == 60
    assert report["rules"]["P001_sensitive_file_access"]["case_count"] == 2
    assert report["cases"]["P007_unprofiled_tool_resource_review_positive"][
        "actual_decision"
    ] == "ask"
    assert report["cases"]["P007_unprofiled_tool_resource_review_override"][
        "actual_decision"
    ] == "deny"
    assert "P109_mcp_tool_hijacking" in markdown


def test_core_rule_matrix_rejects_missing_rule(tmp_path: Path) -> None:
    source = Path("tests/fixtures/core_rule_matrix.jsonl").read_text(encoding="utf-8")
    incomplete_dataset = tmp_path / "incomplete.jsonl"
    incomplete_dataset.write_text(
        "\n".join(source.splitlines()[:-1]) + "\n", encoding="utf-8"
    )

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/core-rule-matrix.py",
            "--dataset",
            str(incomplete_dataset),
            "--output-dir",
            str(tmp_path / "matrix"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "incomplete rule matrix" in completed.stderr
    assert "P109_mcp_tool_hijacking" in completed.stderr
