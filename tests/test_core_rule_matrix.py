from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


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
    assert stdout["case_count"] == 5
    assert report["summary"]["case_count"] == 5
    assert report["summary"]["fpr"] == 0.0
    assert report["summary"]["fnr"] == 0.0
    assert report["rules"]["P001_sensitive_file_access"]["blocked"] == 1
    assert report["rules"]["P005_external_send"]["case_count"] == 2
    assert report["rules"]["P007_unprofiled_tool_resource_review"]["blocked"] == 1
    assert report["cases"]["unknown_tool_outbound"]["actual_decision"] == "ask"
    assert report["cases"]["unknown_tool_outbound"]["rule_hits"] == [
        "P007_unprofiled_tool_resource_review"
    ]
    assert "P007_unprofiled_tool_resource_review" in markdown
