from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.e2e


def _run_gate(*extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/core-metrics-gate.py", *extra_args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_eval_gate_passes_with_default_thresholds() -> None:
    completed = _run_gate()

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout.splitlines()[0])
    assert report["ok"] is True
    assert report["attack_cases"] >= 20
    assert report["benign_cases"] >= 10
    assert report["recall"] >= report["min_recall"]
    assert report["fpr"] <= report["max_fpr"]
    assert report["fnr"] == 1.0 - report["recall"]
    assert report["false_positives"] == []


def test_eval_gate_fails_when_recall_threshold_not_met() -> None:
    completed = _run_gate("--min-recall", "1.01")

    assert completed.returncode == 1
    report = json.loads(completed.stdout.splitlines()[0])
    assert report["ok"] is False


def test_eval_gate_fails_when_fpr_budget_exhausted() -> None:
    completed = _run_gate("--max-fpr", "-0.01")

    assert completed.returncode == 1
    report = json.loads(completed.stdout.splitlines()[0])
    assert report["ok"] is False


def test_eval_gate_rejects_missing_dataset(tmp_path: Path) -> None:
    completed = _run_gate("--attack-dataset", str(tmp_path / "missing.jsonl"))

    assert completed.returncode == 2
    assert "eval gate dataset not found" in completed.stderr


def test_eval_gate_rejects_non_object_jsonl_line(tmp_path: Path) -> None:
    dataset = tmp_path / "non_object.jsonl"
    dataset.write_text("[1, 2, 3]\n", encoding="utf-8")

    completed = _run_gate("--attack-dataset", str(dataset))

    assert completed.returncode == 2
    assert "non_object.jsonl:1 case must be a JSON object" in completed.stderr
