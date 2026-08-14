from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_baseline_module():
    path = ROOT / "scripts" / "v21-baseline.py"
    spec = importlib.util.spec_from_file_location("v21_baseline", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wilson_interval_and_nearest_rank_are_deterministic() -> None:
    baseline = _load_baseline_module()

    assert baseline.wilson_interval(0, 0) is None
    interval = baseline.wilson_interval(9, 10)
    assert interval["low"] == pytest.approx(0.5958499732047616)
    assert interval["high"] == pytest.approx(0.9821237869049271)
    assert baseline.nearest_rank([5, 1, 4, 2, 3], 0.5) == 3
    assert baseline.nearest_rank([5, 1, 4, 2, 3], 0.95) == 5


def test_redaction_removes_credentials_and_query() -> None:
    baseline = _load_baseline_module()
    source = {
        "database_url": "postgresql://user:password@db.example:5432/agent_guard_test?sslmode=require",
        "api_token": "plaintext",
    }

    redacted = baseline.redact_secrets(source)
    serialized = json.dumps(redacted)

    assert "password" not in serialized
    assert "plaintext" not in serialized
    assert "sslmode" not in serialized
    assert (
        redacted["database_url"] == "postgresql://***@db.example:5432/agent_guard_test"
    )


def test_formal_profile_rejects_non_frozen_iteration_counts(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="formal_baseline requires"):
        baseline.main(
            [
                "--output-dir",
                str(tmp_path),
                "--core-iterations",
                "2",
            ]
        )


def test_formal_profile_requires_both_backends(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="requires both memory and postgres"):
        baseline.main(
            [
                "--output-dir",
                str(tmp_path),
                "--backends",
                "memory",
            ]
        )


def test_unknown_backend_is_rejected_before_measurement(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="unsupported Guard API backends: typo"):
        baseline.main(
            [
                "--output-dir",
                str(tmp_path),
                "--backends",
                "typo",
            ]
        )


def test_backend_blockers_include_memory_failure() -> None:
    baseline = _load_baseline_module()

    blockers = baseline.backend_blockers(
        {"memory", "postgres"},
        {
            "memory": {"status": "blocked", "reason": "memory failure"},
            "postgres": {"status": "measured"},
        },
    )

    assert blockers == ["memory Guard API 基线未完成：memory failure"]


def _prepare_legacy_snapshot_repo(tmp_path: Path, monkeypatch):
    baseline = _load_baseline_module()
    tracked_inputs = [
        tmp_path / "packages" / "agentguard-core" / "tracked.py",
        tmp_path / "scripts" / "core-metrics-gate.py",
        tmp_path / "tests" / "fixtures" / "eval_gate" / "cases.jsonl",
    ]
    for path in tracked_inputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=V21 Test",
            "-c",
            "user.email=v21@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "baseline",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    snapshot = tmp_path / "tests" / "fixtures" / "v21" / "snapshot.json"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(baseline, "ROOT", tmp_path)
    monkeypatch.setattr(baseline, "LEGACY_BASE_SHA", head)
    monkeypatch.setattr(baseline, "LEGACY_SNAPSHOT", snapshot)
    return baseline, tracked_inputs[0]


@pytest.mark.parametrize("input_state", ["staged", "unstaged", "untracked"])
def test_legacy_snapshot_rejects_all_dirty_input_states(
    tmp_path: Path, monkeypatch, input_state: str
) -> None:
    baseline, tracked_input = _prepare_legacy_snapshot_repo(tmp_path, monkeypatch)
    if input_state == "untracked":
        (tracked_input.parent / "untracked.py").write_text("new\n", encoding="utf-8")
    else:
        tracked_input.write_text("changed\n", encoding="utf-8")
        if input_state == "staged":
            subprocess.run(["git", "add", str(tracked_input)], cwd=tmp_path, check=True)

    with pytest.raises(ValueError, match="staged, unstaged, or untracked"):
        baseline.write_legacy_snapshot([])


def test_postgres_benchmark_rejects_non_test_database(monkeypatch) -> None:
    baseline = _load_baseline_module()
    monkeypatch.setenv(
        "AGENTGUARD_TEST_DATABASE_URL",
        "postgresql://user:secret@127.0.0.1:5432/agent_guard",
    )

    result = baseline.run_postgres_api_benchmark(
        {},
        warmup=0,
        serial_iterations=1,
        concurrency=1,
        concurrent_total=1,
    )

    assert result["status"] == "blocked"
    assert "UnsafeTestDatabaseUrlError" in result["reason"]


def test_quick_memory_baseline_writes_machine_and_human_reports(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    exit_code = baseline.main(
        [
            "--output-dir",
            str(tmp_path),
            "--measurement-profile",
            "functional_smoke",
            "--core-warmup",
            "1",
            "--core-iterations",
            "2",
            "--api-warmup",
            "1",
            "--api-serial-iterations",
            "2",
            "--api-concurrency",
            "2",
            "--api-concurrent-total",
            "4",
            "--backends",
            "memory",
        ]
    )

    assert exit_code == 0
    report = json.loads((tmp_path / "baseline.json").read_text(encoding="utf-8"))
    assert report["regression"]["attack"]["count"] == 30
    assert report["regression"]["benign"]["count"] == 13
    assert report["regression"]["legacy_parity"]["ok"] is True
    assert report["performance"]["guard_api"]["memory"]["status"] == "measured"
    assert report["performance"]["guard_api"]["postgres"]["status"] == "not_requested"
    assert report["completion_status"] == "functional_smoke_passed"
    assert report["runtime_effectiveness"]["final_asr"] == "not_measured"
    assert (tmp_path / "baseline.md").is_file()
