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


def test_shadow_argument_defaults_and_choices() -> None:
    baseline = _load_baseline_module()

    args = baseline.parse_args(["--output-dir", "x"])
    assert args.shadow == "off"
    assert args.task_ref == "off"
    args = baseline.parse_args(["--output-dir", "x", "--shadow", "both"])
    assert args.shadow == "both"
    args = baseline.parse_args(["--output-dir", "x", "--shadow", "on"])
    assert args.shadow == "on"
    args = baseline.parse_args(
        ["--output-dir", "x", "--shadow", "tri", "--task-ref", "on"]
    )
    assert args.shadow == "tri"
    assert args.task_ref == "on"


def test_api_event_attaches_task_ref_metadata() -> None:
    baseline = _load_baseline_module()
    from agentguard_core import GuardEvent

    event = GuardEvent.model_validate(
        {
            "event_id": "evt_task_ref_1",
            "event_type": "tool_call_proposed",
            "runtime": "langgraph",
            "trace_id": "trace_task_ref_1",
            "timestamp": "2026-08-15T00:00:00+00:00",
            "security_context": {"agent_id": "main", "user_task": "fixture"},
            "payload": {
                "tool": {"name": "read_file"},
                "arguments": {},
                "derived_resources": [],
            },
        }
    )

    without = baseline._api_event(event, backend="memory", sequence=1)
    assert "task_id" not in (without.get("metadata") or {})

    with_ref = baseline._api_event(
        event, backend="memory", sequence=2, task_ref="task_bench"
    )
    assert with_ref["metadata"]["task_id"] == "task_bench"


def test_seed_benchmark_task_fact_creates_authoritative_head() -> None:
    baseline = _load_baseline_module()
    from guard_api.storage.memory import MemoryControlPlaneStore

    store = MemoryControlPlaneStore()
    baseline._seed_benchmark_task_fact(store)

    record = store.get_task_fact(baseline.BENCHMARK_TASK_REF_ID)
    assert record is not None
    assert record.task_fact.task_id == baseline.BENCHMARK_TASK_REF_ID
    assert record.task_fact.authority == "authoritative"
    assert record.task_fact.scope_digest == baseline.BENCHMARK_TASK_SCOPE_DIGEST


def test_pipeline_disabled_context_restores_enabled_property() -> None:
    baseline = _load_baseline_module()
    from guard_api.services.v21_pipeline import V21PipelineService

    original = V21PipelineService.enabled
    with baseline._pipeline_disabled():
        assert V21PipelineService.enabled is not original

        class _Stub:
            pass

        assert V21PipelineService.enabled.fget(_Stub()) is False
    assert V21PipelineService.enabled is original


def test_build_pipeline_overhead_computes_pairwise_deltas() -> None:
    baseline = _load_baseline_module()

    def _result(p50: int, p95: int, *, task_ref=None) -> dict:
        return {
            "task_ref": task_ref,
            "serial": {
                "scenario_a": {
                    "sample_count": 10,
                    "p50_ns": p50,
                    "p95_ns": p95,
                    "p99_ns": p95 + 10,
                    "max_ns": p95 + 20,
                }
            },
            "concurrent": {
                "workers": 2,
                "sample_count": 10,
                "p50_ns": p50,
                "p95_ns": p95,
                "p99_ns": p95 + 10,
                "max_ns": p95 + 20,
            },
        }

    off = _result(100, 200)
    v2108 = _result(150, 260)
    v2109 = _result(180, 300, task_ref="task_v2109_bench")

    overhead = baseline.build_pipeline_overhead(off, v2108, v2109)

    assert overhead["flag"] == "AGENTGUARD_V21_SHADOW_ENABLED"
    assert overhead["task_ref"] == "task_v2109_bench"
    assert set(overhead) >= {"v2108_vs_off", "v2109_vs_off", "v2109_vs_v2108"}
    assert overhead["v2108_vs_off"]["scenarios"]["scenario_a"]["delta_ns"] == {
        "p50_ns": 50,
        "p95_ns": 60,
        "p99_ns": 60,
        "max_ns": 60,
    }
    assert overhead["v2109_vs_off"]["scenarios"]["scenario_a"]["delta_ns"]["p50_ns"] == 80
    assert overhead["v2109_vs_v2108"]["scenarios"]["scenario_a"]["delta_ns"]["p95_ns"] == 40
    assert overhead["v2109_vs_v2108"]["concurrent"]["delta_ns"]["p50_ns"] == 30
    assert overhead["disclaimer"] == baseline.TASK_REF_DISCLAIMER


def test_shadow_tri_requires_measured_memory_baseline(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="does not participate"):
        baseline.main(
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
                "postgres",
                "--allow-missing-postgres",
                "--shadow",
                "tri",
            ]
        )


def test_shadow_tri_smoke_writes_pipeline_overhead_report(tmp_path: Path) -> None:
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
            "--shadow",
            "tri",
            "--task-ref",
            "on",
        ]
    )

    assert exit_code == 0
    report = json.loads((tmp_path / "baseline.json").read_text(encoding="utf-8"))
    assert report["completion_status"] == "functional_smoke_passed"
    assert report["performance"]["shadow_mode"] == "tri"
    assert report["performance"]["task_ref"] == baseline.BENCHMARK_TASK_REF_ID
    memory_result = report["performance"]["guard_api"]["memory"]
    assert memory_result["shadow_enabled"] is False
    assert memory_result["task_ref"] == baseline.BENCHMARK_TASK_REF_ID
    overhead = report["pipeline_overhead"]
    assert overhead["flag"] == "AGENTGUARD_V21_SHADOW_ENABLED"
    assert set(overhead) >= {"v2108_vs_off", "v2109_vs_off", "v2109_vs_v2108"}
    for comparison in (
        overhead["v2108_vs_off"],
        overhead["v2109_vs_off"],
        overhead["v2109_vs_v2108"],
    ):
        assert comparison["scenarios"]
        for entry in comparison["scenarios"].values():
            assert set(entry["delta_ns"]) == {"p50_ns", "p95_ns", "p99_ns", "max_ns"}
    markdown = (tmp_path / "baseline.md").read_text(encoding="utf-8")
    assert "三档开销对照" in markdown


def test_build_shadow_overhead_computes_nearest_rank_deltas() -> None:
    baseline = _load_baseline_module()
    off = {
        "serial": {
            "scenario_a": {
                "sample_count": 10,
                "p50_ns": 100,
                "p95_ns": 200,
                "p99_ns": 300,
                "max_ns": 400,
            }
        },
        "concurrent": {
            "workers": 2,
            "sample_count": 10,
            "p50_ns": 50,
            "p95_ns": 60,
            "p99_ns": 70,
            "max_ns": 80,
        },
    }
    on = {
        "serial": {
            "scenario_a": {
                "sample_count": 10,
                "p50_ns": 150,
                "p95_ns": 260,
                "p99_ns": 380,
                "max_ns": 520,
            }
        },
        "concurrent": {
            "workers": 2,
            "sample_count": 10,
            "p50_ns": 55,
            "p95_ns": 68,
            "p99_ns": 79,
            "max_ns": 92,
        },
    }

    overhead = baseline.build_shadow_overhead(off, on)

    assert overhead["flag"] == "AGENTGUARD_V21_SHADOW_ENABLED"
    assert overhead["scenarios"]["scenario_a"]["delta_ns"] == {
        "p50_ns": 50,
        "p95_ns": 60,
        "p99_ns": 80,
        "max_ns": 120,
    }
    assert overhead["concurrent"]["delta_ns"]["p95_ns"] == 8
    assert overhead["disclaimer"] == baseline.SHADOW_OVERHEAD_DISCLAIMER


def test_shadow_both_requires_measured_memory_baseline(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="does not participate"):
        baseline.main(
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
                "postgres",
                "--allow-missing-postgres",
                "--shadow",
                "both",
            ]
        )


def test_shadow_on_requires_memory_backend(tmp_path: Path) -> None:
    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="does not participate"):
        baseline.main(
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
                "postgres",
                "--allow-missing-postgres",
                "--shadow",
                "on",
            ]
        )


def test_task_ref_on_rejects_postgres_backend(tmp_path: Path) -> None:
    """S3：postgres 档不接收 task-ref 参数，无效组合参数校验阶段报错。"""

    baseline = _load_baseline_module()

    with pytest.raises(ValueError, match="does not participate"):
        baseline.main(
            [
                "--output-dir",
                str(tmp_path),
                "--measurement-profile",
                "functional_smoke",
                "--backends",
                "postgres",
                "--allow-missing-postgres",
                "--task-ref",
                "on",
            ]
        )


def test_shadow_both_smoke_writes_overhead_report(tmp_path: Path) -> None:
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
            "--shadow",
            "both",
        ]
    )

    assert exit_code == 0
    report = json.loads((tmp_path / "baseline.json").read_text(encoding="utf-8"))
    assert report["completion_status"] == "functional_smoke_passed"
    assert report["performance"]["shadow_mode"] == "both"
    assert report["performance"]["guard_api"]["memory"]["shadow_enabled"] is False
    overhead = report["shadow_overhead"]
    assert overhead["flag"] == "AGENTGUARD_V21_SHADOW_ENABLED"
    assert overhead["scenarios"]
    for entry in overhead["scenarios"].values():
        assert set(entry["delta_ns"]) == {"p50_ns", "p95_ns", "p99_ns", "max_ns"}
    markdown = (tmp_path / "baseline.md").read_text(encoding="utf-8")
    assert "Shadow 开销对照" in markdown


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
