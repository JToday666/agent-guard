from __future__ import annotations

from pathlib import Path

from agentguard_langgraph_bench.bench.paired_runner import (
    _dataset_evidence,
    build_paired_report,
)


def _summary(*, defense_enabled: bool) -> dict:
    return {
        "defense_enabled": defense_enabled,
        "dataset_locked": True,
        "dataset_id": "agentguard-main-attack-cases",
        "dataset_version": "2026.08.11",
        "dataset_digest": "sha256:" + "a" * 64,
        "case_count": 2,
        "run_integrity_failed": False,
        "artifact_integrity": {"ok": True},
        "core_mode": "real_core" if defense_enabled else "disabled",
        "asr_before": None if defense_enabled else 1.0,
        "asr_after": 0.0 if defense_enabled else None,
        "block_rate": 1.0 if defense_enabled else None,
        "fpr": 0.0 if defense_enabled else None,
        "fnr": 0.0 if defense_enabled else None,
        "precision": 1.0 if defense_enabled else None,
        "recall": 1.0 if defense_enabled else None,
        "f1": 1.0 if defense_enabled else None,
    }


def _rows(*, valid: bool = True) -> list[dict]:
    return [
        {"case_run_key": "AA-001", "run_valid": valid},
        {"case_run_key": "BN-001", "run_valid": True},
    ]


def test_paired_report_accepts_matching_trustworthy_runs() -> None:
    report = build_paired_report(
        _summary(defense_enabled=False),
        _rows(),
        _summary(defense_enabled=True),
        _rows(),
    )

    assert report["run_valid"] is True
    assert report["defense_effect_interpretable"] is True
    assert report["invalid_reasons"] == []
    assert report["effects"]["asr_reduction"] == 1.0
    assert report["dataset"]["case_count"] == 2


def test_paired_report_rejects_infrastructure_failure_and_case_drift() -> None:
    on_summary = _summary(defense_enabled=True)
    on_summary["core_mode"] = "real_core"
    on_rows = _rows(valid=False)
    on_rows[1]["case_run_key"] = "BN-002"

    report = build_paired_report(
        _summary(defense_enabled=False),
        _rows(),
        on_summary,
        on_rows,
    )

    assert report["run_valid"] is False
    assert report["defense_effect_interpretable"] is False
    assert report["invalid_reasons"] == [
        "paired_case_set_mismatch",
        "defense_on_invalid_cases",
    ]


def test_paired_report_rejects_fake_core_and_unlocked_dataset() -> None:
    on_summary = _summary(defense_enabled=True)
    on_summary["core_mode"] = "fake_deny"
    on_summary["dataset_locked"] = False

    report = build_paired_report(
        _summary(defense_enabled=False),
        _rows(),
        on_summary,
        _rows(),
    )

    assert report["run_valid"] is False
    assert report["invalid_reasons"] == [
        "defense_on_dataset_unlocked",
        "defense_on_core_not_real",
    ]


def test_paired_runner_binds_rows_to_locked_case_provenance() -> None:
    dataset = Path("agentguard_langgraph_bench/bench/datasets/attack_cases")
    rows = [
        {
            "case_id": "PI-001",
            "case_run_key": "PI-001",
            "dataset_file": "prompt_injection.jsonl",
            "dataset_row_index": 1,
        },
        {
            "case_id": "BN-001",
            "case_run_key": "BN-001",
            "dataset_file": "benign.jsonl",
            "dataset_row_index": 1,
        },
    ]

    snapshot, evidence = _dataset_evidence(dataset, rows)

    assert snapshot["dataset_locked"] is True
    assert snapshot["selected_case_count"] == 2
    assert all(item["case_digest"].startswith("sha256:") for item in evidence)
    assert [item["provenance"]["line"] for item in evidence] == [1, 1]
