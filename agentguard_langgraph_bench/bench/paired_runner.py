"""Run defense-off/on AttackBench passes and validate one trustworthy pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
FORBIDDEN_RUNNER_OPTIONS = {"--defense", "--results-dir", "--no-reset-env"}


def main(argv: list[str] | None = None) -> int:
    args, runner_args = build_parser().parse_known_args(argv)
    _validate_runner_args(runner_args)
    root = args.paired_results_dir.resolve()
    if root.exists():
        raise SystemExit(f"paired results directory must not exist: {root}")
    off_dir = root / "defense-off"
    on_dir = root / "defense-on"
    _run_pass(runner_args, defense="off", results_dir=off_dir)
    _run_pass(runner_args, defense="on", results_dir=on_dir)

    off_summary_path, off_rows_path = _result_paths(off_dir)
    on_summary_path, on_rows_path = _result_paths(on_dir)
    off_summary = _read_json_object(off_summary_path)
    on_summary = _read_json_object(on_summary_path)
    off_rows = _read_json_array(off_rows_path)
    on_rows = _read_json_array(on_rows_path)
    report = build_paired_report(off_summary, off_rows, on_summary, on_rows)
    report["artifacts"] = {
        "defense_off": _artifact_identity(root, off_summary_path, off_rows_path),
        "defense_on": _artifact_identity(root, on_summary_path, on_rows_path),
    }
    report_path = root / "paired-baseline-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_path), **report}, ensure_ascii=False))
    return 0 if report["run_valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired-results-dir", required=True, type=Path)
    return parser


def build_paired_report(
    off_summary: dict[str, Any],
    off_rows: list[dict[str, Any]],
    on_summary: dict[str, Any],
    on_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons: list[str] = []
    _require(off_summary.get("defense_enabled") is False, "defense_off_mode_invalid", reasons)
    _require(on_summary.get("defense_enabled") is True, "defense_on_mode_invalid", reasons)
    for name, summary in (("defense_off", off_summary), ("defense_on", on_summary)):
        _require(summary.get("dataset_locked") is True, f"{name}_dataset_unlocked", reasons)
        _require(
            summary.get("run_integrity_failed") is False,
            f"{name}_run_integrity_failed",
            reasons,
        )
        artifact_integrity = summary.get("artifact_integrity")
        _require(
            isinstance(artifact_integrity, dict) and artifact_integrity.get("ok") is True,
            f"{name}_artifact_integrity_failed",
            reasons,
        )
    for field in ("dataset_id", "dataset_version", "dataset_digest", "case_count"):
        _require(
            off_summary.get(field) == on_summary.get(field),
            f"paired_{field}_mismatch",
            reasons,
        )
    off_case_keys = _case_keys(off_rows, "defense_off", reasons)
    on_case_keys = _case_keys(on_rows, "defense_on", reasons)
    _require(off_case_keys == on_case_keys, "paired_case_set_mismatch", reasons)
    _require(not _invalid_rows(off_rows), "defense_off_invalid_cases", reasons)
    _require(not _invalid_rows(on_rows), "defense_on_invalid_cases", reasons)
    _require(off_summary.get("asr_before") is not None, "asr_before_missing", reasons)
    _require(on_summary.get("asr_after") is not None, "asr_after_missing", reasons)
    _require(on_summary.get("fpr") is not None, "fpr_missing", reasons)
    _require(on_summary.get("core_mode") == "real_core", "defense_on_core_not_real", reasons)

    effects: dict[str, Any] = {
        "asr_before": off_summary.get("asr_before"),
        "asr_after": on_summary.get("asr_after"),
        "block_rate": on_summary.get("block_rate"),
        "fpr": on_summary.get("fpr"),
        "fnr": on_summary.get("fnr"),
        "precision": on_summary.get("precision"),
        "recall": on_summary.get("recall"),
        "f1": on_summary.get("f1"),
    }
    before = effects["asr_before"]
    after = effects["asr_after"]
    effects["asr_reduction"] = (
        float(before) - float(after)
        if isinstance(before, (int, float)) and isinstance(after, (int, float))
        else None
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "run_valid": not reasons,
        "run_status": "valid" if not reasons else "invalid",
        "invalid_reasons": reasons,
        "defense_effect_interpretable": not reasons,
        "dataset": {
            "dataset_id": off_summary.get("dataset_id"),
            "dataset_version": off_summary.get("dataset_version"),
            "dataset_digest": off_summary.get("dataset_digest"),
            "case_count": len(off_case_keys),
        },
        "effects": effects,
    }


def _run_pass(runner_args: list[str], *, defense: str, results_dir: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "agentguard_langgraph_bench.bench.runner",
        *runner_args,
        "--defense",
        defense,
        "--results-dir",
        str(results_dir),
    ]
    subprocess.run(command, check=True)


def _validate_runner_args(runner_args: list[str]) -> None:
    conflicting = sorted(
        option
        for option in FORBIDDEN_RUNNER_OPTIONS
        if option in runner_args or any(arg.startswith(f"{option}=") for arg in runner_args)
    )
    if conflicting:
        raise SystemExit(
            "paired runner owns these options: " + ", ".join(conflicting)
        )


def _result_paths(results_dir: Path) -> tuple[Path, Path]:
    summaries = list(results_dir.glob("run_*/summary_*.json"))
    rows = [
        path
        for path in results_dir.glob("run_*/run_*.json")
        if not path.name.startswith("run_manifest_")
    ]
    if len(summaries) != 1 or len(rows) != 1:
        raise RuntimeError(
            f"expected one summary and row artifact under {results_dir}, "
            f"found summaries={len(summaries)} rows={len(rows)}"
        )
    return summaries[0], rows[0]


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _read_json_array(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"expected JSON object array: {path}")
    return value


def _case_keys(
    rows: list[dict[str, Any]], label: str, reasons: list[str]
) -> set[str]:
    keys = [str(row.get("case_run_key") or row.get("case_id") or "") for row in rows]
    _require(all(keys), f"{label}_case_identity_missing", reasons)
    _require(len(keys) == len(set(keys)), f"{label}_duplicate_case_identity", reasons)
    return set(keys)


def _invalid_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("run_valid") is not True]


def _require(condition: bool, reason: str, reasons: list[str]) -> None:
    if not condition and reason not in reasons:
        reasons.append(reason)


def _artifact_identity(root: Path, *paths: Path) -> list[dict[str, Any]]:
    return [
        {
            "relative_path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in paths
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


if __name__ == "__main__":
    raise SystemExit(main())
