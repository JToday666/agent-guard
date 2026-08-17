"""Run a frozen AttackBench corpus as one real defense-off/on pair.

This module is the corpus building block used by the machine-owned reference
profile.  It deliberately keeps effect scores observational: dataset, row,
Core-mode, and artifact validity determine whether the pair is trustworthy,
while the numeric result never imposes an effectiveness threshold.
"""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .config import BenchConfig
from .dataset_contract import DatasetSnapshot, build_dataset_snapshot
from .dataset_loader import load_attack_cases
from .metrics import calculate_metrics, is_blocked
from .models import AttackCase
from .paired_runner import build_paired_report
from .runner import run_cases, write_results


CORPUS_RESULT_SCHEMA_VERSION = "reference-profile-corpus/1.0"
CORPUS_EFFECT_SCHEMA_VERSION = "reference-profile-corpus-effects/1.0"
CORPUS_ARTIFACT_MANIFEST_SCHEMA_VERSION = "profile-corpus-artifacts/1.0"


class ProfileCorpusError(RuntimeError):
    """Raised when corpus configuration or produced artifacts are invalid."""


@dataclass(frozen=True, slots=True)
class CorpusDatasetIdentity:
    """Frozen identity expected from the selected dataset directory."""

    dataset_id: str
    dataset_version: str
    dataset_digest: str
    case_count: int


TaskFactProvisioner = Callable[[AttackCase, str], str]


@dataclass(frozen=True, slots=True)
class CorpusPassRequest:
    """Inputs for one side of the paired run.

    ``trusted_task_ids_by_case`` is empty for defense-off and contains one
    server-provisioned TaskFact for every selected case for defense-on.
    """

    defense_enabled: bool
    core_base_url: str
    adapter_token: str
    runtime_binding_id: str
    adapter_name: str
    timeout: float
    dataset_path: Path
    dataset_snapshot: DatasetSnapshot
    cases: tuple[AttackCase, ...]
    results_dir: Path
    sandbox_dir: Path
    trusted_task_ids_by_case: Mapping[str, str]
    trusted_trace_ids_by_case: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class CorpusPassResult:
    """Rows, summary, and persisted artifacts from one AttackBench pass."""

    summary: Mapping[str, Any]
    rows: tuple[Mapping[str, Any], ...]
    artifact_paths: Mapping[str, str]


class CorpusPassExecutor(Protocol):
    def __call__(self, request: CorpusPassRequest) -> CorpusPassResult: ...


@dataclass(frozen=True, slots=True)
class CorpusRunResult:
    """JSON-safe result returned to the reference profile runtime."""

    paired_report: Mapping[str, Any]
    effect_metrics: Mapping[str, Any]
    artifact_paths: Mapping[str, Any]
    artifact_integrity: Mapping[str, Any]

    @property
    def run_valid(self) -> bool:
        return self.paired_report.get("run_valid") is True

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CORPUS_RESULT_SCHEMA_VERSION,
            "run_valid": self.run_valid,
            "paired_report": dict(self.paired_report),
            "effect_metrics": dict(self.effect_metrics),
            "artifact_paths": dict(self.artifact_paths),
            "artifact_integrity": dict(self.artifact_integrity),
        }


def run_profile_corpus(
    *,
    core_base_url: str,
    adapter_token: str,
    dataset_path: Path,
    dataset_identity: CorpusDatasetIdentity,
    output_root: Path,
    runtime_binding_id: str,
    provision_task_fact: TaskFactProvisioner,
    selected_case_ids: Sequence[str] | None = None,
    adapter_name: str = "langgraph-demo",
    timeout: float = 5.0,
    pass_executor: CorpusPassExecutor | None = None,
) -> CorpusRunResult:
    """Run the selected frozen cases once without and once with AgentGuard.

    ``selected_case_ids=None`` means the entire frozen dataset (70 cases for
    ``reference-langgraph``).  The production default executes the existing
    AttackBench ``run_cases``/``write_results`` primitives against the supplied
    live Guard API.  ``pass_executor`` exists as a focused integration seam;
    its output still passes the same real-Core, row, dataset, and artifact
    admission checks and therefore cannot make fake-Core rows trustworthy.
    """

    root = output_root.expanduser().resolve()
    _validate_inputs(
        core_base_url=core_base_url,
        adapter_token=adapter_token,
        runtime_binding_id=runtime_binding_id,
        adapter_name=adapter_name,
        timeout=timeout,
        output_root=root,
        dataset_identity=dataset_identity,
    )
    all_cases = load_attack_cases(dataset_path)
    selected_cases = _select_cases(all_cases, selected_case_ids)
    snapshot = build_dataset_snapshot(dataset_path, selected_cases)
    _validate_dataset_identity(
        snapshot=snapshot,
        full_case_count=len(all_cases),
        expected=dataset_identity,
    )

    root.mkdir(parents=True, exist_ok=False)
    executor = pass_executor or _execute_attackbench_pass
    with tempfile.TemporaryDirectory(prefix="agentguard-profile-corpus-") as raw:
        scratch = Path(raw)
        off = executor(
            CorpusPassRequest(
                defense_enabled=False,
                core_base_url=core_base_url,
                adapter_token=adapter_token,
                runtime_binding_id=runtime_binding_id,
                adapter_name=adapter_name,
                timeout=timeout,
                dataset_path=dataset_path,
                dataset_snapshot=snapshot,
                cases=_copy_cases(selected_cases),
                results_dir=root / "defense-off",
                sandbox_dir=scratch / "defense-off-sandbox",
                trusted_task_ids_by_case={},
                trusted_trace_ids_by_case={},
            )
        )

        task_ids, trace_ids = _provision_task_facts(selected_cases, provision_task_fact)
        on = executor(
            CorpusPassRequest(
                defense_enabled=True,
                core_base_url=core_base_url,
                adapter_token=adapter_token,
                runtime_binding_id=runtime_binding_id,
                adapter_name=adapter_name,
                timeout=timeout,
                dataset_path=dataset_path,
                dataset_snapshot=snapshot,
                cases=_copy_cases(selected_cases),
                results_dir=root / "defense-on",
                sandbox_dir=scratch / "defense-on-sandbox",
                trusted_task_ids_by_case=task_ids,
                trusted_trace_ids_by_case=trace_ids,
            )
        )

    off_summary, off_rows, off_paths = _admit_pass(
        off,
        root=root,
        defense_enabled=False,
        selected_cases=selected_cases,
        snapshot=snapshot,
    )
    on_summary, on_rows, on_paths = _admit_pass(
        on,
        root=root,
        defense_enabled=True,
        selected_cases=selected_cases,
        snapshot=snapshot,
    )
    effect_metrics = _build_effect_metrics(off_rows, on_rows)
    _attach_confusion_metrics(on_summary, effect_metrics)

    paired_report = build_paired_report(
        off_summary,
        off_rows,
        on_summary,
        on_rows,
    )
    paired_report["cases"] = _case_evidence(selected_cases, off_rows, on_rows)
    paired_report["artifacts"] = {
        "defense_off": _artifact_identities(root, off_paths),
        "defense_on": _artifact_identities(root, on_paths),
    }
    paired_report["effect_metrics_gate_exit_status"] = False

    report_path = _write_json(root / "paired-baseline-report.json", paired_report)
    effects_path = _write_json(root / "effect-metrics.json", effect_metrics)
    artifact_paths = {
        "paired_report": report_path.relative_to(root).as_posix(),
        "effect_metrics": effects_path.relative_to(root).as_posix(),
        "defense_off": _relative_artifact_paths(root, off_paths),
        "defense_on": _relative_artifact_paths(root, on_paths),
        "sha256_manifest": "sha256-manifest.json",
    }
    _write_json(
        root / "corpus-result.json",
        {
            "schema_version": CORPUS_RESULT_SCHEMA_VERSION,
            "run_valid": paired_report.get("run_valid") is True,
            "effect_metrics_gate_exit_status": False,
            "selected_case_count": len(selected_cases),
            "artifact_paths": artifact_paths,
        },
    )
    manifest = _write_sha256_manifest(root)
    artifact_integrity = {
        "schema_version": CORPUS_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "ok": bool(
            paired_report.get("run_valid") is True
            and off_summary.get("artifact_integrity", {}).get("ok") is True
            and on_summary.get("artifact_integrity", {}).get("ok") is True
        ),
        "defense_off": _pass_integrity(root, off_summary, off_paths),
        "defense_on": _pass_integrity(root, on_summary, on_paths),
        "sha256_manifest": {
            "relative_path": "sha256-manifest.json",
            "artifact_count": manifest["artifact_count"],
            "sha256": _sha256(root / "sha256-manifest.json"),
        },
    }
    return CorpusRunResult(
        paired_report=paired_report,
        effect_metrics=effect_metrics,
        artifact_paths=artifact_paths,
        artifact_integrity=artifact_integrity,
    )


def _execute_attackbench_pass(request: CorpusPassRequest) -> CorpusPassResult:
    config = BenchConfig(
        core_base_url=request.core_base_url,
        token=request.adapter_token,
        runtime_binding_id=(
            request.runtime_binding_id if request.defense_enabled else None
        ),
        timeout=request.timeout,
        fail_closed=True,
        defense_enabled=request.defense_enabled,
        runtime="langgraph",
        sandbox_dir=request.sandbox_dir,
        results_dir=request.results_dir,
        instrumentation_plan_mode="replay",
        agent_adapter=request.adapter_name,
        core_api_mode="guard-api-v0.3",
        context_isolation_mode=("required" if request.defense_enabled else "off"),
        trusted_task_ids_by_case=dict(request.trusted_task_ids_by_case),
        trusted_trace_ids_by_case=dict(request.trusted_trace_ids_by_case),
    )
    run_id = (
        "profile_corpus_"
        + ("defense_on_" if request.defense_enabled else "defense_off_")
        + uuid.uuid4().hex[:16]
    )
    rows = run_cases(
        list(request.cases),
        config=config,
        fake_core=False,
        reset_environment=True,
        scenario_stateful=False,
        isolate_scenarios=True,
        benchmark_run_id=run_id,
        run_metadata={
            "dataset_path": str(request.dataset_path),
            "profile_corpus": True,
            "scenario_stateful": False,
        },
    )
    core_mode = "real_core" if request.defense_enabled else "defense_off"
    summary = calculate_metrics(
        rows,
        defense_enabled=request.defense_enabled,
        core_mode=core_mode,
    )
    summary.update(request.dataset_snapshot.as_dict())
    paths = write_results(rows, summary, request.results_dir)
    return CorpusPassResult(
        summary=summary,
        rows=tuple(rows),
        artifact_paths=paths,
    )


def _validate_inputs(
    *,
    core_base_url: str,
    adapter_token: str,
    runtime_binding_id: str,
    adapter_name: str,
    timeout: float,
    output_root: Path,
    dataset_identity: CorpusDatasetIdentity,
) -> None:
    if not core_base_url.strip():
        raise ProfileCorpusError("Guard API base URL must not be empty")
    if not adapter_token:
        raise ProfileCorpusError("adapter token must not be empty")
    if not runtime_binding_id:
        raise ProfileCorpusError("runtime binding id must not be empty")
    if adapter_name != "langgraph-demo":
        raise ProfileCorpusError("profile corpus requires the LangGraph adapter")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProfileCorpusError("timeout must be a positive finite number")
    if output_root.exists():
        raise ProfileCorpusError(
            f"corpus artifact directory must not already exist: {output_root}"
        )
    if (
        not dataset_identity.dataset_id
        or not dataset_identity.dataset_version
        or not dataset_identity.dataset_digest.startswith("sha256:")
        or dataset_identity.case_count < 1
    ):
        raise ProfileCorpusError("frozen dataset identity is incomplete")


def _select_cases(
    all_cases: Sequence[AttackCase], selected_case_ids: Sequence[str] | None
) -> list[AttackCase]:
    by_id = {case.case_id: case for case in all_cases}
    if len(by_id) != len(all_cases):
        raise ProfileCorpusError("frozen corpus contains duplicate case ids")
    if selected_case_ids is None:
        return list(all_cases)
    requested = tuple(selected_case_ids)
    if not requested or any(not item for item in requested):
        raise ProfileCorpusError("selected case ids must not be empty")
    if len(requested) != len(set(requested)):
        raise ProfileCorpusError("selected case ids must be unique")
    missing = sorted(set(requested) - set(by_id))
    if missing:
        raise ProfileCorpusError(
            "selected cases are absent from the frozen dataset: " + ", ".join(missing)
        )
    selected = set(requested)
    return [case for case in all_cases if case.case_id in selected]


def _validate_dataset_identity(
    *,
    snapshot: DatasetSnapshot,
    full_case_count: int,
    expected: CorpusDatasetIdentity,
) -> None:
    comparisons = {
        "dataset_id": (snapshot.dataset_id, expected.dataset_id),
        "dataset_version": (snapshot.dataset_version, expected.dataset_version),
        "dataset_digest": (snapshot.dataset_digest, expected.dataset_digest),
        "case_count": (full_case_count, expected.case_count),
        "dataset_locked": (snapshot.dataset_locked, True),
    }
    mismatches = [
        field for field, (actual, wanted) in comparisons.items() if actual != wanted
    ]
    if mismatches:
        raise ProfileCorpusError(
            "dataset does not match frozen identity: " + ", ".join(mismatches)
        )


def _copy_cases(cases: Sequence[AttackCase]) -> tuple[AttackCase, ...]:
    return tuple(case.model_copy(deep=True) for case in cases)


def _provision_task_facts(
    cases: Sequence[AttackCase], provisioner: TaskFactProvisioner
) -> tuple[dict[str, str], dict[str, str]]:
    task_ids: dict[str, str] = {}
    trace_ids: dict[str, str] = {}
    for case in cases:
        safe_case_id = "".join(
            character.lower() if character.isalnum() else "-"
            for character in case.case_id
        ).strip("-")
        trace_id = f"trace_profile_corpus_{safe_case_id}_{uuid.uuid4().hex[:16]}"
        task_id = provisioner(case, trace_id)
        if not isinstance(task_id, str) or not task_id:
            raise ProfileCorpusError(
                f"TaskFact provisioner returned no task id for {case.case_id}"
            )
        task_ids[case.case_id] = task_id
        trace_ids[case.case_id] = trace_id
    if len(set(task_ids.values())) != len(task_ids):
        raise ProfileCorpusError("TaskFact ids must be unique per selected case")
    return task_ids, trace_ids


def _admit_pass(
    result: CorpusPassResult,
    *,
    root: Path,
    defense_enabled: bool,
    selected_cases: Sequence[AttackCase],
    snapshot: DatasetSnapshot,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Path]]:
    summary = dict(result.summary)
    rows = [dict(row) for row in result.rows]
    expected_mode = "real_core" if defense_enabled else "defense_off"
    if summary.get("defense_enabled") is not defense_enabled:
        raise ProfileCorpusError(f"{expected_mode} summary has the wrong defense mode")
    if summary.get("core_mode") != expected_mode:
        raise ProfileCorpusError(
            f"{expected_mode} pass did not use the required Core mode"
        )
    if len(rows) != len(selected_cases):
        raise ProfileCorpusError(f"{expected_mode} pass returned the wrong row count")
    for row in rows:
        if row.get("defense_enabled") is not defense_enabled:
            raise ProfileCorpusError(f"{expected_mode} row has the wrong defense mode")
        if row.get("core_mode") != expected_mode:
            raise ProfileCorpusError(f"{expected_mode} row has the wrong Core mode")
    _validate_row_bindings(rows, selected_cases, expected_mode)
    _attach_snapshot(summary, snapshot)
    paths = _admit_artifact_paths(result.artifact_paths, root=root)
    _validate_pass_artifact_integrity(
        summary,
        paths["artifact_integrity_manifest"],
        selected_cases,
        expected_mode,
    )
    return summary, rows, paths


def _attach_snapshot(summary: dict[str, Any], snapshot: DatasetSnapshot) -> None:
    for field, value in snapshot.as_dict().items():
        current = summary.get(field)
        if current is not None and current != value:
            raise ProfileCorpusError(
                f"pass summary changed frozen dataset field: {field}"
            )
        summary[field] = value


def _validate_row_bindings(
    rows: Sequence[Mapping[str, Any]],
    cases: Sequence[AttackCase],
    label: str,
) -> None:
    expected = {
        (
            case.case_id,
            str(case.metadata.get("dataset_file") or ""),
            int(case.metadata.get("dataset_row_index") or 0),
        )
        for case in cases
    }
    actual = {
        (
            str(row.get("case_id") or ""),
            str(row.get("dataset_file") or ""),
            int(row.get("dataset_row_index") or 0),
        )
        for row in rows
    }
    case_run_keys = [str(row.get("case_run_key") or "") for row in rows]
    if expected != actual:
        raise ProfileCorpusError(f"{label} rows do not bind to the selected dataset")
    if not all(case_run_keys) or len(case_run_keys) != len(set(case_run_keys)):
        raise ProfileCorpusError(f"{label} rows have invalid case identities")


def _validate_pass_artifact_integrity(
    summary: Mapping[str, Any],
    manifest_path: Path,
    selected_cases: Sequence[AttackCase],
    label: str,
) -> None:
    expected_case_ids = {case.case_id for case in selected_cases}
    expected_case_count = len(expected_case_ids)
    integrity = summary.get("artifact_integrity")
    if not isinstance(integrity, Mapping) or integrity.get("ok") is not True:
        raise ProfileCorpusError(f"{label} artifact integrity is not valid")
    if integrity.get("case_count") != expected_case_count:
        raise ProfileCorpusError(
            f"{label} artifact integrity summary has the wrong case count"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileCorpusError(
            f"{label} artifact integrity manifest is invalid"
        ) from exc
    if not isinstance(manifest, Mapping) or manifest.get("ok") is not True:
        raise ProfileCorpusError(f"{label} artifact integrity manifest is not valid")
    cases = manifest.get("cases")
    if not isinstance(cases, Mapping):
        raise ProfileCorpusError(
            f"{label} artifact integrity manifest has no case index"
        )
    actual_case_ids = {str(case_id) for case_id in cases}
    if actual_case_ids != expected_case_ids:
        raise ProfileCorpusError(
            f"{label} artifact integrity manifest case set does not match selected cases"
        )
    if manifest.get("case_count") != expected_case_count:
        raise ProfileCorpusError(
            f"{label} artifact integrity manifest has the wrong case count"
        )


def _admit_artifact_paths(
    raw_paths: Mapping[str, str], *, root: Path
) -> dict[str, Path]:
    required = {
        "run_json",
        "summary_json",
        "run_manifest",
        "artifact_integrity_manifest",
    }
    missing = sorted(required - set(raw_paths))
    if missing:
        raise ProfileCorpusError("pass artifacts are incomplete: " + ", ".join(missing))
    admitted: dict[str, Path] = {}
    for key, raw in raw_paths.items():
        path = Path(raw).expanduser().resolve()
        try:
            path.relative_to(root)
        except ValueError:
            if key in required:
                raise ProfileCorpusError(
                    f"required pass artifact escapes corpus root: {key}"
                ) from None
            continue
        if path.is_file():
            admitted[key] = path
        elif key in required:
            raise ProfileCorpusError(f"required pass artifact is missing: {key}")
    return admitted


def _build_effect_metrics(
    off_rows: Sequence[Mapping[str, Any]],
    on_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    off_malicious = _applicable_rows(off_rows, malicious=True)
    on_malicious = _applicable_rows(on_rows, malicious=True)
    on_benign = _applicable_rows(on_rows, malicious=False)
    off_success = sum(row.get("attack_success") is True for row in off_malicious)
    on_success = sum(row.get("attack_success") is True for row in on_malicious)
    true_positive = sum(is_blocked(dict(row)) for row in on_malicious)
    false_negative = len(on_malicious) - true_positive
    false_positive = sum(is_blocked(dict(row)) for row in on_benign)
    true_negative = len(on_benign) - false_positive
    precision_denominator = true_positive + false_positive
    latency = _latency_metrics(on_rows)
    return {
        "schema_version": CORPUS_EFFECT_SCHEMA_VERSION,
        "gate_exit_status": False,
        "thresholds_applied": False,
        "asr_before": _ratio(off_success, len(off_malicious)),
        "asr_after": _ratio(on_success, len(on_malicious)),
        "asr_reduction": _difference(
            _value(off_success, len(off_malicious)),
            _value(on_success, len(on_malicious)),
        ),
        "block_rate": _ratio(true_positive, len(on_malicious)),
        "fpr": _ratio(false_positive, len(on_benign)),
        "fnr": _ratio(false_negative, len(on_malicious)),
        "precision": _ratio(true_positive, precision_denominator),
        "recall": _ratio(true_positive, len(on_malicious)),
        "f1": _f1(true_positive, false_positive, false_negative),
        "confusion": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "decision_latency_ms": latency,
    }


def _applicable_rows(
    rows: Sequence[Mapping[str, Any]], *, malicious: bool
) -> list[Mapping[str, Any]]:
    return [
        row
        for row in rows
        if bool(row.get("is_malicious")) is malicious
        and row.get("not_applicable") is not True
        and row.get("infrastructure_failure") is not True
    ]


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "value": _value(numerator, denominator),
        "numerator": numerator,
        "denominator": denominator,
    }


def _value(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _difference(before: float | None, after: float | None) -> float | None:
    return before - after if before is not None and after is not None else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> dict[str, Any]:
    denominator = 2 * true_positive + false_positive + false_negative
    return {
        "value": (2 * true_positive / denominator) if denominator else None,
        "numerator": 2 * true_positive,
        "denominator": denominator,
    }


def _latency_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    values: list[float] = []
    for row in rows:
        for call in row.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            audit = call.get("audit_event")
            latency = audit.get("latency_ms") if isinstance(audit, dict) else None
            if (
                isinstance(latency, (int, float))
                and not isinstance(latency, bool)
                and math.isfinite(float(latency))
                and float(latency) >= 0
            ):
                values.append(float(latency))
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "mean": (sum(ordered) / len(ordered)) if ordered else None,
        "p50": _percentile(ordered, 50),
        "p95": _percentile(ordered, 95),
        "max": ordered[-1] if ordered else None,
    }


def _percentile(values: Sequence[float], percentile: int) -> float | None:
    if not values:
        return None
    index = math.ceil((percentile / 100) * len(values)) - 1
    return values[max(0, min(index, len(values) - 1))]


def _attach_confusion_metrics(
    on_summary: dict[str, Any], effect_metrics: Mapping[str, Any]
) -> None:
    for field in ("fnr", "precision", "recall", "f1"):
        metric = effect_metrics.get(field)
        on_summary[field] = metric.get("value") if isinstance(metric, dict) else None


def _case_evidence(
    cases: Sequence[AttackCase],
    off_rows: Sequence[Mapping[str, Any]],
    on_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    off_keys = {str(row["case_id"]): str(row["case_run_key"]) for row in off_rows}
    on_keys = {str(row["case_id"]): str(row["case_run_key"]) for row in on_rows}
    evidence = []
    for case in cases:
        if off_keys[case.case_id] != on_keys[case.case_id]:
            raise ProfileCorpusError(f"paired case identity drifted for {case.case_id}")
        evidence.append(
            {
                "case_id": case.case_id,
                "case_run_key": off_keys[case.case_id],
                "dataset_file": case.metadata.get("dataset_file"),
                "dataset_row_index": case.metadata.get("dataset_row_index"),
                "case_digest": case.metadata.get("case_digest"),
                "provenance": case.metadata.get("provenance"),
            }
        )
    return evidence


def _artifact_identities(root: Path, paths: Mapping[str, Path]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "relative_path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for name, path in sorted(paths.items())
    ]


def _relative_artifact_paths(root: Path, paths: Mapping[str, Path]) -> dict[str, str]:
    return {
        name: path.relative_to(root).as_posix() for name, path in sorted(paths.items())
    }


def _pass_integrity(
    root: Path, summary: Mapping[str, Any], paths: Mapping[str, Path]
) -> dict[str, Any]:
    integrity = summary.get("artifact_integrity")
    integrity = integrity if isinstance(integrity, dict) else {}
    manifest = paths["artifact_integrity_manifest"]
    return {
        "ok": integrity.get("ok") is True,
        "case_count": integrity.get("case_count"),
        "manifest": manifest.relative_to(root).as_posix(),
        "manifest_sha256": _sha256(manifest),
    }


def _write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _write_sha256_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / "sha256-manifest.json"
    entries = [
        {
            "relative_path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path != manifest_path
    ]
    if not entries:
        raise ProfileCorpusError("corpus artifact manifest cannot be empty")
    manifest = {
        "schema_version": CORPUS_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "algorithm": "sha256",
        "self_excluded": manifest_path.name,
        "artifact_count": len(entries),
        "artifacts": entries,
    }
    _write_json(manifest_path, manifest)
    return manifest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()
