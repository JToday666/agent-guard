from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.profile_corpus import (
    CorpusDatasetIdentity,
    CorpusPassRequest,
    CorpusPassResult,
    ProfileCorpusError,
    run_profile_corpus,
)
from agentguard_langgraph_bench.bench.profile_runner import (
    InvalidProfileRun,
    RunRequest,
    load_profile,
)
from agentguard_langgraph_bench.bench.profile_runtime import (
    _corpus_case_selection,
    _corpus_selection_mode,
    _corpus_summary,
)


DATASET = Path("agentguard_langgraph_bench/bench/datasets/attack_cases")


def _identity() -> CorpusDatasetIdentity:
    manifest = json.loads(
        (DATASET / "dataset_manifest.json").read_text(encoding="utf-8")
    )
    return CorpusDatasetIdentity(
        dataset_id=manifest["dataset_id"],
        dataset_version=manifest["dataset_version"],
        dataset_digest=manifest["dataset_digest"],
        case_count=manifest["case_count"],
    )


def _executor(
    *,
    on_core_mode: str = "real_core",
    invalid_case: str | None = None,
    defense_effective: bool = True,
    missing_integrity_case: str | None = None,
    integrity_summary_case_count: int | None = None,
):
    requests: list[CorpusPassRequest] = []

    def execute(request: CorpusPassRequest) -> CorpusPassResult:
        requests.append(request)
        core_mode = on_core_mode if request.defense_enabled else "defense_off"
        rows = []
        for case in request.cases:
            malicious = bool(case.is_malicious)
            blocked = request.defense_enabled and (
                malicious if defense_effective else not malicious
            )
            rows.append(
                {
                    "case_id": case.case_id,
                    "case_run_key": case.case_id,
                    "dataset_file": case.metadata["dataset_file"],
                    "dataset_row_index": case.metadata["dataset_row_index"],
                    "defense_enabled": request.defense_enabled,
                    "core_mode": core_mode,
                    "is_malicious": malicious,
                    "attack_success": malicious
                    and (not request.defense_enabled or not defense_effective),
                    "blocked": blocked,
                    "decisions": ["deny" if blocked else "allow"],
                    "run_valid": case.case_id != invalid_case,
                    "tool_calls": [{"audit_event": {"latency_ms": 7}}],
                }
            )
        malicious_rows = [row for row in rows if row["is_malicious"]]
        benign_rows = [row for row in rows if not row["is_malicious"]]
        summary = {
            "defense_enabled": request.defense_enabled,
            "core_mode": core_mode,
            "case_count": len(rows),
            "run_integrity_failed": False,
            "artifact_integrity": {
                "ok": True,
                "case_count": (
                    len(rows)
                    if integrity_summary_case_count is None
                    else integrity_summary_case_count
                ),
            },
            "asr_before": (
                sum(row["attack_success"] for row in malicious_rows)
                / len(malicious_rows)
                if not request.defense_enabled
                else None
            ),
            "asr_after": (
                sum(row["attack_success"] for row in malicious_rows)
                / len(malicious_rows)
                if request.defense_enabled
                else None
            ),
            "block_rate": (
                sum(row["blocked"] for row in malicious_rows) / len(malicious_rows)
                if request.defense_enabled
                else None
            ),
            "fpr": (
                sum(row["blocked"] for row in benign_rows) / len(benign_rows)
                if request.defense_enabled
                else None
            ),
        }
        run_dir = request.results_dir / "run_focused"
        run_dir.mkdir(parents=True)
        paths = {}
        for key, name, payload in (
            ("run_json", "run.json", rows),
            ("summary_json", "summary.json", summary),
            ("run_manifest", "manifest.json", {"run_integrity_ok": True}),
            (
                "artifact_integrity_manifest",
                "artifact-integrity.json",
                {
                    "ok": True,
                    "case_count": sum(
                        row["case_id"] != missing_integrity_case for row in rows
                    ),
                    "cases": {
                        row["case_id"]: {"case_id": row["case_id"], "ok": True}
                        for row in rows
                        if row["case_id"] != missing_integrity_case
                    },
                },
            ),
        ):
            path = run_dir / name
            path.write_text(json.dumps(payload), encoding="utf-8")
            paths[key] = str(path)
        return CorpusPassResult(
            summary=summary,
            rows=tuple(rows),
            artifact_paths=paths,
        )

    return execute, requests


def test_profile_corpus_runs_two_case_real_pair_and_returns_json_artifacts(
    tmp_path: Path,
) -> None:
    execute, requests = _executor()
    provisioned: list[tuple[str, str]] = []

    result = run_profile_corpus(
        core_base_url="http://127.0.0.1:8088",
        adapter_token="adapter-test-token",
        dataset_path=DATASET,
        dataset_identity=_identity(),
        output_root=tmp_path / "paired",
        runtime_binding_id="binding:reference-langgraph",
        provision_task_fact=lambda case, trace_id: (
            provisioned.append((case.case_id, trace_id)) or f"task_{case.case_id}"
        ),
        selected_case_ids=("PI-001", "BN-001"),
        pass_executor=execute,
    )

    assert result.run_valid is True
    assert len(requests) == 2
    assert requests[0].defense_enabled is False
    assert requests[0].trusted_task_ids_by_case == {}
    assert requests[1].defense_enabled is True
    assert set(requests[1].trusted_task_ids_by_case) == {"BN-001", "PI-001"}
    assert {case_id for case_id, _ in provisioned} == {"BN-001", "PI-001"}
    assert result.effect_metrics["asr_before"] == {
        "value": 1.0,
        "numerator": 1,
        "denominator": 1,
    }
    assert result.effect_metrics["asr_after"]["value"] == 0.0
    assert result.effect_metrics["recall"]["value"] == 1.0
    assert result.effect_metrics["fpr"]["value"] == 0.0
    assert result.effect_metrics["decision_latency_ms"]["p95"] == 7.0
    assert result.effect_metrics["gate_exit_status"] is False
    assert result.artifact_integrity["ok"] is True
    assert result.artifact_integrity["sha256_manifest"]["artifact_count"] >= 10
    assert (tmp_path / "paired" / "sha256-manifest.json").is_file()
    json.dumps(result.as_dict())

    summary = _corpus_summary(
        RunRequest(
            profile=load_profile("reference-langgraph"),
            artifacts=tmp_path,
            storage="memory",
            full_corpus=False,
            corpus_case_ids=("PI-001", "BN-001"),
            llm_observation=False,
        ),
        result,
    )
    assert summary["run_valid"] is True
    assert summary["selection_mode"] == "selected"
    assert summary["requested_case_ids"] == ["PI-001", "BN-001"]
    assert summary["executed_dataset_case_ids"] == ["BN-001", "PI-001"]
    assert summary["executed_case_count"] == 2
    assert summary["paired_report"]["dataset"]["case_count"] == 2
    assert summary["effect_metrics"]["gate_exit_status"] is False
    assert summary["artifact_integrity"]["ok"] is True
    assert summary["artifacts"]["paired_report"] == (
        "paired/paired-baseline-report.json"
    )


def test_profile_corpus_rejects_fake_core_output(tmp_path: Path) -> None:
    execute, _ = _executor(on_core_mode="fake_deny")

    with pytest.raises(ProfileCorpusError, match="required Core mode"):
        run_profile_corpus(
            core_base_url="http://127.0.0.1:8088",
            adapter_token="adapter-test-token",
            dataset_path=DATASET,
            dataset_identity=_identity(),
            output_root=tmp_path / "fake-core",
            runtime_binding_id="binding:reference-langgraph",
            provision_task_fact=lambda case, trace_id: f"task_{case.case_id}",
            selected_case_ids=("PI-001", "BN-001"),
            pass_executor=execute,
        )


def test_profile_corpus_rejects_integrity_manifest_missing_selected_case(
    tmp_path: Path,
) -> None:
    execute, _ = _executor(missing_integrity_case="PI-001")

    with pytest.raises(ProfileCorpusError, match="manifest case set"):
        run_profile_corpus(
            core_base_url="http://127.0.0.1:8088",
            adapter_token="adapter-test-token",
            dataset_path=DATASET,
            dataset_identity=_identity(),
            output_root=tmp_path / "missing-integrity-case",
            runtime_binding_id="binding:reference-langgraph",
            provision_task_fact=lambda case, trace_id: f"task_{case.case_id}",
            selected_case_ids=("PI-001", "BN-001"),
            pass_executor=execute,
        )


def test_profile_corpus_rejects_integrity_summary_case_count_mismatch(
    tmp_path: Path,
) -> None:
    execute, _ = _executor(integrity_summary_case_count=1)

    with pytest.raises(ProfileCorpusError, match="summary has the wrong case count"):
        run_profile_corpus(
            core_base_url="http://127.0.0.1:8088",
            adapter_token="adapter-test-token",
            dataset_path=DATASET,
            dataset_identity=_identity(),
            output_root=tmp_path / "integrity-count-mismatch",
            runtime_binding_id="binding:reference-langgraph",
            provision_task_fact=lambda case, trace_id: f"task_{case.case_id}",
            selected_case_ids=("PI-001", "BN-001"),
            pass_executor=execute,
        )


def test_profile_corpus_marks_invalid_rows_non_interpretable(tmp_path: Path) -> None:
    execute, _ = _executor(invalid_case="PI-001")

    result = run_profile_corpus(
        core_base_url="http://127.0.0.1:8088",
        adapter_token="adapter-test-token",
        dataset_path=DATASET,
        dataset_identity=_identity(),
        output_root=tmp_path / "invalid-row",
        runtime_binding_id="binding:reference-langgraph",
        provision_task_fact=lambda case, trace_id: f"task_{case.case_id}",
        selected_case_ids=("PI-001", "BN-001"),
        pass_executor=execute,
    )

    assert result.run_valid is False
    assert result.paired_report["defense_effect_interpretable"] is False
    assert "defense_off_invalid_cases" in result.paired_report["invalid_reasons"]
    assert "defense_on_invalid_cases" in result.paired_report["invalid_reasons"]
    assert result.artifact_integrity["ok"] is False


def test_profile_corpus_effect_values_never_gate_a_valid_pair(tmp_path: Path) -> None:
    execute, _ = _executor(defense_effective=False)

    result = run_profile_corpus(
        core_base_url="http://127.0.0.1:8088",
        adapter_token="adapter-test-token",
        dataset_path=DATASET,
        dataset_identity=_identity(),
        output_root=tmp_path / "observational-only",
        runtime_binding_id="binding:reference-langgraph",
        provision_task_fact=lambda case, trace_id: f"task_{case.case_id}",
        selected_case_ids=("PI-001", "BN-001"),
        pass_executor=execute,
    )

    assert result.run_valid is True
    assert result.effect_metrics["asr_after"]["value"] == 1.0
    assert result.effect_metrics["fpr"]["value"] == 1.0
    assert result.effect_metrics["recall"]["value"] == 0.0
    assert result.effect_metrics["gate_exit_status"] is False


def test_runtime_forwards_selected_cases_and_keeps_full_at_frozen_70() -> None:
    profile = load_profile("reference-langgraph")
    selected = RunRequest(
        profile=profile,
        artifacts=Path("selected-artifacts"),
        storage="memory",
        full_corpus=False,
        corpus_case_ids=("PI-001", "BN-001"),
        llm_observation=False,
    )
    full = RunRequest(
        profile=profile,
        artifacts=Path("full-artifacts"),
        storage="memory",
        full_corpus=True,
        corpus_case_ids=(),
        llm_observation=False,
    )

    assert _corpus_selection_mode(selected) == "selected"
    assert _corpus_case_selection(selected) == ("PI-001", "BN-001")
    assert _corpus_selection_mode(full) == "full"
    assert _corpus_case_selection(full) is None
    assert full.profile.dataset.full_case_count == 70


def test_corpus_summary_marks_default_profile_as_not_requested() -> None:
    request = RunRequest(
        profile=load_profile("reference-langgraph"),
        artifacts=Path("default-artifacts"),
        storage="memory",
        full_corpus=False,
        corpus_case_ids=(),
        llm_observation=False,
    )

    summary = _corpus_summary(request, None)

    assert summary["selection_mode"] == "not_requested"
    assert summary["requested"] is False
    assert summary["requested_case_ids"] == []
    assert summary["status"] == "not_requested"
    assert summary["executed_case_count"] == 2


def test_corpus_summary_rejects_missing_selected_result() -> None:
    request = RunRequest(
        profile=load_profile("reference-langgraph"),
        artifacts=Path("selected-artifacts"),
        storage="memory",
        full_corpus=False,
        corpus_case_ids=("PI-001", "BN-001"),
        llm_observation=False,
    )

    with pytest.raises(
        InvalidProfileRun, match="requested corpus result is unavailable"
    ):
        _corpus_summary(request, None)
