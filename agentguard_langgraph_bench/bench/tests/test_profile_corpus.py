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
            "artifact_integrity": {"ok": True, "case_count": len(rows)},
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
                {"ok": True},
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
