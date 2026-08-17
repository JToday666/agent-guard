from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agentguard_langgraph_bench.bench.profile_runner import (
    ARTIFACT_MANIFEST_SCHEMA_VERSION,
    ExecutionResult,
    ExitCode,
    RunRequest,
    load_profile,
    main,
    run,
)


def _contracts(profile, *, failed: str | None = None):
    return {
        probe: {
            "status": "failed" if probe == failed else "passed",
            "evidence_refs": [f"artifact:contract-results.json:{probe}"],
            "reason_code": f"{probe}_{'failed' if probe == failed else 'passed'}",
        }
        for probe in profile.contract_probes
    }


def test_packaged_reference_profile_is_machine_owned_and_non_gating() -> None:
    profile = load_profile("reference-langgraph")

    assert profile.profile_id == "reference-langgraph"
    assert profile.official_decision_source == "current"
    assert profile.v2_decision_mode == "shadow"
    assert profile.context_isolation_mode == "required"
    assert profile.strong_binding_required is True
    assert profile.dataset.full_case_count == 70
    assert profile.effect_metrics_mode == "observational"
    assert profile.effect_metrics_gate_exit_status is False
    assert profile.digest.startswith("sha256:")


def test_profile_run_writes_complete_sha256_manifest(tmp_path: Path) -> None:
    profile = load_profile("reference-langgraph")
    root = tmp_path / "new-profile-artifacts"

    exit_code = run(
        RunRequest(
            profile=profile,
            artifacts=root,
            storage="memory",
            full_corpus=False,
            llm_observation=False,
        ),
        executor=lambda _: ExecutionResult(
            contracts=_contracts(profile),
            metrics={"gate_exit_status": False, "asr": 0.91},
            artifacts={"trace/trace-1.json": {"trace_id": "trace-1"}},
        ),
    )

    assert exit_code == ExitCode.PASSED
    manifest = json.loads((root / "sha256-manifest.json").read_text())
    assert manifest["schema_version"] == ARTIFACT_MANIFEST_SCHEMA_VERSION
    assert manifest["self_excluded"] == "sha256-manifest.json"
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "sha256-manifest.json"
    }
    assert {item["relative_path"] for item in manifest["artifacts"]} == actual_paths
    for item in manifest["artifacts"]:
        content = (root / item["relative_path"]).read_bytes()
        assert item["sha256"] == "sha256:" + hashlib.sha256(content).hexdigest()
    result = json.loads((root / "result.json").read_text())
    assert result["exit_code"] == 0
    assert result["effect_metrics_gate_exit_status"] is False


def test_functional_failure_is_exit_one_even_when_effect_metric_is_good(
    tmp_path: Path,
) -> None:
    profile = load_profile("reference-langgraph")
    failed_probe = profile.contract_probes[0]

    exit_code = run(
        RunRequest(
            profile=profile,
            artifacts=tmp_path / "failed-contract",
            storage="memory",
            full_corpus=False,
            llm_observation=False,
        ),
        executor=lambda _: ExecutionResult(
            contracts=_contracts(profile, failed=failed_probe),
            metrics={"gate_exit_status": False, "asr": 0.0, "fpr": 0.0},
            artifacts={},
        ),
    )

    assert exit_code == ExitCode.FUNCTIONAL_CONTRACT_FAILED


def test_preexisting_artifact_directory_is_exit_two(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()

    exit_code = main(
        [
            "run",
            "--profile",
            "reference-langgraph",
            "--artifacts",
            str(existing),
        ]
    )

    assert exit_code == ExitCode.INVALID_RUN
    assert list(existing.iterdir()) == []
