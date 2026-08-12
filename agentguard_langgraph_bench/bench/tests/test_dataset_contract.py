from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.config import DEFAULT_DATASET_DIR
from agentguard_langgraph_bench.bench.dataset_contract import (
    DatasetContractError,
    build_dataset_snapshot,
)
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


def test_committed_attackbench_dataset_is_locked_and_traceable() -> None:
    cases = load_attack_cases(DEFAULT_DATASET_DIR)
    snapshot = build_dataset_snapshot(DEFAULT_DATASET_DIR, cases)

    assert len(cases) == 70
    assert snapshot.dataset_id == "agentguard-attackbench"
    assert snapshot.dataset_version == "2026.08.1"
    assert snapshot.dataset_locked is True
    assert snapshot.dataset_digest.startswith("sha256:")
    assert snapshot.selected_case_digest.startswith("sha256:")
    assert all(case.metadata["case_digest"].startswith("sha256:") for case in cases)
    assert all(case.metadata["provenance"]["line"] >= 1 for case in cases)


def test_locked_dataset_rejects_silent_source_drift(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "attack_cases"
    shutil.copytree(DEFAULT_DATASET_DIR, dataset_dir)
    benign = dataset_dir / "benign.jsonl"
    benign.write_text(
        benign.read_text(encoding="utf-8").replace("BN-001", "BN-DRIFT", 1),
        encoding="utf-8",
    )

    with pytest.raises(DatasetContractError, match="digest mismatch"):
        load_attack_cases(dataset_dir)


def test_locked_dataset_digest_is_stable_across_line_endings(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "attack_cases"
    shutil.copytree(DEFAULT_DATASET_DIR, dataset_dir)
    for source in dataset_dir.glob("*.jsonl"):
        source.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))

    cases = load_attack_cases(dataset_dir)
    snapshot = build_dataset_snapshot(dataset_dir, cases)

    assert len(cases) == 70
    assert snapshot.dataset_locked is True


def test_unregistered_dataset_is_explicitly_unlocked(tmp_path: Path) -> None:
    source = DEFAULT_DATASET_DIR / "benign.jsonl"
    target = tmp_path / "custom.jsonl"
    target.write_bytes(source.read_bytes())

    cases = load_attack_cases(target)
    snapshot = build_dataset_snapshot(target, cases[:1])

    assert snapshot.dataset_locked is False
    assert snapshot.dataset_version == "unlocked"
    assert snapshot.selected_case_count == 1
    assert snapshot.dataset_digest.startswith("sha256:")


def test_manifest_declares_exact_attack_type_counts() -> None:
    manifest = json.loads(
        (DEFAULT_DATASET_DIR / "dataset_manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["case_count"] == 70
    assert manifest["digest_canonicalization"] == "utf8-lf"
    assert manifest["attack_type_counts"] == {
        "agent_abuse": 10,
        "benign": 10,
        "file_exfiltration": 10,
        "jailbreak": 10,
        "memory_poisoning": 10,
        "prompt_injection": 10,
        "tool_hijacking": 10,
    }
