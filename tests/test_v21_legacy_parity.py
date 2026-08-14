"""V21-01 acceptance: legacy decision parity against frozen 69efe2f snapshot."""

from __future__ import annotations

import functools
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ATTACK_DATASET = (
    ROOT / "tests" / "fixtures" / "eval_gate" / "retained_attack_cases.jsonl"
)
BENIGN_DATASET = ROOT / "tests" / "fixtures" / "eval_gate" / "retained_benign.jsonl"
LEGACY_SNAPSHOT = ROOT / "tests" / "fixtures" / "v21" / "legacy_69efe2f_snapshot.json"

EXPECTED_BASE_COMMIT = "69efe2f027d9a4ba9c18623838e84f6ce30ffa62"
EXPECTED_DISTRIBUTION = {"allow": 14, "ask": 2, "deny": 27}


@functools.lru_cache(maxsize=1)
def _load_eval_gate_module():
    # 缓存加载结果，避免每个测试重复 spec 构建与 exec_module。
    path = ROOT / "scripts" / "core-metrics-gate.py"
    spec = importlib.util.spec_from_file_location("agentguard_core_metrics_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_retained_datasets() -> list[dict]:
    gate = _load_eval_gate_module()
    attack_cases = gate.load_cases(ATTACK_DATASET)
    benign_cases = gate.load_cases(BENIGN_DATASET)
    attacks = [gate.evaluate_case(case, is_malicious=True) for case in attack_cases]
    benign = [gate.evaluate_case(case, is_malicious=False) for case in benign_cases]
    return attacks + benign


def test_retained_dataset_sizes_are_frozen() -> None:
    gate = _load_eval_gate_module()

    attack_cases = gate.load_cases(ATTACK_DATASET)
    benign_cases = gate.load_cases(BENIGN_DATASET)

    assert len(attack_cases) == 30
    assert len(benign_cases) == 13


def test_snapshot_is_anchored_to_baseline_commit() -> None:
    snapshot = json.loads(LEGACY_SNAPSHOT.read_text(encoding="utf-8"))

    assert snapshot["schema_version"] == "1.0"
    assert snapshot["base_commit"] == EXPECTED_BASE_COMMIT
    assert snapshot["decision_distribution"] == EXPECTED_DISTRIBUTION
    assert len(snapshot["cases"]) == 43


def test_current_legacy_path_matches_frozen_snapshot_case_by_case() -> None:
    snapshot = json.loads(LEGACY_SNAPSHOT.read_text(encoding="utf-8"))
    frozen_cases = {case["case_id"]: case for case in snapshot["cases"]}

    results = _run_retained_datasets()
    actual_cases = {
        result["case_id"]: {
            "case_id": result["case_id"],
            "decision": result["decision"],
            "rule_hits": result["rule_hits"],
        }
        for result in results
    }

    assert set(actual_cases) == set(frozen_cases)

    mismatches = []
    for case_id in sorted(frozen_cases):
        expected = frozen_cases[case_id]
        actual = actual_cases[case_id]
        if (
            expected["decision"] != actual["decision"]
            or expected["rule_hits"] != actual["rule_hits"]
        ):
            mismatches.append(
                {"case_id": case_id, "expected": expected, "actual": actual}
            )

    assert mismatches == [], json.dumps(mismatches, ensure_ascii=False, indent=2)


def test_current_decision_distribution_matches_frozen_distribution() -> None:
    results = _run_retained_datasets()

    distribution: dict[str, int] = {}
    for result in results:
        distribution[result["decision"]] = distribution.get(result["decision"], 0) + 1

    assert distribution == EXPECTED_DISTRIBUTION
