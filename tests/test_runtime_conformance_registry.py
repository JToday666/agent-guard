"""RTE-04 Conformance Suite — 注册表自洽与能力矩阵 guard（契约 05 §5）。

守护 ``tests/runtime_conformance/`` 两份 fixture 的完整性与真实性：

1. case ID 集合与矩阵键集合一致（CF-01~CF-17）；
2. 结果状态只允许 05 §5 四值，禁止 PARTIAL PASS；
3. 每个 PASS 条目必须带存在的 evidence 工件，且 evidence 文件必须
   实际引用对应 CF case（矩阵声明与测试漂移即红，PR-04b 起对 Python/
   Node 证据一律收紧）；
4. NOT_SUPPORTED / BLOCKED_BY_DEPENDENCY 必须带原因 note。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "tests" / "runtime_conformance" / "contract_cases.json"
MATRIX_PATH = ROOT / "tests" / "runtime_conformance" / "expected_capabilities.json"

EXPECTED_CASE_IDS = [f"CF-{index:02d}" for index in range(1, 18)]
ALLOWED_STATUSES = {"PASS", "FAIL", "NOT_SUPPORTED", "BLOCKED_BY_DEPENDENCY"}
EXPECTED_RUNTIMES = {"langgraph", "openclaw"}
REQUIRED_CASE_FIELDS = {"id", "title", "tier", "scope", "input", "expect"}


def _load_cases() -> dict:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def _load_matrix() -> dict:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def test_registry_schema_marker_and_case_id_sequence() -> None:
    registry = _load_cases()
    assert registry["schema"] == "rte-05-contract-cases/1"

    case_ids = [case["id"] for case in registry["cases"]]
    # RTE-04 + RTE-05 连续且无重复；新增 case 必须显式升级本冻结集合。
    assert case_ids == EXPECTED_CASE_IDS


def test_registry_cases_carry_complete_machine_readable_fields() -> None:
    registry = _load_cases()
    for case in registry["cases"]:
        missing = REQUIRED_CASE_FIELDS - set(case)
        assert not missing, f"{case.get('id')} missing fields: {missing}"
        assert case["tier"] in {1, 2, 3}
        expect = case["expect"]
        if case["scope"] == "idempotency":
            assert expect["same_content"] == "idempotent_replay"
            assert expect["different_content"] == "conflict"
        elif case["scope"] == "capacity":
            assert case["input"]["active_calls"] == ">capacity"
            assert expect["silent_fifo_evictions"] == 0
            assert expect["capacity_degradation"] == "observable"
        else:
            assert isinstance(expect["invocation_count"], int)
            for receipt in expect["receipts"]:
                # 每个 receipt 断言必须带精确 kind 或 runtime 差异 kind_any。
                assert ("kind" in receipt) ^ ("kind_any" in receipt), case["id"]


def test_matrix_status_enum_matches_contract_05_section_5() -> None:
    matrix = _load_matrix()
    assert matrix["schema"] == "rte-05-capability-matrix/1"
    assert set(matrix["allowed_statuses"]) == ALLOWED_STATUSES
    # 任何条目的实际状态都不得超出四值枚举（变相 PARTIAL 即红）。
    for runtime, entries in matrix["runtimes"].items():
        for case_id, entry in entries.items():
            assert entry["status"] in ALLOWED_STATUSES, (runtime, case_id)


def test_matrix_keys_cover_every_case_for_every_runtime() -> None:
    matrix = _load_matrix()
    assert set(matrix["runtimes"]) == EXPECTED_RUNTIMES
    for runtime, entries in matrix["runtimes"].items():
        assert set(entries) == set(EXPECTED_CASE_IDS), runtime
        for case_id, entry in entries.items():
            assert entry["status"] in ALLOWED_STATUSES, (runtime, case_id)
            if entry["status"] in {"NOT_SUPPORTED", "BLOCKED_BY_DEPENDENCY"}:
                assert str(entry.get("note") or "").strip(), (runtime, case_id)


def test_rte05_integration_capability_claims_match_runtime_boundaries() -> None:
    """Integration 的 strong-binding 声明必须精确匹配 runtime 边界。"""
    matrix = _load_matrix()
    langgraph = matrix["runtimes"]["langgraph"]
    openclaw = matrix["runtimes"]["openclaw"]

    for case_id in (f"CF-{index:02d}" for index in range(13, 17)):
        assert langgraph[case_id]["status"] == "PASS", case_id
    assert langgraph["CF-17"]["status"] == "NOT_SUPPORTED"
    assert "active-call" in langgraph["CF-17"]["note"]

    assert openclaw["CF-13"]["status"] == "NOT_SUPPORTED"
    assert "replace-and-seal" in openclaw["CF-13"]["note"]
    for case_id in (f"CF-{index:02d}" for index in range(14, 18)):
        assert openclaw[case_id]["status"] == "PASS", case_id


def test_matrix_pass_entries_have_existing_evidence_artifacts() -> None:
    matrix = _load_matrix()
    for runtime, entries in matrix["runtimes"].items():
        for case_id, entry in entries.items():
            if entry["status"] != "PASS":
                continue
            evidence = entry.get("evidence")
            assert evidence, (runtime, case_id, "PASS requires evidence")
            assert (ROOT / evidence).is_file(), (runtime, case_id, evidence)


def test_evidence_files_reference_their_claimed_case_ids() -> None:
    """矩阵 guard：PASS 声明的 evidence 必须实际引用该 CF case。

    任何声明与实测漂移（测试改名/删除/未覆盖）都会使本断言变红。
    PR-04b 起 Python/Node 证据一律收紧为引用校验。
    """
    matrix = _load_matrix()
    for runtime, entries in matrix["runtimes"].items():
        for case_id, entry in entries.items():
            if entry["status"] != "PASS":
                continue
            evidence = str(entry["evidence"])
            body = (ROOT / evidence).read_text(encoding="utf-8")
            assert case_id in body, (
                f"{runtime} {case_id}: evidence {evidence} does not "
                "reference the case id"
            )


@pytest.mark.parametrize("runtime", sorted(EXPECTED_RUNTIMES))
def test_matrix_terminal_cases_align_with_c2_requirements(runtime: str) -> None:
    """c2_required 的 case 在该 runtime 声明 PASS 时不得自相矛盾。"""
    registry = {case["id"]: case for case in _load_cases()["cases"]}
    entries = _load_matrix()["runtimes"][runtime]
    for case_id, case in registry.items():
        if not case["expect"].get("c2_required"):
            continue
        entry = entries[case_id]
        if runtime == "openclaw" and case_id in {"CF-08", "CF-09"}:
            # Tier 3：真实运行时语义，evidence 为绑定测试，其内校验
            # live 取证工件；当前 CI 没有真实 runtime smoke 矩阵。
            assert entry["status"] == "PASS"
            assert entry["evidence"].endswith("rte-conformance-tier3-evidence.test.mjs")
            assert "rte02-live-evidence.json" in entry["note"]
            assert "当前 CI 不含真实 runtime smoke 矩阵" in entry["note"]
            assert "scripts/openclaw-runtime-smoke.mjs" in entry["note"]
        elif entry["status"] == "PASS":
            assert entry.get("evidence"), (runtime, case_id)
