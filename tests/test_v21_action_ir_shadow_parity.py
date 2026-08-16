"""V21-02 shadow parity: legacy 判定逐 case 不变，ActionIR 旁路构建。

数据集加载模式参照 ``tests/test_v21_legacy_parity.py``：importlib 加载
``scripts/core-metrics-gate.py``（lru_cache 缓存），对 43 条 retained case
逐条运行 legacy ``evaluate()`` 并旁路 ``build_action_ir``，断言
decision + rule_hits 与 ``tests/fixtures/v21/legacy_69efe2f_snapshot.json``
逐 case 一致。另含 builder 人为异常的降级场景与 AST 导入隔离守卫。
"""

from __future__ import annotations

import ast
import functools
import importlib.util
import json
from pathlib import Path

import pytest

from agentguard_core import GuardEvent, PolicyBundle, evaluate
from agentguard_core.actions import (
    ShadowEvaluation,
    build_action_ir,
    build_shadow_evaluation,
)
from agentguard_core.actions import builder as builder_module

ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT / "packages" / "agentguard-core" / "agentguard_core"

ATTACK_DATASET = (
    ROOT / "tests" / "fixtures" / "eval_gate" / "retained_attack_cases.jsonl"
)
BENIGN_DATASET = ROOT / "tests" / "fixtures" / "eval_gate" / "retained_benign.jsonl"
LEGACY_SNAPSHOT = ROOT / "tests" / "fixtures" / "v21" / "legacy_69efe2f_snapshot.json"

EXPECTED_BASE_COMMIT = "69efe2f027d9a4ba9c18623838e84f6ce30ffa62"
EXPECTED_DISTRIBUTION = {"allow": 14, "ask": 2, "deny": 27}
SHADOW_SECRET = b"v21-02-shadow-parity-secret"


@functools.lru_cache(maxsize=1)
def _load_eval_gate_module():
    path = ROOT / "scripts" / "core-metrics-gate.py"
    spec = importlib.util.spec_from_file_location(
        "agentguard_core_metrics_gate_v2102", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=1)
def _load_snapshot() -> dict:
    return json.loads(LEGACY_SNAPSHOT.read_text(encoding="utf-8"))


def _iter_retained_cases():
    gate = _load_eval_gate_module()
    for case in gate.load_cases(ATTACK_DATASET):
        yield case, True
    for case in gate.load_cases(BENIGN_DATASET):
        yield case, False


def _guard_event(case: dict) -> GuardEvent:
    """Migrate frozen legacy fixtures to the server-owned phase contract."""

    payload = dict(case["event"])
    if payload.get("event_type") in {
        "model_output_produced",
        "tool_result_produced",
    }:
        payload["pre_execution"] = False
    return GuardEvent.model_validate(payload)


def _shadow_evaluate(case: dict, *, is_malicious: bool) -> ShadowEvaluation:
    """legacy evaluate 为主，ActionIR 旁路；正常路径下无降级。"""
    event = _guard_event(case)
    if event.is_malicious is not is_malicious:
        raise ValueError(f"case {case['case_id']} label conflict")
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    decision = evaluate(event, policies)
    action_ir = build_action_ir(event, server_secret=SHADOW_SECRET)
    return ShadowEvaluation(decision=decision, action_ir=action_ir, degradation=None)


# ---------------------------------------------------------------------------
# Shadow parity：43 条 retained case 逐条一致
# ---------------------------------------------------------------------------


def test_snapshot_anchor_unchanged() -> None:
    snapshot = _load_snapshot()
    assert snapshot["schema_version"] == "1.0"
    assert snapshot["base_commit"] == EXPECTED_BASE_COMMIT
    assert snapshot["decision_distribution"] == EXPECTED_DISTRIBUTION
    assert len(snapshot["cases"]) == 43


def test_shadow_parity_case_by_case_with_action_ir_bypass() -> None:
    snapshot = _load_snapshot()
    frozen_cases = {case["case_id"]: case for case in snapshot["cases"]}

    mismatches: list[dict] = []
    distribution: dict[str, int] = {}
    seen_case_ids: set[str] = set()
    for case, is_malicious in _iter_retained_cases():
        shadow = _shadow_evaluate(case, is_malicious=is_malicious)
        case_id = str(case["case_id"])
        seen_case_ids.add(case_id)
        decision = shadow.decision.decision
        distribution[decision] = distribution.get(decision, 0) + 1

        expected = frozen_cases[case_id]
        if (
            expected["decision"] != decision
            or expected["rule_hits"] != [
                hit.rule_id for hit in shadow.decision.rule_hits
            ]
        ):
            mismatches.append({"case_id": case_id, "expected": expected})

        # ActionIR 旁路构建必须成功且确定性（不影响 legacy 判定）。
        assert shadow.action_ir is not None
        assert shadow.action_ir.authorization_fingerprint.startswith("hmac-sha256:")
        assert shadow.action_ir.audit_fingerprint.startswith("sha256:")
        assert shadow.action_ir.argument_digest == (
            shadow.action_ir.canonical_arguments.argument_digest
        )

    assert seen_case_ids == set(frozen_cases)
    assert distribution == EXPECTED_DISTRIBUTION
    assert mismatches == [], json.dumps(mismatches, ensure_ascii=False, indent=2)


def test_action_ir_build_is_deterministic_on_retained_cases() -> None:
    for index, (case, is_malicious) in enumerate(_iter_retained_cases()):
        if index >= 5:
            break
        event = _guard_event(case)
        first = build_action_ir(event, server_secret=SHADOW_SECRET)
        second = build_action_ir(event, server_secret=SHADOW_SECRET)
        assert first == second, case["case_id"]


def test_builder_failure_does_not_alter_legacy_decision(monkeypatch) -> None:
    """builder 人为抛异常：legacy 判定仍与冻结快照逐 case 一致。"""

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated V21-02 builder failure")

    monkeypatch.setattr(builder_module, "normalize_arguments", _boom)

    snapshot = _load_snapshot()
    frozen_cases = {case["case_id"]: case for case in snapshot["cases"]}

    checked = 0
    for case, is_malicious in _iter_retained_cases():
        event = _guard_event(case)
        policies = PolicyBundle.model_validate(case.get("policies", {}))

        # builder 旁路必须失败（模拟注入的异常）。
        with pytest.raises(RuntimeError, match="simulated V21-02 builder failure"):
            build_action_ir(event, server_secret=SHADOW_SECRET)

        # legacy 判定不受影响。
        decision = evaluate(event, policies)
        expected = frozen_cases[str(case["case_id"])]
        assert decision.decision == expected["decision"], case["case_id"]
        assert [hit.rule_id for hit in decision.rule_hits] == expected["rule_hits"]

        checked += 1
        if checked >= 10:
            break
    assert checked == 10


# ---------------------------------------------------------------------------
# build_shadow_evaluation：成功与降级两条路径（C5）
# ---------------------------------------------------------------------------


def test_build_shadow_evaluation_success_path_has_no_degradation() -> None:
    case, is_malicious = next(iter(_iter_retained_cases()))
    event = _guard_event(case)
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    decision = evaluate(event, policies)

    shadow = build_shadow_evaluation(
        event, decision=decision, server_secret=SHADOW_SECRET
    )

    assert shadow.decision == decision
    assert shadow.degradation is None
    assert shadow.action_ir is not None
    assert shadow.action_ir.authorization_fingerprint.startswith("hmac-sha256:")
    assert shadow.action_ir.audit_fingerprint.startswith("sha256:")


def test_build_shadow_evaluation_failure_path_degrades_without_raising(
    monkeypatch,
) -> None:
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated V21-02 builder failure")

    monkeypatch.setattr(builder_module, "normalize_arguments", _boom)

    case, is_malicious = next(iter(_iter_retained_cases()))
    event = _guard_event(case)
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    decision = evaluate(event, policies)

    # 降级路径绝不外抛：legacy 判定原样保留，ActionIR 侧结构化降级。
    shadow = build_shadow_evaluation(
        event, decision=decision, server_secret=SHADOW_SECRET
    )

    assert shadow.decision == decision
    assert shadow.action_ir is None
    assert shadow.degradation is not None
    assert shadow.degradation.component_id == "v21-02-action-ir-builder"
    assert shadow.degradation.failure_kind == "unavailable"
    assert shadow.degradation.required_for_action is False
    assert "action_ir.build_failed" in shadow.degradation.reason_codes


# ---------------------------------------------------------------------------
# AST 导入隔离守卫：判定路径不得 import actions
# ---------------------------------------------------------------------------


def _import_references(source: str) -> list[str]:
    """收集源码中所有 import 引用的模块名与 alias 名。

    ImportFrom 同时纳入 ``node.module``（相对 import 时为 ``""``）与
    ``node.names`` 的 alias 名，保证 ``from ..actions import builder``、
    ``from . import actions`` 等自然写法都能被检查到。
    """
    references: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            references.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            references.append(node.module or "")
            references.extend(alias.name for alias in node.names)
    return references


def _assert_no_actions_references(relative_path: str, references: list[str]) -> None:
    for reference in references:
        parts = reference.replace(".", " ").split()
        assert "actions" not in parts and "actions" not in reference.split("."), (
            f"{relative_path} imports the V21-02 actions module {reference!r}"
        )


@pytest.mark.parametrize(
    "relative_path",
    [
        "engine.py",
        "decisions/policy.py",
        "decisions/results.py",
    ],
)
def test_decision_path_does_not_import_actions(relative_path: str) -> None:
    source = (CORE_DIR / relative_path).read_text(encoding="utf-8")
    _assert_no_actions_references(relative_path, _import_references(source))


@pytest.mark.parametrize(
    "sample_source",
    [
        "from ..actions import builder",
        "from . import actions",
        "import agentguard_core.actions",
        "from agentguard_core.actions.models import ActionIR",
        "from ..actions.canonical_json import canonical_sha256",
    ],
)
def test_isolation_guard_detects_actions_imports(sample_source: str) -> None:
    # 守卫自身的负例验证：上述任一样例源码都必须被识别为违规。
    with pytest.raises(AssertionError):
        _assert_no_actions_references(
            "sample.py", _import_references(sample_source)
        )
