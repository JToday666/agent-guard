"""V21-08 T3：shadow assess 契约测试（engine 只读旁路 + shadow 评估）。

数据集加载模式参照 ``tests/test_v21_action_ir_shadow_parity.py``：
importlib 加载 ``scripts/core-metrics-gate.py``，对 43 条 retained case
验证 ``evaluate()`` 与 ``evaluate_with_results()`` 的决策逐字节一致
（V21-08 唯一 engine 侵入点：只读旁路，行为不变）。
"""

from __future__ import annotations

import functools
import importlib.util
from pathlib import Path

from agentguard_core import GuardEvent, PolicyBundle, evaluate
from agentguard_core.engine import GuardEngine

ROOT = Path(__file__).resolve().parents[1]

ATTACK_DATASET = (
    ROOT / "tests" / "fixtures" / "eval_gate" / "retained_attack_cases.jsonl"
)
BENIGN_DATASET = ROOT / "tests" / "fixtures" / "eval_gate" / "retained_benign.jsonl"
LEGACY_SNAPSHOT = ROOT / "tests" / "fixtures" / "v21" / "legacy_69efe2f_snapshot.json"

EXPECTED_DISTRIBUTION = {"allow": 14, "ask": 2, "deny": 27}


@functools.lru_cache(maxsize=1)
def _load_eval_gate_module():
    path = ROOT / "scripts" / "core-metrics-gate.py"
    spec = importlib.util.spec_from_file_location(
        "agentguard_core_metrics_gate_v2108", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _iter_retained_cases():
    gate = _load_eval_gate_module()
    for case in gate.load_cases(ATTACK_DATASET):
        yield case, True
    for case in gate.load_cases(BENIGN_DATASET):
        yield case, False


def _decision_semantic_dump(decision):
    """决策语义投影：剔除非确定性字段后的全字段 dump。

    GuardDecision 中两个逐调用必然不同的非语义字段：
    ``decision_id``（uuid default_factory）与 ``latency_ms``（wall-clock）；
    除此之外逐字段一致即“行为逐字节不变”。
    """
    dump = decision.model_dump(mode="json")
    dump.pop("decision_id", None)
    dump.pop("latency_ms", None)
    return dump


# ---------------------------------------------------------------------------
# engine 只读旁路：evaluate() 行为逐字节不变
# ---------------------------------------------------------------------------


def test_evaluate_with_results_decision_matches_evaluate_case_by_case() -> None:
    """对全部 43 条 retained case：evaluate() 与旁路决策完全一致。"""
    engine = GuardEngine()
    distribution: dict[str, int] = {}
    checked = 0
    for case, _is_malicious in _iter_retained_cases():
        event = GuardEvent.model_validate(case["event"])
        policies = PolicyBundle.model_validate(case.get("policies", {}))

        official = evaluate(event, policies)
        bypass_decision, detections = engine.evaluate_with_results(event, policies)

        assert _decision_semantic_dump(bypass_decision) == _decision_semantic_dump(
            official
        ), case["case_id"]
        # 旁路返回的检测结果是决策的真实输入（非空校验留给聚合语义）。
        assert isinstance(detections, list)
        distribution[official.decision] = (
            distribution.get(official.decision, 0) + 1
        )
        checked += 1

    assert checked == 43
    assert distribution == EXPECTED_DISTRIBUTION


def test_evaluate_with_results_exposes_detector_failure_results() -> None:
    """检测器失败契约在旁路下同样可见：失败 → 保守 ask 结构化结果。"""
    from agentguard_core.detectors import Detector

    class _BoomDetector(Detector):
        def evaluate(self, event, policies):
            raise RuntimeError("simulated detector failure")

    case, _ = next(iter(_iter_retained_cases()))
    event = GuardEvent.model_validate(case["event"])

    engine = GuardEngine(detectors=[_BoomDetector()])
    decision, detections = engine.evaluate_with_results(event)

    assert decision.decision == "ask"
    assert len(detections) == 1
    assert detections[0].category == "detector_failure"
    assert detections[0].rule_hit.rule_id == "detector_failure:_BoomDetector"
    # 与直接 evaluate() 的官方行为一致（失败即保守；剔除 latency 比对）。
    official = GuardEngine(detectors=[_BoomDetector()]).evaluate(event)
    assert _decision_semantic_dump(official) == _decision_semantic_dump(decision)
