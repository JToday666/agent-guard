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
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions import shadow as shadow_module
from agentguard_core.decisions.divergence import (
    SHADOW_COMPONENT_ID,
    SNAPSHOT_ABSENT_REASON,
)
from agentguard_core.decisions.evidence import CoverageMap, DomainCoverage
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_DIGEST,
    REASON_ACTION_IR_FAILED,
    REASON_COMPONENT_FAILED,
    assessment_digest_projection,
    compute_assessment_digest,
    finalize_shadow,
    shadow_assess,
)
from agentguard_core.engine import GuardEngine
from agentguard_core.security_context.facts import StateWatermarks
from agentguard_core.security_context.snapshot import SecuritySnapshot

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


# ---------------------------------------------------------------------------
# shadow_assess 构造辅助
# ---------------------------------------------------------------------------

SERVER_SECRET = b"v21-08-shadow-test-secret"
PROJECTOR_VERSION = "v21-07.projector.2"


def _first_case():
    case, _ = next(iter(_iter_retained_cases()))
    event = GuardEvent.model_validate(case["event"])
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    return event, policies


def _coverage(dataflow_status: str = "complete") -> CoverageMap:
    return CoverageMap(
        **{
            domain: DomainCoverage(
                domain=domain,
                status=dataflow_status if domain == "dataflow" else "complete",
                as_of_sequence=None,
                projector_version=PROJECTOR_VERSION,
                reason_codes=[],
            )
            for domain in (
                "task",
                "source",
                "capability",
                "behavior",
                "dataflow",
                "memory",
                "runtime_outcome",
            )
        }
    )


def _snapshot() -> SecuritySnapshot:
    return SecuritySnapshot(
        snapshot_id="snap-shadow-1",
        state_version=7,
        scope=SecurityStateScope(
            principal_id="principal-1",
            runtime="langgraph",
            runtime_binding_id="binding-1",
            trace_id="trace-1",
            session_id=None,
            scope_digest="sha256:" + "0" * 64,
        ),
        evaluation_clock=EvaluationClock(
            evaluated_at="2026-08-15T00:00:00+00:00",
            clock_version="v1",
        ),
        as_of_sequence=None,
        projector_version=PROJECTOR_VERSION,
        policy_revision="rev-1",
        policy_digest="sha256:" + "1" * 64,
        coverage=_coverage(),
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        ),
        task=None,
        sources=[],
        grants=[],
        recent_actions=[],
        flows=[],
        memory_facts=[],
        runtime_outcomes=[],
        behavior_aggregates=[],
        sticky_taint_summaries=[],
        declassifications=[],
        dirty_domains=[],
        snapshot_digest="sha256:" + "2" * 64,
    )


def _shadow_degradation_ids(assessment) -> list[str]:
    return [
        degradation.degradation_id
        for degradation in assessment.degradations
        if degradation.component_id == SHADOW_COMPONENT_ID
    ]


# ---------------------------------------------------------------------------
# snapshot 缺失 → coverage unknown + DEFER + degradation（01 §25）
# ---------------------------------------------------------------------------


def test_snapshot_absent_yields_defer_unknown_coverage_and_degradation() -> None:
    event, policies = _first_case()
    assessment = shadow_assess(
        event, policies, None, server_secret=SERVER_SECRET
    )

    # 严禁伪造 Snapshot：哨兵身份 + 全降级构件 + DEFER。
    # FastAssessment 不直接携带 CoverageMap/snapshot_id（前者在 evidence
    # 组装时由 state + plan 重算，后者属 DecisionEvidenceV21）；降级路径
    # 的可审计锚点是 snapshot_digest 哨兵 + shadow 降级记录 + plan。
    assert assessment.disposition == "DEFER"
    assert assessment.snapshot_digest == ABSENT_SNAPSHOT_DIGEST
    assert (
        assessment.required_check_plan.plan_id
        == f"v21-08-degraded-plan:{SNAPSHOT_ABSENT_REASON}"
    )
    assert assessment.required_check_plan.impact == assessment.impact
    assert assessment.authority.status == "unknown"
    assert assessment.flow.status == "uncertain"
    assert assessment.task_digest is None

    shadow_ids = _shadow_degradation_ids(assessment)
    assert len(shadow_ids) == 1
    degradation = next(
        item
        for item in assessment.degradations
        if item.degradation_id == shadow_ids[0]
    )
    assert SNAPSHOT_ABSENT_REASON in degradation.reason_codes
    assert degradation.required_for_action is True


def test_snapshot_absent_assessment_is_deterministic() -> None:
    event, policies = _first_case()
    first = shadow_assess(event, policies, None, server_secret=SERVER_SECRET)
    second = shadow_assess(event, policies, None, server_secret=SERVER_SECRET)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


# ---------------------------------------------------------------------------
# snapshot 在场：完整编排 + 五元组真实值
# ---------------------------------------------------------------------------


def test_snapshot_present_full_pipeline_and_revalidation_tuple() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    assessment = shadow_assess(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )

    # 无 shadow 组件降级（完整路径）。
    assert _shadow_degradation_ids(assessment) == []
    assert assessment.disposition in ("CLEAR_ALLOW", "DEFER", "CLEAR_DENY")

    # V21-09 revalidation 五元组全部真实值（不留占位）。
    assert assessment.task_digest is None  # fixture snapshot 无 task 属正常
    assert assessment.policy_digest.startswith("sha256:")
    assert assessment.snapshot_digest == snapshot.snapshot_digest
    assert assessment.authorization_fingerprint != ""
    assert assessment.audit_fingerprint != ""

    # assessment_id 确定性派生（非 uuid）。
    assert assessment.assessment_id.startswith("asm:sha256:")
    # assessment_digest 已计算且不含自身/assessment_id。
    assert assessment.assessment_digest.startswith("sha256:")
    projection = assessment_digest_projection(assessment)
    assert "assessment_digest" not in projection
    assert "assessment_id" not in projection
    assert compute_assessment_digest(assessment) == assessment.assessment_digest

    # semantic 预留：V21-13 前恒 ineligible。
    assert assessment.semantic_routing.eligible is False
    assert assessment.policy_violations == []
    assert assessment.evidence_refs == []

    # finalize 最小映射（V21-09 预留）。
    assert finalize_shadow(assessment) in ("allow", "ask", "deny")


def test_snapshot_with_task_fact_projects_task_digest() -> None:
    """S1：snapshot 携带权威 TaskFact 时 assessment.task_digest 同源非空。"""
    from agentguard_core.authority.models import TaskFact

    task = TaskFact(
        task_id="task_shadow_assessment_fixture",
        scope_digest="sha256:" + "0" * 64,
        scope_key_id="scope_key_test",
        principal_id="principal-1",
        task_summary="shadow assessment fixture task",
        task_digest="sha256:" + "cd" * 32,
        revision=1,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )
    snapshot = _snapshot().model_copy(update={"task": task})
    event, policies = _first_case()

    assessment = shadow_assess(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )
    assert assessment.task_digest is not None
    assert assessment.task_digest == task.task_digest


def test_finalize_shadow_minimal_mapping() -> None:
    event, policies = _first_case()
    assessment = shadow_assess(
        event, policies, None, server_secret=SERVER_SECRET
    )
    assert assessment.disposition == "DEFER"
    assert finalize_shadow(assessment) == "ask"


# ---------------------------------------------------------------------------
# 组件注入异常 → 降级路径（monkeypatch，绝不上抛）
# ---------------------------------------------------------------------------


def test_action_ir_failure_degrades_without_raising(monkeypatch) -> None:
    from agentguard_core.actions import builder as builder_module

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated normalizer failure")

    monkeypatch.setattr(builder_module, "normalize_arguments", _boom)

    event, policies = _first_case()
    snapshot = _snapshot()
    assessment = shadow_assess(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )

    assert assessment.disposition == "DEFER"
    assert assessment.impact == "high"  # 保守假设
    assert assessment.action_id == f"act_{event.event_id}"
    assert assessment.authorization_fingerprint == ""
    shadow_ids = _shadow_degradation_ids(assessment)
    assert len(shadow_ids) == 1
    degradation = assessment.degradations[
        [item.degradation_id for item in assessment.degradations].index(
            shadow_ids[0]
        )
    ]
    assert REASON_ACTION_IR_FAILED in degradation.reason_codes


def test_component_failure_degrades_without_raising(monkeypatch) -> None:
    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated flow verdict failure")

    monkeypatch.setattr(shadow_module, "compute_flow_verdict", _boom)

    event, policies = _first_case()
    snapshot = _snapshot()
    assessment = shadow_assess(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )

    assert assessment.disposition == "DEFER"
    shadow_ids = _shadow_degradation_ids(assessment)
    assert len(shadow_ids) == 1
    degradation = next(
        item
        for item in assessment.degradations
        if item.degradation_id == shadow_ids[0]
    )
    assert REASON_COMPONENT_FAILED in degradation.reason_codes


# ---------------------------------------------------------------------------
# assessment_digest 确定性 + canonicalization attack 回归
# ---------------------------------------------------------------------------


def test_assessment_digest_deterministic_same_input_same_output() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    first = shadow_assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    second = shadow_assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    assert first.assessment_digest == second.assessment_digest
    assert first.assessment_id == second.assessment_id


def test_assessment_digest_immune_to_field_order_and_irrelevant_fields() -> None:
    """canonicalization attack 回归（参照 test_v21_canonicalization_attacks）：

    - canonical JSON 键排序：投影 dict 插入顺序不影响摘要；
    - 白名单外字段（``assessment_id``）不影响摘要；
    - 白名单内字段（``disposition``）变化必然改变摘要。
    """
    event, policies = _first_case()
    snapshot = _snapshot()
    assessment = shadow_assess(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )

    # 无关字段篡改：assessment_id 不在 digest_fields 白名单内。
    mutated = assessment.model_copy(
        update={"assessment_id": "asm:attacker-controlled-id"}
    )
    assert compute_assessment_digest(mutated) == assessment.assessment_digest

    # 投影键顺序无关（canonical JSON 排序键）。
    projection = assessment_digest_projection(assessment)
    reversed_projection = dict(reversed(list(projection.items())))
    from agentguard_core.actions.canonical_json import canonical_sha256

    assert canonical_sha256(reversed_projection) == assessment.assessment_digest

    # 白名单内语义字段变化 → 摘要必变（摘要不可碰撞掩盖不同 disposition）。
    flipped_disposition = (
        "CLEAR_DENY" if assessment.disposition != "CLEAR_DENY" else "DEFER"
    )
    altered = assessment.model_copy(
        update={"disposition": flipped_disposition}
    )
    assert compute_assessment_digest(altered) != assessment.assessment_digest


def test_legacy_detections_feed_signals_deterministically() -> None:
    """detection_results 经 legacy_adapter 转 signals 后喂给 fusion。"""
    engine = GuardEngine()
    case, _ = next(iter(_iter_retained_cases()))
    event = GuardEvent.model_validate(case["event"])
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    _decision, detections = engine.evaluate_with_results(event, policies)

    assessment = shadow_assess(
        event,
        policies,
        _snapshot(),
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    assert len(assessment.signals) == len(detections)
    repeat = shadow_assess(
        event,
        policies,
        _snapshot(),
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    assert repeat.assessment_digest == assessment.assessment_digest
