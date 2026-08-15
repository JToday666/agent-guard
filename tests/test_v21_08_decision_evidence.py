"""V21-08 T3：DecisionEvidenceV21 组装与 divergence 分类契约测试。

口径：

- ``11_决策记录_V21-08前置.md`` D2：九宫格受控词表 + 两个降级类目，
  parity 对角线为 None，降级优先，词表封闭（未定义组合 fail-closed）；
- 完整方案 §14：九项证据保存项逐项断言（evidence 组装测试在本文件
  后续提交补齐）。
"""

from __future__ import annotations

import functools
import importlib.util
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentguard_core import GuardEvent, PolicyBundle, evaluate
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.divergence import (
    DEGRADED_COMPONENT_FAILURE,
    DEGRADED_NO_SNAPSHOT,
    DIVERGENCE_GRID,
    DIVERGENCE_VOCABULARY,
    SHADOW_COMPONENT_ID,
    SNAPSHOT_ABSENT_REASON,
    DivergenceVocabularyError,
    classify_divergence,
)
from agentguard_core.decisions.evidence import CoverageMap, DomainCoverage
from agentguard_core.decisions.evidence_builder import (
    MAX_DEGRADATION_IDS,
    MAX_FLOW_PATH_REFS,
    MAX_SIGNAL_IDS,
    REASON_REFS_TRUNCATED,
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.decisions.models import RuleHit
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_ID,
    shadow_assess,
    shadow_assess_with_coverage,
)
from agentguard_core.security_context.facts import StateWatermarks
from agentguard_core.security_context.snapshot import SecuritySnapshot
from agentguard_core.signals.models import EvaluationDegradation

LEGACY_DECISIONS = ("allow", "ask", "deny")
DISPOSITIONS = ("CLEAR_ALLOW", "DEFER", "CLEAR_DENY")

#: D2 冻结词表逐字期望（九宫格 + 对角线 None）。
EXPECTED_GRID = {
    ("allow", "CLEAR_ALLOW"): None,
    ("allow", "DEFER"): "legacy_allow__v21_defer",
    ("allow", "CLEAR_DENY"): "legacy_allow__v21_clear_deny",
    ("ask", "CLEAR_ALLOW"): "legacy_ask__v21_clear_allow",
    ("ask", "DEFER"): None,
    ("ask", "CLEAR_DENY"): "legacy_ask__v21_clear_deny",
    ("deny", "CLEAR_ALLOW"): "legacy_deny__v21_clear_allow",
    ("deny", "DEFER"): "legacy_deny__v21_defer",
    ("deny", "CLEAR_DENY"): None,
}


def _shadow_degradation(reason_codes: list[str]) -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id=f"deg:{reason_codes[0]}",
        component_id=SHADOW_COMPONENT_ID,
        domain=None,
        required_for_action=True,
        failure_kind="unavailable",
        reason_codes=reason_codes,
        evidence_refs=[],
    )


def _detector_degradation() -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id="deg_evt_detector_failure:Boom",
        component_id="BoomDetector",
        domain=None,
        required_for_action=True,
        failure_kind="unavailable",
        reason_codes=["detector_failure:BoomDetector"],
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# 九宫格穷尽性（表驱动全组合）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("legacy", LEGACY_DECISIONS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_grid_is_exhaustive_and_matches_frozen_vocabulary(
    legacy: str, disposition: str
) -> None:
    expected = EXPECTED_GRID[(legacy, disposition)]
    assert classify_divergence(legacy, disposition) == expected
    # 非 parity 类目必须落在封闭词表内（不得自造新词）。
    if expected is not None:
        assert expected in DIVERGENCE_VOCABULARY


def test_parity_diagonal_is_none() -> None:
    assert classify_divergence("allow", "CLEAR_ALLOW") is None
    assert classify_divergence("ask", "DEFER") is None
    assert classify_divergence("deny", "CLEAR_DENY") is None


def test_section14_three_analysis_combinations_are_covered() -> None:
    """完整方案 §14 列出的三个分析组合必须可被词表表达。"""
    assert (
        classify_divergence("allow", "CLEAR_DENY")
        == "legacy_allow__v21_clear_deny"
    )
    assert (
        classify_divergence("ask", "CLEAR_ALLOW")
        == "legacy_ask__v21_clear_allow"
    )
    assert classify_divergence("deny", "DEFER") == "legacy_deny__v21_defer"


def test_vocabulary_is_closed_with_exactly_eight_categories() -> None:
    assert DIVERGENCE_VOCABULARY == {
        "legacy_allow__v21_defer",
        "legacy_allow__v21_clear_deny",
        "legacy_ask__v21_clear_allow",
        "legacy_ask__v21_clear_deny",
        "legacy_deny__v21_clear_allow",
        "legacy_deny__v21_defer",
        DEGRADED_NO_SNAPSHOT,
        DEGRADED_COMPONENT_FAILURE,
    }
    assert set(DIVERGENCE_GRID) == {
        (legacy, disposition)
        for legacy in LEGACY_DECISIONS
        for disposition in DISPOSITIONS
    }


# ---------------------------------------------------------------------------
# 降级类目优先级
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("legacy", LEGACY_DECISIONS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_snapshot_absent_degradation_overrides_grid(
    legacy: str, disposition: str
) -> None:
    degradations = [_shadow_degradation([SNAPSHOT_ABSENT_REASON])]
    assert (
        classify_divergence(legacy, disposition, degradations)
        == DEGRADED_NO_SNAPSHOT
    )


@pytest.mark.parametrize("legacy", LEGACY_DECISIONS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_shadow_component_failure_overrides_grid(
    legacy: str, disposition: str
) -> None:
    degradations = [_shadow_degradation(["v21-08:action_ir_failed"])]
    assert (
        classify_divergence(legacy, disposition, degradations)
        == DEGRADED_COMPONENT_FAILURE
    )


def test_snapshot_absent_takes_priority_over_generic_component_failure() -> None:
    degradations = [
        _shadow_degradation(["v21-08:action_ir_failed"]),
        _shadow_degradation([SNAPSHOT_ABSENT_REASON]),
    ]
    assert classify_divergence("allow", "DEFER", degradations) == (
        DEGRADED_NO_SNAPSHOT
    )


def test_legacy_detector_degradation_does_not_override_grid() -> None:
    """detector 失败降级已被 fusion required_degradation→DEFER 如实消费，
    九宫格仍可信（不静默归入降级类目）。"""
    degradations = [_detector_degradation()]
    # parity 对角线仍返回 None
    assert classify_divergence("ask", "DEFER", degradations) is None
    assert (
        classify_divergence("allow", "CLEAR_DENY", degradations)
        == "legacy_allow__v21_clear_deny"
    )


# ---------------------------------------------------------------------------
# 词表封闭：未定义组合 fail-closed
# ---------------------------------------------------------------------------


def test_undefined_combination_raises_fail_closed() -> None:
    with pytest.raises(DivergenceVocabularyError):
        classify_divergence("approve", "DEFER")  # type: ignore[arg-type]
    with pytest.raises(DivergenceVocabularyError):
        classify_divergence("allow", "MAYBE")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DecisionEvidenceV21 组装（§14 九项保存项）
# ---------------------------------------------------------------------------

SERVER_SECRET = b"v21-08-evidence-test-secret"
PROJECTOR_VERSION = "v21-07.projector.2"
ROOT = Path(__file__).resolve().parents[1]
ATTACK_DATASET = (
    ROOT / "tests" / "fixtures" / "eval_gate" / "retained_attack_cases.jsonl"
)


@functools.lru_cache(maxsize=1)
def _load_eval_gate_module():
    spec = importlib.util.spec_from_file_location(
        "agentguard_core_metrics_gate_v2108_evidence",
        ROOT / "scripts" / "core-metrics-gate.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _first_case():
    gate = _load_eval_gate_module()
    case = next(iter(gate.load_cases(ATTACK_DATASET)))
    event = GuardEvent.model_validate(case["event"])
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    return event, policies


def _coverage_map() -> CoverageMap:
    return CoverageMap(
        **{
            domain: DomainCoverage(
                domain=domain,
                status="complete",
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
        snapshot_id="snap-evidence-1",
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
        coverage=_coverage_map(),
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


def _detection(index: int) -> DetectionResult:
    return DetectionResult(
        decision="ask",
        risk_score=55,
        category="command_risk",
        rule_hit=RuleHit(
            rule_id=f"rule_{index:03d}",
            rule_name=f"rule {index}",
            severity="medium",
            evidence=[f"evidence-{index}"],
        ),
        reason="test fixture detection",
    )


def _build_full_pipeline():
    """完整路径（无 shadow 降级）的 evidence 三元组（coverage 同源）。"""
    event, policies = _first_case()
    snapshot = _snapshot()
    detections = [_detection(0), _detection(1)]
    outcome = shadow_assess_with_coverage(
        event,
        policies,
        snapshot,
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    legacy = evaluate(event, policies).decision
    evidence = build_decision_evidence_v21(
        outcome.assessment,
        legacy_decision=legacy,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        coverage=outcome.coverage,
    )
    return outcome.assessment, evidence, outcome.coverage


def test_evidence_section14_nine_saved_items() -> None:
    """§14 九项保存项逐项落字段。"""
    assessment, evidence, fused_coverage = _build_full_pipeline()

    # 1) assessment_digest（D1 口径）。
    assert evidence.assessment_digest == assessment.assessment_digest
    assert evidence.assessment_digest.startswith("sha256:")
    # 2) coverage（与判定时喂给 fusion 的同源真值，非另行重算）。
    assert evidence.coverage == fused_coverage
    assert evidence.required_domains == list(
        assessment.required_check_plan.required_domains
    )
    # 3) state_version。
    assert evidence.state_version == 7
    assert evidence.snapshot_id == "snap-evidence-1"
    assert evidence.snapshot_digest == assessment.snapshot_digest
    # 4) authority：status + matched_grant_ids。
    assert evidence.authority_status == assessment.authority.status
    assert evidence.matched_grant_ids == list(
        assessment.authority.matched_grant_ids
    )
    # 5) flow：status + path_refs。
    assert evidence.flow_status == assessment.flow.status
    assert evidence.flow_path_refs == list(assessment.flow.path_refs)
    # 6) signal/policy/degradation refs 只存 id。
    assert evidence.signal_ids == [
        signal.signal_id for signal in assessment.signals
    ]
    assert evidence.policy_violation_ids == []
    assert evidence.degradation_ids == [
        degradation.degradation_id for degradation in assessment.degradations
    ]
    # 7) legacy decision；8) v21 disposition。
    assert evidence.legacy_decision == evidence.final_decision
    assert evidence.v21_fast_disposition == assessment.disposition
    # 9) divergence category（无 shadow 降级 → 九宫格值）。
    assert evidence.divergence_category == classify_divergence(
        evidence.legacy_decision, assessment.disposition, assessment.degradations
    )
    assert (
        evidence.divergence_category is None
        or evidence.divergence_category in DIVERGENCE_VOCABULARY
    )

    # shadow 期冻结约定：mode/final_decision/semantic 预留。
    assert evidence.mode == "shadow"
    assert evidence.semantic_judgment_id is None
    assert evidence.semantic_digest is None
    assert evidence.evidence_refs == []


def test_evidence_snapshot_absent_sentinels_and_degraded_category() -> None:
    event, policies = _first_case()
    outcome = shadow_assess_with_coverage(
        event, policies, None, server_secret=SERVER_SECRET
    )
    assessment = outcome.assessment
    # 降级路径同源 coverage：七域全 unknown（不伪造 Snapshot）。
    for domain_coverage in (
        outcome.coverage.task,
        outcome.coverage.source,
        outcome.coverage.capability,
        outcome.coverage.behavior,
        outcome.coverage.dataflow,
        outcome.coverage.memory,
        outcome.coverage.runtime_outcome,
    ):
        assert domain_coverage.status == "unknown"
        assert SNAPSHOT_ABSENT_REASON in domain_coverage.reason_codes

    legacy = evaluate(event, policies).decision
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision=legacy,
        snapshot_id=ABSENT_SNAPSHOT_ID,
        state_version=0,
        coverage=outcome.coverage,
    )
    assert evidence.snapshot_id == ABSENT_SNAPSHOT_ID
    assert evidence.state_version == 0
    assert evidence.v21_fast_disposition == "DEFER"
    # snapshot 缺失 → 降级类目取代九宫格（降级优先）。
    assert evidence.divergence_category == DEGRADED_NO_SNAPSHOT
    assert evidence.final_decision == legacy


def test_evidence_envelope_shape_matches_scaffold_contract() -> None:
    """envelope 形状与 tests/test_v21_contract_scaffold.py L574-584 一致。"""
    _assessment, evidence, _coverage = _build_full_pipeline()
    envelope = decision_evidence_v21_envelope(evidence)
    assert envelope == {
        "decision_v21": {
            "schema_version": "2.1",
            "payload": evidence.model_dump(mode="json"),
        }
    }
    assert set(envelope) == {"decision_v21"}
    assert set(envelope["decision_v21"]) == {"schema_version", "payload"}


def test_evidence_round_trip_and_extra_forbid() -> None:
    _assessment, evidence, _coverage = _build_full_pipeline()
    dumped = evidence.model_dump(mode="json")
    restored = type(evidence).model_validate(dumped)
    assert restored == evidence
    assert restored.model_dump(mode="json") == dumped

    with pytest.raises(ValidationError):
        type(evidence).model_validate({**dumped, "attacker_field": "x"})


# ---------------------------------------------------------------------------
# D4 refs 上限截断 + degradation 记录
# ---------------------------------------------------------------------------


def test_signal_ids_truncated_with_overflow_degradation() -> None:
    """35 条 signal > 上限 32 → 截断 + overflow degradation + 降级类目。"""
    event, policies = _first_case()
    snapshot = _snapshot()
    detections = [_detection(i) for i in range(35)]
    assessment = shadow_assess(
        event,
        policies,
        snapshot,
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    assert len(assessment.signals) == 35

    legacy = evaluate(event, policies).decision
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision=legacy,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        coverage=snapshot.coverage,
    )

    assert len(evidence.signal_ids) == MAX_SIGNAL_IDS
    assert evidence.signal_ids == [
        signal.signal_id for signal in assessment.signals[:MAX_SIGNAL_IDS]
    ]
    overflow_ids = [
        degradation_id
        for degradation_id in evidence.degradation_ids
        if degradation_id.startswith("v21-08-refs-truncated:")
    ]
    assert overflow_ids == [
        f"v21-08-refs-truncated:{event.event_id}:signal_ids"
    ]
    # 截断降级与 degraded_component_failure 同类语义（D4）。
    assert evidence.divergence_category == DEGRADED_COMPONENT_FAILURE


def test_flow_path_refs_truncated_with_overflow_degradation() -> None:
    _assessment, _evidence, _coverage = _build_full_pipeline()
    assessment = _assessment
    bloated_flow = assessment.flow.model_copy(
        update={"path_refs": [f"flow-{i:03d}" for i in range(20)]}
    )
    assessment = assessment.model_copy(update={"flow": bloated_flow})

    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="deny",
        snapshot_id="snap-evidence-1",
        state_version=7,
        coverage=_coverage_map(),
    )
    assert len(evidence.flow_path_refs) == MAX_FLOW_PATH_REFS
    assert evidence.flow_path_refs == [f"flow-{i:03d}" for i in range(16)]
    assert (
        f"v21-08-refs-truncated:{assessment.event_id}:flow_path_refs"
        in evidence.degradation_ids
    )
    assert evidence.divergence_category == DEGRADED_COMPONENT_FAILURE


def test_degradation_ids_truncation_keeps_overflow_record_visible() -> None:
    """40 条降级 > 上限 32 → 保留前 31 + 1 条合并截断降级（单轮收敛，
    截断留痕记录自身不被截断丢失）。"""
    _assessment, _evidence, _coverage = _build_full_pipeline()
    assessment = _assessment
    many = [
        EvaluationDegradation(
            degradation_id=f"deg-{i:03d}",
            component_id=f"component-{i}",
            domain=None,
            required_for_action=False,
            failure_kind="unavailable",
            reason_codes=[f"fixture:{i}"],
            evidence_refs=[],
        )
        for i in range(40)
    ]
    assessment = assessment.model_copy(update={"degradations": many})

    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="allow",
        snapshot_id="snap-evidence-1",
        state_version=7,
        coverage=_coverage_map(),
    )
    assert len(evidence.degradation_ids) == MAX_DEGRADATION_IDS
    assert evidence.degradation_ids[:31] == [
        f"deg-{i:03d}" for i in range(31)
    ]
    merged_id = evidence.degradation_ids[-1]
    assert merged_id.startswith("v21-08-refs-truncated:")
    assert merged_id.endswith(":degradation_ids")
    # 截断降级 → 降级类目取代九宫格。
    assert evidence.divergence_category == DEGRADED_COMPONENT_FAILURE


def test_truncation_degradation_reason_codes_leave_trace() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    detections = [_detection(i) for i in range(35)]
    assessment = shadow_assess(
        event,
        policies,
        snapshot,
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="allow",
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        coverage=snapshot.coverage,
    )
    # 截断降级不在 assessment 内，仅存在于 evidence 的 degradation_ids；
    # 重建同一确定性 id 验证 reason 留痕口径。
    expected_id = f"v21-08-refs-truncated:{event.event_id}:signal_ids"
    assert expected_id in evidence.degradation_ids
    # 截断降级 component_id 归 shadow 组件（divergence 降级优先的输入）。
    from agentguard_core.decisions.evidence_builder import (
        _truncation_degradation,
    )

    degradation = _truncation_degradation(
        event_id=event.event_id, field="signal_ids", dropped=3
    )
    assert degradation.component_id == SHADOW_COMPONENT_ID
    assert degradation.failure_kind == "overflow"
    assert REASON_REFS_TRUNCATED in degradation.reason_codes
    assert degradation.required_for_action is False
