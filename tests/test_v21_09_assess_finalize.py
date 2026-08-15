"""V21-09 T1：正式 assess/finalize 契约测试（structure-only，behavior 不变）。

覆盖范围：

- ``decisions/shadow.py::assess`` 与 ``shadow_assess`` 逐字段 parity
  （assessment_digest 逐字节相等——D1 锚点；公共内核同源）；
- ``assess`` snapshot=None → ValueError（01 §25 必须有 Snapshot）；
- ``GuardEngine.assess/finalize`` 薄委托（lazy import，legacy
  ``evaluate()`` 语义零变化由 test_core_engine.py targeted 回归覆盖）；
- ``finalize_v21`` disposition × semantic{None/valid/stale} 矩阵
  （03 §14 优先级；hard deny 不降级分支形态）；
- D7 口径：decision 映射沿用 ``_SHADOW_FINALIZE_MAP`` 语义、
  risk_score/severity 按 D7 映射表逐项断言、reason/categories 由
  reason_codes 派生、rule_hits 恒空、latency_ms 恒 None；
- decision_id/audit_id 确定性派生（同输入同 id，禁 uuid 默认触发）。
"""

from __future__ import annotations

import functools
import importlib.util
from pathlib import Path

import pytest

from agentguard_core import GuardEvent, PolicyBundle
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.evidence import FastAssessment
from agentguard_core.decisions.finalize import (
    FINALIZE_DECISION_MAP,
    FINALIZE_RISK_SEVERITY_MAP,
    NO_REASON_CODES_REASON,
    derive_final_audit_id,
    derive_final_decision_id,
    finalize_v21,
)
from agentguard_core.decisions.shadow import (
    _SHADOW_FINALIZE_MAP,
    assess,
    shadow_assess,
    shadow_assess_with_coverage,
)
from agentguard_core.engine import GuardEngine
from agentguard_core.security_context.facts import StateWatermarks
from agentguard_core.security_context.snapshot import SecuritySnapshot

from tests.test_v21_09_revalidation import _assessment, _judgment

ROOT = Path(__file__).resolve().parents[1]

ATTACK_DATASET = (
    ROOT / "tests" / "fixtures" / "eval_gate" / "retained_attack_cases.jsonl"
)

SERVER_SECRET = b"v21-09-assess-finalize-test-secret"
PROJECTOR_VERSION = "v21-07.projector.2"


@functools.lru_cache(maxsize=1)
def _load_eval_gate_module():
    path = ROOT / "scripts" / "core-metrics-gate.py"
    spec = importlib.util.spec_from_file_location(
        "agentguard_core_metrics_gate_v2109", path
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


def _coverage(dataflow_status: str = "complete"):
    from agentguard_core.decisions.evidence import CoverageMap, DomainCoverage

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
        snapshot_id="snap-v2109-1",
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


# ---------------------------------------------------------------------------
# assess 与 shadow_assess 逐字段 parity（公共内核同源，D1 锚点）
# ---------------------------------------------------------------------------


def test_assess_matches_shadow_assess_field_by_field() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    formal = assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    shadow = shadow_assess(event, policies, snapshot, server_secret=SERVER_SECRET)

    assert formal.model_dump(mode="json") == shadow.model_dump(mode="json")
    # D1 锚点：assessment_digest 逐字节相等（两期同函数同口径）。
    assert formal.assessment_digest == shadow.assessment_digest
    assert formal.assessment_id == shadow.assessment_id


def test_assess_parity_with_legacy_detection_results() -> None:
    engine = GuardEngine()
    event, policies = _first_case()
    _decision, detections = engine.evaluate_with_results(event, policies)

    formal = assess(
        event,
        policies,
        _snapshot(),
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    shadow = shadow_assess(
        event,
        policies,
        _snapshot(),
        server_secret=SERVER_SECRET,
        detection_results=detections,
    )
    assert formal.model_dump(mode="json") == shadow.model_dump(mode="json")
    assert formal.assessment_digest == shadow.assessment_digest


def test_assess_matches_with_coverage_assessment() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    formal = assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    outcome = shadow_assess_with_coverage(
        event, policies, snapshot, server_secret=SERVER_SECRET
    )
    assert formal.model_dump(mode="json") == outcome.assessment.model_dump(
        mode="json"
    )


def test_assess_is_deterministic() -> None:
    event, policies = _first_case()
    snapshot = _snapshot()
    first = assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    second = assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


# ---------------------------------------------------------------------------
# 01 §25：assess 必须有 Snapshot（snapshot=None → ValueError）
# ---------------------------------------------------------------------------


def test_assess_without_snapshot_raises_value_error() -> None:
    event, policies = _first_case()
    with pytest.raises(ValueError, match="Snapshot"):
        assess(event, policies, None, server_secret=SERVER_SECRET)


def test_shadow_assess_keeps_degraded_semantics_without_snapshot() -> None:
    """对照：shadow 期降级分支保留（DEFER + 哨兵 digest，绝不上抛）。"""
    event, policies = _first_case()
    shadow = shadow_assess(event, policies, None, server_secret=SERVER_SECRET)
    assert shadow.disposition == "DEFER"


def test_engine_assess_delegates_and_validates_snapshot() -> None:
    engine = GuardEngine()
    event, policies = _first_case()
    snapshot = _snapshot()

    formal = engine.assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    shadow = shadow_assess(event, policies, snapshot, server_secret=SERVER_SECRET)
    assert formal.model_dump(mode="json") == shadow.model_dump(mode="json")

    with pytest.raises(ValueError, match="Snapshot"):
        engine.assess(event, policies, None, server_secret=SERVER_SECRET)


# ---------------------------------------------------------------------------
# finalize_v21：03 §14 优先级矩阵（disposition × semantic{None/valid/stale}）
# ---------------------------------------------------------------------------


def _finalize(assessment: FastAssessment, semantic=None):
    return finalize_v21(
        assessment,
        semantic,
        decision_id=derive_final_decision_id(
            assessment,
            semantic_digest=semantic.semantic_digest if semantic else None,
        ),
    )


def test_finalize_decision_map_matches_shadow_finalize_map() -> None:
    """D7-1：decision 映射沿用 _SHADOW_FINALIZE_MAP 语义。"""
    assert dict(FINALIZE_DECISION_MAP) == dict(_SHADOW_FINALIZE_MAP)


@pytest.mark.parametrize("disposition", ["CLEAR_DENY", "CLEAR_ALLOW", "DEFER"])
def test_finalize_semantic_none_follows_minimal_mapping(disposition: str) -> None:
    assessment = _assessment(disposition=disposition)
    decision = _finalize(assessment)
    assert decision.decision == _SHADOW_FINALIZE_MAP[disposition]


@pytest.mark.parametrize("disposition", ["CLEAR_DENY", "CLEAR_ALLOW", "DEFER"])
def test_finalize_hard_deny_and_allow_unaffected_by_semantic(
    disposition: str,
) -> None:
    """Hard deny 永远不由 semantic 降级；CLEAR_ALLOW 亦不受 semantic 影响。"""
    assessment = _assessment(disposition=disposition)
    valid_semantic = _judgment(assessment)
    stale_semantic = _judgment(assessment, assessment_digest="sha256:" + "f0" * 32)

    expected = _SHADOW_FINALIZE_MAP[disposition]
    assert _finalize(assessment, valid_semantic).decision == expected
    assert _finalize(assessment, stale_semantic).decision == expected


def test_finalize_defer_with_valid_semantic_stays_ask_in_shadow_stage() -> None:
    """03 §14 ``semantic_stage == "shadow"`` 分支形态：V21-09 不放开升级。"""
    assessment = _assessment(disposition="DEFER")
    decision = _finalize(assessment, _judgment(assessment))
    assert decision.decision == "ask"


def test_finalize_defer_with_stale_or_invalid_binding_stays_ask() -> None:
    assessment = _assessment(disposition="DEFER")
    # binding 漂移（stale 语义：judgment 锚定的 assessment_digest 已变）。
    stale = _judgment(assessment, assessment_digest="sha256:" + "f0" * 32)
    assert _finalize(assessment, stale).decision == "ask"
    # binding 任一项不符（invalid）→ ask（fail-closed）。
    invalid = _judgment(assessment, snapshot_digest="sha256:" + "ee" * 32)
    assert _finalize(assessment, invalid).decision == "ask"


def test_finalize_requires_explicit_decision_id() -> None:
    assessment = _assessment()
    with pytest.raises(ValueError, match="decision_id"):
        finalize_v21(assessment, decision_id="")


def test_engine_finalize_thin_delegation_matches_finalize_v21() -> None:
    assessment = _assessment(disposition="CLEAR_DENY", impact="high")
    engine_decision = GuardEngine().finalize(assessment)
    direct = finalize_v21(
        assessment, decision_id=derive_final_decision_id(assessment)
    )
    assert engine_decision.model_dump(mode="json") == direct.model_dump(
        mode="json"
    )
    assert engine_decision.decision_id == direct.decision_id


# ---------------------------------------------------------------------------
# D7 映射表：risk_score / severity（disposition × impact 逐项）
# ---------------------------------------------------------------------------

D7_EXPECTED = {
    ("CLEAR_DENY", "critical"): (95, "critical"),
    ("CLEAR_DENY", "high"): (85, "high"),
    ("CLEAR_DENY", "moderate"): (70, "medium"),
    ("CLEAR_DENY", "low"): (55, "medium"),
    ("DEFER", "critical"): (80, "high"),
    ("DEFER", "high"): (65, "medium"),
    ("DEFER", "moderate"): (50, "medium"),
    ("DEFER", "low"): (35, "low"),
    ("CLEAR_ALLOW", "critical"): (30, "low"),
    ("CLEAR_ALLOW", "high"): (20, "low"),
    ("CLEAR_ALLOW", "moderate"): (10, "low"),
    ("CLEAR_ALLOW", "low"): (5, "low"),
}


def test_d7_map_constant_matches_frozen_table() -> None:
    assert dict(FINALIZE_RISK_SEVERITY_MAP) == D7_EXPECTED


@pytest.mark.parametrize(
    ("disposition", "impact"),
    [
        (disposition, impact)
        for disposition in ("CLEAR_DENY", "DEFER", "CLEAR_ALLOW")
        for impact in ("critical", "high", "moderate", "low")
    ],
)
def test_finalize_risk_score_severity_follow_d7_table(
    disposition: str, impact: str
) -> None:
    assessment = _assessment(disposition=disposition, impact=impact)
    decision = _finalize(assessment)
    expected_score, expected_severity = D7_EXPECTED[(disposition, impact)]
    assert decision.risk_score == expected_score
    assert decision.severity == expected_severity


# ---------------------------------------------------------------------------
# D7：reason/categories 派生、rule_hits 恒空、latency_ms 恒 None
# ---------------------------------------------------------------------------


def test_finalize_reason_and_categories_derived_from_reason_codes() -> None:
    assessment = _assessment(
        reason_codes=[
            "v21-08:hard_policy_deny:H-1",
            "v21-08:coverage_incomplete:behavior:unknown",
        ]
    )
    decision = _finalize(assessment)
    assert decision.reason == (
        "v21-08:hard_policy_deny:H-1; v21-08:coverage_incomplete:behavior:unknown"
    )
    assert decision.categories == ["coverage_incomplete", "hard_policy_deny"]


def test_finalize_empty_reason_codes_use_sentinel_reason() -> None:
    assessment = _assessment(reason_codes=[])
    decision = _finalize(assessment)
    assert decision.reason == NO_REASON_CODES_REASON
    assert decision.categories == []


def test_finalize_rule_hits_always_empty_and_latency_none() -> None:
    for disposition in ("CLEAR_DENY", "DEFER", "CLEAR_ALLOW"):
        decision = _finalize(_assessment(disposition=disposition))
        assert decision.rule_hits == []  # D7-4：恒空表
        assert decision.latency_ms is None  # D7-6：禁 wall-clock
        assert decision.safe_message is None
        assert decision.approval_intent is None


# ---------------------------------------------------------------------------
# D7-5：decision_id / audit_id 确定性派生（禁 uuid 默认触发）
# ---------------------------------------------------------------------------


def test_decision_id_deterministic_same_input_same_id() -> None:
    assessment = _assessment()
    first = derive_final_decision_id(assessment)
    second = derive_final_decision_id(assessment)
    assert first == second
    assert first.startswith("dec:sha256:")
    # 与 GuardDecision uuid 默认工厂形态（dec_<32 hex>）明确区分。
    assert not first.startswith("dec_")


def test_decision_id_includes_semantic_digest_when_present() -> None:
    assessment = _assessment()
    without = derive_final_decision_id(assessment)
    with_semantic = derive_final_decision_id(
        assessment, semantic_digest="sha256:" + "5a" * 32
    )
    assert without != with_semantic
    assert with_semantic == derive_final_decision_id(
        assessment, semantic_digest="sha256:" + "5a" * 32
    )


def test_decision_id_changes_with_assessment_identity() -> None:
    base = _assessment()
    altered = _assessment(disposition="CLEAR_DENY")
    assert derive_final_decision_id(base) != derive_final_decision_id(altered)


def test_finalize_decision_id_never_triggers_uuid_default() -> None:
    assessment = _assessment()
    decision = _finalize(assessment)
    assert decision.decision_id == derive_final_decision_id(assessment)


def test_audit_id_deterministic_and_distinct_from_decision_id() -> None:
    assessment = _assessment()
    first = derive_final_audit_id(assessment)
    assert first == derive_final_audit_id(assessment)
    assert first.startswith("audit:sha256:")
    assert first != derive_final_decision_id(assessment)


# ---------------------------------------------------------------------------
# finalize 确定性：同输入同产物（replay 锚点）
# ---------------------------------------------------------------------------


def test_finalize_is_fully_deterministic() -> None:
    assessment = _assessment(disposition="CLEAR_DENY", impact="high")
    first = _finalize(assessment)
    for _ in range(5):
        repeat = _finalize(assessment)
        assert repeat.model_dump(mode="json") == first.model_dump(mode="json")


def test_finalize_on_real_assessment_from_assess_entry() -> None:
    """正式 assess 产物直接喂给 finalize（端到端纯函数链，无 IO）。"""
    event, policies = _first_case()
    assessment = assess(
        event, policies, _snapshot(), server_secret=SERVER_SECRET
    )
    decision = _finalize(assessment)
    assert decision.decision in ("allow", "ask", "deny")
    assert decision.decision == _SHADOW_FINALIZE_MAP[assessment.disposition]
    assert decision.risk_score == D7_EXPECTED[
        (assessment.disposition, assessment.impact)
    ][0]
    assert decision.latency_ms is None
