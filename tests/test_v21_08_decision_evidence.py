"""V21-08 T3：DecisionEvidenceV21 组装与 divergence 分类契约测试。

口径：

- ``11_决策记录_V21-08前置.md`` D2：九宫格受控词表 + 两个降级类目，
  parity 对角线为 None，降级优先，词表封闭（未定义组合 fail-closed）；
- 完整方案 §14：九项证据保存项逐项断言（evidence 组装测试在本文件
  后续提交补齐）。
"""

from __future__ import annotations

import pytest

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
