"""V21-09 T1：revalidation 五元组/state version CAS + semantic binding 校验。

契约依据：

- 03 §12（L439-467）五元组 compare + state version re-read，stale →
  作废并 reassess/ASK；
- 01 §26（L1003-1041）SemanticJudgment 字段冻结（含五 digest binding）；
- ``12_决策记录_V21-09前置.md`` D8：revalidation stale 归受控类目
  ``degraded_stale_judgment``（divergence 封闭词表同步扩展，
  fail-closed 语义不变）。

全部断言基于纯函数确定性：同输入必同输出，无 wall-clock/uuid。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.divergence import (
    DEGRADED_COMPONENT_FAILURE,
    DEGRADED_NO_SNAPSHOT,
    DEGRADED_STALE_JUDGMENT,
    DIVERGENCE_GRID,
    DIVERGENCE_VOCABULARY,
    SHADOW_COMPONENT_ID,
    classify_divergence,
)
from agentguard_core.decisions.evidence import (
    FastAssessment,
    RequiredCheckPlan,
    SemanticRoutingAssessment,
)
from agentguard_core.decisions.revalidation import (
    STALE_ASSESSMENT_DIGEST_REASON,
    STALE_POLICY_DIGEST_REASON,
    STALE_SNAPSHOT_DIGEST_REASON,
    STALE_STATE_VERSION_REASON,
    STALE_TASK_DIGEST_REASON,
    revalidate_assessment,
    validate_semantic_binding,
)
from agentguard_core.decisions.shadow import compute_assessment_digest
from agentguard_core.semantic.models import SemanticJudgment
from agentguard_core.signals.models import (
    AuthorityVerdict,
    EvaluationDegradation,
    FlowVerdict,
)

# ---------------------------------------------------------------------------
# 构造辅助：自洽 FastAssessment（assessment_digest 按 D1 口径计算）
# ---------------------------------------------------------------------------

TASK_DIGEST = "sha256:" + "11" * 32
POLICY_DIGEST = "sha256:" + "22" * 32
SNAPSHOT_DIGEST = "sha256:" + "33" * 32
AUTH_FINGERPRINT = "hmac-sha256:" + "ab" * 32
STATE_VERSION = 7


def _assessment(**overrides) -> FastAssessment:
    """合成自洽 assessment：overrides 生效后按 D1 口径重算摘要。"""
    assessment = FastAssessment(
        assessment_id="asm:" + "0f" * 32,
        event_id="evt-v2109-1",
        action_id="act-v2109-1",
        disposition="DEFER",
        impact="moderate",
        required_check_plan=RequiredCheckPlan(
            plan_id="plan-v2109-1",
            impact="moderate",
            required_domains=["task", "dataflow"],
            optional_domains=[],
            required_capabilities=[],
            semantic_resolvable_dimensions=[],
            reason_codes=[],
        ),
        policy_violations=[],
        signals=[],
        degradations=[],
        authority=AuthorityVerdict(
            status="unknown",
            matched_grant_ids=[],
            missing_capabilities=[],
            explicit_scope_mismatches=[],
            evidence_refs=[],
        ),
        flow=FlowVerdict(
            status="uncertain",
            strongest_strength=None,
            taints=[],
            external_sink=False,
            path_refs=[],
            evidence_refs=[],
        ),
        semantic_routing=SemanticRoutingAssessment(
            eligible=False,
            hard_deny_present=False,
            semantic_resolvable=False,
            required_facts_available=False,
            reason_codes=[],
        ),
        reason_codes=["v21-08:input_missing:authority"],
        evidence_refs=[],
        authorization_fingerprint=AUTH_FINGERPRINT,
        audit_fingerprint="hmac-sha256:" + "cd" * 32,
        task_digest=TASK_DIGEST,
        policy_digest=POLICY_DIGEST,
        snapshot_digest=SNAPSHOT_DIGEST,
        assessment_digest="",
    )
    if overrides:
        assessment = assessment.model_copy(update=overrides)
    return assessment.model_copy(
        update={"assessment_digest": compute_assessment_digest(assessment)}
    )


def _current_kwargs(**overrides) -> dict:
    """revalidate_assessment 的"无漂移"当前权威值基线。"""
    kwargs = {
        "assessment_state_version": STATE_VERSION,
        "current_state_version": STATE_VERSION,
        "current_task_digest": TASK_DIGEST,
        "current_policy_digest": POLICY_DIGEST,
        "current_snapshot_digest": SNAPSHOT_DIGEST,
    }
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# revalidate_assessment：全等 → valid；逐项漂移 → stale + reason code
# ---------------------------------------------------------------------------


def test_revalidation_all_equal_is_valid() -> None:
    result = revalidate_assessment(_assessment(), **_current_kwargs())
    assert result.status == "valid"
    assert result.reason_codes == []


def test_revalidation_is_deterministic() -> None:
    assessment = _assessment()
    kwargs = _current_kwargs(current_state_version=STATE_VERSION + 1)
    first = revalidate_assessment(assessment, **kwargs)
    for _ in range(5):
        assert revalidate_assessment(assessment, **kwargs) == first


def test_revalidation_task_digest_none_on_both_sides_is_valid() -> None:
    assessment = _assessment(task_digest=None)
    result = revalidate_assessment(
        assessment, **_current_kwargs(current_task_digest=None)
    )
    assert result.status == "valid"


@pytest.mark.parametrize(
    ("override", "current_override", "expected_reason"),
    [
        (
            {},
            {"current_state_version": STATE_VERSION + 1},
            STALE_STATE_VERSION_REASON,
        ),
        (
            {},
            {"current_task_digest": "sha256:" + "ee" * 32},
            STALE_TASK_DIGEST_REASON,
        ),
        (
            {},
            {"current_task_digest": None},
            STALE_TASK_DIGEST_REASON,
        ),
        (
            {},
            {"current_policy_digest": "sha256:" + "dd" * 32},
            STALE_POLICY_DIGEST_REASON,
        ),
        (
            {},
            {"current_snapshot_digest": "sha256:" + "cc" * 32},
            STALE_SNAPSHOT_DIGEST_REASON,
        ),
    ],
)
def test_revalidation_single_drift_is_stale_with_matching_reason(
    override: dict, current_override: dict, expected_reason: str
) -> None:
    assessment = _assessment(**override)
    result = revalidate_assessment(assessment, **_current_kwargs(**current_override))
    assert result.status == "stale"
    assert result.reason_codes == [expected_reason]


def test_revalidation_tampered_assessment_digest_is_stale() -> None:
    """assessment_digest 自洽完整性：重算摘要与自带值不符 → stale。"""
    assessment = _assessment()
    tampered = assessment.model_copy(
        update={"assessment_digest": "sha256:" + "99" * 32}
    )
    result = revalidate_assessment(tampered, **_current_kwargs())
    assert result.status == "stale"
    assert result.reason_codes == [STALE_ASSESSMENT_DIGEST_REASON]


def test_revalidation_multiple_drifts_collect_all_reasons() -> None:
    result = revalidate_assessment(
        _assessment(),
        **_current_kwargs(
            current_state_version=STATE_VERSION + 1,
            current_policy_digest="sha256:" + "dd" * 32,
            current_snapshot_digest="sha256:" + "cc" * 32,
        ),
    )
    assert result.status == "stale"
    assert result.reason_codes == [
        STALE_STATE_VERSION_REASON,
        STALE_POLICY_DIGEST_REASON,
        STALE_SNAPSHOT_DIGEST_REASON,
    ]


def test_stale_reason_codes_follow_v2109_prefix_discipline() -> None:
    for code in (
        STALE_ASSESSMENT_DIGEST_REASON,
        STALE_STATE_VERSION_REASON,
        STALE_TASK_DIGEST_REASON,
        STALE_POLICY_DIGEST_REASON,
        STALE_SNAPSHOT_DIGEST_REASON,
    ):
        assert code.startswith("v21-09:stale_")


# ---------------------------------------------------------------------------
# validate_semantic_binding：五 digest binding + 过期判定
# ---------------------------------------------------------------------------

JUDGMENT_CREATED_AT = "2026-08-15T00:00:00+00:00"
JUDGMENT_EXPIRES_AT = "2026-08-15T00:10:00+00:00"


def _judgment(assessment: FastAssessment, **overrides) -> SemanticJudgment:
    """binding 与 assessment 全等的 SemanticJudgment 构造器。"""
    payload = {
        "judgment_id": "judg-v2109-1",
        "verdict": "aligned",
        "reported_confidence": "high",
        "reason_codes": ["v21-13:task_alignment:aligned"],
        "evidence_refs": [],
        "assessment_digest": assessment.assessment_digest,
        "authorization_fingerprint": assessment.authorization_fingerprint,
        "task_digest": assessment.task_digest,
        "policy_digest": assessment.policy_digest,
        "snapshot_digest": assessment.snapshot_digest,
        "provider": "provider-fixture",
        "model": "model-fixture",
        "prompt_version": "v1",
        "created_at": JUDGMENT_CREATED_AT,
        "expires_at": JUDGMENT_EXPIRES_AT,
        "degraded": False,
        "semantic_digest": canonical_sha256({"judgment_id": "judg-v2109-1"}),
    }
    payload.update(overrides)
    return SemanticJudgment(**payload)


def test_semantic_binding_all_five_digests_match_is_valid() -> None:
    assessment = _assessment()
    assert validate_semantic_binding(assessment, _judgment(assessment)) is True


@pytest.mark.parametrize(
    ("binding_field", "assessment_field"),
    [
        ("assessment_digest", "assessment_digest"),
        ("authorization_fingerprint", "authorization_fingerprint"),
        ("task_digest", "task_digest"),
        ("policy_digest", "policy_digest"),
        ("snapshot_digest", "snapshot_digest"),
    ],
)
def test_semantic_binding_single_digest_drift_is_invalid(
    binding_field: str, assessment_field: str
) -> None:
    assessment = _assessment()
    judgment = _judgment(
        assessment, **{binding_field: "sha256:" + "f0" * 32}
    )
    assert validate_semantic_binding(assessment, judgment) is False
    # 对照：仅 assessment 侧同字段取值不同（judgment 锚定旧上下文）。
    drifted_assessment = _assessment(
        **{assessment_field: "sha256:" + "f0" * 32}
    ) if assessment_field not in {"assessment_digest", "authorization_fingerprint"} else None
    if drifted_assessment is not None:
        assert (
            validate_semantic_binding(drifted_assessment, _judgment(assessment))
            is False
        )


def test_semantic_binding_expired_is_invalid() -> None:
    assessment = _assessment()
    judgment = _judgment(assessment)
    # 参考时间晚于 expires_at → 过期（03 §13 hard deadline）。
    assert (
        validate_semantic_binding(
            assessment, judgment, reference_time="2026-08-15T00:20:00+00:00"
        )
        is False
    )
    # 参考时间早于 expires_at → 未过期，binding 有效。
    assert (
        validate_semantic_binding(
            assessment, judgment, reference_time="2026-08-15T00:05:00+00:00"
        )
        is True
    )


def test_semantic_binding_expiry_normalizes_z_suffix() -> None:
    assessment = _assessment()
    judgment = _judgment(assessment, expires_at="2026-08-15T00:10:00Z")
    assert (
        validate_semantic_binding(
            assessment, judgment, reference_time="2026-08-15T00:20:00Z"
        )
        is False
    )


def test_semantic_binding_is_deterministic() -> None:
    assessment = _assessment()
    judgment = _judgment(assessment)
    first = validate_semantic_binding(
        assessment, judgment, reference_time=JUDGMENT_EXPIRES_AT
    )
    for _ in range(5):
        assert (
            validate_semantic_binding(
                assessment, judgment, reference_time=JUDGMENT_EXPIRES_AT
            )
            == first
        )


# ---------------------------------------------------------------------------
# SemanticJudgment 冻结模型（01 §26 逐字）
# ---------------------------------------------------------------------------

SEMANTIC_JUDGMENT_FROZEN_FIELDS = {
    "schema_version",
    "judgment_id",
    "verdict",
    "reported_confidence",
    "reason_codes",
    "evidence_refs",
    "assessment_digest",
    "authorization_fingerprint",
    "task_digest",
    "policy_digest",
    "snapshot_digest",
    "provider",
    "model",
    "prompt_version",
    "created_at",
    "expires_at",
    "degraded",
    "semantic_digest",
}


def test_semantic_judgment_fields_match_frozen_contract() -> None:
    assert set(SemanticJudgment.model_fields) == SEMANTIC_JUDGMENT_FROZEN_FIELDS


def test_semantic_judgment_forbids_extra_fields() -> None:
    assessment = _assessment()
    with pytest.raises(ValidationError):
        _judgment(assessment, unexpected_field="x")


@pytest.mark.parametrize("verdict", ["allow", "deny", "approve", ""])
def test_semantic_judgment_rejects_non_frozen_verdict(verdict: str) -> None:
    """03 §11：只允许 aligned/misaligned/uncertain，不允许输出 allow/deny。"""
    assessment = _assessment()
    with pytest.raises(ValidationError):
        _judgment(assessment, verdict=verdict)


def test_semantic_judgment_has_no_uuid_or_clock_defaults() -> None:
    """01 §29 确定性纪律：全部身份/时间/digest 字段必填，无默认工厂。"""
    with pytest.raises(ValidationError):
        SemanticJudgment()  # type: ignore[call-arg]
    for name in (
        "judgment_id",
        "created_at",
        "expires_at",
        "semantic_digest",
        "provider",
    ):
        field_info = SemanticJudgment.model_fields[name]
        assert field_info.is_required(), name


def test_semantic_judgment_digest_fields_whitelist_excludes_identity_and_ttl() -> None:
    fields = SemanticJudgment.digest_fields()
    assert "semantic_digest" not in fields
    assert "judgment_id" not in fields
    assert "created_at" not in fields
    assert "expires_at" not in fields
    assert {"verdict", "assessment_digest", "policy_digest"} <= fields


# ---------------------------------------------------------------------------
# divergence D8：受控类目 degraded_stale_judgment
# ---------------------------------------------------------------------------

LEGACY_DECISIONS = ("allow", "ask", "deny")
DISPOSITIONS = ("CLEAR_ALLOW", "DEFER", "CLEAR_DENY")


def _shadow_degradation(reason_codes: list[str]) -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id=f"deg_v2109:{reason_codes[0]}",
        component_id=SHADOW_COMPONENT_ID,
        domain=None,
        required_for_action=True,
        failure_kind="stale",
        reason_codes=reason_codes,
        evidence_refs=[],
    )


def test_stale_category_registered_in_closed_vocabulary() -> None:
    assert DEGRADED_STALE_JUDGMENT == "degraded_stale_judgment"
    assert DEGRADED_STALE_JUDGMENT in DIVERGENCE_VOCABULARY
    # 九宫格非 parity 6 值 + 三个降级类目 = 9（封闭词表扩展，不自造新词）。
    assert len(DIVERGENCE_VOCABULARY) == 9


@pytest.mark.parametrize("legacy", LEGACY_DECISIONS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_revalidation_stale_overrides_grid_for_all_combinations(
    legacy: str, disposition: str
) -> None:
    assert (
        classify_divergence(legacy, disposition, (), revalidation_stale=True)
        == DEGRADED_STALE_JUDGMENT
    )


def test_revalidation_stale_default_false_preserves_v2108_semantics() -> None:
    # parity 对角线仍为 None；非 parity 组合仍查九宫格。
    assert classify_divergence("allow", "CLEAR_ALLOW") is None
    assert (
        classify_divergence("allow", "CLEAR_DENY")
        == "legacy_allow__v21_clear_deny"
    )


def test_shadow_component_degradation_takes_priority_over_stale() -> None:
    """组件故障意味着 disposition 本就未可信产出，归因更根本（D8 优先级）。"""
    degradations = [_shadow_degradation(["v21-08:component_failed"])]
    assert (
        classify_divergence("ask", "DEFER", degradations, revalidation_stale=True)
        == DEGRADED_COMPONENT_FAILURE
    )


def test_snapshot_absent_takes_priority_over_stale() -> None:
    degradations = [_shadow_degradation(["v21-08:snapshot_absent"])]
    assert (
        classify_divergence(
            "deny", "CLEAR_DENY", degradations, revalidation_stale=True
        )
        == DEGRADED_NO_SNAPSHOT
    )


def test_vocabulary_closed_after_d8_extension() -> None:
    assert DIVERGENCE_VOCABULARY == {
        "legacy_allow__v21_defer",
        "legacy_allow__v21_clear_deny",
        "legacy_ask__v21_clear_allow",
        "legacy_ask__v21_clear_deny",
        "legacy_deny__v21_clear_allow",
        "legacy_deny__v21_defer",
        DEGRADED_NO_SNAPSHOT,
        DEGRADED_COMPONENT_FAILURE,
        DEGRADED_STALE_JUDGMENT,
    }
    assert set(DIVERGENCE_GRID) == {
        (legacy, disposition)
        for legacy in LEGACY_DECISIONS
        for disposition in DISPOSITIONS
    }
