"""V21-01 legacy adapter tests: mapping fidelity, determinism, isolation."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from agentguard_core.actions.canonical_json import canonical_json_bytes
from agentguard_core.decisions.models import RuleHit
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.signals.legacy_adapter import (
    _stable_evidence_digest,
    legacy_detection_to_signal,
    legacy_failure_to_degradation,
)
from agentguard_core.signals.models import EvidenceRef

ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT / "packages" / "agentguard-core" / "agentguard_core"


def _result(
    *,
    decision: str = "deny",
    risk_score: int = 80,
    category: str = "sensitive_resource",
    rule_id: str = "P001_sensitive_file_access",
    evidence: list[str] | None = None,
    severity: str | None = "high",
) -> DetectionResult:
    return DetectionResult(
        decision=decision,
        risk_score=risk_score,
        category=category,
        rule_hit=RuleHit(
            rule_id=rule_id,
            rule_name="rule",
            severity=severity,
            evidence=evidence if evidence is not None else ["hit evidence"],
        ),
        reason="matched",
        severity=severity,
    )


def _failure_result(
    rule_id: str = "detector_failure:PromptInjectionDetector",
) -> DetectionResult:
    return DetectionResult(
        decision="ask",
        risk_score=60,
        category="detector_failure",
        rule_hit=RuleHit(
            rule_id=rule_id,
            rule_name="Detector Failure",
            severity="medium",
            evidence=[
                "detector PromptInjectionDetector raised RuntimeError",
                "fail-closed: detector failure always requires review",
            ],
        ),
        reason="Detector PromptInjectionDetector failed with RuntimeError",
        severity="medium",
    )


# ---------------------------------------------------------------------------
# Field fidelity and determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
def test_signal_mapping_is_deterministic(decision: str) -> None:
    result = _result(decision=decision)

    first = legacy_detection_to_signal(result, event_id="evt_1", result_index=0)
    second = legacy_detection_to_signal(result, event_id="evt_1", result_index=0)

    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_signal_preserves_regular_result_fields() -> None:
    result = _result(
        decision="deny",
        category="sensitive_resource",
        rule_id="P001_sensitive_file_access",
        evidence=["read /etc/shadow"],
        severity="high",
    )

    signal = legacy_detection_to_signal(result, event_id="evt_42", result_index=0)

    assert signal.signal_id.startswith("sig_evt_42_P001_sensitive_file_access_0_")
    assert signal.detector_id == "P001_sensitive_file_access"
    assert signal.category == "sensitive_resource"
    assert signal.scope == "event"
    assert signal.impact == "high"
    assert signal.confidence == "high"
    assert signal.evidence_group == "P001_sensitive_file_access"
    assert signal.reason_codes == ["P001_sensitive_file_access"]
    assert signal.evidence_refs == []
    assert signal.facts == []
    assert signal.tags == ["legacy"]


def test_same_rule_hits_have_distinct_stable_signal_ids() -> None:
    first_result = _result(evidence=["target=/etc/shadow"])
    second_result = _result(evidence=["target=/home/user/.ssh/id_rsa"])

    first = legacy_detection_to_signal(
        first_result, event_id="evt_multi", result_index=0
    )
    second = legacy_detection_to_signal(
        second_result, event_id="evt_multi", result_index=1
    )

    assert first.signal_id != second.signal_id
    assert (
        first.signal_id
        == legacy_detection_to_signal(
            first_result, event_id="evt_multi", result_index=0
        ).signal_id
    )


def test_signal_only_attaches_caller_supplied_persisted_evidence_ref() -> None:
    persisted_ref = EvidenceRef(
        ref_id="ev_audit_policy_1_rule_0",
        kind="policy_rule",
        record_type="policy_evaluation",
        record_id="audit_policy_1",
        json_pointer="/evidence/guard_decision/rule_hits/0",
        digest="a" * 64,
        redaction_state="none",
    )

    signal = legacy_detection_to_signal(
        _result(),
        event_id="evt_ref",
        result_index=0,
        evidence_refs=[persisted_ref],
    )

    assert signal.evidence_refs == [persisted_ref]


def test_result_index_must_be_non_negative() -> None:
    with pytest.raises(ValueError, match="result_index must be non-negative"):
        legacy_detection_to_signal(_result(), event_id="evt_bad", result_index=-1)


def test_detector_failure_signal_parses_detector_name() -> None:
    result = _failure_result()

    signal = legacy_detection_to_signal(result, event_id="evt_9", result_index=0)

    assert signal.detector_id == "PromptInjectionDetector"
    assert signal.category == "detector_failure"
    assert signal.signal_id.startswith(
        "sig_evt_9_detector_failure:PromptInjectionDetector_0_"
    )
    assert signal.confidence == "medium"


def test_malformed_detector_failure_rule_id_is_consistent_across_paths() -> None:
    # rule_id 恰为 "detector_failure:"（无检测器名）：两条消费路径必须
    # 一致收敛，不得一边回退一边产出 component_id 为空的无效降级。
    result = _failure_result(rule_id="detector_failure:")

    signal = legacy_detection_to_signal(result, event_id="evt_m", result_index=0)
    assert signal.detector_id == "detector_failure:"

    assert legacy_failure_to_degradation(result, event_id="evt_m") is None


def test_severity_table_mapping_covers_all_four_levels() -> None:
    expected = {
        "low": "low",
        "medium": "moderate",
        "high": "high",
        "critical": "critical",
    }
    for severity, impact in expected.items():
        signal = legacy_detection_to_signal(
            _result(severity=severity, risk_score=50),
            event_id="evt_s",
            result_index=0,
        )
        assert signal.impact == impact, severity


@pytest.mark.parametrize(
    ("risk_score", "expected_impact"),
    [
        (95, "critical"),
        (90, "critical"),
        (89, "high"),
        (70, "high"),
        (69, "moderate"),
        (40, "moderate"),
        (39, "low"),
        (0, "low"),
    ],
)
def test_missing_severity_falls_back_to_score_thresholds(
    risk_score: int, expected_impact: str
) -> None:
    signal = legacy_detection_to_signal(
        _result(severity=None, risk_score=risk_score),
        event_id="evt_f",
        result_index=0,
    )
    assert signal.impact == expected_impact


@pytest.mark.parametrize(
    ("evidence", "severity", "risk_score", "expected_confidence"),
    [
        (["high_confidence=true"], "medium", 64, "high"),
        (["high_confidence=false"], "high", 84, "medium"),
        (["ordinary evidence"], "low", 95, "low"),
        (["ordinary evidence"], "medium", 95, "medium"),
        (["ordinary evidence"], "critical", 10, "high"),
        (["ordinary evidence"], None, 39, "low"),
        (["ordinary evidence"], None, 69, "medium"),
        (["ordinary evidence"], None, 70, "high"),
    ],
)
def test_confidence_preserves_legacy_result_semantics(
    evidence: list[str],
    severity: str | None,
    risk_score: int,
    expected_confidence: str,
) -> None:
    signal = legacy_detection_to_signal(
        _result(evidence=evidence, severity=severity, risk_score=risk_score),
        event_id="evt_confidence",
        result_index=0,
    )

    assert signal.confidence == expected_confidence


# ---------------------------------------------------------------------------
# Evidence digest: V21-02 受限 canonical JSON digest
# ---------------------------------------------------------------------------


def test_stable_evidence_digest_is_canonical_json_sha256() -> None:
    evidence = ["read /etc/shadow", "high_confidence=true"]
    expected = hashlib.sha256(canonical_json_bytes(list(evidence))).hexdigest()
    assert _stable_evidence_digest(evidence) == expected


def test_stable_evidence_digest_keeps_injective_encoding() -> None:
    # 单射：["a\nb"] 与 ["a", "b"] 不得同摘要；顺序敏感（语义有序）。
    assert _stable_evidence_digest(["a\nb"]) != _stable_evidence_digest(["a", "b"])
    assert _stable_evidence_digest(["x", "y"]) != _stable_evidence_digest(["y", "x"])
    assert _stable_evidence_digest([]) != _stable_evidence_digest([""])


def test_signal_id_stays_deterministic_after_digest_upgrade() -> None:
    result = _result(evidence=["target=/etc/shadow"])
    first = legacy_detection_to_signal(result, event_id="evt_d", result_index=0)
    second = legacy_detection_to_signal(result, event_id="evt_d", result_index=0)
    assert first.signal_id == second.signal_id


# ---------------------------------------------------------------------------
# Degradation mapping
# ---------------------------------------------------------------------------


def test_failure_result_yields_degradation_with_parsed_component() -> None:
    degradation = legacy_failure_to_degradation(_failure_result(), event_id="evt_7")

    assert degradation is not None
    assert degradation.degradation_id == (
        "deg_evt_7_detector_failure:PromptInjectionDetector"
    )
    assert degradation.component_id == "PromptInjectionDetector"
    assert degradation.failure_kind == "unavailable"
    assert degradation.required_for_action is True
    assert degradation.domain is None
    assert degradation.reason_codes == ["detector_failure:PromptInjectionDetector"]
    assert degradation == legacy_failure_to_degradation(
        _failure_result(), event_id="evt_7"
    )


def test_regular_result_yields_no_degradation() -> None:
    assert legacy_failure_to_degradation(_result(), event_id="evt_r") is None
    assert (
        legacy_failure_to_degradation(_result(decision="allow"), event_id="evt_r")
        is None
    )
    assert (
        legacy_failure_to_degradation(_result(decision="ask"), event_id="evt_r") is None
    )


# ---------------------------------------------------------------------------
# Import isolation: the decision path must stay untouched
# ---------------------------------------------------------------------------


def _import_references(source: str) -> list[str]:
    """收集源码中所有 import 引用的模块名与 alias 名。

    ImportFrom 同时纳入 ``node.module``（相对 import 时为 ``""``）与
    ``node.names`` 的 alias 名，保证 ``from ..decisions import evidence``、
    ``from . import evidence`` 等自然写法都能被检查到。
    """
    references: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            references.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            references.append(node.module or "")
            references.extend(alias.name for alias in node.names)
    return references


def _assert_no_scaffold_references(relative_path: str, references: list[str]) -> None:
    for reference in references:
        # docstring 可以提及迁移目标；但判定路径代码不得 import 新脚手架。
        assert (
            "signals" not in reference
        ), f"{relative_path} imports the V21 scaffold module {reference!r}"
        assert (
            reference != "evidence"
            and not reference.endswith(".evidence")
            and ".evidence." not in reference
        ), f"{relative_path} imports the V21 scaffold module {reference!r}"


@pytest.mark.parametrize(
    "relative_path",
    [
        "engine.py",
        "decisions/policy.py",
        "decisions/results.py",
    ],
)
def test_decision_path_does_not_reference_new_scaffold(
    relative_path: str,
) -> None:
    source = (CORE_DIR / relative_path).read_text(encoding="utf-8")
    _assert_no_scaffold_references(relative_path, _import_references(source))


@pytest.mark.parametrize(
    "sample_source",
    [
        "from ..decisions import evidence",
        "from . import evidence",
        "from ..signals.models import SecuritySignal",
        "import agentguard_core.signals",
    ],
)
def test_isolation_guard_detects_relative_and_alias_imports(
    sample_source: str,
) -> None:
    # 守卫自身的负例验证：上述任一样例源码都必须被识别为违规。
    with pytest.raises(AssertionError):
        _assert_no_scaffold_references("sample.py", _import_references(sample_source))
