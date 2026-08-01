"""Model input jailbreak and output leakage detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ModelCallPayload
from ..matchers import has_jailbreak_text, looks_like_sensitive_model_leak
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class JailbreakDetector(Detector):
    rule_id = "P102_jailbreak"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ModelCallPayload):
            return []
        text = event.payload.content_preview
        if (
            event.payload.phase == "input"
            and not event.payload.sanitized
            and has_jailbreak_text(text, policies)
        ):
            return self._result(
                policies,
                risk_score=86,
                severity="high",
                evidence=["phase=input", "jailbreak_pattern=true"],
                reason="The model input contains jailbreak instructions.",
            )
        if event.payload.phase == "output" and looks_like_sensitive_model_leak(
            event.payload, policies
        ):
            return self._result(
                policies,
                risk_score=90,
                severity="critical",
                evidence=["phase=output", "sensitive_leakage=true"],
                reason="The model output appears to disclose sensitive hidden context.",
            )
        return []

    def _result(
        self,
        policies: PolicyBundle,
        *,
        risk_score: int,
        severity: str,
        evidence: list[str],
        reason: str,
    ) -> list[DetectionResult]:
        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=risk_score,
                category="jailbreak",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Jailbreak Or Sensitive Model Leakage",
                    severity=severity,
                    evidence=evidence,
                ),
                reason=reason,
                severity=severity,
            ),
            policies,
        )
        return [result] if result is not None else []
