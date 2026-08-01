"""Sensitive resource detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, derive_resources
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class SensitiveResourceDetector(Detector):
    rule_id = "P001_sensitive_file_access"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        results: list[DetectionResult] = []
        for resource in derive_resources(event):
            target = resource.target
            lowered = target.lower()
            markers = [marker.lower() for marker in policies.sensitive_resource_markers]
            if any(marker in lowered for marker in markers):
                result = apply_rule_override(
                    DetectionResult(
                        decision="deny",
                        risk_score=95,
                        category="sensitive_file_access",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Sensitive Resource Access",
                            severity="critical",
                            evidence=[f"target={target}"],
                        ),
                        reason="The tool call targets a sensitive local resource.",
                        severity="critical",
                    ),
                    policies,
                )
                if result is not None:
                    results.append(result)
        return results
