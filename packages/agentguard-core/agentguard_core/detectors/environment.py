"""Environment and tool-result poisoning detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolResultPayload
from ..matchers import has_high_confidence_memory_poisoning_text, has_instruction_like_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class EnvironmentPoisoningDetector(Detector):
    rule_id = "P105_environment_poisoning"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolResultPayload):
            return []
        if event.payload.sanitized or not (event.payload.will_enter_context or event.payload.will_persist):
            return []
        if not (
            event.payload.contains_instruction_like_text
            or has_instruction_like_text(event.payload.result.content_preview, policies)
        ):
            return []
        if (event.payload.will_enter_context or event.payload.will_persist) and has_high_confidence_memory_poisoning_text(
            event.payload.result.content_preview, policies
        ):
            return []
        call_id = event.payload.tool.call_id
        result = apply_rule_override(
            DetectionResult(
                decision="ask",
                risk_score=68,
                category="environment_poisoning",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Tool Result Environment Poisoning",
                    severity="medium",
                    evidence=[
                        f"tool={event.payload.tool.name}",
                        f"tool_call_id={call_id}",
                        f"will_enter_context={event.payload.will_enter_context}",
                        f"will_persist={event.payload.will_persist}",
                    ],
                ),
                reason="A tool result contains instruction-like content that may influence later reasoning.",
                approval_resource=f"tool_result:{call_id}",
                severity="medium",
            ),
            policies,
        )
        return [result] if result is not None else []
