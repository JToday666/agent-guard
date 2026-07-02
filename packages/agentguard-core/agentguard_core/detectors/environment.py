"""Environment and tool-result poisoning detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolResultPayload
from ..matchers import (
    environment_poisoning_intents,
    has_high_confidence_memory_poisoning_text,
    has_instruction_like_text,
)
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
        instruction_like = event.payload.contains_instruction_like_text or has_instruction_like_text(
            event.payload.result.content_preview, policies
        )
        if not instruction_like:
            return []
        if (event.payload.will_enter_context or event.payload.will_persist) and has_high_confidence_memory_poisoning_text(
            event.payload.result.content_preview, policies
        ):
            return []
        call_id = event.payload.tool.call_id
        intents = environment_poisoning_intents(event.payload.result.content_preview, policies)
        high_confidence = bool(intents)
        result = apply_rule_override(
            DetectionResult(
                decision="deny" if high_confidence else "ask",
                risk_score=86 if high_confidence else 68,
                category="environment_poisoning",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Tool Result Environment Poisoning",
                    severity="high" if high_confidence else "medium",
                    evidence=[
                        f"tool={event.payload.tool.name}",
                        f"tool_call_id={call_id}",
                        f"will_enter_context={event.payload.will_enter_context}",
                        f"will_persist={event.payload.will_persist}",
                        f"high_confidence={high_confidence}",
                        *[
                            f"environment_poisoning_intent={intent}"
                            for intent in intents
                        ],
                    ],
                ),
                reason=(
                    "High-confidence tool result environment poisoning was blocked before context admission."
                    if high_confidence
                    else "A tool result contains instruction-like content that may influence later reasoning."
                ),
                approval_resource=None if high_confidence else f"tool_result:{call_id}",
                severity="high" if high_confidence else "medium",
            ),
            policies,
        )
        return [result] if result is not None else []
