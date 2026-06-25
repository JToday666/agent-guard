"""Prompt injection detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import ContextBuildPayload, GuardEvent, ModelCallPayload
from ..matchers import has_instruction_like_text, has_jailbreak_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class PromptInjectionDetector(Detector):
    rule_id = "P101_prompt_injection"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if isinstance(event.payload, ModelCallPayload):
            return self._evaluate_model_input(event, policies)
        if not isinstance(event.payload, ContextBuildPayload):
            return []
        if not event.payload.will_enter_context or event.payload.sanitized:
            return []
        for source in event.payload.sources:
            if source.source_trust.lower() != "untrusted":
                continue
            if source.contains_instruction_like_text or has_instruction_like_text(source.summary, policies):
                result = apply_rule_override(
                    DetectionResult(
                        decision="ask",
                        risk_score=64,
                        category="prompt_injection",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Prompt Injection In Context",
                            severity="medium",
                            evidence=[
                                f"source_id={source.source_id}",
                                f"source_type={source.source_type}",
                                "source_trust=untrusted",
                                "will_enter_context=true",
                                "sanitized=false",
                            ],
                        ),
                        reason="Untrusted instruction-like content is about to enter the model context.",
                        approval_resource=f"context:{source.source_id}",
                        severity="medium",
                    ),
                    policies,
                )
                return [result] if result is not None else []
        return []

    def _evaluate_model_input(
        self,
        event: GuardEvent,
        policies: PolicyBundle,
    ) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, ModelCallPayload):
            return []
        if payload.phase != "input" or payload.sanitized:
            return []
        if event.security_context.source_trust.lower() != "untrusted":
            return []
        if has_jailbreak_text(payload.content_preview, policies):
            return []
        if not (
            payload.contains_instruction_like_text
            or has_instruction_like_text(payload.content_preview, policies)
        ):
            return []

        result = apply_rule_override(
            DetectionResult(
                decision="ask",
                risk_score=64,
                category="prompt_injection",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Prompt Injection In Model Input",
                    severity="medium",
                    evidence=[
                        "phase=input",
                        "source_trust=untrusted",
                        f"contains_instruction_like_text={payload.contains_instruction_like_text}",
                        "sanitized=false",
                    ],
                ),
                reason="Untrusted instruction-like model input requires review.",
                approval_resource=f"model_input:{event.trace_id}",
                severity="medium",
            ),
            policies,
        )
        return [result] if result is not None else []
