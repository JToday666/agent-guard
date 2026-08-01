"""Prompt injection detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import ContextBuildPayload, GuardEvent, ModelCallPayload
from ..matchers import (
    has_instruction_like_text,
    has_jailbreak_text,
    prompt_injection_intents,
)
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class PromptInjectionDetector(Detector):
    rule_id = "P101_prompt_injection"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
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
            instruction_like = (
                source.contains_instruction_like_text
                or has_instruction_like_text(source.summary, policies)
            )
            if instruction_like:
                intents = prompt_injection_intents(source.summary, policies)
                high_confidence = bool(intents)
                result = apply_rule_override(
                    DetectionResult(
                        decision="deny" if high_confidence else "ask",
                        risk_score=84 if high_confidence else 64,
                        category="prompt_injection",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Prompt Injection In Context",
                            severity="high" if high_confidence else "medium",
                            evidence=[
                                f"source_id={source.source_id}",
                                f"source_type={source.source_type}",
                                "source_trust=untrusted",
                                "will_enter_context=true",
                                "sanitized=false",
                                f"high_confidence={high_confidence}",
                                *[
                                    f"prompt_injection_intent={intent}"
                                    for intent in intents
                                ],
                            ],
                        ),
                        reason="Untrusted instruction-like content is about to enter the model context.",
                        approval_resource=(
                            None if high_confidence else f"context:{source.source_id}"
                        ),
                        severity="high" if high_confidence else "medium",
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
        instruction_like = (
            payload.contains_instruction_like_text
            or has_instruction_like_text(payload.content_preview, policies)
        )
        if not instruction_like:
            return []
        intents = prompt_injection_intents(payload.content_preview, policies)
        high_confidence = bool(intents)

        result = apply_rule_override(
            DetectionResult(
                decision="deny" if high_confidence else "ask",
                risk_score=84 if high_confidence else 64,
                category="prompt_injection",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Prompt Injection In Model Input",
                    severity="high" if high_confidence else "medium",
                    evidence=[
                        "phase=input",
                        "source_trust=untrusted",
                        f"contains_instruction_like_text={payload.contains_instruction_like_text}",
                        "sanitized=false",
                        f"high_confidence={high_confidence}",
                        *[f"prompt_injection_intent={intent}" for intent in intents],
                    ],
                ),
                reason=(
                    "High-confidence prompt injection was blocked before model execution."
                    if high_confidence
                    else "Untrusted instruction-like model input requires review."
                ),
                approval_resource=(
                    None if high_confidence else f"model_input:{event.trace_id}"
                ),
                severity="high" if high_confidence else "medium",
            ),
            policies,
        )
        return [result] if result is not None else []
