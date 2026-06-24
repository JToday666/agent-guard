"""Memory poisoning detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, MemoryEventPayload
from ..matchers import has_memory_poisoning_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class MemoryPoisoningDetector(Detector):
    rule_id = "P104_memory_poisoning"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, MemoryEventPayload):
            return []
        memory = event.payload.memory
        if memory.operation.lower() != "write" or not event.payload.will_persist:
            return []
        if (
            event.payload.requires_approval
            or memory.source_trust.lower() == "untrusted"
            or has_memory_poisoning_text(memory.value_preview, policies)
        ):
            target = f"{memory.namespace}/{memory.key}"
            result = apply_rule_override(
                DetectionResult(
                    decision="ask",
                    risk_score=66,
                    category="memory_poisoning",
                    rule_hit=RuleHit(
                        rule_id=self.rule_id,
                        rule_name="Untrusted Memory Write",
                        severity="medium",
                        evidence=[
                            f"memory={target}",
                            f"source_trust={memory.source_trust}",
                            f"requires_approval={event.payload.requires_approval}",
                        ],
                    ),
                    reason="A persistent memory write from an untrusted or policy-sensitive source requires review.",
                    approval_resource=f"memory:{target}",
                    severity="medium",
                ),
                policies,
            )
            return [result] if result is not None else []
        return []
