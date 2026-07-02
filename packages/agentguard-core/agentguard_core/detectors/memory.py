"""Memory poisoning detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from typing import Any

from ..events import GuardEvent, MemoryEventPayload, ToolCallPayload, ToolResultPayload
from ..matchers import (
    has_high_confidence_memory_poisoning_text,
    has_memory_poisoning_text,
    memory_poisoning_intents,
)
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class MemoryPoisoningDetector(Detector):
    rule_id = "P104_memory_poisoning"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if isinstance(event.payload, ToolCallPayload):
            return self._evaluate_tool_call(event, policies)
        if isinstance(event.payload, ToolResultPayload):
            return self._evaluate_tool_result(event, policies)
        if not isinstance(event.payload, MemoryEventPayload):
            return []
        memory = event.payload.memory
        if memory.operation.lower() != "write" or not event.payload.will_persist:
            return []
        source_trust = memory.source_trust.lower()
        if source_trust in {"sanitized", "clean"}:
            return []
        intents = memory_poisoning_intents(memory.value_preview, policies)
        high_confidence = has_high_confidence_memory_poisoning_text(memory.value_preview, policies)
        has_poisoning_text = has_memory_poisoning_text(memory.value_preview, policies)
        should_review = (
            high_confidence
            or event.payload.requires_approval
            or source_trust not in {"trusted", "verified"}
            or has_poisoning_text
        )
        if should_review:
            target = f"{memory.namespace}/{memory.key}"
            result = apply_rule_override(
                DetectionResult(
                    decision="deny" if high_confidence else "ask",
                    risk_score=86 if high_confidence else 66,
                    category="memory_poisoning",
                    rule_hit=RuleHit(
                        rule_id=self.rule_id,
                        rule_name="Untrusted Memory Write",
                        severity="high" if high_confidence else "medium",
                        evidence=[
                            f"memory={target}",
                            f"source_trust={memory.source_trust}",
                            f"requires_approval={event.payload.requires_approval}",
                            f"high_confidence={high_confidence}",
                            *[f"memory_poisoning_intent={intent}" for intent in intents],
                        ],
                    ),
                    reason=(
                        "High-confidence persistent memory poisoning was blocked."
                        if high_confidence
                        else "A persistent memory write from an untrusted or policy-sensitive source requires review."
                    ),
                    approval_resource=None if high_confidence else f"memory:{target}",
                    severity="high" if high_confidence else "medium",
                ),
                policies,
            )
            return [result] if result is not None else []
        return []

    def _evaluate_tool_call(
        self,
        event: GuardEvent,
        policies: PolicyBundle,
    ) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, ToolCallPayload):
            return []
        if payload.tool.name not in {"rag_answer", "rag_retrieve"}:
            return []
        evidence = _poisoned_rag_evidence(payload.arguments, event.security_context.metadata, event.metadata, policies)
        if not evidence and payload.tool.name == "rag_answer":
            evidence = _unverified_rag_answer_evidence(payload, event, policies)
            if not evidence:
                return []
            target = _rag_answer_target(payload)
            result = apply_rule_override(
                DetectionResult(
                    decision="ask",
                    risk_score=64,
                    category="memory_poisoning",
                    rule_hit=RuleHit(
                        rule_id=self.rule_id,
                        rule_name="Unverified RAG Answer",
                        severity="medium",
                        evidence=evidence,
                    ),
                    reason=(
                        "A RAG answer derived from unverified local or retrieved knowledge requires review "
                        "before it is submitted or persisted."
                    ),
                    approval_resource=f"rag_answer:{target}",
                    severity="medium",
                ),
                policies,
            )
            return [result] if result is not None else []
        if not evidence:
            return []
        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=88,
                category="memory_poisoning",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Poisoned RAG Context",
                    severity="high",
                    evidence=[
                        f"tool={payload.tool.name}",
                        f"source_trust={event.security_context.source_trust}",
                        *evidence,
                    ],
                ),
                reason="Poisoned RAG context or answer was blocked before it entered persistent or model context.",
                severity="high",
            ),
            policies,
        )
        return [result] if result is not None else []

    def _evaluate_tool_result(
        self,
        event: GuardEvent,
        policies: PolicyBundle,
    ) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, ToolResultPayload):
            return []
        if payload.sanitized or not (payload.will_enter_context or payload.will_persist):
            return []
        text = payload.result.content_preview
        high_confidence = has_high_confidence_memory_poisoning_text(text, policies)
        has_poisoning_text = has_memory_poisoning_text(text, policies)
        if not high_confidence and not has_poisoning_text:
            return []
        intents = memory_poisoning_intents(text, policies)
        call_id = payload.tool.call_id
        result = apply_rule_override(
            DetectionResult(
                decision="deny" if high_confidence else "ask",
                risk_score=86 if high_confidence else 66,
                category="memory_poisoning",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Poisoned Persistent Tool Result",
                    severity="high" if high_confidence else "medium",
                    evidence=[
                        f"tool={payload.tool.name}",
                        f"tool_call_id={call_id}",
                        f"will_enter_context={payload.will_enter_context}",
                        f"will_persist={payload.will_persist}",
                        "sanitized=false",
                        f"high_confidence={high_confidence}",
                        *[f"memory_poisoning_intent={intent}" for intent in intents],
                    ],
                ),
                reason=(
                    "High-confidence poisoned tool/RAG result was blocked before entering context or persistence."
                    if high_confidence
                    else "A tool/RAG result contains persistent memory poisoning text and requires review."
                ),
                approval_resource=None if high_confidence else f"tool_result:{call_id}",
                severity="high" if high_confidence else "medium",
            ),
            policies,
        )
        return [result] if result is not None else []


def _poisoned_rag_evidence(
    arguments: dict[str, Any],
    security_metadata: dict[str, Any],
    event_metadata: dict[str, Any],
    policies: PolicyBundle,
) -> list[str]:
    evidence: list[str] = []
    for label, text in _rag_text_fragments(arguments, security_metadata, event_metadata):
        if has_high_confidence_memory_poisoning_text(text, policies):
            evidence.append(f"{label}=high_confidence_instruction")
    return evidence


def _unverified_rag_answer_evidence(
    payload: ToolCallPayload,
    event: GuardEvent,
    policies: PolicyBundle,
) -> list[str]:
    source_trust = event.security_context.source_trust.lower()
    if source_trust in {"trusted", "verified", "sanitized", "clean"}:
        return []
    if not _is_rag_answer_submission(payload):
        return []
    explicit_review = _truthy(
        event.security_context.metadata.get("requires_review")
        or event.security_context.metadata.get("requires_rag_answer_review")
        or event.metadata.get("requires_review")
        or event.metadata.get("requires_rag_answer_review")
    )
    poisoning_evidence = [
        f"{label}=memory_poisoning_marker"
        for label, text in _rag_text_fragments(payload.arguments, event.security_context.metadata, event.metadata)
        if has_memory_poisoning_text(text, policies)
    ]
    if not explicit_review and not poisoning_evidence:
        return []
    if not explicit_review and _is_low_risk_mcp_metadata_answer(payload, event, policies):
        return []
    evidence = [
        f"tool={payload.tool.name}",
        f"source_trust={event.security_context.source_trust}",
        f"source_type={event.security_context.source_type}",
    ]
    if explicit_review:
        evidence.append("requires_review=explicit_rag_answer_review")
    evidence.extend(poisoning_evidence)
    return evidence


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def _is_rag_answer_submission(payload: ToolCallPayload) -> bool:
    if payload.tool.name == "rag_answer":
        return True
    return any(
        resource.resource_type.lower() == "rag" and resource.operation.lower() in {"answer", "submit", "persist"}
        for resource in payload.derived_resources
    )


def _is_low_risk_mcp_metadata_answer(
    payload: ToolCallPayload,
    event: GuardEvent,
    policies: PolicyBundle,
) -> bool:
    source_type = event.security_context.source_type.lower()
    if source_type not in {"mcp_tool_metadata", "mcp_metadata", "tool_metadata"}:
        return False
    for resource in payload.derived_resources:
        if resource.resource_type.lower() == "rag" and resource.operation.lower() == "persist":
            return False
    for _label, text in _rag_text_fragments(payload.arguments, event.security_context.metadata):
        if has_high_confidence_memory_poisoning_text(text, policies) or has_memory_poisoning_text(text, policies):
            return False
    return True


def _rag_answer_target(payload: ToolCallPayload) -> str:
    dataset = payload.arguments.get("dataset")
    question_id = payload.arguments.get("question_id")
    if isinstance(dataset, str) and dataset.strip() and isinstance(question_id, str) and question_id.strip():
        return f"{dataset.strip()}:{question_id.strip()}"
    for key in ("question_id", "memory_key", "target", "id"):
        value = payload.arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for resource in payload.derived_resources:
        if resource.resource_type.lower() == "rag" and resource.target:
            return resource.target
    return payload.tool.call_id


def _rag_text_fragments(*values: Any) -> list[tuple[str, str]]:
    fragments: list[tuple[str, str]] = []
    for value in values:
        _collect_rag_text_fragments(value, fragments)
    return fragments


def _collect_rag_text_fragments(value: Any, fragments: list[tuple[str, str]], path: str = "rag") -> None:
    if isinstance(value, str):
        text = value.strip()
        if text:
            fragments.append((path, text))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _collect_rag_text_fragments(item, fragments, f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, nested in value.items():
        normalized_key = str(key).lower()
        if any(
            marker in normalized_key
            for marker in (
                "answer",
                "context",
                "content",
                "doc",
                "evidence",
                "citation",
                "source",
                "text",
                "message",
                "memory",
                "value",
                "instruction",
                "rule",
            )
        ):
            _collect_rag_text_fragments(nested, fragments, f"{path}.{key}")
