"""Shared audit evidence and event description helpers."""

from __future__ import annotations

from dataclasses import dataclass

from agentguard_core import (
    AuditEvent,
    ConfigAuditEvent,
    ConfigAuditFinding,
    ConfigAuditResult,
    GuardDecision,
    GuardEvent,
    MemoryGuardChange,
    ToolCallPayload,
)
from agentguard_core.resources import derive_resources


@dataclass(frozen=True, slots=True)
class EventDescription:
    subject_id: str
    subject_type: str
    action_id: str
    action_name: str
    resource_targets: list[str]
    summary: str
    metadata: dict[str, object]


def build_audit_event(
    event: GuardEvent,
    decision: GuardDecision,
    *,
    approval_id: str | None = None,
    critic_review_id: str | None = None,
    memory_change_id: str | None = None,
) -> AuditEvent:
    description = describe_guard_event(event)
    links = {"event_id": event.event_id, "decision_id": decision.decision_id}
    if approval_id is not None:
        links["approval_id"] = approval_id
    if critic_review_id is not None:
        links["critic_review_id"] = critic_review_id
    if memory_change_id is not None:
        links["memory_change_id"] = memory_change_id
    return AuditEvent(
        trace_id=event.trace_id,
        case_id=event.case_id,
        runtime=event.runtime,
        event_type=event.event_type,
        attack_type=event.attack_type,
        is_malicious=event.is_malicious,
        summary=description.summary,
        decision=decision.decision,
        risk_score=decision.risk_score,
        severity=decision.severity,
        blocked=decision.blocked,
        resource_targets=description.resource_targets,
        rule_hits=[hit.rule_id for hit in decision.rule_hits],
        reason=decision.reason,
        links=links,
        latency_ms=decision.latency_ms,
        metadata=_merge_metadata(
            _security_context_metadata(event),
            event.metadata,
            description.metadata,
        ),
    )


def _approval_evidence(
    event: GuardEvent,
    decision: GuardDecision,
    description: EventDescription,
) -> dict[str, object]:
    return {
        "event": {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "trace_id": event.trace_id,
            "case_id": event.case_id,
            "runtime": event.runtime,
            "current_step": event.security_context.current_step,
            "source_type": event.security_context.source_type,
            "source_trust": event.security_context.source_trust,
            "resource_targets": description.resource_targets,
        },
        "decision": {
            "decision_id": decision.decision_id,
            "decision": decision.decision,
            "categories": list(decision.categories),
            "rule_hits": [hit.model_dump(mode="json") for hit in decision.rule_hits],
            "risk_score": decision.risk_score,
            "severity": decision.severity,
            "reason": decision.reason,
        },
        "payload": _approval_payload_preview(event.payload),
    }


def _approval_payload_preview(value: object) -> object:
    if hasattr(value, "model_dump"):
        return _approval_payload_preview(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    if isinstance(value, dict):
        return {
            str(key): _approval_field_preview(str(key), nested)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_approval_payload_preview(item) for item in value[:20]]
    if isinstance(value, str):
        return value if len(value) <= 500 else f"{value[:500]}..."
    return value


def _approval_field_preview(key: str, value: object) -> object:
    if _looks_sensitive_key(key):
        return "[redacted]"
    return _approval_payload_preview(value)


def _looks_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(
        marker in normalized
        for marker in ("token", "secret", "password", "authorization", "credential")
    )


def _config_audit_event(
    event: ConfigAuditEvent, result: ConfigAuditResult
) -> AuditEvent:
    worst = _worst_finding_severity(result.findings)
    risk_score = {"low": 15, "medium": 45, "high": 80, "critical": 95}[worst]
    return AuditEvent(
        trace_id=str(event.metadata.get("trace_id") or event.event_id),
        runtime=event.runtime,
        stage=event.action,
        event_type="config_audit",
        summary=f"Configuration audit for {event.target_type}:{event.target_id}",
        decision="deny" if result.decision == "block" else "allow",
        risk_score=risk_score,
        severity=worst,
        blocked=result.decision == "block",
        resource_targets=[event.target_id],
        rule_hits=[finding.category for finding in result.findings],
        reason=result.reason,
        links={"config_audit_event_id": event.event_id},
        metadata=_merge_metadata(
            event.metadata,
            {
                "target_type": event.target_type,
                "target_id": event.target_id,
                "finding_count": len(result.findings),
            },
        ),
    )


def _worst_finding_severity(findings: list[ConfigAuditFinding]) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    worst = "low"
    for finding in findings:
        severity = getattr(finding, "severity", "low")
        if severity in rank and rank[severity] > rank[worst]:
            worst = severity
    return worst


def _should_quarantine_memory_change(change: MemoryGuardChange) -> bool:
    preview = change.value_preview.lower()
    if change.source_trust != "trusted":
        return True
    return any(
        marker in preview for marker in ("secret", "token", "password", "always send")
    )


def _event_hook_name(event: AuditEvent) -> str | None:
    hook_name = event.metadata.get("openclaw_hook") or event.metadata.get("hook_name")
    if isinstance(hook_name, str) and hook_name:
        return hook_name
    if event.event_type == "runtime_observation" and event.stage:
        return event.stage
    return None


def _security_context_metadata(event: GuardEvent) -> dict[str, object]:
    context = event.security_context
    metadata: dict[str, object] = {}
    scalar_fields = (
        "user_task",
        "source_type",
        "source_trust",
        "channel",
        "sender_id",
        "run_id",
        "agent_id",
        "current_step",
        "model_intent",
    )
    for field_name in scalar_fields:
        value = getattr(context, field_name)
        if value not in (None, ""):
            metadata[field_name] = value
    if context.derived_paths:
        metadata["derived_paths"] = list(context.derived_paths)
    if context.context_sources:
        metadata["context_sources"] = list(context.context_sources)
    return metadata


def _merge_metadata(*items: dict[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    for item in items:
        for key, value in item.items():
            if value in (None, ""):
                continue
            metadata[key] = value
    return metadata


def describe_guard_event(event: GuardEvent) -> EventDescription:
    resources = derive_resources(event)
    resource_targets = [resource.target for resource in resources if resource.target]
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        action_id = payload.tool.call_id
        action_name = payload.tool.name
        return EventDescription(
            subject_id=action_id,
            subject_type="tool_call",
            action_id=action_id,
            action_name=action_name,
            resource_targets=resource_targets,
            summary=f"Agent attempted to call {action_name}",
            metadata={
                "event_type": event.event_type,
                "subject_id": action_id,
                "subject_type": "tool_call",
                "action_id": action_id,
                "action_name": action_name,
                "tool": payload.tool.name,
                "tool_call_id": payload.tool.call_id,
            },
        )

    action_id = event.event_id
    action_name = event.event_type
    metadata: dict[str, object] = {
        "event_type": event.event_type,
        "subject_id": action_id,
        "subject_type": event.event_type,
        "action_id": action_id,
        "action_name": action_name,
    }
    payload_tool = getattr(payload, "tool", None)
    if payload_tool is not None:
        metadata["source_tool"] = payload_tool.name
        metadata["source_tool_call_id"] = payload_tool.call_id
    payload_phase = getattr(payload, "phase", None)
    if payload_phase is not None:
        metadata["phase"] = payload_phase
    payload_model = getattr(payload, "model", None)
    if payload_model is not None:
        metadata["model"] = payload_model
    payload_provider = getattr(payload, "provider", None)
    if payload_provider is not None:
        metadata["provider"] = payload_provider
    payload_channel = getattr(payload, "channel", None)
    if payload_channel is not None:
        metadata["channel"] = payload_channel
    payload_recipient = getattr(payload, "recipient", None)
    if payload_recipient is not None:
        metadata["recipient"] = payload_recipient
    payload_memory = getattr(payload, "memory", None)
    if payload_memory is not None:
        metadata["memory_namespace"] = payload_memory.namespace
        metadata["memory_key"] = payload_memory.key

    return EventDescription(
        subject_id=action_id,
        subject_type=event.event_type,
        action_id=action_id,
        action_name=action_name,
        resource_targets=resource_targets,
        summary=f"Agent evaluated {action_name}",
        metadata=metadata,
    )
