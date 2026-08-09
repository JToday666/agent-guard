"""Shared audit evidence and event description helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from agentguard_core import (
    AuditEvent,
    ConfigAuditEvent,
    ConfigAuditFinding,
    ConfigAuditResult,
    ContextBuildPayload,
    GuardDecision,
    GuardEvent,
    MemoryGuardChange,
    MemoryEventPayload,
    MessageSendPayload,
    ModelCallPayload,
    PolicyBundle,
    ToolCallPayload,
    ToolResultPayload,
)
from agentguard_core.events import derive_resources

from guard_api.storage.integrity import canonical_sha256

from .redaction import (
    CONTENT_PREVIEW_LIMIT,
    CONTEXT_SOURCES_LIMIT,
    NORMALIZED_RESOURCES_LIMIT,
    RULE_HITS_LIMIT,
    SUMMARY_TEXT_LIMIT,
    bound_redacted_value,
    bound_value,
    enforce_evidence_budget,
    redact_structure,
    truncate_text,
)

# §9.3 事件时策略 digest 规范化标识。
POLICY_CANONICALIZATION = "json:sorted-keys:v1"


@dataclass(frozen=True, slots=True)
class EventDescription:
    subject_id: str
    subject_type: str
    action_id: str
    action_name: str
    is_action: bool
    resource_targets: list[str]
    summary: str
    metadata: dict[str, object]


def build_audit_event(
    event: GuardEvent,
    decision: GuardDecision,
    *,
    policy_bundle: PolicyBundle,
    policy_revision: int | None,
    approval_id: str | None = None,
    critic_review_id: str | None = None,
    memory_change_id: str | None = None,
    extra_links: dict[str, str] | None = None,
    extra_metadata: dict[str, object] | None = None,
    decision_dump: dict[str, object] | None = None,
) -> AuditEvent:
    """Build the Guard API 0.4 policy_evaluation AuditEvent (§8-§10)."""

    description = describe_guard_event(event)
    links: dict[str, str] = {
        "event_id": event.event_id,
        "decision_id": decision.decision_id,
    }
    if description.is_action or approval_id is not None:
        links["action_id"] = description.action_id
    if approval_id is not None:
        links["approval_id"] = approval_id
    if critic_review_id is not None:
        links["critic_review_id"] = critic_review_id
    if memory_change_id is not None:
        links["memory_change_id"] = memory_change_id
    if extra_links:
        collision = set(extra_links) & set(links)
        if collision:
            raise ValueError(
                f"extra_links collides with reserved link keys: {sorted(collision)}"
            )
        links.update(extra_links)
    metadata = _merge_metadata(
        _security_context_metadata(event),
        event.metadata,
        description.metadata,
    )
    if extra_metadata:
        for key, value in extra_metadata.items():
            if value in (None, ""):
                continue
            metadata[key] = value
    if policy_revision is None:
        # §9.3：使用启动时默认策略时不得伪造 revision，只标记来源。
        metadata["policy_source"] = "default"
    # 幂等回放只依赖 evidence.guard_decision 这一处权威 decision 快照。
    dump = (
        decision_dump if decision_dump is not None else decision.model_dump(mode="json")
    )
    evidence = _policy_evaluation_evidence(
        event,
        decision,
        dump,
        policy_bundle=policy_bundle,
        policy_revision=policy_revision,
        approval_id=approval_id,
    )
    return AuditEvent(
        schema_version="0.4",
        record_type="policy_evaluation",
        trace_id=event.trace_id,
        case_id=event.case_id,
        runtime=event.runtime,
        event_type=event.event_type,
        attack_type=event.attack_type,
        is_malicious=event.is_malicious,
        summary=truncate_text(description.summary, SUMMARY_TEXT_LIMIT),
        decision=decision.decision,
        risk_score=decision.risk_score,
        severity=decision.severity,
        blocked=decision.blocked,
        resource_targets=description.resource_targets,
        rule_hits=[hit.rule_id for hit in decision.rule_hits][:RULE_HITS_LIMIT],
        reason=decision.reason,
        links=links,
        latency_ms=decision.latency_ms,
        metadata=metadata,
        evidence=evidence,
    )


def _policy_evaluation_evidence(
    event: GuardEvent,
    decision: GuardDecision,
    decision_dump: dict[str, object],
    *,
    policy_bundle: PolicyBundle,
    policy_revision: int | None,
    approval_id: str | None,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "guard_event": _guard_event_projection(event),
        "guard_decision": _bounded_decision_dump(decision_dump),
        "policy": {
            "bundle_id": policy_bundle.bundle_id,
            "version": policy_bundle.version,
            "revision": policy_revision,
            # §9.3：digest 必须来自同一次快照读取的 PolicyBundle。
            "canonical_digest": canonical_sha256(policy_bundle.model_dump(mode="json")),
            "canonicalization": POLICY_CANONICALIZATION,
        },
        "intervention": _policy_intervention(decision),
        "execution": {
            "status": "unknown",
            "receipt_recorded": False,
            "invoked_at": None,
            "completed_at": None,
            "error": None,
            "tool_result_entered_context": None,
            "persisted": None,
        },
        "side_effects": {
            "measurement_status": "unknown",
            "count": None,
            "summary": None,
        },
        "result": {
            "disposition": "unknown",
            "summary": None,
            "sanitized": None,
        },
        "approval": (
            {
                "approval_id": approval_id,
                "status": "pending",
                "decision": None,
                "resolved_at": None,
            }
            if approval_id is not None
            else {
                "approval_id": None,
                "status": "not_required",
                "decision": None,
                "resolved_at": None,
            }
        ),
    }
    return enforce_evidence_budget(evidence)


def _guard_event_projection(event: GuardEvent) -> dict[str, object]:
    """§9.1 有界、脱敏的 GuardEvent 投影。"""

    context = event.security_context
    projection: dict[str, object] = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "user_task": bound_redacted_value(
            context.user_task, text_limit=CONTENT_PREVIEW_LIMIT
        ),
    }
    source: dict[str, object] = {
        "type": context.source_type,
        "trust_level": context.source_trust,
    }
    if context.sender_id:
        source["source_id"] = redact_structure(context.sender_id)
    projection["source"] = source
    context_sources = list(context.context_sources)
    payload = event.payload
    if isinstance(payload, ContextBuildPayload):
        context_sources.extend(
            source.model_dump(mode="json") for source in payload.sources
        )
    projection["context_sources"] = bound_value(
        redact_structure(_unique_context_sources(context_sources)),
        text_limit=SUMMARY_TEXT_LIMIT,
        array_limit=CONTEXT_SOURCES_LIMIT,
    )
    projection["model_intent"] = (
        bound_redacted_value(context.model_intent, text_limit=CONTENT_PREVIEW_LIMIT)
        if context.model_intent is not None
        else None
    )
    if isinstance(payload, (ToolCallPayload, ToolResultPayload)):
        tool_projection: dict[str, object] = {
            "name": payload.tool.name,
            "category": payload.tool.category,
            "call_id": payload.tool.call_id,
        }
        if isinstance(payload, ToolCallPayload):
            # tool.arguments 必须服务端递归脱敏。
            tool_projection["arguments"] = bound_redacted_value(payload.arguments)
        projection["tool"] = tool_projection
    else:
        projection["tool"] = None
    resources = [
        {
            "type": resource.resource_type,
            "operation": resource.operation,
            "target": resource.target,
            "sensitivity": resource.data_classification,
            "direction": resource.direction,
        }
        for resource in derive_resources(event)
    ]
    projection["normalized_resources"] = bound_value(
        redact_structure(resources),
        text_limit=SUMMARY_TEXT_LIMIT,
        array_limit=NORMALIZED_RESOURCES_LIMIT,
    )
    return projection


def _unique_context_sources(items: Sequence[object]) -> list[object]:
    unique: list[object] = []
    fingerprints: set[str] = set()
    for item in items:
        fingerprint = (
            canonical_sha256(item)
            if isinstance(item, dict)
            else f"{type(item).__name__}:{item!s}"
        )
        if fingerprint in fingerprints:
            continue
        fingerprints.add(fingerprint)
        unique.append(item)
    return unique


def _bounded_decision_dump(dump: dict[str, object]) -> dict[str, object]:
    """完整 decision dump，仅套用 §21.2 规则 evidence / reason 单项边界。"""

    bounded = dict(dump)
    rule_hits = bounded.get("rule_hits")
    if isinstance(rule_hits, list):
        bounded_hits: list[object] = []
        for hit in rule_hits[:RULE_HITS_LIMIT]:
            if isinstance(hit, dict):
                item = dict(hit)
                evidence_items = item.get("evidence")
                if isinstance(evidence_items, list):
                    item["evidence"] = [
                        truncate_text(str(entry), SUMMARY_TEXT_LIMIT)
                        for entry in evidence_items
                    ]
                if isinstance(item.get("reason"), str):
                    item["reason"] = truncate_text(
                        str(item["reason"]), SUMMARY_TEXT_LIMIT
                    )
                bounded_hits.append(item)
            else:
                bounded_hits.append(hit)
        bounded["rule_hits"] = bounded_hits
    if isinstance(bounded.get("reason"), str):
        bounded["reason"] = truncate_text(str(bounded["reason"]), SUMMARY_TEXT_LIMIT)
    return bounded


def _policy_intervention(decision: GuardDecision) -> dict[str, object]:
    if decision.decision == "allow":
        return {
            "type": "none",
            "reason": "The action was allowed without intervention.",
        }
    if decision.decision == "deny":
        reason = "策略已拒绝，尚未收到 Adapter 执行回执"
    else:
        reason = "策略要求审批，尚未收到 Adapter 执行回执"
    return {"type": "unknown", "reason": reason}


def _approval_evidence(
    event: GuardEvent,
    decision: GuardDecision,
    description: EventDescription,
) -> dict[str, object]:
    evidence = {
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
    bounded = bound_redacted_value(
        evidence,
        text_limit=CONTENT_PREVIEW_LIMIT,
        array_limit=RULE_HITS_LIMIT,
    )
    return bounded if isinstance(bounded, dict) else {}


def _approval_payload_preview(value: object) -> object:
    # §21.2：审批 payload 清洗与 evidence 投影共用同一服务端工具。
    return bound_redacted_value(value, text_limit=SUMMARY_TEXT_LIMIT)


def _config_audit_event(
    event: ConfigAuditEvent, result: ConfigAuditResult
) -> AuditEvent:
    worst = _worst_finding_severity(result.findings)
    risk_score = {"low": 15, "medium": 45, "high": 80, "critical": 95}[worst]
    return AuditEvent(
        schema_version="0.4",
        record_type="config_audit",
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
            is_action=True,
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

    if isinstance(payload, ToolResultPayload):
        action_id = payload.tool.call_id
        action_name = payload.tool.name
        return EventDescription(
            subject_id=action_id,
            subject_type="tool_result",
            action_id=action_id,
            action_name=action_name,
            is_action=True,
            resource_targets=resource_targets,
            summary=f"Agent evaluated the result from {action_name}",
            metadata={
                "event_type": event.event_type,
                "subject_id": action_id,
                "subject_type": "tool_result",
                "action_id": action_id,
                "action_name": action_name,
                "source_tool": payload.tool.name,
                "source_tool_call_id": payload.tool.call_id,
            },
        )

    explicit_action_id = getattr(payload, "action_id", None)
    action_id = (
        explicit_action_id.strip()
        if isinstance(explicit_action_id, str) and explicit_action_id.strip()
        else event.event_id
    )
    action_name = event.event_type
    is_action = isinstance(payload, (MemoryEventPayload, MessageSendPayload)) or (
        isinstance(payload, ModelCallPayload) and payload.phase == "output"
    )
    metadata: dict[str, object] = {
        "event_type": event.event_type,
        "subject_id": action_id,
        "subject_type": event.event_type,
    }
    if is_action:
        metadata["action_id"] = action_id
        metadata["action_name"] = action_name
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
        is_action=is_action,
        resource_targets=resource_targets,
        summary=f"Agent evaluated {action_name}",
        metadata=metadata,
    )
