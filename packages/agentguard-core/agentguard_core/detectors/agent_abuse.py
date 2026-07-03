"""Agent abuse detectors for unauthorized high-impact actions."""

from __future__ import annotations

import json
from typing import Any

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload, derive_resources, is_exec_like_tool, tool_argument_text
from ..matchers import agent_abuse_intents, has_dangerous_command_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled
from .tool import low_risk_observation_action_allowed, task_allows_tool_action


class AgentAbuseDetector(Detector):
    rule_id = "P108_agent_abuse"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        if event.security_context.source_trust.lower() in {"trusted", "verified", "sanitized", "clean"}:
            return []

        tool_name = event.payload.tool.name
        resources = derive_resources(event)
        intents = agent_abuse_intents(_agent_abuse_text(event, resources), policies)
        high_confidence = bool(intents) and _is_agent_abuse_action_surface(event.payload, resources)
        if high_confidence and _is_p103_owned_exec_abuse(event.payload, policies):
            return []
        if high_confidence:
            result = apply_rule_override(
                DetectionResult(
                    decision="deny",
                    risk_score=90,
                    category="agent_abuse",
                    rule_hit=RuleHit(
                        rule_id=self.rule_id,
                        rule_name="High-Confidence Agent Abuse",
                        severity="high",
                        evidence=[
                            f"tool={tool_name}",
                            f"source_trust={event.security_context.source_trust}",
                            "task_authorized=ignored_high_confidence",
                            *[f"agent_abuse_intent={intent}" for intent in intents],
                            *_resource_evidence(resources),
                        ],
                    ),
                    reason="A high-confidence agent-abuse action was blocked before execution.",
                    severity="high",
                ),
                policies,
            )
            return [result] if result is not None else []

        if low_risk_observation_action_allowed(event, policies):
            return []
        if not _is_high_impact_tool(event.payload, resources):
            return []
        if task_allows_tool_action(event.security_context.user_task, tool_name, policies):
            return []

        evidence = [
            f"tool={tool_name}",
            f"source_trust={event.security_context.source_trust}",
            "task_authorized=false",
        ]
        if resources:
            resource = resources[0]
            evidence.extend(
                [
                    f"resource_operation={resource.operation}",
                    f"resource_target={resource.target}",
                    f"resource_direction={resource.direction}",
                ]
            )
        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=88,
                category="agent_abuse",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Unauthorized Agent Action",
                    severity="high",
                    evidence=evidence,
                ),
                reason="An untrusted instruction attempted a high-impact action not authorized by the user task.",
                severity="high",
            ),
            policies,
        )
        return [result] if result is not None else []


def _is_high_impact_tool(payload: ToolCallPayload, resources: list[Any] | None = None) -> bool:
    tool_name = payload.tool.name
    if tool_name in {"write_file", "memory_write"} or is_exec_like_tool(payload.tool):
        return True
    resources = resources if resources is not None else payload.derived_resources
    return any(
        resource.operation.lower() in {"delete", "execute", "patch", "put", "write", "submit", "publish", "restore"}
        or resource.direction.lower() == "persistent"
        for resource in resources
    )


def _is_agent_abuse_action_surface(payload: ToolCallPayload, resources: list[Any]) -> bool:
    if payload.tool.name in {"call_api", "send_email", "write_file", "browser_input", "browser_click", "memory_write"}:
        return True
    if is_exec_like_tool(payload.tool):
        return True
    return any(
        str(resource.operation).lower()
        in {"click", "delete", "execute", "input", "patch", "post", "publish", "put", "restore", "send", "submit", "write"}
        or str(resource.direction).lower() in {"outbound", "persistent"}
        for resource in resources
    )


def _is_p103_owned_exec_abuse(payload: ToolCallPayload, policies: PolicyBundle) -> bool:
    if is_rule_disabled("P103_code_execution_abuse", policies):
        return False
    if not is_exec_like_tool(payload.tool):
        return False
    command = tool_argument_text(payload.arguments, "command", "cmd", "code")
    return has_dangerous_command_text(command, policies)


def _agent_abuse_text(event: GuardEvent, resources: list[Any]) -> str:
    payload = event.payload
    if not isinstance(payload, ToolCallPayload):
        return ""
    document = {
        "tool": {
            "name": payload.tool.name,
            "category": payload.tool.category,
            "kind": payload.tool.kind,
            "input_kind": payload.tool.input_kind,
        },
        "arguments": payload.arguments,
        "metadata": event.metadata,
        "security_metadata": event.security_context.metadata,
        "resources": [
            {
                "resource_type": getattr(resource, "resource_type", ""),
                "operation": getattr(resource, "operation", ""),
                "target": getattr(resource, "target", ""),
                "direction": getattr(resource, "direction", ""),
                "data_classification": getattr(resource, "data_classification", None),
            }
            for resource in resources
        ],
    }
    try:
        return json.dumps(document, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(document)


def _resource_evidence(resources: list[Any]) -> list[str]:
    if not resources:
        return []
    resource = resources[0]
    return [
        f"resource_operation={getattr(resource, 'operation', '')}",
        f"resource_target={getattr(resource, 'target', '')}",
        f"resource_direction={getattr(resource, 'direction', '')}",
    ]
