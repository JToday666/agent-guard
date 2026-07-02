"""Agent abuse detectors for unauthorized high-impact actions."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload, derive_resources, is_exec_like_tool
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
        if event.security_context.source_trust.lower() != "untrusted":
            return []
        if low_risk_observation_action_allowed(event, policies):
            return []

        tool_name = event.payload.tool.name
        if not _is_high_impact_tool(event.payload):
            return []
        if task_allows_tool_action(event.security_context.user_task, tool_name, policies):
            return []

        resources = derive_resources(event)
        evidence = [
            f"tool={tool_name}",
            "source_trust=untrusted",
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


def _is_high_impact_tool(payload: ToolCallPayload) -> bool:
    tool_name = payload.tool.name
    if tool_name in {"write_file", "memory_write"} or is_exec_like_tool(payload.tool):
        return True
    return any(
        resource.operation.lower() in {"delete", "execute", "patch", "put", "write"}
        or resource.direction.lower() == "persistent"
        for resource in payload.derived_resources
    )
