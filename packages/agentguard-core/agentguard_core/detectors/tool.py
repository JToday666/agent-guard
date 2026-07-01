"""Tool identity and task alignment detectors."""

from __future__ import annotations

import re

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload, derive_resources, is_exec_like_tool
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class ToolHijackDetector(Detector):
    rule_id = "P002_tool_identity_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        profile = policies.tool_profiles.get(event.payload.tool.name)
        if profile is None:
            return []
        tool = event.payload.tool
        category = (tool.category or "").lower()
        kind = (tool.kind or tool.name).lower()
        evidence: list[str] = []

        profile_categories = {item.lower() for item in profile.categories}
        profile_kinds = {item.lower() for item in profile.kinds}
        profile_directions = {item.lower() for item in profile.directions}
        profile_operations = {item.lower() for item in profile.operations}

        if category and profile_categories and category not in profile_categories:
            evidence.append(f"tool_category={category}")
        if kind and profile_kinds and kind not in profile_kinds:
            evidence.append(f"tool_kind={kind}")

        for resource in derive_resources(event):
            direction = resource.direction.lower()
            operation = resource.operation.lower()
            if direction and profile_directions and direction not in profile_directions:
                evidence.append(f"resource_direction={direction}")
            if operation and profile_operations and operation not in profile_operations:
                evidence.append(f"resource_operation={operation}")

        if not evidence:
            return []

        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=88,
                category="tool_hijack",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Tool Identity Mismatch",
                    severity="high",
                    evidence=[f"tool={tool.name}", *evidence],
                ),
                reason="The tool identity or derived resource behavior conflicts with its built-in profile.",
                severity="high",
            ),
            policies,
        )
        return [result] if result is not None else []


class UnprofiledToolResourceDetector(Detector):
    rule_id = "P007_unprofiled_tool_resource_review"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        if event.payload.tool.name in policies.tool_profiles:
            return []

        risky_resources = [
            resource
            for resource in derive_resources(event)
            if resource_is_high_risk_for_unprofiled_tool(resource.direction, resource.operation)
        ]
        if not risky_resources:
            return []

        resource = risky_resources[0]
        result = apply_rule_override(
            DetectionResult(
                decision="ask",
                risk_score=58,
                category="unprofiled_tool_resource_review",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Unprofiled Tool Resource Review",
                    severity="medium",
                    evidence=[
                        f"tool={event.payload.tool.name}",
                        f"resource_direction={resource.direction}",
                        f"resource_operation={resource.operation}",
                        f"resource_target={resource.target}",
                    ],
                ),
                reason="An unprofiled tool targets a high-risk resource and requires approval.",
                approval_resource=resource.target,
                severity="medium",
            ),
            policies,
        )
        return [result] if result is not None else []


class TaskMismatchDetector(Detector):
    rule_id = "P004_task_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        source_trust = event.security_context.source_trust.lower()
        if source_trust != "untrusted":
            return []
        tool_name = event.payload.tool.name
        if tool_name in {"send_email", "call_api", "read_file", "write_file", "memory_write", "code_exec"} or is_exec_like_tool(
            event.payload.tool
        ):
            if not task_allows_tool_action(event.security_context.user_task, tool_name, policies):
                result = apply_rule_override(
                    DetectionResult(
                        decision="ask",
                        risk_score=45,
                        category="task_mismatch",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Task Mismatch",
                            severity="medium",
                            evidence=[f"tool={tool_name}", "source_trust=untrusted"],
                        ),
                        reason="The tool action is not clearly aligned with the current user task.",
                        severity="medium",
                    ),
                    policies,
                )
                return [result] if result is not None else []
        return []


def action_aliases(tool_name: str, policies: PolicyBundle) -> set[str]:
    aliases = {tool_name.lower(), verb_for_tool(tool_name).lower()}
    aliases.update(alias.lower() for alias in policies.tool_action_aliases.get(tool_name, []))
    return aliases


def task_allows_tool_action(user_task: str, tool_name: str, policies: PolicyBundle) -> bool:
    aliases = action_aliases(tool_name, policies)
    if task_negates_action(user_task, aliases):
        return False
    normalized = normalize_task_text(user_task)
    return any(alias in normalized for alias in aliases)


def task_negates_action(user_task: str, aliases: set[str]) -> bool:
    normalized = normalize_task_text(user_task)
    for alias in aliases:
        escaped = re.escape(alias)
        patterns = [
            rf"\bdo not {escaped}\b",
            rf"\bdon't {escaped}\b",
            rf"\bnever {escaped}\b",
            rf"\bnot {escaped}\b",
            rf"不要{escaped}",
            rf"不要 {escaped}",
            rf"禁止{escaped}",
            rf"禁止 {escaped}",
        ]
        if any(re.search(pattern, normalized) for pattern in patterns):
            return True
    return False


def normalize_task_text(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[\t\r\n]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def resource_is_high_risk_for_unprofiled_tool(direction: str, operation: str) -> bool:
    return direction.lower() in {"outbound", "persistent"} or operation.lower() in {
        "delete",
        "execute",
        "patch",
        "post",
        "put",
        "send",
        "write",
    }


def verb_for_tool(tool_name: str) -> str:
    if tool_name in {"code_exec", "exec", "shell", "command", "bash", "sh", "powershell", "terminal"}:
        return "execute"
    return {
        "read_file": "read",
        "write_file": "write",
        "send_email": "email",
        "call_api": "api",
        "memory_write": "memory",
    }.get(tool_name, tool_name)
