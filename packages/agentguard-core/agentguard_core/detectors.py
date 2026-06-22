"""P0 deterministic detectors for the stateless Core."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlparse

from .models import DerivedResource, GuardEvent, PolicyBundle, RuleHit


@dataclass(frozen=True, slots=True)
class DetectionResult:
    decision: str
    risk_score: int
    category: str
    rule_hit: RuleHit
    reason: str
    approval_resource: str | None = None
    severity: str | None = None


class Detector:
    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        raise NotImplementedError


class SensitiveResourceDetector(Detector):
    rule_id = "P001_sensitive_file_access"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if _is_rule_disabled(self.rule_id, policies):
            return []
        results: list[DetectionResult] = []
        for resource in derive_resources(event):
            target = resource.target
            lowered = target.lower()
            markers = [marker.lower() for marker in policies.sensitive_resource_markers]
            if any(marker in lowered for marker in markers):
                result = _apply_rule_override(
                    DetectionResult(
                        decision="deny",
                        risk_score=95,
                        category="sensitive_file_access",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Sensitive Resource Access",
                            severity="critical",
                            evidence=[f"target={target}"],
                        ),
                        reason="The tool call targets a sensitive local resource.",
                        severity="critical",
                    ),
                    policies,
                )
                if result is not None:
                    results.append(result)
        return results


class ToolHijackDetector(Detector):
    rule_id = "P002_tool_identity_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if _is_rule_disabled(self.rule_id, policies):
            return []
        profile = _TOOL_PROFILES.get(event.payload.tool.name)
        if profile is None:
            return []
        tool = event.payload.tool
        category = (tool.category or "").lower()
        kind = (tool.kind or tool.name).lower()
        evidence: list[str] = []

        if category and category not in profile["categories"]:
            evidence.append(f"tool_category={category}")
        if kind and kind not in profile["kinds"]:
            evidence.append(f"tool_kind={kind}")

        allowed_directions = profile["directions"]
        allowed_operations = profile["operations"]
        for resource in derive_resources(event):
            direction = resource.direction.lower()
            operation = resource.operation.lower()
            if direction and direction not in allowed_directions:
                evidence.append(f"resource_direction={direction}")
            if operation and operation not in allowed_operations:
                evidence.append(f"resource_operation={operation}")

        if not evidence:
            return []

        result = _apply_rule_override(
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


class OutboundDetector(Detector):
    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        tool_name = event.payload.tool.name
        if tool_name == "send_email":
            rule_id = "P005_external_send"
            if _is_rule_disabled(rule_id, policies):
                return []
            target = str(event.payload.arguments.get("to") or "")
            if not _is_allowed_recipient(target, policies):
                result = _apply_rule_override(
                    DetectionResult(
                        decision="ask",
                        risk_score=62,
                        category="outbound_dlp",
                        rule_hit=RuleHit(
                            rule_id=rule_id,
                            rule_name="External Send Review",
                            severity="medium",
                            evidence=[f"recipient={target or 'unknown'}"],
                        ),
                        reason="The tool call sends data to a non-local or review recipient and requires approval.",
                        approval_resource=target,
                        severity="medium",
                    ),
                    policies,
                )
                return [result] if result is not None else []

        if tool_name == "call_api":
            rule_id = "P006_outbound_api_review"
            if _is_rule_disabled(rule_id, policies):
                return []
            target = str(event.payload.arguments.get("url") or "")
            if _is_collection_endpoint(target, policies):
                result = _apply_rule_override(
                    DetectionResult(
                        decision="ask",
                        risk_score=70,
                        category="outbound_dlp",
                        rule_hit=RuleHit(
                            rule_id=rule_id,
                            rule_name="Outbound API Review",
                            severity="high",
                            evidence=[f"url={target}"],
                        ),
                        reason="The tool call posts data to a collection endpoint and requires approval.",
                        approval_resource=target,
                        severity="high",
                    ),
                    policies,
                )
                return [result] if result is not None else []
        return []


class TaskMismatchDetector(Detector):
    rule_id = "P004_task_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if _is_rule_disabled(self.rule_id, policies):
            return []
        source_trust = event.security_context.source_trust.lower()
        if source_trust != "untrusted":
            return []
        user_task = event.security_context.user_task.lower()
        tool_name = event.payload.tool.name
        if tool_name in {"send_email", "call_api", "read_file", "write_file", "memory_write", "code_exec"}:
            if not any(alias in user_task for alias in _action_aliases(tool_name, policies)):
                result = _apply_rule_override(
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


def derive_resources(event: GuardEvent) -> list[DerivedResource]:
    if event.payload.derived_resources:
        return event.payload.derived_resources
    tool = event.payload.tool.name
    args: dict[str, Any] = event.payload.arguments
    if tool == "read_file":
        return [
            DerivedResource(
                resource_type="file",
                operation="read",
                target=str(args.get("path") or ""),
                data_classification=None,
                direction="local",
            )
        ]
    if tool == "write_file":
        return [
            DerivedResource(
                resource_type="file",
                operation="write",
                target=str(args.get("path") or ""),
                data_classification=None,
                direction="local",
            )
        ]
    if tool == "send_email":
        return [
            DerivedResource(
                resource_type="message",
                operation="send",
                target=str(args.get("to") or ""),
                data_classification=None,
                direction="outbound",
            )
        ]
    if tool == "call_api":
        return [
            DerivedResource(
                resource_type="api",
                operation=str(args.get("method") or "GET").upper(),
                target=str(args.get("url") or ""),
                data_classification=None,
                direction="outbound",
            )
        ]
    return []


_TOOL_PROFILES: dict[str, dict[str, set[str]]] = {
    "read_file": {
        "categories": {"tool", "file"},
        "kinds": {"read_file", "file_read"},
        "operations": {"read"},
        "directions": {"local"},
    },
    "write_file": {
        "categories": {"tool", "file"},
        "kinds": {"write_file", "file_write"},
        "operations": {"write"},
        "directions": {"local"},
    },
    "send_email": {
        "categories": {"tool", "message", "email"},
        "kinds": {"send_email", "email_send"},
        "operations": {"send"},
        "directions": {"outbound"},
    },
    "call_api": {
        "categories": {"tool", "api", "network"},
        "kinds": {"call_api", "api_call", "http_request"},
        "operations": {"get", "post", "put", "patch", "delete"},
        "directions": {"outbound"},
    },
}


def _is_allowed_recipient(recipient: str, policies: PolicyBundle) -> bool:
    lowered = recipient.lower()
    if "@" not in lowered:
        return False
    domain = lowered.rsplit("@", 1)[-1]
    return domain in {item.lower() for item in policies.allowed_email_domains}


def _is_collection_endpoint(url: str, policies: PolicyBundle) -> bool:
    lowered = url.lower()
    parsed = urlparse(lowered)
    allowed_hosts = {item.lower() for item in policies.allowed_api_hosts}
    allowed_paths = {item.lower() for item in policies.allowed_api_paths}
    if parsed.hostname in allowed_hosts and parsed.path.lower() in allowed_paths:
        return False
    return any(marker.lower() in lowered for marker in policies.collection_path_markers)


def _action_aliases(tool_name: str, policies: PolicyBundle) -> set[str]:
    aliases = {tool_name.lower(), _verb_for_tool(tool_name).lower()}
    aliases.update(alias.lower() for alias in policies.tool_action_aliases.get(tool_name, []))
    return aliases


def _verb_for_tool(tool_name: str) -> str:
    return {
        "read_file": "read",
        "write_file": "write",
        "send_email": "email",
        "call_api": "api",
        "memory_write": "memory",
        "code_exec": "execute",
    }.get(tool_name, tool_name)


def _is_rule_disabled(rule_id: str, policies: PolicyBundle) -> bool:
    return rule_id in set(policies.disabled_rules)


def _apply_rule_override(result: DetectionResult, policies: PolicyBundle) -> DetectionResult | None:
    if _is_rule_disabled(result.rule_hit.rule_id, policies):
        return None
    override = policies.rule_overrides.get(result.rule_hit.rule_id)
    if override is None:
        return result
    updates: dict[str, Any] = {}
    if override.decision is not None:
        updates["decision"] = override.decision
    if override.risk_score is not None:
        updates["risk_score"] = override.risk_score
    if override.severity is not None:
        updates["severity"] = override.severity
        updates["rule_hit"] = result.rule_hit.model_copy(update={"severity": override.severity})
    return replace(result, **updates) if updates else result
