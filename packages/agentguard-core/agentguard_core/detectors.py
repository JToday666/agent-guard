"""P0 deterministic detectors for the formal Core."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .models import DerivedResource, RuleHit, ToolCallEvent


@dataclass(frozen=True, slots=True)
class DetectionResult:
    decision: str
    risk_score: int
    rule_hit: RuleHit
    reason: str


class Detector:
    def evaluate(self, event: ToolCallEvent) -> list[DetectionResult]:
        raise NotImplementedError


class SensitiveResourceDetector(Detector):
    rule_id = "P001_sensitive_file_access"

    def evaluate(self, event: ToolCallEvent) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for resource in derive_resources(event):
            target = resource.target
            lowered = target.lower()
            markers = [
                ".env",
                "token",
                "secret",
                "private",
                "credential",
                "id_rsa",
                "password",
                "payment_details",
                "tacacs",
                "business_plan",
                "ssh_access",
            ]
            if any(marker in lowered for marker in markers):
                results.append(
                    DetectionResult(
                        decision="deny",
                        risk_score=95,
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Sensitive Resource Access",
                            severity="critical",
                            evidence=[f"target={target}"],
                        ),
                        reason="The tool call targets a sensitive local resource.",
                    )
                )
        return results


class OutboundDetector(Detector):
    def evaluate(self, event: ToolCallEvent) -> list[DetectionResult]:
        if event.tool.name == "send_email":
            target = str(event.arguments.get("to") or "")
            if not _is_allowed_recipient(target):
                return [
                    DetectionResult(
                        decision="ask",
                        risk_score=62,
                        rule_hit=RuleHit(
                            rule_id="P005_external_send",
                            rule_name="External Send Review",
                            severity="medium",
                            evidence=[f"recipient={target or 'unknown'}"],
                        ),
                        reason="The tool call sends data to a non-local or review recipient and requires approval.",
                    )
                ]

        if event.tool.name == "call_api":
            target = str(event.arguments.get("url") or "")
            if _is_collection_endpoint(target):
                return [
                    DetectionResult(
                        decision="ask",
                        risk_score=70,
                        rule_hit=RuleHit(
                            rule_id="P006_outbound_api_review",
                            rule_name="Outbound API Review",
                            severity="high",
                            evidence=[f"url={target}"],
                        ),
                        reason="The tool call posts data to a collection endpoint and requires approval.",
                    )
                ]
        return []


class TaskMismatchDetector(Detector):
    def evaluate(self, event: ToolCallEvent) -> list[DetectionResult]:
        source_trust = event.security_context.source_trust.lower()
        if source_trust != "untrusted":
            return []
        user_task = event.security_context.user_task.lower()
        tool_name = event.tool.name
        if tool_name in {"send_email", "call_api", "read_file", "write_file", "memory_write", "code_exec"}:
            if tool_name not in user_task and _verb_for_tool(tool_name) not in user_task:
                return [
                    DetectionResult(
                        decision="ask",
                        risk_score=45,
                        rule_hit=RuleHit(
                            rule_id="P004_task_mismatch",
                            rule_name="Task Mismatch",
                            severity="medium",
                            evidence=[f"tool={tool_name}", "source_trust=untrusted"],
                        ),
                        reason="The tool action is not clearly aligned with the current user task.",
                    )
                ]
        return []


def derive_resources(event: ToolCallEvent) -> list[DerivedResource]:
    if event.derived_resources:
        return event.derived_resources
    tool = event.tool.name
    args: dict[str, Any] = event.arguments
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


def _is_allowed_recipient(recipient: str) -> bool:
    lowered = recipient.lower()
    return lowered.endswith("@agentguard.local")


def _is_collection_endpoint(url: str) -> bool:
    lowered = url.lower()
    parsed = urlparse(lowered)
    if parsed.hostname in {"127.0.0.1", "localhost"} and parsed.path == "/status":
        return False
    return any(marker in lowered for marker in ("/collect/", "upload", "exfil", "webhook"))


def _verb_for_tool(tool_name: str) -> str:
    return {
        "read_file": "read",
        "write_file": "write",
        "send_email": "email",
        "call_api": "api",
        "memory_write": "memory",
        "code_exec": "execute",
    }.get(tool_name, tool_name)
