"""File and data exfiltration detectors."""

from __future__ import annotations

import json
from typing import Any

from ..decisions import DetectionResult, RuleHit
from ..events import (
    DerivedResource,
    GuardEvent,
    MessageSendPayload,
    ToolCallPayload,
    derive_resources,
)
from ..matchers import contains_any, has_credential_exposure_text, has_sensitive_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled
from .outbound import is_allowed_api_target, is_allowed_recipient


class FileExfiltrationDetector(Detector):
    rule_id = "P107_file_exfiltration"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if isinstance(event.payload, MessageSendPayload):
            return self._evaluate_message(event, policies)
        if isinstance(event.payload, ToolCallPayload):
            return self._evaluate_tool(event, policies)
        return []

    def _evaluate_message(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, MessageSendPayload):
            return []
        if is_allowed_recipient(payload.recipient, policies):
            return []
        sensitive = (
            any(
                _resource_is_sensitive(resource)
                for resource in payload.derived_resources
            )
            or payload.contains_sensitive_data
            or _text_contains_exfiltrated_data(payload.content_preview, policies)
        )
        return self._deny_if_sensitive_outbound(
            policies,
            sensitive=sensitive,
            target=payload.recipient,
            evidence=[
                f"recipient={payload.recipient}",
                f"contains_sensitive_data={payload.contains_sensitive_data}",
                f"sensitive_text_match={_text_contains_exfiltrated_data(payload.content_preview, policies)}",
            ],
        )

    def _evaluate_tool(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, ToolCallPayload):
            return []
        resources = derive_resources(event)
        tool_name = payload.tool.name

        if tool_name == "write_file":
            target = str(
                payload.arguments.get("path") or _first_resource_target(resources) or ""
            )
            content = _argument_text(
                payload.arguments, "content", "body", "text", "data"
            )
            sink_target = _sink_target_indicates_exfiltration(target, policies)
            sensitive = _text_contains_exfiltrated_data(content, policies)
            return self._deny_if_sensitive_outbound(
                policies,
                sensitive=sensitive,
                target=target,
                evidence=[
                    f"tool={tool_name}",
                    f"resource_target={target}",
                    "sink=write_file",
                    f"exfiltration_sink_target={sink_target}",
                    f"sensitive_text_match={_text_contains_exfiltrated_data(content, policies)}",
                ],
            )

        if tool_name == "browser_input":
            if event.security_context.source_trust.lower() in {
                "trusted",
                "verified",
                "sanitized",
                "clean",
            }:
                return []
            value = _argument_text(
                payload.arguments, "value", "text", "content", "body"
            )
            target = str(
                payload.arguments.get("selector")
                or _first_resource_target(resources)
                or "browser"
            )
            return self._deny_if_sensitive_outbound(
                policies,
                sensitive=_text_contains_exfiltrated_data(value, policies),
                target=target,
                evidence=[
                    f"tool={tool_name}",
                    f"resource_target={target}",
                    "sink=browser_input",
                    f"sensitive_text_match={_text_contains_exfiltrated_data(value, policies)}",
                ],
            )

        outbound = [
            resource
            for resource in resources
            if resource.direction.lower() == "outbound"
            or resource.operation.lower() in {"send", "post", "put", "patch"}
        ]
        if not outbound:
            return []
        target = outbound[0].target
        if tool_name == "send_email" and is_allowed_recipient(
            str(payload.arguments.get("to") or ""), policies
        ):
            return []
        if tool_name == "call_api" and is_allowed_api_target(target, policies):
            return []
        argument_text = _payload_text(payload.arguments)
        sensitive = any(
            _resource_is_sensitive(resource)
            for resource in [*outbound, *payload.derived_resources]
        ) or (_text_contains_exfiltrated_data(argument_text, policies))
        return self._deny_if_sensitive_outbound(
            policies,
            sensitive=sensitive,
            target=target,
            evidence=[
                f"tool={tool_name}",
                f"resource_target={target}",
                f"sensitive_resource={sensitive}",
                f"sensitive_text_match={_text_contains_exfiltrated_data(argument_text, policies)}",
            ],
        )

    def _deny_if_sensitive_outbound(
        self,
        policies: PolicyBundle,
        *,
        sensitive: bool,
        target: str,
        evidence: list[str],
    ) -> list[DetectionResult]:
        if not sensitive:
            return []
        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=90,
                category="file_exfiltration",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Sensitive Data Externalization",
                    severity="critical",
                    evidence=evidence,
                ),
                reason="Sensitive data was about to be sent to an external sink.",
                severity="critical",
            ),
            policies,
        )
        return [result] if result is not None else []


SENSITIVE_CLASSIFICATIONS = {
    "sensitive",
    "secret",
    "confidential",
    "credential",
    "restricted",
    "persistent_memory",
}


def _resource_is_sensitive(resource: DerivedResource) -> bool:
    return (resource.data_classification or "").lower() in SENSITIVE_CLASSIFICATIONS


def _text_contains_exfiltrated_data(text: str, policies: PolicyBundle) -> bool:
    if not text:
        return False
    return (
        has_sensitive_text(text, policies)
        or has_credential_exposure_text(text, policies)
        or _text_mentions_sensitive_resource(text, policies)
    )


def _text_mentions_sensitive_resource(text: str, policies: PolicyBundle) -> bool:
    markers = [
        marker
        for marker in policies.sensitive_resource_markers
        if marker.lower() != "private"
    ]
    return contains_any(text, markers)


def _sink_target_indicates_exfiltration(target: str, policies: PolicyBundle) -> bool:
    lowered = target.lower()
    return contains_any(lowered, policies.file_exfiltration_sink_markers) or any(
        marker in lowered
        for marker in ("leaked", "exfil", "incident evidence", "raw_credentials")
    )


def _payload_text(arguments: dict[str, Any]) -> str:
    return _preview(arguments)


def _argument_text(arguments: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if key in arguments:
            return _preview(arguments[key])
    return ""


def _first_resource_target(resources: list[DerivedResource]) -> str | None:
    for resource in resources:
        if resource.target:
            return resource.target
    return None


def _preview(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)
