"""File and data exfiltration detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, MessageSendPayload, ToolCallPayload, derive_resources
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled
from .outbound import is_allowed_recipient


class FileExfiltrationDetector(Detector):
    rule_id = "P107_file_exfiltration"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if isinstance(event.payload, MessageSendPayload):
            return self._evaluate_message(event, policies)
        if isinstance(event.payload, ToolCallPayload):
            return self._evaluate_tool(event, policies)
        return []

    def _evaluate_message(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, MessageSendPayload):
            return []
        if is_allowed_recipient(payload.recipient, policies):
            return []
        sensitive = any(
            (resource.data_classification or "").lower() == "sensitive"
            for resource in payload.derived_resources
        )
        return self._deny_if_sensitive_outbound(
            policies,
            sensitive=sensitive,
            target=payload.recipient,
            evidence=[
                f"recipient={payload.recipient}",
                f"contains_sensitive_data={payload.contains_sensitive_data}",
            ],
        )

    def _evaluate_tool(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        payload = event.payload
        if not isinstance(payload, ToolCallPayload):
            return []
        resources = derive_resources(event)
        outbound = [
            resource
            for resource in resources
            if resource.direction.lower() == "outbound"
            or resource.operation.lower() in {"send", "post", "put", "patch"}
        ]
        if not outbound:
            return []
        target = outbound[0].target
        if payload.tool.name == "send_email" and is_allowed_recipient(str(payload.arguments.get("to") or ""), policies):
            return []
        sensitive = any(
            (resource.data_classification or "").lower() == "sensitive"
            for resource in [*outbound, *payload.derived_resources]
        )
        return self._deny_if_sensitive_outbound(
            policies,
            sensitive=sensitive,
            target=target,
            evidence=[
                f"tool={payload.tool.name}",
                f"resource_target={target}",
                f"sensitive_resource={sensitive}",
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
