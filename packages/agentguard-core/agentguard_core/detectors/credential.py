"""Credential exposure detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import (
    GuardEvent,
    ModelCallPayload,
    ToolCallPayload,
    ToolResultPayload,
    is_exec_like_tool,
    tool_argument_text,
)
from ..matchers import (
    has_credential_command_text,
    has_credential_exposure_text,
    looks_like_sensitive_model_leak,
)
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class CredentialExposureDetector(Detector):
    rule_id = "P106_credential_exposure"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []

        evidence = self._evidence(event, policies)
        if not evidence:
            return []

        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=94,
                category="credential_exposure",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Credential Exposure",
                    severity="critical",
                    evidence=evidence,
                ),
                reason="The event attempts to read or disclose credential material.",
                severity="critical",
            ),
            policies,
        )
        return [result] if result is not None else []

    def _evidence(self, event: GuardEvent, policies: PolicyBundle) -> list[str]:
        payload = event.payload
        if isinstance(payload, ToolCallPayload) and is_exec_like_tool(payload.tool):
            command = tool_argument_text(payload.arguments, "command", "cmd", "code")
            if has_credential_command_text(command, policies):
                return [
                    "surface=tool_call",
                    f"tool={payload.tool.name}",
                    "credential_command=true",
                ]
            return []

        if isinstance(payload, ToolResultPayload):
            if payload.sanitized or not (
                payload.will_enter_context or payload.will_persist
            ):
                return []
            if has_credential_exposure_text(payload.result.content_preview, policies):
                return [
                    "surface=tool_result",
                    f"tool={payload.tool.name}",
                    f"tool_call_id={payload.tool.call_id}",
                ]
            return []

        if isinstance(payload, ModelCallPayload):
            if payload.phase != "output" or payload.sanitized:
                return []
            if looks_like_sensitive_model_leak(payload, policies):
                return []
            if has_credential_exposure_text(payload.content_preview, policies):
                return ["surface=model_output", "credential_value=true"]
            return []

        return []
