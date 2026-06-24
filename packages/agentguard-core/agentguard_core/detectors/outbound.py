"""Outbound DLP and collection endpoint detectors."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, MessageSendPayload, ToolCallPayload
from ..matchers import has_sensitive_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class OutboundDetector(Detector):
    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if isinstance(event.payload, MessageSendPayload):
            return self._evaluate_message_send(event.payload, policies)
        if not isinstance(event.payload, ToolCallPayload):
            return []

        tool_name = event.payload.tool.name
        if tool_name == "send_email":
            rule_id = "P005_external_send"
            if is_rule_disabled(rule_id, policies):
                return []
            target = str(event.payload.arguments.get("to") or "")
            if not is_allowed_recipient(target, policies):
                has_sensitive_content = tool_email_has_sensitive_text(event.payload.arguments, policies)
                result = apply_rule_override(
                    DetectionResult(
                        decision="deny" if has_sensitive_content else "ask",
                        risk_score=82 if has_sensitive_content else 62,
                        category="outbound_dlp",
                        rule_hit=RuleHit(
                            rule_id=rule_id,
                            rule_name="External Send Review",
                            severity="high" if has_sensitive_content else "medium",
                            evidence=[
                                f"recipient={target or 'unknown'}",
                                f"sensitive_text_match={has_sensitive_content}",
                            ],
                        ),
                        reason=(
                            "The tool call sends sensitive text to an external recipient."
                            if has_sensitive_content
                            else "The tool call sends data to a non-local or review recipient and requires approval."
                        ),
                        approval_resource=None if has_sensitive_content else target,
                        severity="high" if has_sensitive_content else "medium",
                    ),
                    policies,
                )
                return [result] if result is not None else []

        if tool_name == "call_api":
            rule_id = "P006_outbound_api_review"
            if is_rule_disabled(rule_id, policies):
                return []
            target = str(event.payload.arguments.get("url") or "")
            if is_collection_endpoint(target, policies):
                result = apply_rule_override(
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

    def _evaluate_message_send(
        self,
        payload: MessageSendPayload,
        policies: PolicyBundle,
    ) -> list[DetectionResult]:
        rule_id = "P005_external_send"
        if is_rule_disabled(rule_id, policies):
            return []
        target = payload.recipient
        if is_allowed_recipient(target, policies):
            return []
        has_sensitive_content = payload.contains_sensitive_data or has_sensitive_text(
            payload.content_preview, policies
        )
        decision = "deny" if has_sensitive_content else "ask"
        result = apply_rule_override(
            DetectionResult(
                decision=decision,
                risk_score=82 if has_sensitive_content else 62,
                category="outbound_dlp",
                rule_hit=RuleHit(
                    rule_id=rule_id,
                    rule_name="External Send Review",
                    severity="high" if has_sensitive_content else "medium",
                    evidence=[
                        f"recipient={target or 'unknown'}",
                        f"channel={payload.channel}",
                        f"contains_sensitive_data={payload.contains_sensitive_data}",
                        f"sensitive_text_match={has_sensitive_text(payload.content_preview, policies)}",
                    ],
                ),
                reason=(
                    "The outbound message sends sensitive content to an external recipient."
                    if has_sensitive_content
                    else "The outbound message targets an external recipient and requires approval."
                ),
                approval_resource=None if has_sensitive_content else target,
                severity="high" if has_sensitive_content else "medium",
            ),
            policies,
        )
        return [result] if result is not None else []


def is_allowed_recipient(recipient: str, policies: PolicyBundle) -> bool:
    lowered = recipient.lower()
    if "@" not in lowered:
        return False
    domain = lowered.rsplit("@", 1)[-1]
    return domain in {item.lower() for item in policies.allowed_email_domains}


def is_collection_endpoint(url: str, policies: PolicyBundle) -> bool:
    lowered = url.lower()
    parsed = urlparse(lowered)
    allowed_hosts = {item.lower() for item in policies.allowed_api_hosts}
    allowed_paths = {item.lower() for item in policies.allowed_api_paths}
    if parsed.hostname in allowed_hosts and parsed.path.lower() in allowed_paths:
        return False
    return any(marker.lower() in lowered for marker in policies.collection_path_markers)


def tool_email_has_sensitive_text(arguments: dict[str, Any], policies: PolicyBundle) -> bool:
    return any(
        has_sensitive_text(str(arguments.get(key) or ""), policies)
        for key in ("subject", "body", "content", "text")
    )
