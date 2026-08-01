"""MCP tool hijacking detectors."""

from __future__ import annotations

import json
from typing import Any

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload
from ..matchers import contains_any, normalize_match_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class McpToolHijackingDetector(Detector):
    rule_id = "P109_mcp_tool_hijacking"

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle
    ) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        if event.payload.tool.name != "mcp_call":
            return []

        args = event.payload.arguments
        hijacking = (
            args.get("hijacking") if isinstance(args.get("hijacking"), dict) else {}
        )
        inner_args = (
            args.get("arguments") if isinstance(args.get("arguments"), dict) else {}
        )
        evidence: list[str] = [
            f"server={args.get('server') or 'unknown'}",
            f"tool={args.get('tool') or 'unknown'}",
        ]
        high_confidence = False

        if hijacking:
            mode = str(
                hijacking.get("mode") or hijacking.get("hijacking_mode") or "unknown"
            )
            evidence.append(f"hijacking_mode={mode}")
            if (
                hijacking.get("argument_mutation")
                or hijacking.get("required_dependency")
                or hijacking.get("trigger")
                or hijacking.get("hijacked_tool")
                or hijacking.get("hijacked_server")
            ):
                high_confidence = True
                evidence.append("hijacking_metadata_risk=true")
            if hijacking.get("hijacked_tool"):
                evidence.append(f"hijacked_tool={hijacking.get('hijacked_tool')}")
            if hijacking.get("required_dependency"):
                evidence.append(
                    f"required_dependency={hijacking.get('required_dependency')}"
                )

        serialized_args = json.dumps(inner_args, ensure_ascii=False, sort_keys=True)
        if contains_any(serialized_args, policies.mcp_hijack_argument_markers):
            high_confidence = True
            evidence.append("mcp_hijack_argument_marker=true")
        if (
            event.security_context.source_trust.lower() == "untrusted"
            and _contains_callback_url(inner_args)
        ):
            high_confidence = True
            evidence.append("collection_callback=true")

        descriptor_evidence = _descriptor_risk_evidence(args)
        if descriptor_evidence:
            high_confidence = True
            evidence.extend(descriptor_evidence)
        permission_evidence = _permission_risk_evidence(
            args, source_trust=event.security_context.source_trust
        )
        if permission_evidence:
            high_confidence = True
            evidence.extend(permission_evidence)

        if not high_confidence:
            return []

        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=90,
                category="tool_hijack",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="MCP Tool Hijacking",
                    severity="critical",
                    evidence=evidence,
                ),
                reason="High-confidence MCP tool hijacking was blocked at the MCP call boundary.",
                severity="critical",
            ),
            policies,
        )
        return [result] if result is not None else []


def _contains_callback_url(arguments: Any) -> bool:
    if isinstance(arguments, list):
        return any(_contains_callback_url(item) for item in arguments)
    if not isinstance(arguments, dict):
        return False
    for key, value in arguments.items():
        key_text = normalize_match_text(str(key))
        compact_key = "".join(ch for ch in key_text if ch.isalnum())
        value_text = normalize_match_text(str(value))
        if "callback" in key_text and (
            "/collect/" in value_text
            or "http://" in value_text
            or "https://" in value_text
        ):
            return True
        if _is_external_sink_key(key_text, compact_key) and (
            "http://" in value_text or "https://" in value_text
        ):
            return True
        if _contains_callback_url(value):
            return True
    return False


def _is_external_sink_key(key_text: str, compact_key: str) -> bool:
    if key_text in {
        "webhook_url",
        "redirect_uri",
        "upload_url",
        "forward_to",
        "send_to",
        "external_url",
    }:
        return True
    return compact_key in {
        "webhookurl",
        "redirecturi",
        "uploadurl",
        "forwardto",
        "sendto",
        "externalurl",
    } or (
        compact_key.endswith("url")
        and any(
            marker in compact_key
            for marker in ("webhook", "callback", "upload", "external")
        )
    )


def _descriptor_risk_evidence(arguments: dict[str, Any]) -> list[str]:
    descriptor_diff = arguments.get("descriptor_diff")
    if not isinstance(descriptor_diff, list):
        return []
    risky_items: list[str] = []
    for item in descriptor_diff:
        if not isinstance(item, dict):
            continue
        risk = normalize_match_text(str(item.get("risk") or ""))
        field = normalize_match_text(str(item.get("field") or ""))
        poisoned = json.dumps(item.get("poisoned"), ensure_ascii=False, sort_keys=True)
        high_risk_field = risk in {
            "added_tool",
            "permission_change",
            "parameter_bias",
            "descriptor_poisoning",
        } or any(
            marker in field
            for marker in (
                "permission",
                "input_schema",
                "parameter",
                "description",
                "example",
            )
        )
        sink_added = _contains_callback_url({"value": poisoned}) or contains_any(
            poisoned,
            [
                "callback_url",
                "webhook_url",
                "redirect_uri",
                "upload_url",
                "/collect/",
                "exfil",
            ],
        )
        if high_risk_field or sink_added:
            risky_items.append(
                str(item.get("field") or item.get("risk") or "descriptor_change")
            )
    if not risky_items:
        return []
    return [
        "descriptor_diff_risk=true",
        f"descriptor_diff_fields={','.join(risky_items[:5])}",
    ]


def _permission_risk_evidence(
    arguments: dict[str, Any], *, source_trust: str
) -> list[str]:
    permissions = _permissions_from(arguments)
    baseline = _permissions_from(
        arguments.get("clean_descriptor")
    ) or _permissions_from(arguments.get("expected_descriptor"))
    if baseline:
        added = sorted(set(permissions) - set(baseline))
        risky_added = [
            permission for permission in added if _is_high_risk_permission(permission)
        ]
        if risky_added:
            return [
                "permission_escalation=true",
                f"added_permissions={','.join(risky_added[:5])}",
            ]
    if source_trust.lower() == "untrusted":
        risky = sorted(
            permission
            for permission in permissions
            if _is_high_risk_permission(permission)
        )
        if risky:
            return [
                "untrusted_high_risk_permission=true",
                f"permissions={','.join(risky[:5])}",
            ]
    return []


def _permissions_from(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    permissions = (
        value.get("permissions")
        or value.get("permission")
        or value.get("required_permissions")
    )
    if not permissions:
        descriptor = value.get("descriptor")
        if not isinstance(descriptor, dict):
            descriptor = {}
        permissions = descriptor.get("permissions") or descriptor.get(
            "required_permissions"
        )
    if not permissions:
        descriptor = value.get("poisoned_descriptor")
        if not isinstance(descriptor, dict):
            descriptor = {}
        permissions = descriptor.get("permissions") or descriptor.get(
            "required_permissions"
        )
    if isinstance(permissions, str):
        permissions = [permissions]
    if not isinstance(permissions, list):
        return []
    return [
        normalize_match_text(str(permission))
        for permission in permissions
        if str(permission).strip()
    ]


def _is_high_risk_permission(permission: str) -> bool:
    return any(
        marker in permission
        for marker in (
            ":write",
            ":send",
            ":admin",
            "collection-write",
            "identity",
            "profile",
            "account",
            "credential",
            "secret",
        )
    )
