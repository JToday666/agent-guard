"""Configuration audit evaluator."""

from __future__ import annotations

from .models import ConfigAuditEvent, ConfigAuditResult


def evaluate_config_audit(event: ConfigAuditEvent) -> ConfigAuditResult:
    blocking = [finding for finding in event.findings if finding.severity in {"high", "critical"}]
    if blocking:
        return ConfigAuditResult(
            decision="block",
            findings=event.findings,
            reason="Configuration audit found high or critical risk findings.",
        )
    return ConfigAuditResult(
        decision="allow",
        findings=event.findings,
        reason="Configuration audit did not find blocking findings.",
    )
