"""Configuration audit service."""

from __future__ import annotations

from agentguard_core import ConfigAuditEvent, ConfigAuditResult, evaluate_config_audit

from guard_api.storage.base import ControlPlaneStore

from .audit import AuditService
from .evidence import _config_audit_event


class ConfigAuditService:
    def __init__(
        self, *, store: ControlPlaneStore, audit_service: AuditService | None = None
    ) -> None:
        self.store = store
        self.audit_service = audit_service or AuditService(store=store)

    def evaluate(self, event: ConfigAuditEvent) -> ConfigAuditResult:
        result = evaluate_config_audit(event)
        for finding in result.findings:
            self.store.add_config_audit_finding(event, finding)
        self.audit_service.submit(_config_audit_event(event, result))
        return result
