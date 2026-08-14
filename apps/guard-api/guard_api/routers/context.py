"""Dependencies shared by Guard API route registration."""

from __future__ import annotations

from dataclasses import dataclass

from guard_api.auth import CapabilityAuthService
from guard_api.services import (
    ApprovalService,
    AuditService,
    AuditWindowService,
    ConfigAuditService,
    EvaluationService,
    MemoryGuardService,
    MetricService,
    PolicyService,
    TaskIngressService,
    TraceService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ControlPlaneStore


@dataclass(frozen=True, slots=True)
class ApiContext:
    settings: GuardApiSettings
    store: ControlPlaneStore
    auth: CapabilityAuthService
    audit_service: AuditService
    audit_window_service: AuditWindowService
    config_audit_service: ConfigAuditService
    memory_guard_service: MemoryGuardService
    approval_service: ApprovalService
    metric_service: MetricService
    trace_service: TraceService
    policy_service: PolicyService
    evaluation_service: EvaluationService
    task_ingress_service: TaskIngressService
