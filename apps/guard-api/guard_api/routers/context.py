"""Dependencies shared by Guard API route registration."""

from __future__ import annotations

from dataclasses import dataclass

from guard_api.auth import CapabilityAuthService
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import ApprovalExecutionLeaseService
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
    V21ShadowService,
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
    approval_execution_lease_service: ApprovalExecutionLeaseService
    metric_service: MetricService
    trace_service: TraceService
    policy_service: PolicyService
    evaluation_service: EvaluationService
    task_ingress_service: TaskIngressService
    # V21-08：安全状态门面（snapshot 只读入口）与 shadow 旁路编排器
    # （flag 默认关闭；不新增 HTTP 路由，仅供 T5 审计证据接线可达）。
    security_state_service: SecurityStateService
    v21_shadow_service: V21ShadowService
