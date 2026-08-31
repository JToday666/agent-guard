"""Guard API service layer."""

from .approval import ApprovalService
from .audit import AuditService
from .audit_checkpoint import AuditCheckpointService
from .audit_window import AuditWindowRequestError, AuditWindowService
from .config_audit import ConfigAuditService
from .competition import (
    CriticalDecisionEvidenceError,
    FrozenCompetitionActivation,
    load_frozen_competition_activation,
)
from .context_builder import ContextBuilderService
from .context_manifest import (
    ContextManifestAuditRecord,
    ContextManifestBudgetDroppedRef,
    ContextManifestEnvelope,
    ContextManifestPrepared,
    prepare_context_manifest,
)
from .ct_projection import CtProjectionService
from .evaluation import EvaluationService
from .evidence import EventDescription, build_audit_event, describe_guard_event
from .memory import MemoryGuardService
from .metrics import MetricService
from .policy import PolicyService, PolicyValidationError
from .product_activation import (
    FrozenProductActivation,
    ProductActivePreSelectorFuse,
    ProductRuntimeObservationReconciliation,
    load_frozen_product_activation,
    reconcile_product_runtime_observations,
)
from .provenance import ProvenanceWriter
from .runtime_binding import (
    ResolvedRuntimeBinding,
    RuntimeBindingResolutionError,
    RuntimeBindingResolver,
)
from .task_ingress import TaskIngressService
from .trace import TraceService
from .v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
    V21PhaseBOutcome,
    V21PipelineMaterials,
    V21PipelineService,
)
from .v21_shadow import V21ShadowService

__all__ = [
    "ApprovalService",
    "AuditService",
    "AuditCheckpointService",
    "AuditWindowRequestError",
    "AuditWindowService",
    "ConfigAuditService",
    "CriticalDecisionEvidenceError",
    "FrozenCompetitionActivation",
    "ContextBuilderService",
    "ContextManifestAuditRecord",
    "ContextManifestBudgetDroppedRef",
    "ContextManifestEnvelope",
    "ContextManifestPrepared",
    "CtProjectionService",
    "EvaluationService",
    "EventDescription",
    "MemoryGuardService",
    "MetricService",
    "PolicyService",
    "PolicyValidationError",
    "FrozenProductActivation",
    "ProductActivePreSelectorFuse",
    "ProductRuntimeObservationReconciliation",
    "ProvenanceWriter",
    "ResolvedRuntimeBinding",
    "RuntimeBindingResolutionError",
    "RuntimeBindingResolver",
    "TaskIngressService",
    "TraceService",
    "V21PhaseBOutcome",
    "V21OfficialEvaluationUnavailableError",
    "V21PipelineMaterials",
    "V21PipelineService",
    "V21ShadowService",
    "build_audit_event",
    "describe_guard_event",
    "prepare_context_manifest",
    "load_frozen_competition_activation",
    "load_frozen_product_activation",
    "reconcile_product_runtime_observations",
]
