"""V2.1 security context scaffold (V21-04: State Projection/Snapshot).

纯新增模块组：OnlineSecurityState → SecuritySnapshot 的冻结模型与
确定性纯函数（Idempotent Projector、安全保持型驱逐、RequiredCheckPlan、
Coverage/gap localized degradation）。判定路径（``engine.py`` /
``decisions/*``）不引用本包；顶层 ``agentguard_core/__init__.py``
不在 V21-04 本期范围内改动。

冻结契约出处：01_F1字段与契约冻结.md §10-§19/§27/§29、
02_状态投影_Provenance_Authority.md、05_评测_性能_可信验收.md §12。
"""

from __future__ import annotations

from .coverage import (
    COVERAGE_DOMAINS,
    GapContext,
    RequiredHistoryWindow,
    compute_coverage,
    default_coverage_context,
    localize_gaps,
)
from .context import (
    ContextAssemblyPlan,
    ContextChunk,
    ContextCompartment,
    ContextTransformState,
    ContextTransformation,
    ContextTransformationAction,
    compute_context_chunk_digest,
    compute_context_plan_digest,
    context_chunk_digest_projection,
    context_plan_digest_projection,
)
from .delta import (
    SOURCE_RECORD_TYPES,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)
from .eviction import (
    CONTAINER_EVICTION_CLASS,
    EvictionClass,
    EvictionLimits,
    EvictionReport,
    apply_safe_eviction,
    is_benign_source,
    is_sticky_taint_summary,
)
from .facts import (
    BehaviorAggregate,
    CapabilityGrant,
    DeclassificationFact,
    ExecutionLease,
    FlowFact,
    GapRange,
    GrantConsumption,
    MemoryFact,
    RecentActionFact,
    RuntimeOutcomeFact,
    SourceFact,
    StateWatermarks,
    StickyTaintSummary,
    fact_digest,
    fact_digest_projection,
)
from .projector import (
    PROJECTOR_VERSION,
    ApplyOutcome,
    ApplyResult,
    CommittedRecord,
    ProjectionError,
    apply_delta,
    mark_state_dirty,
    project_committed_record,
    rebuild_state,
)
from .required_checks import (
    REQUIRED_CHECK_PLAN_VERSION,
    PolicyProfile,
    build_required_check_plan,
)
from .snapshot import SecuritySnapshot, build_snapshot, snapshot_digest_projection
from .state import (
    AppliedProjection,
    OnlineSecurityState,
    SequenceComparisonError,
    compare_sequence_refs,
    state_digest,
    state_digest_projection,
)

__all__ = [
    "ASSESSMENT_OVERLAY_COMPONENT_ID",
    "ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS",
    "ASSESSMENT_OVERLAY_VERSION",
    "CONTAINER_EVICTION_CLASS",
    "COVERAGE_DOMAINS",
    "ContextAssemblyPlan",
    "ContextChunk",
    "ContextCompartment",
    "ContextTransformState",
    "ContextTransformation",
    "ContextTransformationAction",
    "PROJECTOR_VERSION",
    "REQUIRED_CHECK_PLAN_VERSION",
    "SOURCE_RECORD_TYPES",
    "AppliedProjection",
    "ApplyOutcome",
    "ApplyResult",
    "AssessmentOverlay",
    "AssessmentOverlayError",
    "AssessmentTransientFacts",
    "BehaviorAggregate",
    "CapabilityGrant",
    "CommittedRecord",
    "DeclassificationFact",
    "EvictionClass",
    "EvictionLimits",
    "EvictionReport",
    "ExecutionLease",
    "FlowFact",
    "GapContext",
    "GapRange",
    "GrantConsumption",
    "MemoryFact",
    "OnlineSecurityState",
    "PolicyProfile",
    "ProjectionError",
    "ProjectionRecordIdentity",
    "RecentActionFact",
    "RequiredHistoryWindow",
    "RuntimeOutcomeFact",
    "SecuritySnapshot",
    "SecurityStateDeltaV21",
    "SequenceComparisonError",
    "SourceFact",
    "StateWatermarks",
    "StickyTaintSummary",
    "WatermarkDelta",
    "apply_delta",
    "apply_safe_eviction",
    "build_required_check_plan",
    "build_assessment_overlay",
    "build_snapshot",
    "compare_sequence_refs",
    "compute_context_chunk_digest",
    "compute_context_plan_digest",
    "context_chunk_digest_projection",
    "context_plan_digest_projection",
    "compute_coverage",
    "compute_overlay_digest",
    "default_coverage_context",
    "delta_digest_projection",
    "fact_digest",
    "fact_digest_projection",
    "is_benign_source",
    "is_sticky_taint_summary",
    "localize_gaps",
    "mark_state_dirty",
    "overlay_digest_projection",
    "project_committed_record",
    "projection_identity_key",
    "rebuild_state",
    "snapshot_digest_projection",
    "state_digest",
    "state_digest_projection",
]

# Gate A assessment overlay depends on a projection lookup module. Import it
# only after the base security-context package has finished initialization to
# avoid entering the handlers/projection cycle from a partially initialized
# package.
from .assessment_overlay import (  # noqa: E402
    ASSESSMENT_OVERLAY_COMPONENT_ID,
    ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS,
    ASSESSMENT_OVERLAY_VERSION,
    AssessmentOverlay,
    AssessmentOverlayError,
    AssessmentTransientFacts,
    build_assessment_overlay,
    compute_overlay_digest,
    overlay_digest_projection,
)
