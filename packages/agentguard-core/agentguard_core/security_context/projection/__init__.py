"""V21-05/06/07 三路分支 handler / coverage 域函数子包。

三路所有权划分（与 ``handlers.CONTAINER_OWNERSHIP`` 对齐）：

- **provenance（V21-05）**：source / flow / declassification / memory /
  sticky taint 投影 handler；
- **capability（V21-06）**：grant upsert / revocation / consumption
  投影 handler；
- **behavior（V21-07）**：recent action / runtime outcome / behavior
  aggregate 投影 handler。

Phase 2 集成：``handlers.TYPED_UPSERT_HANDLERS`` 与
``coverage_context.DOMAIN_COVERAGE_DISPATCH`` 已一次性静态装配；
本子包不导出 coverage 域函数模块（避免与 coverage_context 的导入
环，域函数由 coverage_context 直接从子模块导入）。
"""

from __future__ import annotations

# V21-05 provenance 分支导出（Phase 2 集成接入中央分发表）。
from .provenance import (
    MAX_STICKY_TAINT_SUMMARIES,
    PROVENANCE_TYPED_UPSERT_HANDLERS,
    ProvenanceProjectionError,
    TAINT_LABELS,
    apply_declassification_upserts,
    apply_flow_upserts,
    apply_memory_upserts,
    apply_source_upserts,
    apply_sticky_taint_upserts,
    propagate_taints,
)

# V21-06 capability 分支导出（只追加本分支模块，不改动其他分支行）。
from .authority_verdict import (
    AuthorityProjectionError,
    ConsumptionIntent,
    build_consumption_intent,
    compute_authority_verdict,
    consumption_intent_digest,
)
from .capability import (
    CAPABILITY_COMPILER_VERSION,
    ApprovalGrantProjection,
    CapabilityProjectionError,
    GrantPolicyContext,
    apply_grant_consumptions,
    apply_grant_revocations,
    apply_grant_upserts,
    compile_approval_to_grant,
    compile_task_to_grants,
    derive_grant_id,
    grant_digest_projection,
)

# V21-07 behavior 分支私有模块导出（Phase 1 纯新增，零接线）。
from .behavior import (
    BehaviorProjectionError,
    apply_action_additions,
    apply_behavior_aggregate_upserts,
    apply_runtime_outcome_upserts,
    ordered_by_sequence_partition,
)
from .behavior_coverage import (
    BEHAVIOR_PROVIDER_KEY,
    RUNTIME_OUTCOME_PROVIDER_KEY,
    behavior_coverage,
    runtime_outcome_coverage,
)
from .behavior_matchers import (
    B6_ANOMALY_COUNT_THRESHOLD,
    BehaviorMatch,
    generate_behavior_signals,
    match_b1,
    match_b2,
    match_b3,
    match_b4,
    match_b5,
    match_b6,
    predecessor_link_kind,
    select_predecessor,
)

# V21-08 FlowVerdict 生成器（纯新增，零接线）。
from .flow_verdict import (
    DANGEROUS_TAINTS,
    EXTERNAL_DESTINATION_KINDS,
    compute_flow_verdict,
    compute_flow_verdict_from_state,
)

__all__ = [
    "B6_ANOMALY_COUNT_THRESHOLD",
    "BEHAVIOR_PROVIDER_KEY",
    "CAPABILITY_COMPILER_VERSION",
    "DANGEROUS_TAINTS",
    "EXTERNAL_DESTINATION_KINDS",
    "MAX_STICKY_TAINT_SUMMARIES",
    "PROVENANCE_TYPED_UPSERT_HANDLERS",
    "RUNTIME_OUTCOME_PROVIDER_KEY",
    "TAINT_LABELS",
    "ApprovalGrantProjection",
    "AuthorityProjectionError",
    "BehaviorMatch",
    "BehaviorProjectionError",
    "CapabilityProjectionError",
    "ConsumptionIntent",
    "GrantPolicyContext",
    "ProvenanceProjectionError",
    "apply_action_additions",
    "apply_behavior_aggregate_upserts",
    "apply_declassification_upserts",
    "apply_flow_upserts",
    "apply_grant_consumptions",
    "apply_grant_revocations",
    "apply_grant_upserts",
    "apply_memory_upserts",
    "apply_runtime_outcome_upserts",
    "apply_source_upserts",
    "apply_sticky_taint_upserts",
    "behavior_coverage",
    "build_consumption_intent",
    "compile_approval_to_grant",
    "compile_task_to_grants",
    "compute_authority_verdict",
    "compute_flow_verdict",
    "compute_flow_verdict_from_state",
    "consumption_intent_digest",
    "derive_grant_id",
    "generate_behavior_signals",
    "grant_digest_projection",
    "match_b1",
    "match_b2",
    "match_b3",
    "match_b4",
    "match_b5",
    "match_b6",
    "ordered_by_sequence_partition",
    "predecessor_link_kind",
    "propagate_taints",
    "runtime_outcome_coverage",
    "select_predecessor",
]
