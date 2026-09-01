"""V21-09 四段式编排 pipeline（legacy shadow + Product fail-closed）。

契约依据：``12_决策记录_V21-09前置.md`` D3（revoked 来源：online state
record 同源同锁只读）、D4（四段式事务边界 / S8 消除）、D5（clock 正式化：
source=guard_api_authoritative_clock、evaluated_at 锚定 event.timestamp、
clock_version="v21-09"）、D8（revalidate stale → degraded_stale_judgment）。

四段式分工（D4）：

- **Phase A（事务外只读）**：``run_phase_a`` —— scope 解析（task claim →
  权威 TaskFact → scope）→ ``ensure_ready`` → ``read_snapshot_with_revoked``
  得 snapshot V（携带 state_version V）+ 同源 revoked 集；clock 正式化；
  legacy 检测单跑（``evaluate_with_results``，与官方决策同源不双跑）→
  正式 Core 内核 assess（``shadow_assess_with_coverage`` 与 ``GuardEngine.
  assess`` 共享同一 ``_assess_kernel``，产物逐字节 parity；取 with_coverage
  形态仅为同源透出判定时使用的 coverage 供证据构建）；semantic 预留钩子
  在 assess 后、revalidate 前调用（天然事务外，03 §12 禁止
  ``BEGIN → LLM → COMMIT``）；
- **Phase B（短事务内消费）**：``build_phase_b`` —— 由 ``evaluation.py``
  在 authority transaction 内调用。legacy 路径保持轻量 re-read
  （state version / task head / policy digest）与 D8 stale 语义；Product
  路径在 store-native lockset 下严格重读 activation、双 runtime status、
  credential、精确 policy revision、完整 TaskFact 与 state/projection
  history，形成 composite authority digest。所有 staged side effect 后，
  ``finalize_product_commit`` 再次重读并比对该 digest；任一漂移均回滚并
  返回稳定 503，禁止回退 current；
- **Phase C（事务提交后投影）**：``run_phase_c`` —— Phase B audit
  commit 成功且事务退出后（02 §3 commit→project 时序：实际 state
  投影仍在事务外），V2 mode enabled 且 revalidation valid 时 scope_lock 内
  ensure_ready → base 校验 → ``project_committed``（verify 钩子复核
  审计记录存在性，F0-8）；delta 在 Phase B 以 materials 的
  state_version 为 base 确定性构造（信封 delta_digest 冻结时刻即真实，
  见 ``prepare_phase_c``）。Product 会把 exact projection envelope 作为
  reservation 与 audit 原子提交，阻止同 scope 的第二个事件复用同一
  base；Phase C 锁内 base 漂移 → fail-closed
  跳过**不置脏**；投影失败一律告警收敛、不重试（D9：replay 补投影
  承接；重试/对账机制归 V21-10/11）；stale → 不进入 Phase C；
- **audit**：T5 既有 ``evidence.decision_v21`` 同条记录写面；V21-09
  追加 ``evidence.state_delta_v21`` 引用信封（D2：只存投影身份，全量
  delta 随 projection_records）。

与 ``v21_shadow.py``（V21-08 编排器）的关系（T2 处置裁决）：pipeline
吸收四段式编排主路径；``V21ShadowService`` 保留为 Phase A 彻底失败
（``run_phase_a`` 返回 None）时的逐字节降级回退路径——其降级信封形状
与 V21-08 完全一致，V2 mode off 时两者均零行为变化。

legacy 降级收敛范式（V21-08 既有）：全链路异常不外抛、绝不影响 legacy
decision / approval / audit 主链；Phase A 不可恢复异常 → 返回 None
（调用方回退 V21-08 路径）；Phase B 异常 → 返回 None（本次评估不产
v21 证据，legacy 照常）。Product Active 不使用该收敛路径：任何
authority/phase failure 都是 503，且事务内 side effect 为零。
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from agentguard_core import (
    AuditEvent,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    ProductDecisionAuthorityEvidenceV1,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.models import ActionIR
from agentguard_core.authority import TaskAuthorityError, compile_task_authority
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.evidence import (
    CoverageMap,
    FastAssessment,
    RequiredCheckPlan,
    state_delta_v21_envelope,
)
from agentguard_core.decisions.finalize import derive_final_audit_id
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.decisions.revalidation import (
    RevalidationResult,
    revalidate_assessment,
    validate_semantic_binding,
)
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_ID,
    shadow_assess_with_coverage,
)
from agentguard_core.security_context.snapshot import SecuritySnapshot
from agentguard_core.security_context import (
    OnlineSecurityState,
    PROJECTOR_VERSION,
    CommittedRecord,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)

from guard_api.security_state import SecurityStateNotReadyError, SecurityStateService
from guard_api.auth import AuthContext
from guard_api.runtime_status import ProductRuntime
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import (
    MAX_REBUILD_INPUT_LIMIT,
    ControlPlaneStore,
    ProductAuthorityCredentialUnavailableError,
    ProjectionIdentityRecord,
)

from .policy import PolicyService
from .runtime_binding import (
    PRODUCT_TASK_IDENTITY_MISMATCH,
    PRODUCT_TASK_SCOPE_INVALID,
    ResolvedRuntimeBinding,
    RuntimeBindingResolutionError,
    RuntimeBindingResolver,
)
from .v21_shadow import (
    REASON_SNAPSHOT_READ_FAILED,
    _recategorize_shadow_degradation,
    _task_claim,
)

if TYPE_CHECKING:
    from agentguard_core.security_context import AssessmentTransientFacts
    from agentguard_core.semantic.models import SemanticJudgment

    from .product_activation import FrozenProductActivation

logger = logging.getLogger(__name__)

__all__ = [
    "PHASE_C_BASE_DRIFT_SKIPS",
    "PIPELINE_CLOCK_VERSION",
    "PRODUCT_AUTHORITY_NOT_CURRENT",
    "PRODUCT_CREDENTIAL_NOT_CURRENT",
    "PRODUCT_POLICY_NOT_CURRENT",
    "PRODUCT_SECURITY_STATE_NOT_READY",
    "V21PhaseBOutcome",
    "V21PhaseCPlan",
    "V21PhaseAPrepared",
    "V21PipelineMaterials",
    "V21PipelineService",
    "V21OfficialEvaluationUnavailableError",
    "build_evaluation_delta",
]

#: D5 clock 正式化：V21-09 权威时钟版本（evaluated_at 锚定
#: event.timestamp；source 恒 guard_api_authoritative_clock，
#: EvaluationClock 模型默认值即该单值 Literal）。
PIPELINE_CLOCK_VERSION = "v21-09"

#: pipeline 自有保守 snapshot plan（snapshot 读取先于 ActionIR，impact
#: 保守 high、全域 required；真实 plan 在 assess 内核内重算，语义与
#: V21-08 shadow plan 一致，plan_id 独立便于审计归因）。
_PIPELINE_SNAPSHOT_PLAN_ID = "v21-09-pipeline:snapshot-plan"

#: Legacy Phase B state version 漂移时的 snapshot digest 哨兵：版本已变
#: 则 snapshot 必然漂移，无需重建 snapshot 求 digest；哨兵与任何真实
#: digest（sha256: 前缀）不碰撞，必然触发 stale_snapshot_digest。
#: Product 分支不使用哨兵，而是在持锁事务内严格重建并比对完整 snapshot。
_SNAPSHOT_DRIFT_SENTINEL = "v21-09:snapshot_drift"

#: 无权威 policy snapshot record 时的确定性 revision 占位（与 V21-08
#: shadow 同口径纪律，值独立归因 pipeline）。
_UNVERSIONED_POLICY_REVISION = "v21-09:unversioned"

#: policy_evaluation 权威记录无 revision 链（同 event 幂等唯一）：
#: 投影身份五元组中的 source_revision 固定为 1（确定性，禁 uuid；
#: 仿 approval ``_APPROVAL_SOURCE_REVISION`` 口径）。
_EVALUATION_SOURCE_REVISION = 1

#: S1 结构化留痕：Phase C base 漂移跳过计数器（进程级观测信号）。
#: 该场景下投影永久缺失而信封在场，D9 replay 补投影**不可达**
#: （补投影同样锁内复核 base，漂移时同样 fail-closed 跳过）——
#: 只能由 V21-10 离线对账（audit 信封 × projection_records 差集）
#: 承接；计数器供运维观测该窗口发生频率。
PHASE_C_BASE_DRIFT_SKIPS: dict[str, int] = {"count": 0}

#: Public fail-closed code for a Product state row that cannot be consumed
#: without initialization, rebuild, repair, or ambiguity.
PRODUCT_SECURITY_STATE_NOT_READY = "V21_PRODUCT_SECURITY_STATE_NOT_READY"

#: Product policy/authority inputs are availability failures (503), never
#: ordinary shadow stale evidence and never permission to fall back to current.
PRODUCT_POLICY_NOT_CURRENT = "V21_PRODUCT_POLICY_NOT_CURRENT"
PRODUCT_AUTHORITY_NOT_CURRENT = "V21_PRODUCT_AUTHORITY_NOT_CURRENT"
PRODUCT_CREDENTIAL_NOT_CURRENT = "V21_PRODUCT_CREDENTIAL_NOT_CURRENT"


class V21OfficialEvaluationUnavailableError(RuntimeError):
    """An active V2 evaluation could not produce trusted authority."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _pipeline_snapshot_plan() -> RequiredCheckPlan:
    from agentguard_core.security_context.coverage import COVERAGE_DOMAINS

    return RequiredCheckPlan(
        plan_id=_PIPELINE_SNAPSHOT_PLAN_ID,
        impact="high",
        required_domains=list(COVERAGE_DOMAINS),
        optional_domains=[],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-09:pipeline_snapshot_plan"],
    )


#: Phase A 降级语义分类：无 task 引用/claim 无权威 fact（V21-08
#: degraded_no_snapshot 语义保持）或组件故障（读取失败重分类）。
PhaseADegradedKind = Literal["snapshot_absent", "component_failure"]


@dataclass(frozen=True)
class V21PhaseAPrepared:
    """Phase A 的只读准备材料，尚未执行 V2 shadow assessment。

    Gate A 把事实构建放在历史 Snapshot 读取与 assessment 之间。这个
    中间形态持有 legacy 单跑结果和同源 Snapshot，允许 CT 构造一次
    transient bundle 后，再把同一 bundle 作为 pre-commit overlay
    交给 Core。它不包含可持久化事实，也不改变历史 Snapshot。
    """

    event_id: str
    event_digest: str
    phase_a_payload_digest: str
    bundle: PolicyBundle
    policy_revision: str | None
    decision: GuardDecision
    detection_results: Sequence[DetectionResult]
    snapshot: SecuritySnapshot | None
    state_version: int
    revoked_grant_ids: list[str]
    clock: EvaluationClock
    task_id: str | None
    scope_digest: str | None
    degraded_kind: PhaseADegradedKind | None
    state_authority_digest: str | None
    auth_context: AuthContext | None = None
    runtime_binding: ResolvedRuntimeBinding | None = None


@dataclass(frozen=True)
class V21PipelineMaterials:
    """Phase A 事务外产出（Phase B 短事务消费材料）。

    snapshot 为 None 时 ``degraded_kind`` 标注降级语义（assessment 为
    snapshot 缺态路径产物）；正常路径 ``degraded_kind`` 为 None。
    ``decision`` 是 Phase A 单跑的 legacy 官方决策完整对象（Phase B
    事务内直接消费，不双跑检测器）。
    """

    event_id: str
    event_digest: str
    phase_a_payload_digest: str
    phase_a_output_digest: str
    bundle: PolicyBundle
    policy_revision: str | None
    decision: GuardDecision
    detection_results: Sequence[DetectionResult]
    snapshot: SecuritySnapshot | None
    state_version: int
    revoked_grant_ids: list[str]
    assessment: FastAssessment
    coverage: CoverageMap
    # Exact ActionIR consumed by Core.  It stays transient and is used by the
    # competition selector to distinguish strongly-bindable from forbidden ASK.
    action_ir: ActionIR | None
    clock: EvaluationClock
    task_id: str | None
    scope_digest: str | None
    degraded_kind: PhaseADegradedKind | None
    # Exact Core acknowledgement for Gate A. ``None`` forbids committing the
    # candidate CT bundle even when shadow safely converged to DEFER.
    consumed_overlay_digest: str | None
    state_authority_digest: str | None
    auth_context: AuthContext | None = None
    runtime_binding: ResolvedRuntimeBinding | None = None
    # V21-13 Stage 1 shadow：Phase A 事务外 semantic judgment 产物
    # （provider 缺席/门控未过/异常收敛时为 None）。只供 Phase B
    # 证据/评测消费，绝不改变决策。
    semantic_judgment: "SemanticJudgment | None" = None


@dataclass(frozen=True)
class V21PhaseBOutcome:
    """Phase B 产物：decision_v21 信封 + revalidation 结论 + 材料回溯。

    T3 消费形态：stale（``revalidation.status == "stale"``）时放弃
    V21-09 权威提交与 Phase C 投影；valid 时信封可直接供审计落盘，
    经 ``prepare_phase_c`` 产出 Phase C 投影计划与 state_delta_v21
    引用信封。

    D11 finalize 确定性产物（revalidate valid 时产出，包括预期 required-
    state 缺态所形成的不可释放 ASK；stale 恒 None）：
    ``raw_v21_decision`` 保存完整 ``GuardDecision``，既有
    ``final_decision_id`` =
    ``derive_final_decision_id(assessment)``；``final_decision_digest``
    = finalize 产物 dump 的 canonical sha256。完整 GuardDecision 不落
    审计（shadow 期官方决策者恒 legacy，归 V21-11 再裁决）；引用经
    ``record_evaluation`` extra_metadata 通道写审计 metadata。
    """

    envelope: dict[str, Any]
    revalidation: RevalidationResult
    materials: V21PipelineMaterials
    raw_v21_decision: GuardDecision | None = None
    final_decision_id: str | None = None
    final_decision_digest: str | None = None
    # V21-13 Stage 1 shadow：Phase B 对 materials.semantic_judgment 的
    # 五 digest binding 裁决结论（``validate_semantic_binding``）；
    # judgment 缺席时恒 None。供审计 metadata 承载，避免重复计算。
    semantic_binding_valid: bool | None = None
    # Product-only composite anchor captured while the store-native authority
    # fence is held.  Only this digest is emitted; credential and runtime
    # observation internals remain private.  The timestamp is deliberately
    # named ``initial``: the final precommit recapture happens later and its
    # instant is persisted as the projection reservation ``created_at``.
    product_authority_digest: str | None = None
    product_authority_initial_checked_at: str | None = None
    product_replay_authority_digest: str | None = None


@dataclass(frozen=True)
class V21PhaseCPlan:
    """Phase C 投影计划（Phase B 确定性构造，事务提交后消费）。

    Design 裁决（契约歧义留痕）：任务字面“Phase C 内构造 delta”与
    D2“信封（含 delta_digest）必须在 Phase B audit commit 时写入”
    存在时序张力——delta_digest 白名单含 base_state_version，若
    Phase C 才构造则 Phase B 信封无法持有真实 digest。故 delta 在
    Phase B 以 materials 的 state_version 为 base 确定性构造（信封
    引用真实）；Phase C 锁内复核 base，漂移则 fail-closed 跳过不置
    脏（避免置脏扩散；D9 replay 补投影承接）。Product 在物理 commit
    前只预登记 exact projection reservation，实际 state CAS 仍保持
    commit → project。
    """

    audit_id: str
    scope_digest: str
    delta: SecurityStateDeltaV21
    #: D2 引用信封（07 §10 形状）：只含投影身份（projection_id /
    #: delta_digest / source identity），全量 delta 本体随
    #: projection_records，不内嵌审计证据。
    envelope: dict[str, Any]
    #: Product commits the exact envelope as an audit-side reservation before
    #: returning.  Phase C must reconcile the full bounded history atomically
    #: instead of treating this as a legacy first-time projection.
    precommit_reserved: bool = False


@dataclass(frozen=True)
class _ProductAuthorityCapture:
    """Exact Product authority scalars consumed by Core revalidation."""

    state_version: int
    task_digest: str
    policy_digest: str
    snapshot_digest: str
    authority_digest: str
    replay_authority_digest: str
    checked_at: datetime


def _product_replay_authority_digest(
    *,
    event_digest: str,
    activation_content_digest: str,
    activation_projection: dict[str, Any],
    runtime_binding: ResolvedRuntimeBinding,
    runtime_observation_digest: str,
    credential_projection: dict[str, Any],
    policy_revision: int,
    policy_digest: str,
    task_authority_projection: dict[str, Any],
) -> str:
    """Bind replay-stable Product authority while excluding mutable state.

    The runtime observation projection intentionally excludes only the
    heartbeat timestamp. State/snapshot inputs are absent because the committed
    Product projection is expected to advance them before an exact replay.
    """

    return canonical_sha256(
        {
            "schema_version": "product-replay-authority-anchor/1.0",
            "event_digest": event_digest,
            "activation": {
                "content_digest": activation_content_digest,
                **activation_projection,
            },
            "runtime_binding": {
                "runtime": runtime_binding.runtime,
                "principal_id": runtime_binding.principal_id,
                "agent_id": runtime_binding.agent_id,
                "runtime_binding_id": runtime_binding.runtime_binding_id,
                "actor_principal_id": runtime_binding.actor_principal_id,
                "activation_ref_digest": runtime_binding.activation_ref_digest,
                "source": runtime_binding.source,
            },
            "runtime_observation_digest": runtime_observation_digest,
            "credential_digest": canonical_sha256(credential_projection),
            "policy_revision": policy_revision,
            "policy_digest": policy_digest,
            "task_authority_digest": canonical_sha256(task_authority_projection),
        }
    )


def _phase_a_payload_digest(
    *,
    bundle: PolicyBundle,
    policy_revision: str | None,
    decision: GuardDecision,
    detection_results: Sequence[DetectionResult],
    snapshot: SecuritySnapshot | None,
    state_version: int,
    revoked_grant_ids: Sequence[str],
    clock: EvaluationClock,
    task_id: str | None,
    scope_digest: str | None,
    degraded_kind: PhaseADegradedKind | None,
    state_authority_digest: str | None,
    auth_context: AuthContext | None,
    runtime_binding: ResolvedRuntimeBinding | None,
) -> str:
    """Digest every mutable Phase-A object consumed after the read boundary."""

    binding_projection = (
        None
        if runtime_binding is None
        else {
            "runtime": runtime_binding.runtime,
            "principal_id": runtime_binding.principal_id,
            "agent_id": runtime_binding.agent_id,
            "runtime_binding_id": runtime_binding.runtime_binding_id,
            "actor_principal_id": runtime_binding.actor_principal_id,
            "activation_ref_digest": runtime_binding.activation_ref_digest,
            "source": runtime_binding.source,
        }
    )
    auth_projection = (
        None
        if auth_context is None
        else {
            "principal_type": auth_context.principal_type,
            "principal_id": auth_context.principal_id,
            "role": auth_context.role,
            "scopes": sorted(auth_context.scopes),
            "auth_method": auth_context.auth_method,
            "credential_id": auth_context.credential_id,
            "credential_token_hash": auth_context.credential_token_hash,
            "runtime": auth_context.runtime,
            "agent_id": auth_context.agent_id,
        }
    )
    return canonical_sha256(
        {
            "bundle": bundle.model_dump(mode="json"),
            "policy_revision": policy_revision,
            "decision": decision.model_dump(mode="json"),
            "detection_results": [
                {
                    "decision": result.decision,
                    "risk_score": result.risk_score,
                    "category": result.category,
                    "rule_hit": result.rule_hit.model_dump(mode="json"),
                    "reason": result.reason,
                    "approval_resource": result.approval_resource,
                    "severity": result.severity,
                }
                for result in detection_results
            ],
            "snapshot": (
                snapshot.model_dump(mode="json") if snapshot is not None else None
            ),
            "state_version": state_version,
            "revoked_grant_ids": list(revoked_grant_ids),
            "clock": clock.model_dump(mode="json"),
            "task_id": task_id,
            "scope_digest": scope_digest,
            "degraded_kind": degraded_kind,
            "state_authority_digest": state_authority_digest,
            "auth_context": auth_projection,
            "runtime_binding": binding_projection,
        }
    )


def _phase_a_output_digest(
    *,
    phase_a_payload_digest: str,
    assessment: FastAssessment,
    coverage: CoverageMap,
    action_ir: ActionIR | None,
    consumed_overlay_digest: str | None,
    semantic_judgment: "SemanticJudgment | None",
) -> str:
    """Freeze mutable assessment outputs until Phase B consumes them."""

    return canonical_sha256(
        {
            "phase_a_payload_digest": phase_a_payload_digest,
            "assessment": assessment.model_dump(mode="json"),
            "coverage": coverage.model_dump(mode="json"),
            "action_ir": (
                action_ir.model_dump(mode="json") if action_ir is not None else None
            ),
            "consumed_overlay_digest": consumed_overlay_digest,
            "semantic_judgment": (
                semantic_judgment.model_dump(mode="json")
                if semantic_judgment is not None
                else None
            ),
        }
    )


def build_evaluation_delta(
    *, scope_digest: str, audit_id: str, base_state_version: int
) -> SecurityStateDeltaV21:
    """构造 policy_evaluation 权威记录的最小确定性 delta（禁 uuid）。

    D6：评估权威记录 delta 仅 watermark / evaluation clock 推进——
    PROJECTOR_VERSION 不 bump，不写任何 typed 容器（全空表）；
    evaluation clock 推进由投影身份登记（applied_projections）与
    state_version 推进承载（OnlineSecurityState 无独立 clock 字段）。
    ``projection_id`` 由幂等键五元组确定性派生；``delta_digest`` 为
    白名单投影的受限 JCS sha256（同身份同 base 重放恒定）。仿
    approval ``_build_approval_grant_delta`` 口径。
    """

    identity = ProjectionRecordIdentity(
        source_record_type="policy_evaluation",
        source_record_id=audit_id,
        source_revision=_EVALUATION_SOURCE_REVISION,
        source_sequence=None,
    )
    projection_key = projection_identity_key(
        scope_digest,
        "policy_evaluation",
        audit_id,
        _EVALUATION_SOURCE_REVISION,
        PROJECTOR_VERSION,
    )
    delta = SecurityStateDeltaV21(
        projection_id=f"projection:{projection_key}",
        scope_digest=scope_digest,
        source=identity,
        base_state_version=base_state_version,
        new_state_version=base_state_version + 1,
        projector_version=PROJECTOR_VERSION,
        task_upsert=None,
        source_upserts=[],
        flow_upserts=[],
        declassification_upserts=[],
        memory_upserts=[],
        grant_upserts=[],
        grant_revocations=[],
        grant_consumptions=[],
        action_additions=[],
        runtime_outcome_upserts=[],
        behavior_aggregate_upserts=[],
        sticky_taint_upserts=[],
        watermark_delta=WatermarkDelta(),
        coverage_invalidations=[],
        dirty_domain_updates=[],
        delta_digest="",
    )
    return delta.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(delta))}
    )


class V21PipelineService:
    """V21-09 四段式编排器（legacy shadow + Product fail-closed）。

    构造即完成 mode / secret 解析（与 V21ShadowService 同一门控口径：
    复用 ``AGENTGUARD_V21_MODE`` 与 server secret 配置）；mode off 时
    ``run_phase_a`` 仅一次布尔判断返回 None，零 I/O。兼容路径继续把
    异常收敛为 shadow 旁路；加载 Product activation 时，完整 authority
    fence、最终 precommit 复核和 reservation 为强制 503 边界。内部
    Product selector/replay 已接入；公开 composition root 仍保留外层
    fuse，直到 ACK/freshness 批次完成后才原子移除。
    """

    def __init__(
        self,
        *,
        settings: GuardApiSettings,
        store: ControlPlaneStore,
        state_service: SecurityStateService,
        policy_service: PolicyService,
        semantic_provider: (
            Callable[[GuardEvent, FastAssessment], "SemanticJudgment | None"] | None
        ) = None,
        memory_not_required_actions: frozenset[str] = frozenset(),
        competition_model_output_observation: bool = False,
        runtime_binding_resolver: RuntimeBindingResolver | None = None,
    ) -> None:
        self._store = store
        self._state_service = state_service
        self._policy_service = policy_service
        # V21-13 Stage 1 shadow 钩子：位置在 assess 后、revalidate 前
        # （天然事务外，03 §12）。provider 缺席时恒 None，零开销。
        self._semantic_provider = semantic_provider
        self._memory_not_required_actions = memory_not_required_actions
        self._competition_model_output_observation = (
            competition_model_output_observation
        )
        self._runtime_binding_resolver = (
            runtime_binding_resolver or RuntimeBindingResolver()
        )
        self._task_scope_keyring = (
            settings.task_scope_keyring()
            if self._runtime_binding_resolver.product_active
            else {}
        )
        self._mode = settings.effective_v21_mode()
        self._enabled = self._mode != "off"
        self._server_secret = self._load_server_secret(settings)

    def _load_server_secret(self, settings: GuardApiSettings) -> bytes | None:
        """V2 mode enabled 时解析 server secret；未配置/非法 → pipeline 禁用。

        与 V21ShadowService 同一口径：绝不硬编码兜底密钥；mode off 时
        不读取任何密钥配置。
        """

        if not self._enabled:
            return None
        try:
            secret = settings.v21_shadow_server_secret_bytes()
        except GuardApiConfigurationError:
            logger.warning(
                "v21 pipeline enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is malformed; pipeline evidence disabled"
            )
            return None
        if secret is None:
            logger.warning(
                "v21 pipeline enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is not configured; pipeline evidence disabled"
            )
        return secret

    @property
    def enabled(self) -> bool:
        """flag 且 secret 均已就绪（调用方诊断/编排切换判定）。"""

        # Active mode must enter the pipeline even when a direct service caller
        # bypasses startup validation; the phase boundary then raises a safe
        # 503-mapped error instead of silently taking the current-decision path.
        return self._enabled and (
            self._server_secret is not None or self._mode == "active"
        )

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def active(self) -> bool:
        return self._mode == "active"

    @property
    def product_active(self) -> bool:
        """Whether this pipeline is bound to a verified Product activation."""

        return self._runtime_binding_resolver.product_active

    @property
    def product_activation(self) -> "FrozenProductActivation | None":
        """Return the one process-frozen Product activation used by the fence.

        Authority selection must consume the same verified object as runtime
        binding and Phase-B revalidation. In particular, callers must not use
        the temporary public pre-selector fuse as an activation data source.
        """

        return self._runtime_binding_resolver.product_activation

    @contextmanager
    def authority_transaction(
        self,
        event: GuardEvent,
        materials: V21PipelineMaterials,
    ) -> Iterator[None]:
        """Select the unchanged or Product authority transaction boundary.

        The local per-scope lock is deliberately outermost.  Projectors use
        ``scope_lock -> database state lock``; preserving that order here
        avoids a DB/local lock inversion while the database lock-set remains
        the cross-process source of truth.
        """

        if not self.product_active:
            with self._store.evaluation_transaction(event.event_id):
                yield
            return

        if (
            materials.task_id is None
            or materials.scope_digest is None
            or materials.auth_context is None
            or materials.auth_context.credential_id is None
            or materials.auth_context.credential_token_hash is None
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_CREDENTIAL_NOT_CURRENT)
        activation = self._runtime_binding_resolver.product_activation
        assert activation is not None
        runtime_ids: tuple[ProductRuntime, ProductRuntime] = (
            activation.bundle.runtimes[0].runtime,
            activation.bundle.runtimes[1].runtime,
        )
        if runtime_ids != ("langgraph", "openclaw"):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        with self._state_service.store_access.scope_lock(materials.scope_digest):
            try:
                with self._store.product_evaluation_transaction(
                    event.event_id,
                    task_id=materials.task_id,
                    scope_digest=materials.scope_digest,
                    runtime_ids=runtime_ids,
                    credential_id=materials.auth_context.credential_id,
                    credential_token_hash=(
                        materials.auth_context.credential_token_hash
                    ),
                ):
                    yield
            except ProductAuthorityCredentialUnavailableError as exc:
                raise V21OfficialEvaluationUnavailableError(
                    PRODUCT_CREDENTIAL_NOT_CURRENT
                ) from exc
            except RuntimeBindingResolutionError as exc:
                self._raise_runtime_binding_error(exc)

    @contextmanager
    def product_replay_transaction(
        self,
        event: GuardEvent,
        audit: AuditEvent,
        auth_context: AuthContext | None,
    ) -> Iterator[AuditEvent]:
        """Repair and expose one exact Product replay under its full fence.

        This path deliberately never runs Phase A or Core assessment.  It
        validates replay-stable authority, repairs the exact committed
        reservation/state in the existing Product transaction, validates
        authority a second time, and only then yields so the caller may repair
        provenance and rebuild the immutable response before commit.
        """

        activation = self.product_activation
        task_id = _task_claim(event)
        audit_task_id = audit.metadata.get("task_id")
        if (
            not self.active
            or activation is None
            or task_id is None
            or audit_task_id != task_id
            or auth_context is None
            or auth_context.credential_id is None
            or auth_context.credential_token_hash is None
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        task_record = self._store.get_task_fact(task_id)
        if task_record is None:
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        scope_digest = task_record.task_fact.scope_digest
        runtime_ids: tuple[ProductRuntime, ProductRuntime] = (
            activation.bundle.runtimes[0].runtime,
            activation.bundle.runtimes[1].runtime,
        )
        if runtime_ids != ("langgraph", "openclaw"):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)

        with self._state_service.store_access.scope_lock(scope_digest):
            try:
                with self._store.product_evaluation_transaction(
                    event.event_id,
                    task_id=task_id,
                    scope_digest=scope_digest,
                    runtime_ids=runtime_ids,
                    credential_id=auth_context.credential_id,
                    credential_token_hash=auth_context.credential_token_hash,
                ):
                    locked = self._store.get_policy_evaluation_by_event_id(
                        event.event_id
                    )
                    if locked is None or locked.model_dump(
                        mode="json"
                    ) != audit.model_dump(mode="json"):
                        raise V21OfficialEvaluationUnavailableError(
                            PRODUCT_AUTHORITY_NOT_CURRENT
                        )
                    self.repair_product_replay_locked(
                        event,
                        locked,
                        auth_context=auth_context,
                        task_id=task_id,
                        scope_digest=scope_digest,
                    )
                    yield locked
            except ProductAuthorityCredentialUnavailableError as exc:
                raise V21OfficialEvaluationUnavailableError(
                    PRODUCT_CREDENTIAL_NOT_CURRENT
                ) from exc
            except RuntimeBindingResolutionError as exc:
                self._raise_runtime_binding_error(exc)

    def repair_product_replay_locked(
        self,
        event: GuardEvent,
        audit: AuditEvent,
        *,
        auth_context: AuthContext,
        task_id: str,
        scope_digest: str,
    ) -> None:
        """Validate, repair, then revalidate a replay in an existing fence."""

        evidence = self._revalidate_product_replay_authority(
            event,
            audit,
            auth_context=auth_context,
            task_id=task_id,
            scope_digest=scope_digest,
        )
        self._repair_product_replay_projection_locked(
            audit,
            evidence=evidence,
            scope_digest=scope_digest,
        )
        # Re-sample time validity and every non-state authority input after
        # reconciliation, before provenance becomes mutable.
        self._revalidate_product_replay_authority(
            event,
            audit,
            auth_context=auth_context,
            task_id=task_id,
            scope_digest=scope_digest,
        )

    def _revalidate_product_replay_authority(
        self,
        event: GuardEvent,
        audit: AuditEvent,
        *,
        auth_context: AuthContext,
        task_id: str,
        scope_digest: str,
    ) -> ProductDecisionAuthorityEvidenceV1:
        """Re-capture replay-stable Product authority without reassessment."""

        activation = self.product_activation
        if activation is None:
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        try:
            sampled = self._runtime_binding_resolver.clock()
            if sampled.tzinfo is None or sampled.utcoffset() is None:
                raise ValueError("authority clock must be timezone-aware")
            checked_at = sampled.astimezone(timezone.utc)
            activation.assert_unchanged()
            if not activation.bundle.valid_at(checked_at):
                raise ValueError("Product activation is not current")
            raw_envelope = (
                audit.evidence.get("decision_authority")
                if isinstance(audit.evidence, dict)
                else None
            )
            from .competition import (  # noqa: PLC0415
                parse_decision_authority_evidence_payload,
            )

            parsed = parse_decision_authority_evidence_payload(
                {"decision_authority": raw_envelope}
            )
            if not isinstance(parsed, ProductDecisionAuthorityEvidenceV1):
                raise ValueError("historical authority is not Product schema 2.0")
            runtime_entry = activation.bundle.runtime_entry(parsed.runtime)
        except V21OfficialEvaluationUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - stable Product replay boundary.
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_AUTHORITY_NOT_CURRENT
            ) from exc

        task_record = self._store.get_task_fact(task_id)
        if task_record is None:
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
        task = task_record.task_fact
        scope = SecurityStateScope(
            principal_id=runtime_entry.principal_id,
            runtime=runtime_entry.runtime,
            runtime_binding_id=runtime_entry.runtime_binding_id,
            trace_id=event.trace_id,
            session_id=event.security_context.session_id,
            scope_digest=scope_digest,
        )
        try:
            compile_task_authority(
                task,
                scope,
                server_keys=self._task_scope_keyring,
            )
        except TaskAuthorityError as exc:
            raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID) from exc
        if (
            task.status != "active"
            or task.task_id != task_id
            or task.scope_digest != scope_digest
            or canonical_sha256(task_record.canonical_payload)
            != canonical_sha256(task.model_dump(mode="json"))
            or task_record.expected_revision != task.revision - 1
        ):
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)

        binding = self._runtime_binding_resolver.resolve_evaluation(
            auth_context,
            event=event,
            task_principal_id=task.principal_id,
            reference_time=checked_at,
        )
        self._runtime_binding_resolver.revalidate(
            binding,
            reference_time=checked_at,
        )
        if not all(
            (
                parsed.event_id == event.event_id,
                parsed.event_type == event.event_type,
                parsed.runtime == event.runtime == runtime_entry.runtime,
                parsed.profile_id == runtime_entry.profile_id,
                parsed.profile_digest == runtime_entry.profile_digest,
                parsed.dataset_digest == activation.bundle.dataset_digest,
                parsed.policy_digest == activation.bundle.policy_digest,
                parsed.decision_authority.activation_ref_digest
                == activation.bundle.activation_ref_digest,
                parsed.approval_release_directive.activation_ref_digest
                == activation.bundle.activation_ref_digest,
                parsed.approval_release_directive.scope_digest == scope_digest,
                parsed.approval_release_directive.capability_digest
                == runtime_entry.capability_report_digest,
                binding.runtime_binding_id == runtime_entry.runtime_binding_id,
                binding.principal_id == runtime_entry.principal_id,
                binding.agent_id == runtime_entry.agent_id,
            )
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)

        from .product_activation import (  # noqa: PLC0415
            RUNTIME_OBSERVATION_MISMATCH,
            reconcile_product_runtime_observations,
        )

        observations = reconcile_product_runtime_observations(
            activation,
            self._store,
        )
        if (
            not observations.matched
            or observations.authority_observation_digest is None
        ):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_OBSERVATION_MISMATCH)

        if (
            auth_context.auth_method != "bearer"
            or auth_context.credential_id is None
            or auth_context.credential_token_hash is None
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_CREDENTIAL_NOT_CURRENT)
        credential = self._store.get_credential_by_token_hash(
            auth_context.credential_token_hash
        )
        if credential is None or not all(
            (
                credential.credential_id == auth_context.credential_id,
                credential.token_hash == auth_context.credential_token_hash,
                credential.principal_type == auth_context.principal_type,
                credential.principal_id == auth_context.principal_id,
                credential.role == auth_context.role,
                sorted(credential.scopes) == sorted(auth_context.scopes),
                credential.runtime == auth_context.runtime,
                credential.agent_id == auth_context.agent_id,
                credential.revoked_at is None,
                "event:evaluate" in credential.scopes,
            )
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_CREDENTIAL_NOT_CURRENT)
        if credential.expires_at is not None:
            try:
                credential_expiry = datetime.fromisoformat(
                    credential.expires_at.replace("Z", "+00:00")
                )
                if (
                    credential_expiry.tzinfo is None
                    or credential_expiry.utcoffset() is None
                    or checked_at >= credential_expiry.astimezone(timezone.utc)
                ):
                    raise ValueError("credential expired")
            except (TypeError, ValueError) as exc:
                raise V21OfficialEvaluationUnavailableError(
                    PRODUCT_CREDENTIAL_NOT_CURRENT
                ) from exc

        policy_record = self._store.get_policy_snapshot_record()
        policy_evidence = (
            audit.evidence.get("policy") if isinstance(audit.evidence, dict) else None
        )
        policy_digest = (
            canonical_sha256(policy_record.policy_bundle.model_dump(mode="json"))
            if policy_record is not None
            else None
        )
        if (
            policy_record is None
            or not isinstance(policy_evidence, dict)
            or policy_evidence.get("revision") != policy_record.revision
            or policy_evidence.get("canonical_digest") != policy_digest
            or policy_digest != activation.bundle.policy_digest
            or parsed.policy_digest != policy_digest
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_POLICY_NOT_CURRENT)
        assert policy_digest is not None

        activation_projection = {
            "activation_ref_digest": activation.bundle.activation_ref_digest,
            "signer_key_id": activation.bundle.signer_key_id,
            "candidate_artifact_manifest_digest": (
                activation.bundle.candidate_artifact_manifest_digest
            ),
            "policy_digest": activation.bundle.policy_digest,
            "dataset_digest": activation.bundle.dataset_digest,
            "contract_digest": activation.bundle.contract_digest,
        }
        task_projection = {
            "task_fact": task.model_dump(mode="json"),
            "canonical_payload": task_record.canonical_payload,
            "request_digest": task_record.request_digest,
            "expected_revision": task_record.expected_revision,
        }
        replay_digest = _product_replay_authority_digest(
            event_digest=canonical_sha256(event.model_dump(mode="json")),
            activation_content_digest=activation.content_digest,
            activation_projection=activation_projection,
            runtime_binding=binding,
            runtime_observation_digest=(observations.authority_observation_digest),
            credential_projection=credential.model_dump(mode="json"),
            policy_revision=policy_record.revision,
            policy_digest=policy_digest,
            task_authority_projection=task_projection,
        )
        if audit.metadata.get("product_replay_authority_digest") != replay_digest:
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        return parsed

    def _repair_product_replay_projection_locked(
        self,
        audit: AuditEvent,
        *,
        evidence: ProductDecisionAuthorityEvidenceV1,
        scope_digest: str,
    ) -> None:
        """Strictly reconcile one Product reservation in the active transaction."""

        try:
            raw_delta = (
                audit.evidence.get("state_delta_v21")
                if isinstance(audit.evidence, dict)
                else None
            )
            if (
                not isinstance(raw_delta, dict)
                or set(raw_delta) != {"schema_version", "payload"}
                or raw_delta.get("schema_version") != "2.1"
                or not isinstance(raw_delta.get("payload"), dict)
            ):
                raise ValueError("Product replay state delta envelope is invalid")
            delta = build_evaluation_delta(
                scope_digest=scope_digest,
                audit_id=audit.audit_id,
                base_state_version=evidence.state_version,
            )
            expected_reference = {
                "projection_id": delta.projection_id,
                "delta_digest": delta.delta_digest,
                "source_record_type": delta.source.source_record_type,
                "source_record_id": delta.source.source_record_id,
                "source_revision": delta.source.source_revision,
            }
            if raw_delta.get("payload") != expected_reference:
                raise ValueError("Product replay state delta reference drifted")

            def projection_ready() -> bool:
                projection = self._store.get_projection(
                    scope_digest,
                    delta.source.source_record_type,
                    delta.source.source_record_id,
                    delta.source.source_revision,
                    delta.projector_version,
                )
                state_record = self._store.get_security_state(scope_digest)
                if (
                    projection is None
                    or state_record is None
                    or state_record.dirty
                    or state_record.projector_version != PROJECTOR_VERSION
                    or state_record.state_version < delta.new_state_version
                    or projection.delta_digest != delta.delta_digest
                    or projection.delta_payload != delta.model_dump(mode="json")
                    or projection.applied_state_version != delta.new_state_version
                ):
                    return False
                state = OnlineSecurityState.model_validate(
                    state_record.canonical_payload
                )
                expected_key = projection_identity_key(
                    scope_digest,
                    delta.source.source_record_type,
                    delta.source.source_record_id,
                    delta.source.source_revision,
                    delta.projector_version,
                )
                return any(
                    item.projection_key == expected_key
                    and item.delta_digest == delta.delta_digest
                    for item in state.applied_projections
                )

            if projection_ready():
                return
            reservation = ProjectionIdentityRecord(
                scope_digest=scope_digest,
                source_record_type=delta.source.source_record_type,
                source_record_id=delta.source.source_record_id,
                source_revision=delta.source.source_revision,
                projector_version=delta.projector_version,
                delta_digest=delta.delta_digest,
                delta_payload=delta.model_dump(mode="json"),
                applied_state_version=delta.new_state_version,
                created_at=audit.timestamp,
            )
            self._store.record_projection(reservation)
            self._state_service.reconcile_projection_history(scope_digest)
            if not projection_ready():
                raise ValueError("Product replay projection is not reflected")
        except V21OfficialEvaluationUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - strict rollback boundary.
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            ) from exc

    def _raise_if_active(self, code: str, exc: Exception) -> None:
        if self.active:
            raise V21OfficialEvaluationUnavailableError(code) from exc

    @staticmethod
    def _raise_runtime_binding_error(exc: RuntimeBindingResolutionError) -> None:
        raise V21OfficialEvaluationUnavailableError(exc.code) from exc

    # ------------------------------------------------------------------
    # Phase A：事务外只读
    # ------------------------------------------------------------------

    def run_phase_a(
        self,
        event: GuardEvent,
        *,
        auth_context: AuthContext | None = None,
    ) -> V21PipelineMaterials | None:
        """Phase A（D4：evaluation_transaction **之前**执行）。

        返回 None 的语义：flag/secret 门控未就绪，或 Phase A 不可恢复
        异常——调用方（evaluation 编排）据此回退 V21-08 逐字节路径
        （``V21ShadowService``）。**绝不外抛**。
        """

        if not self.enabled:
            return None
        try:
            return self._run_phase_a(event, auth_context=auth_context)
        except V21OfficialEvaluationUnavailableError:
            raise
        except RuntimeBindingResolutionError as exc:
            self._raise_runtime_binding_error(exc)
        except Exception as exc:  # noqa: BLE001 - mode-specific boundary.
            self._raise_if_active("V21_OFFICIAL_PHASE_A_FAILED", exc)
            logger.warning(
                "v21 pipeline phase A failed for event %s; falling back "
                "to V21-08 shadow path",
                event.event_id,
                exc_info=True,
            )
            return None

    def _run_phase_a(
        self,
        event: GuardEvent,
        *,
        auth_context: AuthContext | None = None,
    ) -> V21PipelineMaterials | None:
        prepared = self._prepare_phase_a(event, auth_context=auth_context)
        return self._finish_phase_a(
            event,
            prepared,
            transient_facts=None,
            auth_context=auth_context,
        )

    def prepare_phase_a(
        self,
        event: GuardEvent,
        *,
        auth_context: AuthContext | None = None,
    ) -> V21PhaseAPrepared | None:
        """读取 legacy/policy/Snapshot，但暂不执行 shadow assessment。

        Gate A 生产编排使用这个边界在同一历史 Snapshot 上构造当前事件
        transient facts。异常仍按既有旁路纪律收敛为 ``None``。
        """

        if not self.enabled:
            return None
        try:
            return self._prepare_phase_a(event, auth_context=auth_context)
        except V21OfficialEvaluationUnavailableError:
            raise
        except RuntimeBindingResolutionError as exc:
            self._raise_runtime_binding_error(exc)
        except Exception as exc:  # noqa: BLE001 - mode-specific boundary.
            self._raise_if_active("V21_OFFICIAL_PHASE_A_PREPARE_FAILED", exc)
            logger.warning(
                "v21 pipeline phase A preparation failed for event %s; "
                "falling back to V21-08 shadow path",
                event.event_id,
                exc_info=True,
            )
            return None

    def finish_phase_a(
        self,
        event: GuardEvent,
        prepared: V21PhaseAPrepared,
        *,
        transient_facts: "AssessmentTransientFacts | None" = None,
        auth_context: AuthContext | None = None,
    ) -> V21PipelineMaterials | None:
        """以历史 Snapshot + 当前 transient overlay 完成 shadow assessment。"""

        if not self.enabled:
            return None
        try:
            return self._finish_phase_a(
                event,
                prepared,
                transient_facts=transient_facts,
                auth_context=auth_context,
            )
        except V21OfficialEvaluationUnavailableError:
            raise
        except RuntimeBindingResolutionError as exc:
            self._raise_runtime_binding_error(exc)
        except Exception as exc:  # noqa: BLE001 - mode-specific boundary.
            self._raise_if_active("V21_OFFICIAL_PHASE_A_ASSESS_FAILED", exc)
            logger.warning(
                "v21 pipeline phase A assessment failed for event %s; "
                "falling back to V21-08 shadow path",
                event.event_id,
                exc_info=True,
            )
            return None

    def _prepare_phase_a(
        self,
        event: GuardEvent,
        *,
        auth_context: AuthContext | None = None,
    ) -> V21PhaseAPrepared:
        assert self._server_secret is not None
        event_digest = canonical_sha256(event.model_dump(mode="json"))

        # 策略解析与 legacy 单跑（detection 不双跑：decision 与
        # detection_results 存入材料供 Phase B 直接消费）。
        snapshot_record = self._policy_service.current_snapshot_record()
        if snapshot_record is not None:
            bundle = snapshot_record.policy_bundle
            policy_revision: str | None = str(snapshot_record.revision)
        else:
            if self.product_active:
                # A callback/default policy cannot be frozen by the Product
                # store transaction and has no exact monotonic revision.
                raise V21OfficialEvaluationUnavailableError(PRODUCT_POLICY_NOT_CURRENT)
            bundle = self._policy_service.current_snapshot()
            policy_revision = None
        if self.product_active:
            activation = self._runtime_binding_resolver.product_activation
            assert activation is not None
            if (
                snapshot_record is None
                or snapshot_record.revision <= 0
                or canonical_sha256(bundle.model_dump(mode="json"))
                != activation.bundle.policy_digest
            ):
                raise V21OfficialEvaluationUnavailableError(PRODUCT_POLICY_NOT_CURRENT)
        decision, detection_results = GuardEngine().evaluate_with_results(event, bundle)

        clock = EvaluationClock(
            evaluated_at=event.timestamp,
            clock_version=PIPELINE_CLOCK_VERSION,
        )

        try:
            resolved = self._resolve_snapshot_v(
                event,
                bundle,
                clock,
                policy_revision,
                auth_context=auth_context,
            )
        except (RuntimeBindingResolutionError, V21OfficialEvaluationUnavailableError):
            raise
        except Exception as exc:  # noqa: BLE001 - mode-specific boundary.
            if self.active:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_SNAPSHOT_READ_FAILED"
                ) from exc
            logger.warning(
                "v21 pipeline phase A snapshot read failed for event %s",
                event.event_id,
                exc_info=True,
            )
            return V21PhaseAPrepared(
                event_id=event.event_id,
                event_digest=event_digest,
                phase_a_payload_digest=_phase_a_payload_digest(
                    bundle=bundle,
                    policy_revision=policy_revision,
                    decision=decision,
                    detection_results=detection_results,
                    snapshot=None,
                    state_version=0,
                    revoked_grant_ids=(),
                    clock=clock,
                    task_id=_task_claim(event),
                    scope_digest=None,
                    degraded_kind="component_failure",
                    state_authority_digest=None,
                    auth_context=auth_context,
                    runtime_binding=None,
                ),
                bundle=bundle,
                policy_revision=policy_revision,
                decision=decision,
                detection_results=list(detection_results),
                snapshot=None,
                state_version=0,
                revoked_grant_ids=[],
                clock=clock,
                task_id=_task_claim(event),
                scope_digest=None,
                degraded_kind="component_failure",
                state_authority_digest=None,
                auth_context=auth_context,
            )

        (
            snapshot,
            revoked_grant_ids,
            task_id,
            scope_digest,
            runtime_binding,
            state_authority_digest,
        ) = resolved
        state_version = snapshot.state_version if snapshot is not None else 0
        degraded_kind: PhaseADegradedKind | None = (
            None if snapshot is not None else "snapshot_absent"
        )
        return V21PhaseAPrepared(
            event_id=event.event_id,
            event_digest=event_digest,
            phase_a_payload_digest=_phase_a_payload_digest(
                bundle=bundle,
                policy_revision=policy_revision,
                decision=decision,
                detection_results=detection_results,
                snapshot=snapshot,
                state_version=state_version,
                revoked_grant_ids=revoked_grant_ids,
                clock=clock,
                task_id=task_id,
                scope_digest=scope_digest,
                degraded_kind=degraded_kind,
                state_authority_digest=state_authority_digest,
                auth_context=auth_context,
                runtime_binding=runtime_binding,
            ),
            bundle=bundle,
            policy_revision=policy_revision,
            decision=decision,
            detection_results=list(detection_results),
            snapshot=snapshot,
            state_version=state_version,
            revoked_grant_ids=list(revoked_grant_ids),
            clock=clock,
            task_id=task_id,
            scope_digest=scope_digest,
            degraded_kind=degraded_kind,
            state_authority_digest=state_authority_digest,
            auth_context=auth_context,
            runtime_binding=runtime_binding,
        )

    def _finish_phase_a(
        self,
        event: GuardEvent,
        prepared: V21PhaseAPrepared,
        *,
        transient_facts: "AssessmentTransientFacts | None",
        auth_context: AuthContext | None = None,
    ) -> V21PipelineMaterials:
        assert self._server_secret is not None
        if prepared.event_id != event.event_id:
            raise ValueError("phase A prepared materials do not match event_id")
        if (
            self._runtime_binding_resolver.product_active
            and prepared.event_digest != canonical_sha256(event.model_dump(mode="json"))
        ):
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
        if (
            self._runtime_binding_resolver.product_active
            and prepared.phase_a_payload_digest
            != _phase_a_payload_digest(
                bundle=prepared.bundle,
                policy_revision=prepared.policy_revision,
                decision=prepared.decision,
                detection_results=prepared.detection_results,
                snapshot=prepared.snapshot,
                state_version=prepared.state_version,
                revoked_grant_ids=prepared.revoked_grant_ids,
                clock=prepared.clock,
                task_id=prepared.task_id,
                scope_digest=prepared.scope_digest,
                degraded_kind=prepared.degraded_kind,
                state_authority_digest=prepared.state_authority_digest,
                auth_context=prepared.auth_context,
                runtime_binding=prepared.runtime_binding,
            )
        ):
            raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID)
        if auth_context is not None and prepared.auth_context != auth_context:
            raise ValueError("phase A AuthContext changed between prepare and finish")
        if self._runtime_binding_resolver.product_active:
            if (
                auth_context is None
                or prepared.runtime_binding is None
                or prepared.snapshot is None
                or prepared.snapshot.task is None
            ):
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            current_binding = self._runtime_binding_resolver.resolve_evaluation(
                auth_context,
                event=event,
                task_principal_id=prepared.snapshot.task.principal_id,
            )
            if current_binding != prepared.runtime_binding:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)

        assess_kwargs: dict[str, Any] = {
            "server_secret": self._server_secret,
            "detection_results": prepared.detection_results,
        }
        if prepared.snapshot is not None:
            assess_kwargs["revoked_grant_ids"] = prepared.revoked_grant_ids
        # Do not pass the new keyword on the compatibility path. Besides keeping
        # old monkeypatched call sites valid, this guarantees that absence of an
        # overlay exercises the exact pre-Gate-A Core path.
        if transient_facts is not None:
            assess_kwargs["transient_facts"] = transient_facts
        if self._memory_not_required_actions:
            assess_kwargs["memory_not_required_actions"] = (
                self._memory_not_required_actions
            )
        if (
            self._competition_model_output_observation
            and self.active
            and event.event_type == "model_output_produced"
        ):
            # Competition-only contract B: model output is an inbound
            # observation, not a new outbound action. Detectors, signals and
            # taint still run. Source/dataflow are N/A for this already
            # server-attested event; memory remains governed by its independent
            # persistence/resource/lineage safeguards.
            assess_kwargs["source_dataflow_not_required_actions"] = frozenset(
                {"model_call"}
            )
        outcome = shadow_assess_with_coverage(
            event,
            prepared.bundle,
            prepared.snapshot,
            **assess_kwargs,
        )
        assessment = outcome.assessment
        if prepared.degraded_kind == "component_failure":
            assessment = _recategorize_shadow_degradation(
                assessment,
                reason_code=REASON_SNAPSHOT_READ_FAILED,
            )
        semantic_judgment: "SemanticJudgment | None" = None
        if self._semantic_provider is not None and prepared.snapshot is not None:
            # V21-13 Stage 1 shadow：钩子在 assess 后 revalidate 前，
            # 天然事务外（03 §12）。产物只供证据/评测消费，绝不改变
            # 决策；provider 异常一律收敛为 None（fail-closed，shadow
            # 旁路不影响 Phase A 主链）。
            try:
                semantic_judgment = self._semantic_provider(event, assessment)
            except Exception:  # noqa: BLE001 - shadow boundary never raises.
                logger.warning(
                    "v21-13 semantic provider raised for event %s; "
                    "judgment discarded (fail-closed)",
                    event.event_id,
                    exc_info=True,
                )
                semantic_judgment = None
        return V21PipelineMaterials(
            event_id=prepared.event_id,
            event_digest=prepared.event_digest,
            phase_a_payload_digest=prepared.phase_a_payload_digest,
            phase_a_output_digest=_phase_a_output_digest(
                phase_a_payload_digest=prepared.phase_a_payload_digest,
                assessment=assessment,
                coverage=outcome.coverage,
                action_ir=outcome.action_ir,
                consumed_overlay_digest=outcome.consumed_overlay_digest,
                semantic_judgment=semantic_judgment,
            ),
            bundle=prepared.bundle,
            policy_revision=prepared.policy_revision,
            decision=prepared.decision,
            detection_results=list(prepared.detection_results),
            snapshot=prepared.snapshot,
            state_version=prepared.state_version,
            revoked_grant_ids=list(prepared.revoked_grant_ids),
            assessment=assessment,
            coverage=outcome.coverage,
            action_ir=outcome.action_ir,
            clock=prepared.clock,
            task_id=prepared.task_id,
            scope_digest=prepared.scope_digest,
            degraded_kind=prepared.degraded_kind,
            consumed_overlay_digest=outcome.consumed_overlay_digest,
            state_authority_digest=prepared.state_authority_digest,
            auth_context=prepared.auth_context,
            runtime_binding=prepared.runtime_binding,
            semantic_judgment=semantic_judgment,
        )

    def _resolve_snapshot_v(
        self,
        event: GuardEvent,
        bundle: PolicyBundle,
        clock: EvaluationClock,
        policy_revision: str | None,
        *,
        auth_context: AuthContext | None,
    ) -> tuple[
        SecuritySnapshot | None,
        list[str],
        str | None,
        str | None,
        ResolvedRuntimeBinding | None,
        str | None,
    ]:
        """task claim → 权威 TaskFact head → scope → snapshot V + revoked。

        与 V21ShadowService._resolve_snapshot 同源口径升级：clock 正式化
        （D5）+ ``read_snapshot_with_revoked`` 同源同锁读取（D3）。
        返回 ``(snapshot, revoked, task_id, scope_digest, binding)``；无 task
        引用/无权威 fact 时 snapshot 为 None。
        """

        task_id = _task_claim(event)
        if task_id is None:
            if self._runtime_binding_resolver.product_active:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            return None, [], None, None, None, None
        record = self._store.get_task_fact(task_id)
        if record is None:
            # trusted claim 无对应权威 TaskFact：不得据此构造 snapshot。
            if self._runtime_binding_resolver.product_active:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            return None, [], task_id, None, None, None
        task_fact = record.task_fact
        runtime_binding = self._runtime_binding_resolver.resolve_evaluation(
            auth_context,
            event=event,
            task_principal_id=task_fact.principal_id,
        )
        scope_digest = task_fact.scope_digest
        scope = SecurityStateScope(
            principal_id=runtime_binding.principal_id,
            runtime=runtime_binding.runtime,
            runtime_binding_id=runtime_binding.runtime_binding_id,
            trace_id=event.trace_id,
            session_id=event.security_context.session_id,
            scope_digest=scope_digest,
        )
        if self._runtime_binding_resolver.product_active:
            try:
                compile_task_authority(
                    task_fact,
                    scope,
                    server_keys=self._task_scope_keyring,
                )
            except TaskAuthorityError as exc:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID) from exc
        snapshot_kwargs: dict[str, Any] = {
            "scope": scope,
            "task_fact_head": task_fact,
            "evaluation_clock": clock,
            "policy_revision": policy_revision or _UNVERSIONED_POLICY_REVISION,
            "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
            "plan": _pipeline_snapshot_plan(),
        }
        state_authority_digest: str | None = None
        if self._runtime_binding_resolver.product_active:
            try:
                snapshot, revoked, state_authority_digest = (
                    self._state_service.read_ready_snapshot_with_revoked(
                        scope_digest,
                        **snapshot_kwargs,
                    )
                )
            except SecurityStateNotReadyError as exc:
                raise V21OfficialEvaluationUnavailableError(
                    PRODUCT_SECURITY_STATE_NOT_READY
                ) from exc
        else:
            self._state_service.ensure_ready(scope_digest)
            snapshot, revoked = self._state_service.read_snapshot_with_revoked(
                scope_digest,
                **snapshot_kwargs,
            )
        return (
            snapshot,
            list(revoked),
            task_id,
            scope_digest,
            runtime_binding,
            state_authority_digest,
        )

    def _capture_product_authority(
        self,
        event: GuardEvent,
        materials: V21PipelineMaterials,
    ) -> _ProductAuthorityCapture:
        """Re-read one complete Product authority snapshot under its fence."""

        if (
            not self.product_active
            or materials.runtime_binding is None
            or materials.auth_context is None
            or materials.snapshot is None
            or materials.snapshot.task is None
            or materials.task_id is None
            or materials.scope_digest is None
            or materials.state_authority_digest is None
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)

        try:
            sampled = self._runtime_binding_resolver.clock()
            if sampled.tzinfo is None or sampled.utcoffset() is None:
                raise ValueError("authority clock must be timezone-aware")
            checked_at = sampled.astimezone(timezone.utc)
        except Exception as exc:  # noqa: BLE001 - clock is an authority input.
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_AUTHORITY_NOT_CURRENT
            ) from exc

        binding = materials.runtime_binding
        self._runtime_binding_resolver.revalidate(
            binding,
            reference_time=checked_at,
        )
        current_binding = self._runtime_binding_resolver.resolve_evaluation(
            materials.auth_context,
            event=event,
            task_principal_id=materials.snapshot.task.principal_id,
            reference_time=checked_at,
        )
        if current_binding != binding:
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)

        activation = self._runtime_binding_resolver.product_activation
        assert activation is not None
        # Delayed import avoids the intentional product_activation -> pipeline
        # error-boundary dependency during module initialization.
        from .product_activation import (  # noqa: PLC0415
            RUNTIME_OBSERVATION_MISMATCH,
            reconcile_product_runtime_observations,
        )

        observations = reconcile_product_runtime_observations(
            activation,
            self._store,
        )
        if (
            not observations.matched
            or observations.observation_digest is None
            or observations.authority_observation_digest is None
        ):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_OBSERVATION_MISMATCH)

        auth = materials.auth_context
        if (
            auth.auth_method != "bearer"
            or auth.credential_id is None
            or auth.credential_token_hash is None
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_CREDENTIAL_NOT_CURRENT)
        credential = self._store.get_credential_by_token_hash(
            auth.credential_token_hash
        )
        if credential is None or not all(
            (
                credential.credential_id == auth.credential_id,
                credential.token_hash == auth.credential_token_hash,
                credential.principal_type == auth.principal_type,
                credential.principal_id == auth.principal_id,
                credential.role == auth.role,
                sorted(credential.scopes) == sorted(auth.scopes),
                credential.runtime == auth.runtime,
                credential.agent_id == auth.agent_id,
                credential.revoked_at is None,
                "event:evaluate" in credential.scopes,
            )
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_CREDENTIAL_NOT_CURRENT)
        if credential.expires_at is not None:
            try:
                credential_expiry = datetime.fromisoformat(
                    credential.expires_at.replace("Z", "+00:00")
                )
                if (
                    credential_expiry.tzinfo is None
                    or credential_expiry.utcoffset() is None
                    or checked_at >= credential_expiry.astimezone(timezone.utc)
                ):
                    raise ValueError("credential expired")
            except (TypeError, ValueError) as exc:
                raise V21OfficialEvaluationUnavailableError(
                    PRODUCT_CREDENTIAL_NOT_CURRENT
                ) from exc

        policy_record = self._store.get_policy_snapshot_record()
        policy_digest = canonical_sha256(materials.bundle.model_dump(mode="json"))
        if (
            policy_record is None
            or materials.policy_revision is None
            or str(policy_record.revision) != materials.policy_revision
            or canonical_sha256(policy_record.policy_bundle.model_dump(mode="json"))
            != policy_digest
            or policy_digest != activation.bundle.policy_digest
            or materials.snapshot.policy_revision != materials.policy_revision
            or materials.snapshot.policy_digest != policy_digest
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_POLICY_NOT_CURRENT)

        task_record = self._store.get_task_fact(materials.task_id)
        if task_record is None:
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
        current_task = task_record.task_fact
        assessed_task = materials.snapshot.task
        try:
            compile_task_authority(
                current_task,
                materials.snapshot.scope,
                server_keys=self._task_scope_keyring,
            )
        except TaskAuthorityError as exc:
            raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID) from exc
        if (
            current_task.task_id != materials.task_id
            or current_task.model_dump(mode="json")
            != assessed_task.model_dump(mode="json")
            or canonical_sha256(task_record.canonical_payload)
            != canonical_sha256(current_task.model_dump(mode="json"))
            or task_record.expected_revision != current_task.revision - 1
        ):
            raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)

        try:
            current_snapshot, current_revoked, state_authority_digest = (
                self._state_service.read_ready_snapshot_with_revoked(
                    materials.scope_digest,
                    scope=materials.snapshot.scope,
                    task_fact_head=current_task,
                    evaluation_clock=materials.clock,
                    policy_revision=materials.policy_revision,
                    policy_digest=policy_digest,
                    plan=_pipeline_snapshot_plan(),
                )
            )
        except SecurityStateNotReadyError as exc:
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            ) from exc
        if (
            state_authority_digest != materials.state_authority_digest
            or current_snapshot.snapshot_digest != materials.snapshot.snapshot_digest
            or canonical_sha256(current_snapshot.model_dump(mode="json"))
            != canonical_sha256(materials.snapshot.model_dump(mode="json"))
            or current_revoked != materials.revoked_grant_ids
        ):
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            )

        activation_projection = {
            "activation_ref_digest": activation.bundle.activation_ref_digest,
            "signer_key_id": activation.bundle.signer_key_id,
            "candidate_artifact_manifest_digest": (
                activation.bundle.candidate_artifact_manifest_digest
            ),
            "policy_digest": activation.bundle.policy_digest,
            "dataset_digest": activation.bundle.dataset_digest,
            "contract_digest": activation.bundle.contract_digest,
        }
        task_authority_projection = {
            "task_fact": current_task.model_dump(mode="json"),
            "canonical_payload": task_record.canonical_payload,
            "request_digest": task_record.request_digest,
            "expected_revision": task_record.expected_revision,
        }
        authority_digest = canonical_sha256(
            {
                "schema_version": "product-authority-anchor/1.0",
                "event_digest": materials.event_digest,
                "activation": {
                    "content_digest": activation.content_digest,
                    **activation_projection,
                },
                "runtime_binding": {
                    "runtime": binding.runtime,
                    "principal_id": binding.principal_id,
                    "agent_id": binding.agent_id,
                    "runtime_binding_id": binding.runtime_binding_id,
                    "actor_principal_id": binding.actor_principal_id,
                    "activation_ref_digest": binding.activation_ref_digest,
                    "source": binding.source,
                },
                "runtime_observation_digest": observations.observation_digest,
                "credential_digest": canonical_sha256(
                    credential.model_dump(mode="json")
                ),
                "policy_revision": policy_record.revision,
                "policy_digest": policy_digest,
                "task_authority_digest": canonical_sha256(task_authority_projection),
                "state_authority_digest": state_authority_digest,
                "snapshot_digest": current_snapshot.snapshot_digest,
                "revoked_grant_ids": current_revoked,
            }
        )
        return _ProductAuthorityCapture(
            state_version=current_snapshot.state_version,
            task_digest=current_task.task_digest,
            policy_digest=policy_digest,
            snapshot_digest=current_snapshot.snapshot_digest,
            authority_digest=authority_digest,
            replay_authority_digest=_product_replay_authority_digest(
                event_digest=materials.event_digest,
                activation_content_digest=activation.content_digest,
                activation_projection=activation_projection,
                runtime_binding=binding,
                runtime_observation_digest=(observations.authority_observation_digest),
                credential_projection=credential.model_dump(mode="json"),
                policy_revision=policy_record.revision,
                policy_digest=policy_digest,
                task_authority_projection=task_authority_projection,
            ),
            checked_at=checked_at,
        )

    # ------------------------------------------------------------------
    # Phase B：短事务内消费材料
    # ------------------------------------------------------------------

    def build_phase_b(
        self, event: GuardEvent, materials: V21PipelineMaterials
    ) -> V21PhaseBOutcome | None:
        """Phase B（D4：由 evaluation 编排在 evaluation_transaction 内调用）。

        Legacy 分支只做轻量 re-read（state version / task head / policy
        digest）与纯函数 revalidate / 证据构建，保持原有 D8 stale 与
        异常收敛语义。Product 分支在 store-native authority fence 内
        严格重读完整有界 authority，并把任何异常映射为稳定 503；不会
        产生 current fallback。
        """

        try:
            return self._build_phase_b(event, materials)
        except V21OfficialEvaluationUnavailableError:
            raise
        except RuntimeBindingResolutionError as exc:
            self._raise_runtime_binding_error(exc)
        except Exception as exc:  # noqa: BLE001 - mode-specific boundary.
            self._raise_if_active("V21_OFFICIAL_PHASE_B_FAILED", exc)
            logger.warning(
                "v21 pipeline phase B failed for event %s; v21 evidence "
                "omitted, legacy chain unaffected",
                event.event_id,
                exc_info=True,
            )
            return None

    def _build_phase_b(
        self, event: GuardEvent, materials: V21PipelineMaterials
    ) -> V21PhaseBOutcome | None:
        if self._runtime_binding_resolver.product_active:
            if (
                materials.event_id != event.event_id
                or materials.event_digest
                != canonical_sha256(event.model_dump(mode="json"))
            ):
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            if materials.phase_a_payload_digest != _phase_a_payload_digest(
                bundle=materials.bundle,
                policy_revision=materials.policy_revision,
                decision=materials.decision,
                detection_results=materials.detection_results,
                snapshot=materials.snapshot,
                state_version=materials.state_version,
                revoked_grant_ids=materials.revoked_grant_ids,
                clock=materials.clock,
                task_id=materials.task_id,
                scope_digest=materials.scope_digest,
                degraded_kind=materials.degraded_kind,
                state_authority_digest=materials.state_authority_digest,
                auth_context=materials.auth_context,
                runtime_binding=materials.runtime_binding,
            ):
                raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID)
            if materials.phase_a_output_digest != _phase_a_output_digest(
                phase_a_payload_digest=materials.phase_a_payload_digest,
                assessment=materials.assessment,
                coverage=materials.coverage,
                action_ir=materials.action_ir,
                consumed_overlay_digest=materials.consumed_overlay_digest,
                semantic_judgment=materials.semantic_judgment,
            ):
                raise RuntimeBindingResolutionError(PRODUCT_TASK_SCOPE_INVALID)
            if materials.runtime_binding is None:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            # The same immutable resolution produced in Phase A is checked
            # again immediately before revalidation/finalize. Expiry or an
            # entry mismatch cannot fall back to legacy-derived authority.
            self._runtime_binding_resolver.revalidate(materials.runtime_binding)
            if materials.snapshot is None or materials.snapshot.task is None:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            current_binding = self._runtime_binding_resolver.resolve_evaluation(
                materials.auth_context,
                event=event,
                task_principal_id=materials.snapshot.task.principal_id,
            )
            if current_binding != materials.runtime_binding:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
        if materials.snapshot is None:
            if self._runtime_binding_resolver.product_active:
                raise RuntimeBindingResolutionError(PRODUCT_TASK_IDENTITY_MISMATCH)
            # snapshot 缺态降级路径：无五元组锚点可比对，直接产出信封
            # （degraded_no_snapshot / degraded_component_failure 语义
            # 由 assessment 自带降级决定，与 V21-08 逐字节一致）。
            evidence = build_decision_evidence_v21(
                materials.assessment,
                legacy_decision=materials.decision.decision,
                snapshot_id=ABSENT_SNAPSHOT_ID,
                state_version=0,
                coverage=materials.coverage,
            )
            raw_v21_decision = GuardEngine().finalize(materials.assessment)
            raw_v21_decision_digest = canonical_sha256(
                raw_v21_decision.model_dump(mode="json")
            )
            return V21PhaseBOutcome(
                envelope=decision_evidence_v21_envelope(evidence),
                revalidation=RevalidationResult(status="valid"),
                materials=materials,
                raw_v21_decision=raw_v21_decision,
                final_decision_id=raw_v21_decision.decision_id,
                final_decision_digest=raw_v21_decision_digest,
            )

        assert materials.scope_digest is not None
        product_capture: _ProductAuthorityCapture | None = None
        if self.product_active:
            # Product consumes the complete strict authority anchor.  Any
            # mismatch is a 503 availability failure, never ordinary shadow
            # stale evidence and never a legacy/current fallback.
            product_capture = self._capture_product_authority(event, materials)
            current_state_version = product_capture.state_version
            current_task_digest = product_capture.task_digest
            current_policy_digest = product_capture.policy_digest
            current_snapshot_digest = product_capture.snapshot_digest
        else:
            # Compatibility path retains the original scalar re-read and stale
            # evidence semantics byte-for-byte.
            state_record = self._store.get_security_state(materials.scope_digest)
            current_state_version = (
                state_record.state_version if state_record is not None else -1
            )
            task_record = (
                self._store.get_task_fact(materials.task_id)
                if materials.task_id is not None
                else None
            )
            current_task = task_record.task_fact if task_record is not None else None
            current_task_digest = (
                current_task.task_digest if current_task is not None else None
            )
            current_policy_digest = canonical_sha256(
                self._policy_service.current_snapshot().model_dump(mode="json")
            )
            # snapshot digest 派生口径：state version 未变 → snapshot 结构性
            # 输入（state/task/policy/clock/plan）均未变，digest 恒等于评估
            # 时点值；版本漂移 → 哨兵必然触发 stale（不重建 snapshot，S8）。
            current_snapshot_digest = (
                materials.assessment.snapshot_digest
                if current_state_version == materials.state_version
                else _SNAPSHOT_DRIFT_SENTINEL
            )

        revalidation = revalidate_assessment(
            materials.assessment,
            assessment_state_version=materials.state_version,
            current_state_version=current_state_version,
            current_task_digest=current_task_digest,
            current_policy_digest=current_policy_digest,
            current_snapshot_digest=current_snapshot_digest,
        )
        if self.product_active and revalidation.status != "valid":
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        stale_codes = (
            list(revalidation.reason_codes) if revalidation.status == "stale" else []
        )
        # V21-13 Stage 1 shadow 双门禁（fail-closed）：judgment 在场时
        # 先经 core 纯函数 ``validate_semantic_binding`` 五 digest 比对
        # （reference_time 取 materials.clock.evaluated_at——权威时钟
        # 锚点，禁 wall-clock）；仅当 binding 有效且 revalidation valid
        # 时才把 judgment 身份/摘要填进证据槽（03 §14：binding
        # invalid/stale → 保守 ASK，证据面同样不登记）。
        semantic_binding_valid: bool | None = None
        semantic_for_evidence: "SemanticJudgment | None" = None
        if materials.semantic_judgment is not None:
            semantic_binding_valid = validate_semantic_binding(
                materials.assessment,
                materials.semantic_judgment,
                reference_time=materials.clock.evaluated_at,
            )
            if semantic_binding_valid and revalidation.status == "valid":
                semantic_for_evidence = materials.semantic_judgment
            else:
                logger.info(
                    "v21-13 semantic judgment not consumed for event %s "
                    "(binding_valid=%s, revalidation=%s); shadow evidence "
                    "slots stay empty (fail-closed)",
                    event.event_id,
                    semantic_binding_valid,
                    revalidation.status,
                )
        evidence = build_decision_evidence_v21(
            materials.assessment,
            legacy_decision=materials.decision.decision,
            snapshot_id=materials.snapshot.snapshot_id,
            state_version=materials.state_version,
            coverage=materials.coverage,
            revalidation_stale_reason_codes=stale_codes,
            semantic=semantic_for_evidence,
        )
        raw_v21_decision: GuardDecision | None = None
        final_decision_id: str | None = None
        final_decision_digest: str | None = None
        if revalidation.status == "valid":
            # D11：§15 第 5 步 finalize 在 revalidate valid 分支产出；
            # decision_id 经 derive_final_decision_id 确定性派生
            # （GuardEngine.finalize 内部同口径，禁 uuid）；产物以
            # 确定性引用留存审计 metadata，完整 GuardDecision 不落
            # 审计。stale/降级路径不产引用（恒 None）。
            raw_v21_decision = GuardEngine().finalize(materials.assessment)
            final_decision_id = raw_v21_decision.decision_id
            final_decision_digest = canonical_sha256(
                raw_v21_decision.model_dump(mode="json")
            )
        return V21PhaseBOutcome(
            envelope=decision_evidence_v21_envelope(evidence),
            revalidation=revalidation,
            materials=materials,
            raw_v21_decision=raw_v21_decision,
            final_decision_id=final_decision_id,
            final_decision_digest=final_decision_digest,
            semantic_binding_valid=semantic_binding_valid,
            product_authority_digest=(
                product_capture.authority_digest
                if product_capture is not None
                else None
            ),
            product_authority_initial_checked_at=(
                product_capture.checked_at.isoformat()
                if product_capture is not None
                else None
            ),
            product_replay_authority_digest=(
                product_capture.replay_authority_digest
                if product_capture is not None
                else None
            ),
        )

    # ------------------------------------------------------------------
    # Phase C：事务提交后投影（T3；commit → project，02 §3）
    # ------------------------------------------------------------------

    def prepare_phase_c(self, outcome: V21PhaseBOutcome) -> V21PhaseCPlan | None:
        """Phase B 确定性构造 Phase C 投影计划（仍在事务窗口内调用）。

        返回 None 的语义（均不产 state_delta_v21 信封、不进入 Phase C）：

        - ``revalidation.status == "stale"``：D8 放弃权威提交，stale
          不进入 Phase C（任务约束）；
        - snapshot 缺态降级路径（无权威 scope，禁伪造，01 §25）。

        有效时：``audit_id`` 以 ``derive_final_audit_id(assessment)``
        确定性派生（T1 预留消费点；assessment 身份含 event_id，同
        event 幂等短路下无碰撞）；delta 以 materials 的 state_version
        为 base 构造（信封 delta_digest 冻结时刻即真实，见
        ``V21PhaseCPlan`` 裁决留痕）。
        """

        materials = outcome.materials
        if outcome.revalidation.status != "valid":
            return None
        if materials.scope_digest is None or materials.snapshot is None:
            return None
        audit_id = derive_final_audit_id(materials.assessment)
        delta = build_evaluation_delta(
            scope_digest=materials.scope_digest,
            audit_id=audit_id,
            base_state_version=materials.state_version,
        )
        # D2 引用信封：只存投影身份（projection_id / delta_digest /
        # source identity），全量 delta 本体随 projection_records。
        reference = {
            "projection_id": delta.projection_id,
            "delta_digest": delta.delta_digest,
            "source_record_type": delta.source.source_record_type,
            "source_record_id": delta.source.source_record_id,
            "source_revision": delta.source.source_revision,
        }
        return V21PhaseCPlan(
            audit_id=audit_id,
            scope_digest=materials.scope_digest,
            delta=delta,
            envelope=state_delta_v21_envelope(reference),
            precommit_reserved=self.product_active,
        )

    def finalize_product_commit(
        self,
        event: GuardEvent,
        materials: V21PipelineMaterials,
        *,
        audit_id: str,
        phase_c_plan: V21PhaseCPlan | None,
        expected_authority_digest: str | None,
        initial_authority_checked_at: str | None,
    ) -> None:
        """Perform the final Product check and reserve commit→project.

        This is deliberately one last application call inside the Product
        transaction.  It re-captures the complete authority anchor after all
        staged side effects, then atomically pre-registers the exact Phase-C
        envelope alongside the audit commit.  The online-state CAS still runs
        only after commit; the reservation makes a concurrent same-scope
        strict read fail closed instead of committing against the same anchor.
        """

        if not self.product_active:
            return
        if expected_authority_digest is None or initial_authority_checked_at is None:
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        try:
            first_checked_at = datetime.fromisoformat(
                initial_authority_checked_at.replace("Z", "+00:00")
            )
            if first_checked_at.tzinfo is None or first_checked_at.utcoffset() is None:
                raise ValueError("initial_authority_checked_at must be timezone-aware")
        except (TypeError, ValueError) as exc:
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_AUTHORITY_NOT_CURRENT
            ) from exc

        try:
            capture = self._capture_product_authority(event, materials)
        except V21OfficialEvaluationUnavailableError:
            raise
        except RuntimeBindingResolutionError as exc:
            self._raise_runtime_binding_error(exc)
        except Exception as exc:  # noqa: BLE001 - stable final 503 boundary.
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_AUTHORITY_NOT_CURRENT
            ) from exc
        if (
            capture.authority_digest != expected_authority_digest
            or capture.checked_at < first_checked_at.astimezone(timezone.utc)
            or phase_c_plan is None
            or phase_c_plan.audit_id != audit_id
            or not phase_c_plan.precommit_reserved
            or phase_c_plan.scope_digest != materials.scope_digest
            or phase_c_plan.delta.base_state_version != materials.state_version
            or phase_c_plan.delta.new_state_version != materials.state_version + 1
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)
        audit = self._store.get_audit_event(audit_id)
        if (
            audit is None
            or audit.record_type != "policy_evaluation"
            or audit.links.get("event_id") != event.event_id
            or audit.metadata.get("product_replay_authority_digest")
            != capture.replay_authority_digest
        ):
            raise V21OfficialEvaluationUnavailableError(PRODUCT_AUTHORITY_NOT_CURRENT)

        # The strict reader and bounded rebuild deliberately reject a history
        # whose returned size reaches MAX_REBUILD_INPUT_LIMIT because they can
        # no longer prove that the read is complete.  Prove headroom for this
        # new reservation *before* it commits: 998 existing rows may become
        # 999, but 999 may not become the ambiguous/truncated 1000th row.  The
        # Product transaction already holds the scope's state/projection lock,
        # so this count-by-bounded-read and the insert are one authority view.
        existing_history = self._store.list_rebuild_inputs(
            phase_c_plan.scope_digest,
            limit=MAX_REBUILD_INPUT_LIMIT,
        )
        if len(existing_history) >= MAX_REBUILD_INPUT_LIMIT - 1:
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            )

        reservation = ProjectionIdentityRecord(
            scope_digest=phase_c_plan.scope_digest,
            source_record_type=phase_c_plan.delta.source.source_record_type,
            source_record_id=phase_c_plan.delta.source.source_record_id,
            source_revision=phase_c_plan.delta.source.source_revision,
            projector_version=phase_c_plan.delta.projector_version,
            delta_digest=phase_c_plan.delta.delta_digest,
            delta_payload=phase_c_plan.delta.model_dump(mode="json"),
            applied_state_version=phase_c_plan.delta.new_state_version,
            created_at=capture.checked_at.isoformat(),
        )
        try:
            _stored, created = self._store.record_projection(reservation)
        except Exception as exc:  # noqa: BLE001 - stable Product boundary.
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            ) from exc
        if not created:
            raise V21OfficialEvaluationUnavailableError(
                PRODUCT_SECURITY_STATE_NOT_READY
            )

    def run_phase_c(self, plan: V21PhaseCPlan | None) -> None:
        """Phase C（D4：evaluation_transaction 提交**之后**调用）。

        投影失败 / stale / CAS 冲突一律 fail-closed 收敛（告警 +
        projector 既有 dirty 语义），**绝不影响已返回的响应与审计
        记录**；不重试（D9：replay 幂等补投影承接；重试/对账机制归
        V21-10/11）。**绝不外抛**。
        """

        if plan is None:
            return
        try:
            self._project_evaluation(plan)
        except Exception:  # noqa: BLE001 - 投影故障必须收敛，绝不上抛。
            logger.warning(
                "v21-09 evaluation projection failed for audit %s; "
                "response and audit record are unaffected (fail-closed, "
                "no retry; D9 replay backfill / V21-10 reconciliation)",
                plan.audit_id,
                exc_info=True,
            )

    def _project_evaluation(self, plan: V21PhaseCPlan) -> None:
        """commit → project 锁内编排（照搬 approval 范本锁序）。

        新的 legacy envelope 保持原有 ensure_ready → base 校验纪律；
        base 漂移仍 fail-closed 跳过且不 rebase。若 exact projection
        envelope 已存在（Product precommit reservation 或 crash-window
        replay），则直接交给 ``project_committed`` 的幂等/重建分支：它
        会区分已反映 no-op、尚未反映 apply、以及其他 projector 已推进
        时的 bounded rebuild，避免 reservation 永久卡住 strict reader。
        """

        scope_digest = plan.scope_digest
        committed_record = CommittedRecord(
            record_id=f"policy-evaluation:{plan.audit_id}",
            committed=True,
            source_record_type="policy_evaluation",
            source_record_id=plan.audit_id,
            source_revision=_EVALUATION_SOURCE_REVISION,
            scope_digest=scope_digest,
            projector_version=PROJECTOR_VERSION,
            delta=plan.delta,
        )
        # Audit records are append-only.  Verify that source before acquiring
        # either the local scope lock or the backend state transaction, then
        # pass a pure identity check to the projector.  In particular, never
        # read the audit store while holding the Memory state lock: legacy
        # evaluation holds audit before reading state, so state -> audit here
        # would invert that established order and could deadlock mixed-mode
        # services sharing one store.
        source_committed = self._verify_evaluation_committed(committed_record)

        def verify_prechecked_source(record: CommittedRecord) -> bool:
            return source_committed and all(
                (
                    record.committed,
                    record.record_id == committed_record.record_id,
                    record.source_record_type == committed_record.source_record_type,
                    record.source_record_id == committed_record.source_record_id,
                    record.source_revision == committed_record.source_revision,
                    record.scope_digest == committed_record.scope_digest,
                    record.projector_version == committed_record.projector_version,
                    record.delta == committed_record.delta,
                )
            )

        with self._state_service.store_access.scope_lock(scope_digest):
            store_transaction = (
                self._state_service.store_access.transaction(scope_digest)
                if plan.precommit_reserved
                else nullcontext()
            )
            with store_transaction:
                existing = self._state_service.store_access.get_projection(
                    scope_digest,
                    plan.delta.source.source_record_type,
                    plan.delta.source.source_record_id,
                    plan.delta.source.source_revision,
                    plan.delta.projector_version,
                )
                if plan.precommit_reserved:
                    # The normal path already has this row.  Re-recording is
                    # an exact idempotency/digest check and also lets D9 repair
                    # a deleted/missing reservation from the committed audit.
                    self._state_service.store_access.record_projection(
                        ProjectionIdentityRecord(
                            scope_digest=scope_digest,
                            source_record_type=(plan.delta.source.source_record_type),
                            source_record_id=plan.delta.source.source_record_id,
                            source_revision=plan.delta.source.source_revision,
                            projector_version=plan.delta.projector_version,
                            delta_digest=plan.delta.delta_digest,
                            delta_payload=plan.delta.model_dump(mode="json"),
                            applied_state_version=plan.delta.new_state_version,
                            created_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                    # Rebuild while the backend's exclusive scope transaction
                    # remains held.  This absorbs both the Product reservation
                    # and any foreign envelope whose producer crashed before
                    # its state CAS; no projection history can interleave.
                    self._state_service.reconcile_projection_history(scope_digest)
                elif existing is None:
                    self._state_service.ensure_ready(scope_digest)
                    current = self._state_service.store_access.get_security_state(
                        scope_digest
                    )
                    # S2 缺态哨兵口径统一（与 Phase B 同为 -1）：
                    # ensure_ready 后 current 正常必在场；-1 不与任何真实
                    # state_version（empty state 初始为 0）碰撞。
                    base_state_version = (
                        current.state_version if current is not None else -1
                    )
                    if base_state_version != plan.delta.base_state_version:
                        # Compatibility branch: the envelope has not been
                        # reserved, so rebase would invalidate its audited
                        # digest.
                        PHASE_C_BASE_DRIFT_SKIPS["count"] += 1
                        logger.warning(
                            "v21-09 evaluation projection skipped for audit %s: "
                            "base state version drifted (%s -> %s); fail-closed "
                            "without dirtying "
                            "(v21_phase_c_skip_reason=base_drift, "
                            "v21_phase_c_skip_total=%s; V21-10 reconciliation "
                            "owns it)",
                            plan.audit_id,
                            plan.delta.base_state_version,
                            base_state_version,
                            PHASE_C_BASE_DRIFT_SKIPS["count"],
                        )
                        return
                result = self._state_service.project_committed(
                    committed_record,
                    scope_digest=scope_digest,
                    verify_source_committed=verify_prechecked_source,
                )
        logger.info(
            "v21-09 evaluation projection %s for audit %s (state_version=%s)",
            result.outcome,
            plan.audit_id,
            result.state_version,
        )

    def _verify_evaluation_committed(self, record: CommittedRecord) -> bool:
        """``verify_source_committed`` 钩子（F0-8）：复核审计记录存在性。

        policy_evaluation 审计记录已在 evaluation_transaction 内 commit
        （commit→project 时序前置）；查不到 / record_type 不符即拒绝
        投影，未提交记录不得成为后续历史状态。本读取必须发生在任何
        state/scope 锁之前；调用方随后只可把结果封装成无 I/O verifier。
        """

        audit = self._store.get_audit_event(record.source_record_id)
        return audit is not None and audit.record_type == "policy_evaluation"

    # ------------------------------------------------------------------
    # D9：replay 幂等补投影
    # ------------------------------------------------------------------

    def backfill_projection(self, audit: AuditEvent) -> None:
        """D9 replay 补投影：不重算 assess/semantic，仅幂等补投影。

        判定口径：审计 evidence 存在 ``state_delta_v21`` 信封即“当时
        revalidation valid 且 scope 在场”的直接标志（信封仅在
        ``prepare_phase_c`` 成功时写入）；无信封（mode off 存量 /
        降级 / stale）→ 不补。补投影材料全部自审计记录重建（不重
        算）：``metadata.task_id`` → 权威 active TaskFact →
        scope_digest；``decision_v21`` payload 的 state_version →
        重建 delta → digest 与信封引用比对（失真即跳过留痕）；五元
        组幂等键短路保证重复安全。无法补（缺材料）→ 静默跳过留痕。
        **绝不外抛**。
        """

        if not self.enabled:
            return
        try:
            self._backfill_projection(audit)
        except Exception:  # noqa: BLE001 - 补投影故障必须收敛，绝不上抛。
            logger.warning(
                "v21-09 replay projection backfill failed for audit %s; "
                "replayed response is unaffected (fail-closed)",
                audit.audit_id,
                exc_info=True,
            )

    def _backfill_projection(self, audit: AuditEvent) -> None:
        evidence = audit.evidence if isinstance(audit.evidence, dict) else {}
        delta_envelope = evidence.get("state_delta_v21")
        if not isinstance(delta_envelope, dict):
            # 无信封：当时未产生投影计划（mode off / 降级 / stale），
            # 无补投影可做，静默返回。
            return
        reference = delta_envelope.get("payload")
        if not isinstance(reference, dict):
            return
        expected_digest = reference.get("delta_digest")
        source_record_id = reference.get("source_record_id")
        source_record_type = reference.get("source_record_type")
        raw_revision = reference.get("source_revision")
        if (
            not isinstance(expected_digest, str)
            or not isinstance(source_record_id, str)
            or source_record_id != audit.audit_id
            or source_record_type != "policy_evaluation"
            or not isinstance(raw_revision, int)
            or isinstance(raw_revision, bool)
            or raw_revision != _EVALUATION_SOURCE_REVISION
        ):
            logger.info(
                "v21-09 replay projection backfill skipped for audit %s: "
                "state_delta_v21 reference malformed (missing materials)",
                audit.audit_id,
            )
            return

        # scope 重建：metadata.task_id → 权威 active TaskFact（仿
        # approval 同源口径，绝不伪造 scope）。
        task_id = audit.metadata.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            logger.info(
                "v21-09 replay projection backfill skipped for audit %s: "
                "no task_id in audit metadata (missing materials)",
                audit.audit_id,
            )
            return
        task_record = self._store.get_task_fact(task_id)
        if task_record is None or task_record.task_fact.status != "active":
            logger.info(
                "v21-09 replay projection backfill skipped for audit %s: "
                "no active authoritative TaskFact for %s (missing "
                "materials)",
                audit.audit_id,
                task_id,
            )
            return
        scope_digest = task_record.task_fact.scope_digest
        product_precommit_reserved = all(
            isinstance(audit.metadata.get(field), str)
            for field in (
                "product_authority_digest",
                "product_authority_initial_checked_at",
            )
        )

        # Preserve the compatibility D9 contract: an already registered
        # legacy five-tuple is a zero-projector replay.  Product reservations
        # are different because the row may have committed before its state
        # CAS; they must continue through the full reconcile/repair path.
        existing_projection = self._state_service.store_access.get_projection(
            scope_digest,
            "policy_evaluation",
            source_record_id,
            raw_revision,
            PROJECTOR_VERSION,
        )
        if existing_projection is not None and not product_precommit_reserved:
            return

        # delta 重建：decision_v21 payload 的 state_version 即当时
        # base（与 Phase B 构造同源）。
        decision_envelope = evidence.get("decision_v21")
        decision_payload = (
            decision_envelope.get("payload")
            if isinstance(decision_envelope, dict)
            else None
        )
        raw_state_version = (
            decision_payload.get("state_version")
            if isinstance(decision_payload, dict)
            else None
        )
        if not isinstance(raw_state_version, int) or isinstance(
            raw_state_version, bool
        ):
            logger.info(
                "v21-09 replay projection backfill skipped for audit %s: "
                "decision_v21 payload carries no state_version (missing "
                "materials)",
                audit.audit_id,
            )
            return
        delta = build_evaluation_delta(
            scope_digest=scope_digest,
            audit_id=source_record_id,
            base_state_version=raw_state_version,
        )
        if delta.delta_digest != expected_digest:
            # 信封引用与重建结果失真：不得静默覆盖，跳过留痕。
            logger.warning(
                "v21-09 replay projection backfill skipped for audit %s: "
                "rebuilt delta digest does not match the envelope "
                "reference (fail-closed)",
                audit.audit_id,
            )
            return

        # 与 Phase C 同一锁序：base 校验 → project_committed。
        plan = V21PhaseCPlan(
            audit_id=source_record_id,
            scope_digest=scope_digest,
            delta=delta,
            envelope=delta_envelope,
            precommit_reserved=product_precommit_reserved,
        )
        self._project_evaluation(plan)
