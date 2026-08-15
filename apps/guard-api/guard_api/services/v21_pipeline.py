"""V21-09 四段式编排 pipeline（shadow-only，flag 默认关闭）。

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
  在 ``evaluation_transaction`` 内调用：legacy 链照常 + 轻量 re-read
  （state version / task head / policy digest）→ ``revalidate_assessment``
  五元组 CAS → 证据构建；stale → 放弃本次 V21-09 权威提交、证据按 D8 记
  ``degraded_stale_judgment``，legacy 主链不受影响；
- **Phase C（事务提交后投影）**：``run_phase_c`` —— Phase B audit
  commit 成功且事务退出后（02 §3 commit→project 时序：投影在事务
  外），flag on 且 revalidation valid 时 scope_lock 内
  ensure_ready → base 校验 → ``project_committed``（verify 钩子复核
  审计记录存在性，F0-8）；delta 在 Phase B 以 materials 的
  state_version 为 base 确定性构造（信封 delta_digest 冻结时刻即真实，
  见 ``prepare_phase_c``），Phase C 锁内 base 漂移 → fail-closed
  跳过**不置脏**；投影失败一律告警收敛、不重试（D9：replay 补投影
  承接；重试/对账机制归 V21-10/11）；stale → 不进入 Phase C；
- **audit**：T5 既有 ``evidence.decision_v21`` 同条记录写面；V21-09
  追加 ``evidence.state_delta_v21`` 引用信封（D2：只存投影身份，全量
  delta 随 projection_records）。

与 ``v21_shadow.py``（V21-08 编排器）的关系（T2 处置裁决）：pipeline
吸收四段式编排主路径；``V21ShadowService`` 保留为 Phase A 彻底失败
（``run_phase_a`` 返回 None）时的逐字节降级回退路径——其降级信封形状
与 V21-08 完全一致，flag off 时两者均零行为变化。

降级收敛范式（V21-08 既有）：全链路异常不外抛、绝不影响 legacy
decision / approval / audit 主链；Phase A 不可恢复异常 → 返回 None
（调用方回退 V21-08 路径）；Phase B 异常 → 返回 None（本次评估不产
v21 证据，legacy 照常）。
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from agentguard_core import (
    AuditEvent,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
)
from agentguard_core.actions.canonical_json import canonical_sha256
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
)
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_ID,
    shadow_assess_with_coverage,
)
from agentguard_core.security_context.snapshot import SecuritySnapshot
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)

from guard_api.security_state import SecurityStateService
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import ControlPlaneStore

from .policy import PolicyService
from .v21_shadow import (
    REASON_SNAPSHOT_READ_FAILED,
    _recategorize_shadow_degradation,
    _task_claim,
)

if TYPE_CHECKING:
    from agentguard_core.semantic.models import SemanticJudgment

logger = logging.getLogger(__name__)

__all__ = [
    "PIPELINE_CLOCK_VERSION",
    "V21PhaseBOutcome",
    "V21PhaseCPlan",
    "V21PipelineMaterials",
    "V21PipelineService",
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

#: Phase B state version 漂移时的 snapshot digest 哨兵：版本已变则
#: snapshot 必然漂移，无需重建 snapshot 求 digest（事务内禁止 snapshot
#: I/O，S8）；哨兵与任何真实 digest（sha256: 前缀）不碰撞，必然触发
#: stale_snapshot_digest，fail-closed。
_SNAPSHOT_DRIFT_SENTINEL = "v21-09:snapshot_drift"

#: 无权威 policy snapshot record 时的确定性 revision 占位（与 V21-08
#: shadow 同口径纪律，值独立归因 pipeline）。
_UNVERSIONED_POLICY_REVISION = "v21-09:unversioned"

#: policy_evaluation 权威记录无 revision 链（同 event 幂等唯一）：
#: 投影身份五元组中的 source_revision 固定为 1（确定性，禁 uuid；
#: 仿 approval ``_APPROVAL_SOURCE_REVISION`` 口径）。
_EVALUATION_SOURCE_REVISION = 1


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
class V21PipelineMaterials:
    """Phase A 事务外产出（Phase B 短事务消费材料）。

    snapshot 为 None 时 ``degraded_kind`` 标注降级语义（assessment 为
    snapshot 缺态路径产物）；正常路径 ``degraded_kind`` 为 None。
    ``decision`` 是 Phase A 单跑的 legacy 官方决策完整对象（Phase B
    事务内直接消费，不双跑检测器）。
    """

    event_id: str
    bundle: PolicyBundle
    policy_revision: str | None
    decision: GuardDecision
    detection_results: Sequence[DetectionResult]
    snapshot: SecuritySnapshot | None
    state_version: int
    revoked_grant_ids: list[str]
    assessment: FastAssessment
    coverage: CoverageMap
    clock: EvaluationClock
    task_id: str | None
    scope_digest: str | None
    degraded_kind: PhaseADegradedKind | None


@dataclass(frozen=True)
class V21PhaseBOutcome:
    """Phase B 产物：decision_v21 信封 + revalidation 结论 + 材料回溯。

    T3 消费形态：stale（``revalidation.status == "stale"``）时放弃
    V21-09 权威提交与 Phase C 投影；valid 时信封可直接供审计落盘，
    经 ``prepare_phase_c`` 产出 Phase C 投影计划与 state_delta_v21
    引用信封。
    """

    envelope: dict[str, Any]
    revalidation: RevalidationResult
    materials: V21PipelineMaterials


@dataclass(frozen=True)
class V21PhaseCPlan:
    """Phase C 投影计划（Phase B 确定性构造，事务提交后消费）。

    Design 裁决（契约歧义留痕）：任务字面“Phase C 内构造 delta”与
    D2“信封（含 delta_digest）必须在 Phase B audit commit 时写入”
    存在时序张力——delta_digest 白名单含 base_state_version，若
    Phase C 才构造则 Phase B 信封无法持有真实 digest。故 delta 在
    Phase B 以 materials 的 state_version 为 base 确定性构造（信封
    引用真实）；Phase C 锁内复核 base，漂移则 fail-closed 跳过不置
    脏（避免置脏扩散；D9 replay 补投影承接）。
    """

    audit_id: str
    scope_digest: str
    delta: SecurityStateDeltaV21
    #: D2 引用信封（07 §10 形状）：只含投影身份（projection_id /
    #: delta_digest / source identity），全量 delta 本体随
    #: projection_records，不内嵌审计证据。
    envelope: dict[str, Any]


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
    """V21-09 四段式编排器（shadow-only；只读旁路，绝不外抛）。

    构造即完成 flag / secret 解析（与 V21ShadowService 同一门控口径：
    复用 ``AGENTGUARD_V21_SHADOW_ENABLED`` 与 server secret 配置）；
    flag off 时 ``run_phase_a`` 仅一次布尔判断返回 None，零 I/O。
    """

    def __init__(
        self,
        *,
        settings: GuardApiSettings,
        store: ControlPlaneStore,
        state_service: SecurityStateService,
        policy_service: PolicyService,
        semantic_provider: Callable[[GuardEvent, FastAssessment], "SemanticJudgment | None"]
        | None = None,
    ) -> None:
        self._store = store
        self._state_service = state_service
        self._policy_service = policy_service
        # V21-13 预留钩子：位置在 assess 后、revalidate 前（天然事务外）。
        # V21-09 恒 None，零开销。
        self._semantic_provider = semantic_provider
        self._enabled = bool(settings.v21_shadow_enabled)
        self._server_secret = self._load_server_secret(settings)

    def _load_server_secret(self, settings: GuardApiSettings) -> bytes | None:
        """flag on 时解析 server secret；未配置/非法 → pipeline 禁用。

        与 V21ShadowService 同一口径：绝不硬编码兜底密钥；flag off 时
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

        return self._enabled and self._server_secret is not None

    # ------------------------------------------------------------------
    # Phase A：事务外只读
    # ------------------------------------------------------------------

    def run_phase_a(self, event: GuardEvent) -> V21PipelineMaterials | None:
        """Phase A（D4：evaluation_transaction **之前**执行）。

        返回 None 的语义：flag/secret 门控未就绪，或 Phase A 不可恢复
        异常——调用方（evaluation 编排）据此回退 V21-08 逐字节路径
        （``V21ShadowService``）。**绝不外抛**。
        """

        if not self.enabled:
            return None
        try:
            return self._run_phase_a(event)
        except Exception:  # noqa: BLE001 - 旁路故障必须收敛，绝不上抛。
            logger.warning(
                "v21 pipeline phase A failed for event %s; falling back "
                "to V21-08 shadow path",
                event.event_id,
                exc_info=True,
            )
            return None

    def _run_phase_a(self, event: GuardEvent) -> V21PipelineMaterials | None:
        assert self._server_secret is not None

        # 策略解析与 legacy 单跑（detection 不双跑：decision 与
        # detection_results 存入材料供 Phase B 直接消费）。
        snapshot_record = self._policy_service.current_snapshot_record()
        if snapshot_record is not None:
            bundle = snapshot_record.policy_bundle
            policy_revision: str | None = str(snapshot_record.revision)
        else:
            bundle = self._policy_service.current_snapshot()
            policy_revision = None
        decision, detection_results = GuardEngine().evaluate_with_results(
            event, bundle
        )

        clock = EvaluationClock(
            evaluated_at=event.timestamp,
            clock_version=PIPELINE_CLOCK_VERSION,
        )

        try:
            resolved = self._resolve_snapshot_v(event, bundle, clock, policy_revision)
        except Exception:  # noqa: BLE001 - snapshot 读取失败 → 组件降级。
            logger.warning(
                "v21 pipeline phase A snapshot read failed for event %s",
                event.event_id,
                exc_info=True,
            )
            outcome = shadow_assess_with_coverage(
                event,
                bundle,
                None,
                server_secret=self._server_secret,
                detection_results=detection_results,
            )
            assessment = _recategorize_shadow_degradation(
                outcome.assessment, reason_code=REASON_SNAPSHOT_READ_FAILED
            )
            return V21PipelineMaterials(
                event_id=event.event_id,
                bundle=bundle,
                policy_revision=policy_revision,
                decision=decision,
                detection_results=list(detection_results),
                snapshot=None,
                state_version=0,
                revoked_grant_ids=[],
                assessment=assessment,
                coverage=outcome.coverage,
                clock=clock,
                task_id=_task_claim(event),
                scope_digest=None,
                degraded_kind="component_failure",
            )

        snapshot, revoked_grant_ids, task_id, scope_digest = resolved
        if snapshot is None:
            # 无 task 引用 / claim 无权威 TaskFact：degraded_no_snapshot
            # 语义（V21-08 行为保持，禁伪造 Snapshot，01 §25）。
            outcome = shadow_assess_with_coverage(
                event,
                bundle,
                None,
                server_secret=self._server_secret,
                detection_results=detection_results,
            )
            return V21PipelineMaterials(
                event_id=event.event_id,
                bundle=bundle,
                policy_revision=policy_revision,
                decision=decision,
                detection_results=list(detection_results),
                snapshot=None,
                state_version=0,
                revoked_grant_ids=list(revoked_grant_ids),
                assessment=outcome.assessment,
                coverage=outcome.coverage,
                clock=clock,
                task_id=task_id,
                scope_digest=scope_digest,
                degraded_kind="snapshot_absent",
            )

        # 正常路径：正式 Core 内核 assess（与 GuardEngine.assess 共享
        # _assess_kernel，逐字节 parity；with_coverage 形态仅为同源
        # 透出 coverage）；revoked 注入真实集（D3 同源同锁读取）。
        outcome = shadow_assess_with_coverage(
            event,
            bundle,
            snapshot,
            server_secret=self._server_secret,
            detection_results=detection_results,
            revoked_grant_ids=revoked_grant_ids,
        )
        if self._semantic_provider is not None:
            # V21-09 恒 None 分支；钩子在 assess 后 revalidate 前，
            # 天然事务外（03 §12）。产物 V21-09 不消费，仅预留。
            self._semantic_provider(event, outcome.assessment)
        return V21PipelineMaterials(
            event_id=event.event_id,
            bundle=bundle,
            policy_revision=policy_revision,
            decision=decision,
            detection_results=list(detection_results),
            snapshot=snapshot,
            state_version=snapshot.state_version,
            revoked_grant_ids=list(revoked_grant_ids),
            assessment=outcome.assessment,
            coverage=outcome.coverage,
            clock=clock,
            task_id=task_id,
            scope_digest=scope_digest,
            degraded_kind=None,
        )

    def _resolve_snapshot_v(
        self,
        event: GuardEvent,
        bundle: PolicyBundle,
        clock: EvaluationClock,
        policy_revision: str | None,
    ) -> tuple[SecuritySnapshot | None, list[str], str | None, str | None]:
        """task claim → 权威 TaskFact head → scope → snapshot V + revoked。

        与 V21ShadowService._resolve_snapshot 同源口径升级：clock 正式化
        （D5）+ ``read_snapshot_with_revoked`` 同源同锁读取（D3）。
        返回 ``(snapshot, revoked, task_id, scope_digest)``；无 task
        引用/无权威 fact 时 snapshot 为 None。
        """

        task_id = _task_claim(event)
        if task_id is None:
            return None, [], None, None
        record = self._store.get_task_fact(task_id)
        if record is None:
            # trusted claim 无对应权威 TaskFact：不得据此构造 snapshot。
            return None, [], task_id, None
        task_fact = record.task_fact
        scope_digest = task_fact.scope_digest
        scope = SecurityStateScope(
            principal_id=task_fact.principal_id,
            runtime=event.runtime,
            runtime_binding_id=f"binding:{task_fact.principal_id}",
            trace_id=event.trace_id,
            session_id=event.security_context.session_id,
            scope_digest=scope_digest,
        )
        self._state_service.ensure_ready(scope_digest)
        snapshot, revoked = self._state_service.read_snapshot_with_revoked(
            scope_digest,
            scope=scope,
            task_fact_head=task_fact,
            evaluation_clock=clock,
            policy_revision=policy_revision or _UNVERSIONED_POLICY_REVISION,
            policy_digest=canonical_sha256(bundle.model_dump(mode="json")),
            plan=_pipeline_snapshot_plan(),
        )
        return snapshot, list(revoked), task_id, scope_digest

    # ------------------------------------------------------------------
    # Phase B：短事务内消费材料
    # ------------------------------------------------------------------

    def build_phase_b(
        self, event: GuardEvent, materials: V21PipelineMaterials
    ) -> V21PhaseBOutcome | None:
        """Phase B（D4：由 evaluation 编排在 evaluation_transaction 内调用）。

        只做轻量 re-read（state version / task head / policy digest）与
        纯函数 revalidate / 证据构建；**禁止 snapshot/task 全量 I/O**
        （S8 消除锚点）。stale → 信封按 D8 记 degraded_stale_judgment，
        legacy 主链不受影响。任何异常收敛为 None（本次不产 v21 证据）。
        """

        try:
            return self._build_phase_b(event, materials)
        except Exception:  # noqa: BLE001 - 旁路故障必须收敛，绝不上抛。
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
        if materials.snapshot is None:
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
            return V21PhaseBOutcome(
                envelope=decision_evidence_v21_envelope(evidence),
                revalidation=RevalidationResult(status="valid"),
                materials=materials,
            )

        assert materials.scope_digest is not None
        # 事务内轻量 re-read（03 §12 L462）：只取版本/digest 标量，
        # 不做 snapshot / task 全量往返。
        state_record = self._store.get_security_state(materials.scope_digest)
        current_state_version = (
            state_record.state_version if state_record is not None else -1
        )
        task_record = (
            self._store.get_task_fact(materials.task_id)
            if materials.task_id is not None
            else None
        )
        current_task_digest = (
            task_record.task_fact.task_digest if task_record is not None else None
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
        stale_codes = (
            list(revalidation.reason_codes)
            if revalidation.status == "stale"
            else []
        )
        evidence = build_decision_evidence_v21(
            materials.assessment,
            legacy_decision=materials.decision.decision,
            snapshot_id=materials.snapshot.snapshot_id,
            state_version=materials.state_version,
            coverage=materials.coverage,
            revalidation_stale_reason_codes=stale_codes,
        )
        return V21PhaseBOutcome(
            envelope=decision_evidence_v21_envelope(evidence),
            revalidation=revalidation,
            materials=materials,
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

        scope_lock(scope_digest) 内：ensure_ready → 读 base → base
        校验（漂移 → fail-closed 跳过**不置脏**：delta_digest 已在
        Phase B 冻结进审计信封，rebase 会使引用失真；置脏域最小化，
        D9 replay 补投影承接）→ ``project_committed``（verify 钩子
        复核审计记录存在性，F0-8）。
        """

        scope_digest = plan.scope_digest
        with self._state_service.store_access.scope_lock(scope_digest):
            self._state_service.ensure_ready(scope_digest)
            current = self._state_service.store_access.get_security_state(
                scope_digest
            )
            base_state_version = (
                current.state_version if current is not None else 0
            )
            if base_state_version != plan.delta.base_state_version:
                # base 漂移（Phase B→C 窗口内被其他投影推进）：信封
                # 引用已冻结，不 rebase、不重试、不置脏。
                logger.warning(
                    "v21-09 evaluation projection skipped for audit %s: "
                    "base state version drifted (%s -> %s); fail-closed "
                    "without dirtying (D9 replay backfill / V21-10)",
                    plan.audit_id,
                    plan.delta.base_state_version,
                    base_state_version,
                )
                return
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
            result = self._state_service.project_committed(
                committed_record,
                scope_digest=scope_digest,
                verify_source_committed=self._verify_evaluation_committed,
            )
        logger.info(
            "v21-09 evaluation projection %s for audit %s "
            "(state_version=%s)",
            result.outcome,
            plan.audit_id,
            result.state_version,
        )

    def _verify_evaluation_committed(self, record: CommittedRecord) -> bool:
        """``verify_source_committed`` 钩子（F0-8）：复核审计记录存在性。

        policy_evaluation 审计记录已在 evaluation_transaction 内 commit
        （commit→project 时序前置）；查不到 / record_type 不符即拒绝
        投影，未提交记录不得成为后续历史状态。
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
        ``prepare_phase_c`` 成功时写入）；无信封（flag off 存量 /
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
            # 无信封：当时未产生投影计划（flag off / 降级 / stale），
            # 无补投影可做，静默返回。
            return
        reference = delta_envelope.get("payload")
        if not isinstance(reference, dict):
            return
        expected_digest = reference.get("delta_digest")
        source_record_id = reference.get("source_record_id")
        raw_revision = reference.get("source_revision")
        source_revision = (
            raw_revision
            if isinstance(raw_revision, int) and not isinstance(raw_revision, bool)
            else _EVALUATION_SOURCE_REVISION
        )
        if not isinstance(expected_digest, str) or not isinstance(
            source_record_id, str
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

        # 五元组幂等键短路：已登记 → 无补投影可做。
        existing_projection = self._state_service.store_access.get_projection(
            scope_digest,
            "policy_evaluation",
            source_record_id,
            source_revision,
            PROJECTOR_VERSION,
        )
        if existing_projection is not None:
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
        )
        self._project_evaluation(plan)
