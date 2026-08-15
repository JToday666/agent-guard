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
- **Phase C（事务后投影）**：V21-09 shadow 期无权威提交，归 T3 预留；
- **audit**：T5 既有 ``evidence.decision_v21`` 同条记录写面，不改。

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

from agentguard_core import GuardDecision, GuardEngine, GuardEvent, PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.evidence import (
    CoverageMap,
    FastAssessment,
    RequiredCheckPlan,
)
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
    "V21PipelineMaterials",
    "V21PipelineService",
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
    V21-09 权威提交；valid 时信封可直接供审计落盘（V21-09 shadow 期
    到此为止，无权威 finalize 提交）。
    """

    envelope: dict[str, Any]
    revalidation: RevalidationResult
    materials: V21PipelineMaterials


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
