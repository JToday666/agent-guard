"""V21-08 shadow 旁路编排薄层（flag 默认关闭，零行为变化）。

契约依据：``11_决策记录_V21-08前置.md`` D3（feature flag
``AGENTGUARD_V21_SHADOW_ENABLED`` 默认 false）、D7（不 bump
PROJECTOR_VERSION、decision_v21 为 append-only 审计键）与完整方案
§14（shadow 即保存九项证据）。

定位：**纯只读旁路**。legacy ``evaluate()`` 保持唯一官方决策者
（04 §1-§2）；本编排器在 flag 开启时旁路产出 ``decision_v21`` 信封
（01 §28 版本信封形状），由 T5 写入**同一条** policy_evaluation 审计
记录的 ``evidence.decision_v21``（``contract_freeze.yaml`` L84）。
不新增审计记录、不新增 HTTP 路由、不改变 evaluate 响应。

编排骨架（``build_shadow_evidence``）：

1. flag 关 → 立即返回 ``None``（仅一次布尔判断开销）；secret 未配置
   → 返回 ``None``（shadow 禁用，不得用弱密钥产证据）；
2. scope 解析：task 引用 = ``event.metadata["task_id"]`` trusted claim
   （01 §5：Adapter 后续只能携带 task_id/claim）→ 经存储层直读权威
   TaskFact head 解析 ``SecurityStateScope`` 与 ``scope_digest``；
   无 task 引用 / claim 无对应权威 TaskFact → 跳过 snapshot，经 Core
   纯函数直出 ``degraded_no_snapshot`` 语义信封（**严禁伪造
   Snapshot**，01 §25）；
3. 有 scope → ``SecurityStateService.ensure_ready`` / ``read_snapshot``
   （只读语义，bounded rebuild 用既有 ``DEFAULT_REBUILD_LIMIT``；
   task_fact_head 直读权威 TaskFact head）；snapshot 读取失败 /
   projector 不可恢复 → ``degraded_component_failure`` 降级信封，
   不伪造 complete；
4. 调 T3 Core 纯函数：``evaluate_with_results`` 拿 legacy 检测结果
   （只读旁路；调用方亦可注入已算好的 ``detection_results`` 免重跑）
   → ``shadow_assess_with_coverage`` → ``build_decision_evidence_v21``
   → ``decision_evidence_v21_envelope``。

故障收敛范式沿用 core ``actions/builder.py::build_shadow_evaluation``：
全链路 try/except 收敛为降级信封或 ``None``，**绝不外抛、绝不影响
legacy decision / approval / audit 主链**。

V21-09 定位（T2 处置裁决）：四段式编排主路径已迁移至
``services/v21_pipeline.py``（D4）；本编排器保留为 pipeline Phase A
彻底失败时的**逐字节降级回退路径**，同时也是无 task 引用场景的
``degraded_no_snapshot`` 语义组件。V21-09 起 revoked 桩升级为真实
注入：有 snapshot 时撤销集经 ``read_snapshot_with_revoked`` 与
snapshot 同源同锁读取（D3），入参退为无 snapshot 路径兜底。
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from agentguard_core import GuardEngine, GuardEvent, PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.divergence import (
    SHADOW_COMPONENT_ID,
    SNAPSHOT_ABSENT_REASON,
)
from agentguard_core.decisions.evidence import FastAssessment, RequiredCheckPlan
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_ID,
    REASON_COMPONENT_FAILED,
    compute_assessment_digest,
    shadow_assess_with_coverage,
)
from agentguard_core.security_context.coverage import COVERAGE_DOMAINS
from agentguard_core.signals.models import Decision

from guard_api.security_state import SecurityStateService
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import ControlPlaneStore

logger = logging.getLogger(__name__)

__all__ = [
    "REASON_SNAPSHOT_READ_FAILED",
    "SHADOW_CLOCK_VERSION",
    "TASK_CLAIM_METADATA_KEY",
    "V21ShadowService",
]

#: shadow 期 EvaluationClock 的确定性 clock_version（不读 wall-clock 语义
#: 之外的信息；evaluated_at 锚定 event.timestamp 保证同输入同输出）。
SHADOW_CLOCK_VERSION = "v21-08-shadow"

#: task 引用 trusted claim 的读取键（01 §5：Adapter 只能携带 task_id/claim，
#: 权威 TaskFact 永远经存储层直读，claim 不得覆盖）。
TASK_CLAIM_METADATA_KEY = "task_id"

#: snapshot 读取失败的组件降级 reason code（D2 degraded_component_failure）。
REASON_SNAPSHOT_READ_FAILED = "v21-08:snapshot_read_failed"

#: shadow_assess 降级路径的 reason code 前缀（与 core shadow.py 口径一致）。
_SHADOW_DEGRADED_REASON_PREFIX = "v21-08:shadow_degraded:"

#: read_snapshot 注入的保守 shadow plan（snapshot 读取先于 ActionIR，
#: impact 保守 high、全域 required；真实 plan 在 shadow_assess 内重算）。
_SHADOW_SNAPSHOT_PLAN_ID = "v21-08-shadow:snapshot-plan"

#: 调用方未提供 policy_revision 时的确定性占位（snapshot 身份锚点之一）。
_UNVERSIONED_POLICY_REVISION = "v21-08:unversioned"


def _task_claim(event: GuardEvent) -> str | None:
    """提取事件的 task 引用 trusted claim；无引用返回 None。

    口径：``event.metadata["task_id"]`` 非空字符串。claim 只用于定位
    权威 TaskFact（存储层直读 head），不参与任何权威判定。
    """

    value = event.metadata.get(TASK_CLAIM_METADATA_KEY)
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            return normalized
    return None


def _shadow_snapshot_plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id=_SHADOW_SNAPSHOT_PLAN_ID,
        impact="high",
        required_domains=list(COVERAGE_DOMAINS),
        optional_domains=[],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-08:shadow_snapshot_plan"],
    )


def _recategorize_shadow_degradation(
    assessment: FastAssessment, *, reason_code: str
) -> FastAssessment:
    """把 snapshot 缺态降级重分类为具体组件失败（D2 降级类目区分）。

    ``shadow_assess(snapshot=None)`` 恒产出 ``SNAPSHOT_ABSENT_REASON``
    降级（divergence 归 ``degraded_no_snapshot``）；编排层读取失败等
    组件故障必须归 ``degraded_component_failure``。本函数只替换 shadow
    组件降级的 reason codes 并**经 D1 同一函数重算 assessment_digest**
    （assessment_id 四元输入不变，身份稳定）。
    """

    absent_marker = f"{_SHADOW_DEGRADED_REASON_PREFIX}{SNAPSHOT_ABSENT_REASON}"
    degradations = [
        (
            degradation.model_copy(
                update={"reason_codes": [REASON_COMPONENT_FAILED, reason_code]}
            )
            if degradation.component_id == SHADOW_COMPONENT_ID
            and SNAPSHOT_ABSENT_REASON in degradation.reason_codes
            else degradation
        )
        for degradation in assessment.degradations
    ]
    reason_codes = [
        (
            f"{_SHADOW_DEGRADED_REASON_PREFIX}{reason_code}"
            if code == absent_marker
            else code
        )
        for code in assessment.reason_codes
    ]
    updated = assessment.model_copy(
        update={"degradations": degradations, "reason_codes": reason_codes}
    )
    return updated.model_copy(
        update={"assessment_digest": compute_assessment_digest(updated)}
    )


class V21ShadowService:
    """V21-08 shadow 旁路编排器（只读；绝不改变官方决策链）。

    构造即完成 flag / secret 解析：flag off 时 ``build_shadow_evidence``
    仅一次布尔判断后返回 ``None``，不触碰任何配置、存储与状态。
    """

    def __init__(
        self,
        *,
        settings: GuardApiSettings,
        store: ControlPlaneStore,
        state_service: SecurityStateService,
    ) -> None:
        self._store = store
        self._state_service = state_service
        self._enabled = bool(settings.v21_shadow_enabled)
        self._server_secret = self._load_server_secret(settings)

    def _load_server_secret(self, settings: GuardApiSettings) -> bytes | None:
        """flag on 时解析 server secret；任何异常收敛为 shadow 禁用。

        行为口径（写进 D3 实施约定）：flag on 而 secret 未配置/非法 →
        shadow **禁用**（返回 None），不产证据、不降级伪造；绝不硬编码
        兜底密钥。flag off 时不读取任何密钥配置。
        """

        if not self._enabled:
            return None
        try:
            secret = settings.v21_shadow_server_secret_bytes()
        except GuardApiConfigurationError:
            logger.warning(
                "v21 shadow enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is malformed; shadow evidence disabled"
            )
            return None
        if secret is None:
            logger.warning(
                "v21 shadow enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is not configured; shadow evidence disabled"
            )
        return secret

    @property
    def enabled(self) -> bool:
        """flag 且 secret 均已就绪（调用方诊断用；判定以返回 None 为准）。"""

        return self._enabled and self._server_secret is not None

    def build_shadow_evidence(
        self,
        event: GuardEvent,
        bundle: PolicyBundle,
        *,
        legacy_decision: Decision,
        detection_results: Sequence[DetectionResult] | None = None,
        revoked_grant_ids: Sequence[str] = (),
        policy_revision: str | None = None,
    ) -> dict[str, Any] | None:
        """产出 ``decision_v21`` 信封；flag 关/secret 缺/不可恢复时 None。

        T5 预留调用形态（``_evaluate_once`` audit 落盘前）::

            envelope = shadow_service.build_shadow_evidence(
                event,
                bundle,
                legacy_decision=decision.decision,
                detection_results=results,   # evaluate_with_results 旁路产物
                policy_revision=snapshot_record.revision if ... else None,
            )

        入参说明：

        - ``legacy_decision``：legacy 官方决策（divergence 分类与
          evidence ``final_decision`` 的输入；shadow 期官方决策者恒为
          legacy）；
        - ``detection_results``：缺省时经 ``evaluate_with_results`` 只读
          旁路重算（确定性，与官方决策同源）；调用方可注入已算好的结果
          避免双跑检测器；
        - ``revoked_grant_ids``：authority 投影撤销集。有 snapshot 路径
          恒用存储层同源同锁读取的权威集（D3，V21-09 真实注入），
          入参退为无 snapshot 降级路径兜底；
        - ``policy_revision``：缺省用确定性占位（snapshot 身份锚点）。

        返回值形状：``{"decision_v21": {"schema_version": "2.1",
        "payload": <DecisionEvidenceV21 dump>}}``（01 §28 信封；
        ``decision_v21_envelope()`` 既有形状，不改）。**绝不外抛**。
        """

        if not self._enabled:
            return None
        if self._server_secret is None:
            return None
        try:
            return self._build_envelope(
                event,
                bundle,
                legacy_decision=legacy_decision,
                detection_results=detection_results,
                revoked_grant_ids=revoked_grant_ids,
                policy_revision=policy_revision,
            )
        except Exception:  # noqa: BLE001 - 旁路故障必须收敛，绝不上抛。
            logger.warning(
                "v21 shadow orchestration failed for event %s; converging "
                "to degraded envelope",
                event.event_id,
                exc_info=True,
            )
            try:
                return self._component_failure_envelope(
                    event,
                    bundle,
                    legacy_decision=legacy_decision,
                    detection_results=detection_results,
                    revoked_grant_ids=revoked_grant_ids,
                    reason_code=REASON_COMPONENT_FAILED,
                )
            except Exception:  # noqa: BLE001 - 兜底再失败则放弃证据。
                return None

    # ------------------------------------------------------------------
    # 内部编排
    # ------------------------------------------------------------------

    def _build_envelope(
        self,
        event: GuardEvent,
        bundle: PolicyBundle,
        *,
        legacy_decision: Decision,
        detection_results: Sequence[DetectionResult] | None,
        revoked_grant_ids: Sequence[str],
        policy_revision: str | None,
    ) -> dict[str, Any] | None:
        assert self._server_secret is not None
        if detection_results is None:
            # 只读旁路：确定性重算 legacy 检测结果（与官方 evaluate 同源）。
            _decision, detection_results = GuardEngine().evaluate_with_results(
                event, bundle
            )

        try:
            snapshot, authoritative_revoked = self._resolve_snapshot(
                event, bundle, policy_revision
            )
        except Exception:  # noqa: BLE001 - snapshot 读取失败 → 组件降级。
            return self._component_failure_envelope(
                event,
                bundle,
                legacy_decision=legacy_decision,
                detection_results=detection_results,
                revoked_grant_ids=revoked_grant_ids,
                reason_code=REASON_SNAPSHOT_READ_FAILED,
            )

        if snapshot is None:
            # 无 task 引用 / claim 无权威 TaskFact：跳过 snapshot 直出
            # degraded_no_snapshot 语义（禁伪造 Snapshot，01 §25）；
            # 无 snapshot 同源锚点，撤销集用入参兜底（缺省空）。
            outcome = shadow_assess_with_coverage(
                event,
                bundle,
                None,
                server_secret=self._server_secret,
                detection_results=detection_results,
                revoked_grant_ids=revoked_grant_ids,
            )
            snapshot_id = ABSENT_SNAPSHOT_ID
            state_version = 0
        else:
            # 有 snapshot：撤销集恒取同源同锁权威读取值（D3），
            # 覆盖入参桩值，杜绝双源不一致。
            outcome = shadow_assess_with_coverage(
                event,
                bundle,
                snapshot,
                server_secret=self._server_secret,
                detection_results=detection_results,
                revoked_grant_ids=authoritative_revoked,
            )
            snapshot_id = snapshot.snapshot_id
            state_version = snapshot.state_version

        evidence = build_decision_evidence_v21(
            outcome.assessment,
            legacy_decision=legacy_decision,
            snapshot_id=snapshot_id,
            state_version=state_version,
            coverage=outcome.coverage,
        )
        return decision_evidence_v21_envelope(evidence)

    def _resolve_snapshot(self, event, bundle, policy_revision):
        """解析 task 引用 → scope → 只读 snapshot + 同源 revoked 集。

        无引用/无权威 fact 时返回 ``(None, [])``。V21-09 起改用
        ``read_snapshot_with_revoked``：撤销集与 snapshot 取自同一
        ``scope_lock`` 窗口内的同一份 online state record（D3）。

        ``scope`` 为注入式权威输入（01 §19）：``scope_digest`` 直取权威
        TaskFact 绑定值；其余身份字段由事件重建供 ActionIR 指纹使用
        （shadow 期 authorization_fingerprint 与 Task Ingress 派生口径
        不同源，属已知局限，V21-09 pipeline 提供权威 scope 注入）。
        """

        task_id = _task_claim(event)
        if task_id is None:
            return None, []
        record = self._store.get_task_fact(task_id)
        if record is None:
            # trusted claim 无对应权威 TaskFact：不得据此构造 snapshot。
            return None, []
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
        # 既有入口语义：ensure_ready 先行 bounded rebuild 钩子，
        # read_snapshot 直读权威 task_fact_head（dirty/缺态自动 rebuild）。
        self._state_service.ensure_ready(scope_digest)
        return self._state_service.read_snapshot_with_revoked(
            scope_digest,
            scope=scope,
            task_fact_head=task_fact,
            evaluation_clock=EvaluationClock(
                evaluated_at=event.timestamp,
                clock_version=SHADOW_CLOCK_VERSION,
            ),
            policy_revision=policy_revision or _UNVERSIONED_POLICY_REVISION,
            policy_digest=canonical_sha256(bundle.model_dump(mode="json")),
            plan=_shadow_snapshot_plan(),
        )

    def _component_failure_envelope(
        self,
        event: GuardEvent,
        bundle: PolicyBundle,
        *,
        legacy_decision: Decision,
        detection_results: Sequence[DetectionResult] | None,
        revoked_grant_ids: Sequence[str] = (),
        reason_code: str,
    ) -> dict[str, Any] | None:
        """组件故障降级信封：snapshot 缺态评估 + 重分类为组件失败。

        调用方注入的 ``detection_results`` / ``revoked_grant_ids`` 必须
        透传（兜底路径与正常路径同源输入，不得静默丢弃权威输入）。
        自身任何异常上抛由外层 ``build_shadow_evidence`` 兜底收敛。
        """

        assert self._server_secret is not None
        outcome = shadow_assess_with_coverage(
            event,
            bundle,
            None,
            server_secret=self._server_secret,
            detection_results=(
                detection_results if detection_results is not None else ()
            ),
            revoked_grant_ids=revoked_grant_ids,
        )
        assessment = _recategorize_shadow_degradation(
            outcome.assessment, reason_code=reason_code
        )
        evidence = build_decision_evidence_v21(
            assessment,
            legacy_decision=legacy_decision,
            snapshot_id=ABSENT_SNAPSHOT_ID,
            state_version=0,
            coverage=outcome.coverage,
        )
        return decision_evidence_v21_envelope(evidence)
