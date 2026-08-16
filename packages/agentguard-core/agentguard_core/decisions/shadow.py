"""V21-08 shadow 快路径评估纯函数 + V21-09 正式 assess 入口。

V21-09 起本模块承载两个入口（共享同一编排骨架）：

- ``assess``：完整方案 §15（L3181-3198）正式 Core API
  ``GuardEngine.assess(event, policies, snapshot) -> FastAssessment``
  的函数形态落地——按 01 §25 **必须有 Snapshot**，``snapshot is None``
  收敛为 ``ValueError`` 入参校验（不产出降级产物，严禁伪造 Snapshot）；
- ``shadow_assess`` / ``shadow_assess_with_coverage``：V21-08 shadow
  期入口，**前三个位置参数**与正式 API 同形（**零重构升级点**），
  附加允许 ``snapshot is None``（入参缺态）：按 01 §25 不伪造
  Snapshot，产出 coverage 全域 unknown + ``DEFER`` + 结构化降级。

内部编排（公共内核 ``_assess_kernel``，两入口同源）：

1. ``build_action_ir``（V21-02）：GuardEvent → ActionIR；
2. legacy detections 经 ``signals/legacy_adapter`` 转
   ``SecuritySignal`` / ``EvaluationDegradation``；
3. ``compute_authority_verdict``（V21-06）；
4. ``compute_flow_verdict``（V21-08 T2）；
5. ``compute_coverage``（V21-04，经 ``build_required_check_plan``）；
6. ``evaluate_fusion``（T2）得 FastDisposition；
7. ``assessment_digest`` 按 ``11_决策记录_V21-08前置.md`` D1 口径计算
   （``FastAssessment.digest_fields()`` 冻结白名单投影 + JCS
   ``canonical_sha256``）；**V21-09 复用同一计算函数**。

降级范式沿用 ``actions/builder.py::build_shadow_evaluation``：任何组件
异常收敛为 shadow 组件降级（``component_id == SHADOW_COMPONENT_ID``），
disposition 恒 ``DEFER``，**绝不上抛**；legacy 判定路径不受本模块影响。

确定性纪律（01 §29）：不读 wall-clock、不生成 uuid、不含 display-only
reason；``assessment_id`` 由输入确定性派生；五个 digest/fingerprint
（task_digest / policy_digest / snapshot_digest /
authorization_fingerprint / audit_fingerprint）全部填真实值，作为
V21-09 CAS revalidation 五元组，不留占位。

已知局限（shadow 期）：``SecuritySnapshot`` 不携带
``revoked_grant_ids``（01 §19 冻结字段），authority 投影所需的撤销集由
``revoked_grant_ids`` 关键字入参注入（缺省空）；V21-09 由 Guard API
存储层权威提供。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from ..actions.builder import build_action_ir
from ..actions.canonical_json import canonical_sha256
from ..actions.models import ActionIR
from ..decisions.evidence import (
    CoverageMap,
    DomainCoverage,
    FastAssessment,
    RequiredCheckPlan,
    SemanticRoutingAssessment,
)
from ..events.contracts import GuardEvent
from ..policies.models import PolicyBundle
from ..security_context.assessment_overlay import (
    ASSESSMENT_OVERLAY_COMPONENT_ID,
    AssessmentTransientFacts,
    build_assessment_overlay,
    compute_overlay_digest,
)
from ..security_context.coverage import (
    COVERAGE_DOMAINS,
    GapContext,
    compute_coverage,
    default_coverage_context,
)
from ..security_context.projection.authority_verdict import (
    compute_authority_verdict,
)
from ..security_context.projection.behavior_matchers import (
    generate_behavior_signals,
)
from ..security_context.projection.flow_verdict import (
    compute_flow_verdict,
    compute_flow_verdict_from_state,
)
from ..security_context.projection.provenance_coverage import (
    DATAFLOW_PROVIDER_KEY,
)
from ..security_context.projector import PROJECTOR_VERSION
from ..security_context.required_checks import (
    PolicyProfile,
    build_required_check_plan,
)
from ..security_context.snapshot import SecuritySnapshot
from ..security_context.state import OnlineSecurityState
from ..signals.legacy_adapter import (
    legacy_detection_to_signal,
    legacy_failure_to_degradation,
)
from ..signals.models import (
    AuthorityVerdict,
    Decision,
    EvaluationDegradation,
    FlowVerdict,
    ImpactClass,
    SecuritySignal,
)
from .divergence import SHADOW_COMPONENT_ID, SNAPSHOT_ABSENT_REASON
from .fusion import evaluate_fusion
from .results import DetectionResult

__all__ = [
    "ABSENT_SNAPSHOT_DIGEST",
    "ABSENT_SNAPSHOT_ID",
    "REASON_ACTION_IR_FAILED",
    "REASON_COMPONENT_FAILED",
    "ShadowOutcome",
    "assess",
    "assessment_digest_projection",
    "compute_assessment_digest",
    "derive_assessment_id",
    "finalize_shadow",
    "shadow_assess",
    "shadow_assess_with_coverage",
]

#: snapshot 缺失时的注册标识哨兵（不伪造 Snapshot，01 §25）。
ABSENT_SNAPSHOT_ID = "v21-08:snapshot_absent"

#: snapshot 缺失时的 snapshot_digest 哨兵（确定性，不读时钟/不生成 uuid）。
ABSENT_SNAPSHOT_DIGEST = canonical_sha256({"v21-08": "snapshot_absent"})

#: ActionIR 构建失败的 shadow 降级 reason code。
REASON_ACTION_IR_FAILED = "v21-08:action_ir_failed"

#: 编排组件（coverage/authority/flow/fusion）异常的 shadow 降级 reason code。
REASON_COMPONENT_FAILED = "v21-08:component_failed"

#: semantic 路由为 V21-13 预留；shadow 期恒 ineligible。
_SEMANTIC_RESERVED_REASON = "v21-08:semantic_reserved_v21-13"


@dataclass(frozen=True)
class ShadowOutcome:
    """shadow 评估的完整旁路产物。

    ``FastAssessment`` 冻结字段（01 §25）不含 CoverageMap；evidence 组装
    （§14 保存项 2）必须与判定时喂给 fusion 的 coverage 同源，因此本
    数据类把评估时实际使用的 coverage 一并透出（降级路径为七域 unknown
    构件），禁止调用方另行重算造成双真值。
    """

    assessment: FastAssessment
    coverage: CoverageMap
    # Exact digest of the transient overlay that reached every Core component.
    # ``None`` means no overlay was supplied or assessment degraded before the
    # overlay was fully consumed; callers must not commit/project that bundle.
    consumed_overlay_digest: str | None


# ---------------------------------------------------------------------------
# assessment_digest（D1 口径；V21-09 复用同一计算函数）
# ---------------------------------------------------------------------------


def assessment_digest_projection(assessment: FastAssessment) -> dict[str, Any]:
    """``assessment_digest`` 的白名单投影（D1 / 01 §29）。

    只取 ``FastAssessment.digest_fields()`` 冻结白名单字段，键按字典序
    排列；``assessment_id`` 与 ``assessment_digest`` 自身不在白名单内
    （不进入自身摘要）。禁入字段（wall-clock latency、random UUID、
    display-only reason、provider request id、debug metadata）在冻结模型
    中本就不存在，白名单之外一律不投影。
    """
    dump = assessment.model_dump(mode="json")
    return {field: dump[field] for field in sorted(FastAssessment.digest_fields())}


def compute_assessment_digest(assessment: FastAssessment) -> str:
    """``assessment_digest = canonical_sha256(白名单投影)``（D1）。

    V21-08 shadow 期实现；V21-09 正式 ``assess/finalize`` 复用本函数，
    保证两期摘要口径恒等。
    """
    return canonical_sha256(assessment_digest_projection(assessment))


def derive_assessment_id(
    *, event_id: str, action_id: str, policy_digest: str, snapshot_digest: str
) -> str:
    """``assessment_id`` 确定性派生（禁 uuid default_factory）。

    身份由 event/action/policy/snapshot 四个稳定身份共同决定：同输入必
    同 id（T-Replay 锚点语义与 snapshot_digest 一致）。
    """
    return "asm:" + canonical_sha256(
        {
            "action_id": action_id,
            "event_id": event_id,
            "policy_digest": policy_digest,
            "snapshot_digest": snapshot_digest,
        }
    )


# ---------------------------------------------------------------------------
# 降级构件（01 §25 禁伪造 Snapshot；降级范式同 build_shadow_evaluation）
# ---------------------------------------------------------------------------


def _shadow_degradation(reason_code: str, *, event_id: str) -> EvaluationDegradation:
    """shadow 组件自身降级（供 divergence 分类识别为降级类目）。"""
    return EvaluationDegradation(
        degradation_id=f"v21-08-shadow-degrade:{event_id}:{reason_code}",
        component_id=SHADOW_COMPONENT_ID,
        domain=None,
        required_for_action=True,
        failure_kind="unavailable",
        reason_codes=[reason_code],
        evidence_refs=[],
    )


def _unknown_coverage(projector_version: str, reason: str) -> CoverageMap:
    """七域 unknown 的 CoverageMap（缺态降级，fail-closed）。"""
    domains = {
        domain: DomainCoverage(
            domain=domain,
            status="unknown",
            as_of_sequence=None,
            projector_version=projector_version,
            reason_codes=[reason],
        )
        for domain in COVERAGE_DOMAINS
    }
    return CoverageMap(**domains)


def _degraded_authority() -> AuthorityVerdict:
    return AuthorityVerdict(
        status="unknown",
        matched_grant_ids=[],
        missing_capabilities=[],
        explicit_scope_mismatches=[],
        evidence_refs=[],
    )


def _degraded_flow() -> FlowVerdict:
    return FlowVerdict(
        status="uncertain",
        strongest_strength=None,
        taints=[],
        external_sink=False,
        path_refs=[],
        evidence_refs=[],
    )


def _degraded_plan(impact: ImpactClass, reason: str) -> RequiredCheckPlan:
    """ActionIR 缺失时的保守 plan（impact 保守 high，全域 required）。"""
    return RequiredCheckPlan(
        plan_id=f"v21-08-degraded-plan:{reason}",
        impact=impact,
        required_domains=list(COVERAGE_DOMAINS),
        optional_domains=[],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=[reason],
    )


def _digest_well_formed(digest: str | None) -> bool:
    """最小 digest 形态校验（``sha256:`` / ``hmac-sha256:`` 前缀）。"""
    if digest is None:
        return True
    return digest.startswith(("sha256:", "hmac-sha256:")) and len(digest) > 10


def _state_from_snapshot(
    snapshot: SecuritySnapshot, *, revoked_grant_ids: Sequence[str]
) -> OnlineSecurityState:
    """由 snapshot 派生 authority/coverage 投影所需的最小 state。

    snapshot 不携带 ``revoked_grant_ids``（01 §19 冻结字段），由入参注入
    （shadow 期缺省空；V21-09 由存储层权威提供）。
    """
    return OnlineSecurityState(
        task=snapshot.task,
        active_grants=list(snapshot.grants),
        revoked_grant_ids=list(revoked_grant_ids),
        source_index=list(snapshot.sources),
        sticky_taint_summaries=list(snapshot.sticky_taint_summaries),
        relevant_flows=list(snapshot.flows),
        recent_actions=list(snapshot.recent_actions),
        behavior_aggregates=list(snapshot.behavior_aggregates),
        memory_index=list(snapshot.memory_facts),
        runtime_outcomes=list(snapshot.runtime_outcomes),
        watermarks=snapshot.watermarks,
        state_version=snapshot.state_version,
        dirty_domains=list(snapshot.dirty_domains),
    )


def _legacy_signals_and_degradations(
    detection_results: Sequence[DetectionResult], *, event_id: str
) -> tuple[list[SecuritySignal], list[EvaluationDegradation]]:
    """legacy DetectionResult → signals/degradations（legacy_adapter）。"""
    signals: list[SecuritySignal] = []
    degradations: list[EvaluationDegradation] = []
    for index, result in enumerate(detection_results):
        signals.append(
            legacy_detection_to_signal(result, event_id=event_id, result_index=index)
        )
        degradation = legacy_failure_to_degradation(result, event_id=event_id)
        if degradation is not None:
            degradations.append(degradation)
    return signals, degradations


def _overlay_lookup_targets(action_ir: ActionIR) -> tuple[str, ...]:
    """Deterministic current-action and normalized-sink lookup roots."""
    refs = {
        action_ir.action_id,
        f"action:{action_ir.action_id}",
        action_ir.event_id,
        f"event:{action_ir.event_id}",
        *(resource.canonical_id for resource in action_ir.resources),
        *(destination.canonical_id for destination in action_ir.destinations),
    }
    return tuple(sorted(refs))


def _overlay_truncation_degradation(event_id: str) -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id=f"gate-a:overlay-truncated:{event_id}",
        component_id=ASSESSMENT_OVERLAY_COMPONENT_ID,
        domain="dataflow",
        required_for_action=True,
        failure_kind="overflow",
        reason_codes=["v21-05:flow_lookup_truncated"],
        evidence_refs=[],
    )


def _overlay_incomplete_reasons(
    transient_facts: AssessmentTransientFacts,
) -> tuple[str, ...]:
    """Return every producer-declared gap in the current fact graph.

    ``TransientSecurityFacts`` freezes the rule that any degradation means the
    graph is incomplete.  Keeping a reason allowlist here would let a newly
    introduced handler failure silently become eligible for ``CLEAR_ALLOW``.
    """

    reasons: set[str] = set()
    for degradation in transient_facts.degradations:
        if degradation.reason_codes:
            reasons.update(degradation.reason_codes)
        else:
            reasons.add(degradation.degradation_id)
    return tuple(sorted(reasons))


def _overlay_incomplete_degradation(
    event_id: str, *, reason_codes: Sequence[str]
) -> EvaluationDegradation:
    """Promote app-observed lineage gaps into a required Core degradation."""
    return EvaluationDegradation(
        degradation_id=f"gate-a:overlay-incomplete:{event_id}",
        component_id=ASSESSMENT_OVERLAY_COMPONENT_ID,
        domain="dataflow",
        required_for_action=True,
        failure_kind="unavailable",
        reason_codes=list(reason_codes),
        evidence_refs=[],
    )


# ---------------------------------------------------------------------------
# 公共评估内核 + assess 正式入口 / shadow_assess（V21-09 零重构升级点）
# ---------------------------------------------------------------------------


def _assess_kernel(
    event: GuardEvent,
    policies: PolicyBundle,
    snapshot: SecuritySnapshot | None,
    *,
    server_secret: bytes,
    detection_results: Sequence[DetectionResult] = (),
    revoked_grant_ids: Sequence[str] = (),
    transient_facts: AssessmentTransientFacts | None = None,
) -> ShadowOutcome:
    """V21-08 shadow 与 V21-09 正式 assess 的**唯一**编排主体。

    编排骨架见模块 docstring（1-7 步）；``snapshot is None`` 的降级
    分支仅由 shadow 期入口（``shadow_assess`` /
    ``shadow_assess_with_coverage``）可达，正式入口 ``assess`` 在调用
    前已收敛为 ``ValueError``（01 §25）。同输入必同输出；任何组件
    异常收敛为 shadow 降级，绝不上抛。

    evidence 组装（§14 保存项 2）必须消费评估时喂给 fusion 的同一份
    coverage，本函数是该同源真值的唯一出口。
    """
    policy_digest = canonical_sha256(policies.model_dump(mode="json"))
    signals, degradations = _legacy_signals_and_degradations(
        detection_results, event_id=event.event_id
    )
    consumed_overlay_digest: str | None = None

    # 1) ActionIR 构建（失败 → 全降级路径，保守 impact high）。
    action_ir: ActionIR | None = None
    action_ir_failed = False
    try:
        if snapshot is not None:
            scope = snapshot.scope
            action_ir = build_action_ir(
                event,
                server_secret=server_secret,
                task_id=snapshot.task.task_id if snapshot.task else None,
                task_revision=snapshot.task.revision if snapshot.task else None,
                scope_digest=scope.scope_digest,
                principal_id=scope.principal_id,
                runtime_binding_id=scope.runtime_binding_id,
            )
        else:
            action_ir = build_action_ir(event, server_secret=server_secret)
    except Exception:  # noqa: BLE001 - 旁路评估失败必须收敛，不外抛。
        action_ir = None
        action_ir_failed = True

    if action_ir is not None:
        action_id = action_ir.action_id
        impact: ImpactClass = action_ir.impact
        authorization_fingerprint = action_ir.authorization_fingerprint
        audit_fingerprint = action_ir.audit_fingerprint
    else:
        action_id = f"act_{event.event_id}"
        impact = "high"  # 保守假设，fail-closed。
        authorization_fingerprint = ""
        audit_fingerprint = ""

    # 2) snapshot 缺失（01 §25）/ ActionIR 失败 → 降级构件 + DEFER。
    degraded_reason: str | None = None
    if snapshot is None:
        degraded_reason = SNAPSHOT_ABSENT_REASON
        snapshot_digest = ABSENT_SNAPSHOT_DIGEST
        task_digest: str | None = None
        plan = _degraded_plan(impact, SNAPSHOT_ABSENT_REASON)
        coverage = _unknown_coverage(PROJECTOR_VERSION, SNAPSHOT_ABSENT_REASON)
        authority = _degraded_authority()
        flow = _degraded_flow()
    elif action_ir_failed or action_ir is None:
        degraded_reason = REASON_ACTION_IR_FAILED
        snapshot_digest = snapshot.snapshot_digest
        task_digest = snapshot.task.task_digest if snapshot.task else None
        plan = _degraded_plan(impact, REASON_ACTION_IR_FAILED)
        coverage = _unknown_coverage(PROJECTOR_VERSION, REASON_ACTION_IR_FAILED)
        authority = _degraded_authority()
        flow = _degraded_flow()
    else:
        snapshot_digest = snapshot.snapshot_digest
        task_digest = snapshot.task.task_digest if snapshot.task else None
        memory_facts_for_fusion = snapshot.memory_facts
        flows_for_fusion = snapshot.flows
        behavior_aggregates_for_fusion = snapshot.behavior_aggregates
        overlay_digest_valid = True
        try:
            plan = build_required_check_plan(
                action_ir,
                PolicyProfile(
                    policy_revision=snapshot.policy_revision,
                    policy_digest=snapshot.policy_digest,
                ),
            )
            state = _state_from_snapshot(snapshot, revoked_grant_ids=revoked_grant_ids)
            if transient_facts is None:
                # Compatibility path: keep the exact pre-Gate-A component
                # inputs and ordering. This is intentionally a separate branch
                # rather than an empty overlay so assessment parity is strict.
                coverage = compute_coverage(
                    state, plan, projector_version=snapshot.projector_version
                )
                authority = compute_authority_verdict(
                    state,
                    action_ir,
                    evaluated_at=snapshot.evaluation_clock.evaluated_at,
                )
                flow = compute_flow_verdict(
                    snapshot,
                    action_ir,
                    dataflow_status=coverage.dataflow.status,
                )
            else:
                if transient_facts.overlay_digest != compute_overlay_digest(
                    transient_facts
                ):
                    raise ValueError(
                        "assessment transient overlay_digest changed after validation"
                    )
                if transient_facts.event_id != event.event_id:
                    raise ValueError(
                        "assessment transient event does not match GuardEvent"
                    )
                if transient_facts.scope_digest != snapshot.scope.scope_digest:
                    raise ValueError(
                        "assessment transient scope does not match Snapshot"
                    )
                if (
                    transient_facts.current_action is not None
                    and transient_facts.current_action.action_id != action_ir.action_id
                ):
                    raise ValueError(
                        "assessment transient action does not match ActionIR"
                    )

                overlay = build_assessment_overlay(
                    state,
                    transient_facts,
                    target_refs=_overlay_lookup_targets(action_ir),
                )
                state = overlay.state
                incomplete_reasons = _overlay_incomplete_reasons(transient_facts)
                context = default_coverage_context(state, plan).model_copy(
                    update={
                        "gap_context": GapContext(
                            parent_event_ids=frozenset(action_ir.parent_event_ids),
                            stable_refs=frozenset(overlay.stable_source_refs),
                        ),
                        "truncated": (("dataflow",) if overlay.truncated else ()),
                        "provider_available": (
                            {DATAFLOW_PROVIDER_KEY: False} if incomplete_reasons else {}
                        ),
                    }
                )
                coverage = compute_coverage(
                    state,
                    plan,
                    projector_version=snapshot.projector_version,
                    context=context,
                )
                authority = compute_authority_verdict(
                    state,
                    action_ir,
                    evaluated_at=snapshot.evaluation_clock.evaluated_at,
                )
                flow = compute_flow_verdict_from_state(
                    state,
                    action_ir,
                    dataflow_status=coverage.dataflow.status,
                )
                signals = [
                    *signals,
                    *transient_facts.signals,
                    *generate_behavior_signals(state),
                ]
                degradations = [
                    *degradations,
                    *transient_facts.degradations,
                ]
                if overlay.truncated:
                    degradations.append(_overlay_truncation_degradation(event.event_id))
                if incomplete_reasons:
                    degradations.append(
                        _overlay_incomplete_degradation(
                            event.event_id,
                            reason_codes=incomplete_reasons,
                        )
                    )
                memory_facts_for_fusion = state.memory_index
                flows_for_fusion = list(overlay.relevant_flows)
                behavior_aggregates_for_fusion = state.behavior_aggregates
                overlay_digest_valid = _digest_well_formed(
                    transient_facts.overlay_digest
                )
                consumed_overlay_digest = transient_facts.overlay_digest
        except Exception:  # noqa: BLE001 - 组件异常收敛为 shadow 降级。
            degraded_reason = REASON_COMPONENT_FAILED
            plan = _degraded_plan(impact, REASON_COMPONENT_FAILED)
            coverage = _unknown_coverage(PROJECTOR_VERSION, REASON_COMPONENT_FAILED)
            authority = _degraded_authority()
            flow = _degraded_flow()

    if degraded_reason is not None:
        degradations = [
            *degradations,
            _shadow_degradation(degraded_reason, event_id=event.event_id),
        ]
        disposition = "DEFER"
        fusion_reasons = [f"v21-08:shadow_degraded:{degraded_reason}"]
    else:
        disposition, fusion_reasons = evaluate_fusion(
            impact=impact,
            # shadow 期不产生 PolicyViolation（无生成器；策略真值继续由
            # legacy 路径承载，V21-11 前不新增）。
            policy_violations=[],
            signals=signals,
            degradations=degradations,
            authority=authority,
            flow=flow,
            coverage=coverage,
            required_domains=plan.required_domains,
            memory_facts=memory_facts_for_fusion,
            flows=flows_for_fusion,
            behavior_aggregates=behavior_aggregates_for_fusion,
            requires_semantic=False,
            security_digests_valid=(
                _digest_well_formed(policy_digest)
                and _digest_well_formed(snapshot_digest)
                and _digest_well_formed(task_digest)
                and overlay_digest_valid
            ),
        )

    assessment = FastAssessment(
        assessment_id="",
        event_id=event.event_id,
        action_id=action_id,
        disposition=disposition,
        impact=impact,
        required_check_plan=plan,
        policy_violations=[],
        signals=list(signals),
        degradations=list(degradations),
        authority=authority,
        flow=flow,
        semantic_routing=SemanticRoutingAssessment(
            eligible=False,
            hard_deny_present=False,
            semantic_resolvable=False,
            required_facts_available=False,
            reason_codes=[_SEMANTIC_RESERVED_REASON],
        ),
        reason_codes=list(fusion_reasons),
        evidence_refs=[],
        authorization_fingerprint=authorization_fingerprint,
        audit_fingerprint=audit_fingerprint,
        task_digest=task_digest,
        policy_digest=policy_digest,
        snapshot_digest=snapshot_digest,
        assessment_digest="",
    )
    digest = compute_assessment_digest(assessment)
    finalized = assessment.model_copy(
        update={
            "assessment_id": derive_assessment_id(
                event_id=event.event_id,
                action_id=action_id,
                policy_digest=policy_digest,
                snapshot_digest=snapshot_digest,
            ),
            "assessment_digest": digest,
        }
    )
    return ShadowOutcome(
        assessment=finalized,
        coverage=coverage,
        consumed_overlay_digest=consumed_overlay_digest,
    )


def assess(
    event: GuardEvent,
    policies: PolicyBundle,
    snapshot: SecuritySnapshot | None,
    *,
    server_secret: bytes,
    detection_results: Sequence[DetectionResult] = (),
    revoked_grant_ids: Sequence[str] = (),
    transient_facts: AssessmentTransientFacts | None = None,
) -> FastAssessment:
    """V21-09 正式 Core API（完整方案 §15，L3181-3198）。

    与 ``shadow_assess`` 共享同一公共内核 ``_assess_kernel``，同输入
    必同输出（assessment_digest 逐字节相等，D1 锚点）；唯一差异是
    01 §25 入参校验：**assess() 必须有 Snapshot**，``snapshot is None``
    抛 ``ValueError``（不产出降级产物、严禁伪造 Snapshot）；shadow 期
    降级语义继续由 ``shadow_assess`` 承载。

    关键字入参语义与 ``shadow_assess`` 一致：``server_secret``（ActionIR
    指纹）、``detection_results``（legacy 双轨对照输入）、
    ``revoked_grant_ids``（authority 投影撤销集，V21-09 由存储层
    权威提供，D3）。
    """
    if snapshot is None:
        raise ValueError(
            "assess() requires a SecuritySnapshot (01 §25: V2.1 assess must "
            "have a Snapshot; never fabricate one) - use shadow_assess() for "
            "the V21-08 shadow degraded semantics"
        )
    return _assess_kernel(
        event,
        policies,
        snapshot,
        server_secret=server_secret,
        detection_results=detection_results,
        revoked_grant_ids=revoked_grant_ids,
        transient_facts=transient_facts,
    ).assessment


def shadow_assess_with_coverage(
    event: GuardEvent,
    policies: PolicyBundle,
    snapshot: SecuritySnapshot | None,
    *,
    server_secret: bytes,
    detection_results: Sequence[DetectionResult] = (),
    revoked_grant_ids: Sequence[str] = (),
    transient_facts: AssessmentTransientFacts | None = None,
) -> ShadowOutcome:
    """``shadow_assess`` 的完整产物版本（额外透出判定时使用的 coverage）。

    V21-09 起委托公共内核 ``_assess_kernel``（与正式入口 ``assess``
    同源）；snapshot 缺失降级分支保留（shadow 期语义零变化）。
    """
    return _assess_kernel(
        event,
        policies,
        snapshot,
        server_secret=server_secret,
        detection_results=detection_results,
        revoked_grant_ids=revoked_grant_ids,
        transient_facts=transient_facts,
    )


def shadow_assess(
    event: GuardEvent,
    policies: PolicyBundle,
    snapshot: SecuritySnapshot | None,
    *,
    server_secret: bytes,
    detection_results: Sequence[DetectionResult] = (),
    revoked_grant_ids: Sequence[str] = (),
    transient_facts: AssessmentTransientFacts | None = None,
) -> FastAssessment:
    """V21-08 shadow 快路径评估（纯函数；同输入必同输出）。

    签名与完整方案 §15 V21-09 ``GuardEngine.assess(event, policies,
    snapshot) -> FastAssessment`` 的前三个位置参数对齐（**V21-09 零重构
    升级点**）。shadow 期附加关键字入参：

    - ``server_secret``：ActionIR 指纹所需（V21-09 同需）；
    - ``detection_results``：legacy 检测结果，经 legacy_adapter 转
      signals/degradations 喂给 fusion（shadow 双轨对照的输入）；
    - ``revoked_grant_ids``：authority 投影的撤销集（snapshot 不携带，
      见模块 docstring 局限声明）。

    降级契约（绝不上抛）：

    - ``snapshot is None`` → coverage 全域 unknown + ``DEFER`` +
      ``SNAPSHOT_ABSENT_REASON`` 降级（**严禁伪造 Snapshot**，01 §25）；
    - ActionIR 构建失败 → 保守 impact high + 全降级构件 + ``DEFER``；
    - 任一编排组件异常 → shadow 组件降级 + ``DEFER``。

    需要与判定同源 coverage 的调用方（evidence 组装）用
    ``shadow_assess_with_coverage``。
    """
    return shadow_assess_with_coverage(
        event,
        policies,
        snapshot,
        server_secret=server_secret,
        detection_results=detection_results,
        revoked_grant_ids=revoked_grant_ids,
        transient_facts=transient_facts,
    ).assessment


# ---------------------------------------------------------------------------
# finalize_shadow（V21-08 离线对照；V21-09 由 finalize_v21 取代）
# ---------------------------------------------------------------------------

#: finalize 最小映射（完整方案"V21-09 预留接入点"节）：
#: CLEAR_DENY→deny、DEFER→ask、CLEAR_ALLOW→allow。
_SHADOW_FINALIZE_MAP: dict[str, Decision] = {
    "CLEAR_DENY": "deny",
    "DEFER": "ask",
    "CLEAR_ALLOW": "allow",
}


def finalize_shadow(assessment: FastAssessment) -> Decision:
    """shadow 期 v21 disposition → legacy Decision 的最小映射。

    .. superseded:: V21-09
        正式 finalize 由 ``decisions/finalize.py::finalize_v21`` 承接
        （03 §14 完整优先级 + D7 全字段口径）；本函数保留 **V21-08
        离线对照语义**，行为逐字不变，仍不参与线上决策。
    """
    return _SHADOW_FINALIZE_MAP[assessment.disposition]
