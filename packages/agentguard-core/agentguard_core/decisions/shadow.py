"""V21-08 shadow 快路径评估纯函数（纯新增，零接线）。

``shadow_assess`` 的**前三个位置参数**与完整方案 §15（L3181-3198）
V21-09 正式 API ``GuardEngine.assess(event, policies, snapshot) ->
FastAssessment`` 同形 —— 这是 **V21-09 零重构升级点**：V21-09 只需把
本函数挂到 ``GuardEngine.assess``，并把 ``snapshot=None`` 降级分支收敛
为 §25 的入参校验即可，调用方无需改动。shadow 期额外允许
``snapshot is None``（入参缺态）：按 01 §25 **严禁伪造 Snapshot**，
此时产出 coverage 全域 unknown + ``DEFER`` + 结构化降级。

内部编排（与 V21-09 assess 同一编排骨架）：

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
from ..security_context.coverage import COVERAGE_DOMAINS, compute_coverage
from ..security_context.projection.authority_verdict import (
    compute_authority_verdict,
)
from ..security_context.projection.flow_verdict import compute_flow_verdict
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
    "assessment_digest_projection",
    "compute_assessment_digest",
    "derive_assessment_id",
    "finalize_shadow",
    "shadow_assess",
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
            legacy_detection_to_signal(
                result, event_id=event_id, result_index=index
            )
        )
        degradation = legacy_failure_to_degradation(result, event_id=event_id)
        if degradation is not None:
            degradations.append(degradation)
    return signals, degradations


# ---------------------------------------------------------------------------
# shadow_assess（V21-09 GuardEngine.assess 零重构升级点）
# ---------------------------------------------------------------------------


def shadow_assess(
    event: GuardEvent,
    policies: PolicyBundle,
    snapshot: SecuritySnapshot | None,
    *,
    server_secret: bytes,
    detection_results: Sequence[DetectionResult] = (),
    revoked_grant_ids: Sequence[str] = (),
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
    """
    policy_digest = canonical_sha256(policies.model_dump(mode="json"))
    signals, degradations = _legacy_signals_and_degradations(
        detection_results, event_id=event.event_id
    )

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
        try:
            plan = build_required_check_plan(
                action_ir,
                PolicyProfile(
                    policy_revision=snapshot.policy_revision,
                    policy_digest=snapshot.policy_digest,
                ),
            )
            state = _state_from_snapshot(
                snapshot, revoked_grant_ids=revoked_grant_ids
            )
            coverage = compute_coverage(
                state, plan, projector_version=snapshot.projector_version
            )
            authority = compute_authority_verdict(
                state,
                action_ir,
                evaluated_at=snapshot.evaluation_clock.evaluated_at,
            )
            flow = compute_flow_verdict(snapshot, action_ir)
        except Exception:  # noqa: BLE001 - 组件异常收敛为 shadow 降级。
            degraded_reason = REASON_COMPONENT_FAILED
            plan = _degraded_plan(impact, REASON_COMPONENT_FAILED)
            coverage = _unknown_coverage(
                PROJECTOR_VERSION, REASON_COMPONENT_FAILED
            )
            authority = _degraded_authority()
            flow = _degraded_flow()

    if degraded_reason is not None:
        degradations = [*degradations, _shadow_degradation(degraded_reason, event_id=event.event_id)]
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
            memory_facts=snapshot.memory_facts,  # type: ignore[union-attr]
            flows=snapshot.flows,  # type: ignore[union-attr]
            behavior_aggregates=snapshot.behavior_aggregates,  # type: ignore[union-attr]
            requires_semantic=False,
            security_digests_valid=(
                _digest_well_formed(policy_digest)
                and _digest_well_formed(snapshot_digest)
                and _digest_well_formed(task_digest)
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
    return assessment.model_copy(
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


# ---------------------------------------------------------------------------
# finalize_shadow（V21-09 预留接入点）
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

    V21-09 ``GuardEngine.finalize`` 的预留投影（shadow 期官方决策者仍是
    legacy，本函数只用于离线对照分析，不参与线上决策）。
    """
    return _SHADOW_FINALIZE_MAP[assessment.disposition]
