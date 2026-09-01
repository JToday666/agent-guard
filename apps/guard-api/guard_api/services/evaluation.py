"""Guard evaluation orchestration service."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal, cast

from agentguard_core import (
    ActionCritic,
    ApprovalReleaseDirectiveV2,
    AuditEvent,
    DecisionAuthority,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    MemoryEventPayload,
    MemoryGuardChange,
    V21AuthoritySelectionError,
    V21SelectionEligibility,
    V21SelectionResult,
    build_decision_authority_evidence,
    decision_authority_envelope,
    select_v21_authority,
)
from agentguard_core.decisions.evidence_builder import (
    build_decision_evidence_v21,
    decision_evidence_v21_envelope,
)
from agentguard_core.decisions.shadow import ABSENT_SNAPSHOT_ID
from agentguard_core.security_context import (
    ASSESSMENT_OVERLAY_COMPONENT_ID,
    AssessmentTransientFacts,
)
from agentguard_core.signals.models import EvaluationDegradation
from guard_api.models import (
    ApprovalRequest,
    EnforcementBinding,
    EvaluationApproval,
    GuardEvaluationResponse,
)
from guard_api.auth import AuthContext
from guard_api.storage.base import (
    EnforcementBindingConflictError,
    EnforcementBindingRecord,
    parse_audit_timestamp,
)
from guard_api.storage.integrity import canonical_sha256

from .approval import ApprovalService
from .audit import AuditService
from .competition import (
    CriticalDecisionEvidenceError,
    parse_decision_authority_evidence_payload,
)
from .context_manifest import (
    ContextManifestPrepared,
    context_manifest_anchor_from_policy,
    context_manifest_record_digest,
    prepare_context_manifest,
    records_have_same_content,
    validate_context_manifest_audit_event,
)
from .memory import MemoryGuardService
from .policy import PolicyService
from .v21_pipeline import V21OfficialEvaluationUnavailableError

if TYPE_CHECKING:
    from agentguard_core.security_context import ContextAssemblyPlan

    from .context_builder import ContextBuilderService
    from .ct_projection import CtCommitPlan, CtProjectionService
    from guard_api.security_state.transient import TransientSecurityFacts

    from .v21_pipeline import (
        V21PhaseAPrepared,
        V21PhaseBOutcome,
        V21PhaseCPlan,
        V21PipelineMaterials,
        V21PipelineService,
    )
    from .v21_shadow import V21ShadowService
    from .competition import FrozenCompetitionActivation
    from .product_activation import ProductActivePreSelectorFuse


logger = logging.getLogger(__name__)

_CT_OVERLAY_UNAVAILABLE_REASON = "ct-fact:overlay_unavailable"


def _ct_overlay_unavailable(
    *, event_id: str, scope_digest: str
) -> AssessmentTransientFacts:
    """Build a deterministic required degradation when CT cannot reach Core.

    This DTO contains no asserted facts.  It only marks the dataflow provider
    unavailable so an enabled-but-failed Gate A path cannot silently fall back
    to the pre-overlay assessment and produce ``CLEAR_ALLOW``.
    """

    return AssessmentTransientFacts.from_primitives(
        event_id=event_id,
        scope_digest=scope_digest,
        degradations=(
            EvaluationDegradation(
                degradation_id=f"gate-a:ct-overlay-unavailable:{event_id}",
                component_id=ASSESSMENT_OVERLAY_COMPONENT_ID,
                domain="dataflow",
                required_for_action=True,
                failure_kind="unavailable",
                reason_codes=[_CT_OVERLAY_UNAVAILABLE_REASON],
                evidence_refs=[],
            ),
        ),
    )


class EvaluationConflictError(ValueError):
    """Raised when the same event_id is re-evaluated with different content."""


# SecurityContext 后续增补的会话身份字段（见 agentguard_core SecurityContext）。
_SESSION_IDENTITY_FIELDS: tuple[str, ...] = (
    "conversation_id",
    "session_key",
    "session_id",
    "visible_source_refs",
)
# payload 契约扩展时增补的可选字段（见 MemoryEventPayload.action_id）。
_PAYLOAD_EXTENSION_FIELDS: tuple[str, ...] = (
    "action_id",
    "context_plan_id",
    "context_plan_digest",
    "context_ref",
    "visible_source_refs",
)
_CONTEXT_SOURCE_EXTENSION_FIELDS: tuple[str, ...] = (
    "content_digest",
    "role",
    "sequence_index",
)

_ACTION_TYPE_BY_EVENT: dict[str, str] = {
    "tool_call_proposed": "tool_call",
    "context_assembled": "context_build",
    "model_input_prepared": "model_call",
    "model_output_produced": "model_call",
    "tool_result_produced": "tool_result",
    "memory_write_proposed": "memory_write",
    "message_send_proposed": "message_send",
}

# Execution leases authorize only concrete side-effect proposals. Lifecycle
# observations and model/context events cannot acquire authority even if a
# malformed adapter claims ``pre_execution=true``.
_STRONG_BINDING_PRE_EXECUTION_EVENT_TYPES = frozenset(
    {
        "tool_call_proposed",
        "memory_write_proposed",
        "message_send_proposed",
    }
)


def canonical_request_dump(event: GuardEvent) -> dict[str, Any]:
    """request_digest 的规范化 dump 口径。

    SecurityContext / payload 契约增补带默认值的字段后，model_dump 会多出
    默认 null 键，导致存量事件的 digest 与变更前计算值不一致，重放被误判为
    EvaluationConflictError。口径：生产者未显式发送（不在 model_fields_set）
    的增补字段从 dump 中剔除，使旧形状事件的 digest 与变更前全量 dump 完全
    一致；显式携带的字段（含显式 null）仍参与 digest，保留内容变化检测能力。
    """

    dump = event.model_dump(mode="json")
    explicitly_set = event.security_context.model_fields_set
    context_dump = dump.get("security_context")
    if isinstance(context_dump, dict):
        for field_name in _SESSION_IDENTITY_FIELDS:
            if field_name not in explicitly_set:
                context_dump.pop(field_name, None)
    payload_fields_set = getattr(event.payload, "model_fields_set", set())
    payload_dump = dump.get("payload")
    if isinstance(payload_dump, dict):
        for field_name in _PAYLOAD_EXTENSION_FIELDS:
            if field_name not in payload_fields_set:
                payload_dump.pop(field_name, None)
        raw_sources = getattr(event.payload, "sources", None)
        dumped_sources = payload_dump.get("sources")
        if isinstance(raw_sources, list) and isinstance(dumped_sources, list):
            for source, source_dump in zip(raw_sources, dumped_sources, strict=False):
                if not isinstance(source_dump, dict):
                    continue
                fields_set = getattr(source, "model_fields_set", set())
                for field_name in _CONTEXT_SOURCE_EXTENSION_FIELDS:
                    if field_name not in fields_set:
                        source_dump.pop(field_name, None)
    return dump


def _stored_request_digest(audit: AuditEvent) -> object:
    """Return the canonical request digest from the 0.4 audit contract."""

    return audit.metadata.get("request_digest")


def _stored_decision_dump(audit: AuditEvent) -> object:
    """Return the canonical decision snapshot from the 0.4 audit contract."""

    evidence = audit.evidence
    if isinstance(evidence, dict):
        dump = evidence.get("guard_decision")
        if dump is not None:
            return dump
    return None


class EvaluationService:
    def __init__(
        self,
        *,
        policy_service: PolicyService,
        audit_service: AuditService,
        approval_service: ApprovalService,
        memory_guard_service: MemoryGuardService | None = None,
        action_critic: ActionCritic | None = None,
        v21_shadow_service: V21ShadowService | None = None,
        v21_pipeline: "V21PipelineService | None" = None,
        ct_projection_service: "CtProjectionService | None" = None,
        context_builder_service: "ContextBuilderService | None" = None,
        competition_activation: "FrozenCompetitionActivation | None" = None,
        product_active_fuse: "ProductActivePreSelectorFuse | None" = None,
    ) -> None:
        self.policy_service = policy_service
        self.audit_service = audit_service
        self.approval_service = approval_service
        self.memory_guard_service = memory_guard_service
        self.action_critic = action_critic or ActionCritic()
        # V21-08 shadow 旁路编排器（V2 mode 默认 off）。T5 在 audit 落盘前
        # 调用它旁路产出 decision_v21 信封；判定/审批主流程不使用它
        # （legacy = 唯一官方决策者，04 §1-§2）。V21-09 起它同时是
        # pipeline Phase A 彻底失败时的逐字节降级回退路径。
        self.v21_shadow_service = v21_shadow_service
        # V21-09 四段式编排器（D4；flag 门控与 V21ShadowService 同源）。
        # 就绪时 evaluate 编排切换为 pipeline：Phase A 事务外、Phase B
        # 短事务内消费材料；未就绪时既有路径逐字节不变。
        self.v21_pipeline = v21_pipeline
        # CT-PR-03b CT 事实投影编排器（D2/D3：独立 flag，仅 pipeline
        # 材料就绪时生效；事务外构建 → 事务内信封 → 事务后投影）。
        self.ct_projection_service = ct_projection_service
        self.context_builder_service = context_builder_service
        self.competition_activation = competition_activation
        # P0-V21-01a2: loading a Product Active bundle arms a fail-closed
        # pre-selector fuse.  It is deliberately checked at the very top of
        # ``evaluate`` (after authenticated principal normalization) so an
        # unwired Product selector can never fall through to current authority
        # or touch replay/state/policy side-effect paths.
        self.product_active_fuse = product_active_fuse

    def evaluate(
        self,
        event: GuardEvent,
        *,
        requesting_principal_id: str | None = None,
        auth_context: AuthContext | None = None,
    ) -> GuardEvaluationResponse:
        """Evaluate with the router-authenticated identity when available.

        ``requesting_principal_id`` remains as a compatibility boundary for
        direct service tests and internal pre-V2 callers.  Production routing
        passes the complete immutable ``AuthContext`` so authority selection
        can bind principal, runtime, agent and credential provenance together.
        """

        if auth_context is not None:
            if (
                requesting_principal_id is not None
                and requesting_principal_id != auth_context.principal_id
            ):
                raise ValueError("requesting principal conflicts with AuthContext")
            requesting_principal_id = auth_context.principal_id
        if requesting_principal_id is None:
            raise ValueError("requesting principal is required")
        if self.product_active_fuse is not None:
            self.product_active_fuse.enforce(event, auth_context)
        # Validate temporal identity before detectors or any approval/memory side
        # effects run; persistence uses the same parser for defense in depth.
        parse_audit_timestamp(event.timestamp)
        request_digest = canonical_sha256(canonical_request_dump(event))
        # V21-09 D4/D9：pipeline Phase A 在 evaluation_transaction 之前
        # 执行（事务外只读）；replay 不重算 assess——已存在幂等评估
        # 时直接走事务内 replay 检查，不跑 Phase A。
        materials: "V21PipelineMaterials | None" = None
        ct_bundle: "TransientSecurityFacts | None" = None
        context_plan: "ContextAssemblyPlan | None" = None
        context_requested = bool(
            self.context_builder_service is not None
            and self.context_builder_service.enabled
            and event.event_type == "context_assembled"
        )
        if self.v21_pipeline is not None and self.v21_pipeline.enabled:
            existing = self.audit_service.store.get_policy_evaluation_by_event_id(
                event.event_id
            )
            if existing is not None and not context_requested:
                replayed = self._replay_or_conflict(
                    existing, request_digest, event.event_id
                )
                if replayed is not None:
                    # D9：事务外幂等补投影（不重算；五元组幂等键短路
                    # 保证重复安全；绝不外抛、不影响重放响应）。
                    self.v21_pipeline.backfill_projection(existing)
                    if self.ct_projection_service is not None:
                        self.ct_projection_service.backfill(existing)
                    return replayed
            else:
                # Gate A: CT 开启时将 Phase A 拆成 prepare/finish。事实只
                # 构造一次，并在权威 commit 前作为 ephemeral overlay
                # 参与当前 V2 shadow assessment；历史 Snapshot 不变。
                if (
                    self.ct_projection_service is not None
                    and self.ct_projection_service.fact_building_enabled
                ):
                    prepared: "V21PhaseAPrepared | None" = (
                        self.v21_pipeline.prepare_phase_a(
                            event,
                            auth_context=auth_context,
                        )
                    )
                    if prepared is not None:
                        ct_bundle = self.ct_projection_service.build_transient_bundle(
                            event,
                            prepared,
                        )
                        if (
                            context_requested
                            and ct_bundle is not None
                            and prepared.snapshot is not None
                            and self.context_builder_service is not None
                        ):
                            context_result = self.context_builder_service.build(
                                event,
                                bundle=ct_bundle,
                                snapshot=prepared.snapshot,
                            )
                            if context_result is None:
                                # A context-enabled failure is not allowed to
                                # fall back to the unfiltered transient bundle.
                                ct_bundle = None
                            else:
                                ct_bundle = context_result.bundle
                                context_plan = context_result.plan
                        transient_facts = None
                        overlay_scope = (
                            prepared.scope_digest
                            if prepared.snapshot is not None
                            and prepared.task_id is not None
                            else None
                        )
                        if ct_bundle is None and overlay_scope is not None:
                            transient_facts = _ct_overlay_unavailable(
                                event_id=event.event_id,
                                scope_digest=overlay_scope,
                            )
                        elif ct_bundle is not None:
                            try:
                                transient_facts = (
                                    AssessmentTransientFacts.model_validate(
                                        ct_bundle.model_dump(mode="json")
                                    )
                                )
                            except Exception:  # noqa: BLE001 - shadow fail-closed。
                                # A bundle that Core did not consume must never
                                # be committed/projected as if it influenced the
                                # assessment.  Replace it with a degradation-only
                                # overlay and clear the commit candidate.
                                ct_bundle = None
                                if overlay_scope is not None:
                                    transient_facts = _ct_overlay_unavailable(
                                        event_id=event.event_id,
                                        scope_digest=overlay_scope,
                                    )
                                logger.warning(
                                    "ct transient facts could not be mapped to "
                                    "the Core overlay for event %s; using a "
                                    "required dataflow degradation",
                                    event.event_id,
                                    exc_info=True,
                                )
                        materials = self.v21_pipeline.finish_phase_a(
                            event,
                            prepared,
                            transient_facts=transient_facts,
                            auth_context=auth_context,
                        )
                else:
                    # Compatibility path: no new keyword/call boundary when CT
                    # is disabled, preserving V21-09 byte-for-byte behavior.
                    materials = self.v21_pipeline.run_phase_a(
                        event,
                        auth_context=auth_context,
                    )
        # Context isolation has its own flag and must not require V2 shadow.
        # With V2 enabled, the branch above already built and filtered the one
        # shared Gate A bundle.  Only the V2-off path performs one context-only
        # authoritative Snapshot + Fact Authority build; official legacy/V2
        # decision selection is unchanged.
        if (
            context_requested
            and context_plan is None
            and not (self.v21_pipeline is not None and self.v21_pipeline.enabled)
            and self.context_builder_service is not None
        ):
            context_result = (
                self.context_builder_service.build_from_authoritative_state(event)
            )
            if context_result is not None:
                context_plan = context_result.plan
        # CT Gate A：从 assessment 使用过的同一 bundle 准备 commit 计划，
        # 禁止为了投影再次运行 fact builder。
        ct_plan: "CtCommitPlan | None" = None
        if (
            self.ct_projection_service is not None
            and materials is not None
            and ct_bundle is not None
            and materials.consumed_overlay_digest == ct_bundle.overlay_digest
        ):
            ct_plan = self.ct_projection_service.build_commit_plan(
                event,
                materials,
                ct_bundle,
            )
        elif ct_bundle is not None and materials is not None:
            logger.warning(
                "ct bundle for event %s was not acknowledged by Core; "
                "skipping its audit commit and projection",
                event.event_id,
            )
        # CT-PR-04-M preparation is outside the write transaction and consumes
        # only the already-verified ephemeral plan plus this exact request.  A
        # preparation failure removes the plan from the response but does not
        # change the legacy/current official decision.
        context_manifest: ContextManifestPrepared | None = None
        if context_plan is not None:
            try:
                context_manifest = prepare_context_manifest(event, context_plan)
            except Exception as exc:  # noqa: BLE001 - plan disclosure fails closed.
                logger.warning(
                    "context_manifest_prepare_failed event_id=%s error_type=%s",
                    event.event_id,
                    type(exc).__name__,
                )
        # 审批、memory change、审计与 provenance 是一次评估的原子结果。
        # 同 event_id 在事务开始时串行化，失败时不得遗留任何部分状态。
        backfill_audit: AuditEvent | None = None
        phase_c_plan: "V21PhaseCPlan | None" = None
        product_transaction = bool(
            materials is not None
            and self.v21_pipeline is not None
            and self.v21_pipeline.product_active
        )
        transaction = (
            self.v21_pipeline.authority_transaction(event, materials)
            if materials is not None and self.v21_pipeline is not None
            else self.audit_service.store.evaluation_transaction(event.event_id)
        )
        created_evaluation = False
        with transaction:
            existing = self.audit_service.store.get_policy_evaluation_by_event_id(
                event.event_id
            )
            replayed = self._replay_or_conflict(
                existing,
                request_digest,
                event.event_id,
            )
            if replayed is not None:
                assert existing is not None
                replay_plan = self._context_plan_for_replay(
                    existing,
                    context_manifest,
                    context_requested=context_requested,
                )
                response = replayed.model_copy(update={"context_plan": replay_plan})
                backfill_audit = existing
                ct_plan = None  # replay：无新 commit，走 D9 同构 backfill。
            else:
                response, backfill_audit, phase_c_plan = self._evaluate_once(
                    event,
                    request_digest=request_digest,
                    requesting_principal_id=requesting_principal_id,
                    materials=materials,
                    ct_plan=ct_plan,
                    context_manifest=context_manifest,
                )
                created_evaluation = True
            if product_transaction and created_evaluation:
                assert self.v21_pipeline is not None
                assert materials is not None
                assert backfill_audit is not None
                self.v21_pipeline.finalize_product_commit(
                    event,
                    materials,
                    audit_id=backfill_audit.audit_id,
                    phase_c_plan=phase_c_plan,
                    expected_authority_digest=cast(
                        "str | None",
                        backfill_audit.metadata.get("product_authority_digest"),
                    ),
                    initial_authority_checked_at=cast(
                        "str | None",
                        backfill_audit.metadata.get(
                            "product_authority_initial_checked_at"
                        ),
                    ),
                )
        # D4 commit → project：投影在事务提交**之后**执行，绝不影响
        # 已 commit 的审计记录与已确定的响应；两者互斥：新评估走
        # Phase C，重放走 D9 补投影；失败一律收敛不外抛。
        if self.v21_pipeline is not None:
            if phase_c_plan is not None:
                self.v21_pipeline.run_phase_c(phase_c_plan)
            elif backfill_audit is not None:
                self.v21_pipeline.backfill_projection(backfill_audit)
        # CT-PR-03b：新评估 → 事务退出后投影；重放 → backfill 补投影。
        if self.ct_projection_service is not None:
            if ct_plan is not None:
                self.ct_projection_service.project_after_commit(ct_plan)
            elif backfill_audit is not None:
                self.ct_projection_service.backfill(backfill_audit)
        return response

    def _evaluate_once(
        self,
        event: GuardEvent,
        *,
        request_digest: str,
        requesting_principal_id: str,
        materials: "V21PipelineMaterials | None" = None,
        ct_plan: "CtCommitPlan | None" = None,
        context_manifest: ContextManifestPrepared | None = None,
    ) -> tuple[GuardEvaluationResponse, AuditEvent | None, "V21PhaseCPlan | None"]:
        """事务内单次评估；返回（响应, 已落盘审计记录, Phase C 计划）。

        legacy 路径后两项恒 None（无投影、无 D9 补投影语义）；flag
        off 时行为与现状逐字节一致。
        """
        if materials is not None:
            return self._evaluate_once_pipeline(
                event,
                request_digest=request_digest,
                requesting_principal_id=requesting_principal_id,
                materials=materials,
                ct_plan=ct_plan,
                context_manifest=context_manifest,
            )
        snapshot_record = self.policy_service.current_snapshot_record()
        if snapshot_record is not None:
            bundle = snapshot_record.policy_bundle
        else:
            bundle = self.policy_service.current_snapshot()
        # 与 module-level evaluate 同一实现路径（engine.evaluate 委托
        # evaluate_with_results）：decision 语义逐字节不变，仅额外外露
        # DetectionResult 供 shadow 同源注入，避免编排器双跑检测器。
        decision, detections = GuardEngine().evaluate_with_results(event, bundle)
        critic_review = self.action_critic.review(event, decision)
        approval = self.approval_service.create_for_decision(
            event,
            decision,
            requesting_principal_id=requesting_principal_id,
        )
        approval = self.approval_service.auto_review_with_llm(approval)
        memory_change = self._record_memory_change(
            event, decision, requesting_principal_id=requesting_principal_id
        )
        # V21-08 shadow 审计侧信道：audit 落盘前旁路产出 decision_v21
        # 信封。flag 关/secret 缺时编排器内部一次布尔判断即返回 None，
        # audit 路径与现状逐字节一致；旁路故障由编排器自行收敛，绝不
        # 影响 legacy decision/approval/audit 主链。
        v21_evidence = None
        if self.v21_shadow_service is not None:
            v21_evidence = self.v21_shadow_service.build_shadow_evidence(
                event,
                bundle,
                legacy_decision=decision.decision,
                detection_results=detections,
                policy_revision=(
                    str(snapshot_record.revision)
                    if snapshot_record is not None
                    else None
                ),
            )
        # §9.9：links 只放稳定 ID；digest 经 metadata 传入 writer。
        audit_event = self.audit_service.record_evaluation(
            event,
            decision,
            policy_bundle=bundle,
            policy_revision=(
                snapshot_record.revision if snapshot_record is not None else None
            ),
            approval_id=approval.approval_id if approval is not None else None,
            critic_review=critic_review,
            memory_change_id=(
                memory_change.change_id if memory_change is not None else None
            ),
            extra_metadata={
                "request_digest": request_digest,
                "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
                **self._context_manifest_metadata(context_manifest),
            },
            decision_dump=decision.model_dump(mode="json"),
            v21_evidence=v21_evidence,
        )
        committed_context_plan = self._record_context_manifest(
            audit_event, context_manifest
        )
        return (
            GuardEvaluationResponse(
                decision=decision,
                approval=self._approval_summary(approval),
                policy_audit_id=audit_event.audit_id,
                context_plan=committed_context_plan,
            ),
            None,
            None,
        )

    def _evaluate_once_pipeline(
        self,
        event: GuardEvent,
        *,
        request_digest: str,
        requesting_principal_id: str,
        materials: "V21PipelineMaterials",
        ct_plan: "CtCommitPlan | None" = None,
        context_manifest: ContextManifestPrepared | None = None,
    ) -> tuple[GuardEvaluationResponse, AuditEvent | None, "V21PhaseCPlan | None"]:
        """四段式编排路径（D4）：Phase A 产物已在事务外就绪。

        事务窗口内：legacy 链照常（decision/detections 直接消费 Phase A
        单跑结果，不双跑检测器）+ Phase B revalidate 与证据构建。
        legacy 分支保持轻量标量重读；Product 分支在 store-native lockset
        内严格重读完整有界 authority，并在所有 staged writes 后做最终
        precommit revalidation。mode off 路径仍与 legacy 同源同实现。

        审计 policy_revision 直接用 ``materials.policy_revision``（Phase A
        冻结值，与 bundle/policy_digest 同源同时点）：事务内重读
        ``current_snapshot_record()`` 会在并发策略滚动时落新 revision，
        与 Phase A 冻结 bundle 的 digest 组成"revision N+1 × digest
        (bundle N)"矛盾组合（TOCTOU）。因此 legacy 分支不在此处重读；
        Product 分支只在 authority fence 中以精确 revision + digest 做
        相等性校验，绝不替换 Phase A bundle。
        """
        bundle = materials.bundle
        # Phase B and authoritative selection run before every mutating service.
        # No critic, approval, memory, audit, binding or receipt can observe the
        # current decision until the unique selected result is known.
        decision = materials.decision
        v21_evidence = None
        state_delta_evidence = None
        authority: DecisionAuthority | None = None
        authority_evidence: dict[str, object] | None = None
        phase_c_plan: "V21PhaseCPlan | None" = None
        phase_b_outcome: "V21PhaseBOutcome | None" = None
        finalize_metadata: dict[str, str] = {}
        # V21-13 Stage 1 shadow：judgment 缺席时恒空表（metadata 键集
        # 逐字节不变）；在场时条件性追加五个确定性引用键。
        semantic_metadata: dict[str, object] = {}
        product_authority_metadata: dict[str, object] = {}
        if self.v21_pipeline is not None:
            outcome = self.v21_pipeline.build_phase_b(event, materials)
            if outcome is not None:
                phase_b_outcome = outcome
                v21_evidence = outcome.envelope
                selection = self._select_competition_authority(
                    event,
                    materials=materials,
                    outcome=outcome,
                )
                if selection is not None:
                    decision = selection.selected_decision
                    authority = selection.authority
                    activation = self.competition_activation
                    assert activation is not None
                    snapshot_id = (
                        materials.snapshot.snapshot_id
                        if materials.snapshot is not None
                        else ABSENT_SNAPSHOT_ID
                    )
                    evidence = build_decision_authority_evidence(
                        result=selection,
                        assessment=materials.assessment,
                        activation=activation.manifest,
                        snapshot_id=snapshot_id,
                        state_version=(
                            materials.state_version
                            if materials.snapshot is not None
                            else 0
                        ),
                    )
                    authority_evidence = decision_authority_envelope(evidence)
                    stale_codes = (
                        list(outcome.revalidation.reason_codes)
                        if outcome.revalidation.status == "stale"
                        else []
                    )
                    # competition selection 重建信封有意不携带 semantic
                    # 槽（评审 W2，shadow 纪律）：重建路径不复算
                    # binding，宁缺勿滥、fail-closed；judgment 引用仍经
                    # 审计 metadata 五个引用键在场。
                    selected_evidence = build_decision_evidence_v21(
                        materials.assessment,
                        legacy_decision=materials.decision.decision,
                        snapshot_id=snapshot_id,
                        state_version=(
                            materials.state_version
                            if materials.snapshot is not None
                            else 0
                        ),
                        coverage=materials.coverage,
                        mode=authority.mode,
                        selected_decision=decision.decision,
                        revalidation_stale_reason_codes=stale_codes,
                    )
                    v21_evidence = decision_evidence_v21_envelope(selected_evidence)
                phase_c_plan = self.v21_pipeline.prepare_phase_c(outcome)
                if phase_c_plan is not None:
                    state_delta_evidence = phase_c_plan.envelope
                if outcome.final_decision_id is not None:
                    # D11：finalize 产物确定性引用写审计 metadata
                    # （仅 revalidate valid 且非降级路径；stale/降级/
                    # mode off 时键集逐字节不变）。
                    assert outcome.final_decision_digest is not None
                    if authority is not None and authority.source == "v21":
                        finalize_metadata = {
                            "v21_final_decision_id": decision.decision_id,
                            "v21_final_decision_digest": canonical_sha256(
                                decision.model_dump(mode="json")
                            ),
                        }
                    else:
                        finalize_metadata = {
                            "v21_final_decision_id": outcome.final_decision_id,
                            "v21_final_decision_digest": (
                                outcome.final_decision_digest
                            ),
                        }
                if outcome.product_authority_digest is not None:
                    assert outcome.product_authority_initial_checked_at is not None
                    product_authority_metadata = {
                        "product_authority_digest": (outcome.product_authority_digest),
                        # This is the first fenced Phase-B capture, not the
                        # final precommit instant.  The latter is the exact
                        # projection reservation ``created_at``.
                        "product_authority_initial_checked_at": (
                            outcome.product_authority_initial_checked_at
                        ),
                    }
                semantic_judgment = outcome.materials.semantic_judgment
                if semantic_judgment is not None:
                    # V21-13 shadow 产物只走审计 metadata 承载（wire
                    # schema 无 semantic 字段，不改 schemas/）；binding
                    # 结论复用 Phase B 已判定值（outcome 内部字段，
                    # 不重复计算）。只落五个确定性引用键（D11 口径）：
                    # judgment 全文会被 sanitize_audit_event 的 redaction
                    # 改写（authorization_fingerprint 命中敏感 marker 被
                    # REDACTED、reason_codes 超限被截断），落盘全文会与
                    # v21_semantic_digest 永久失配，违反「禁静默丢失」
                    # 纪律（评审 M3）。judgment 全文的审计承载归后续
                    # typed bound 证据通道（仿 ct_transient_facts 先例），
                    # shadow 初版只落确定性引用。
                    semantic_metadata = {
                        "v21_semantic_judgment_id": (semantic_judgment.judgment_id),
                        "v21_semantic_digest": semantic_judgment.semantic_digest,
                        "v21_semantic_verdict": semantic_judgment.verdict,
                        "v21_semantic_degraded": semantic_judgment.degraded,
                        "v21_semantic_binding_valid": (outcome.semantic_binding_valid),
                    }
        if (
            self.competition_activation is not None
            and self.v21_pipeline is not None
            and self.v21_pipeline.active
            and authority is None
        ):
            raise V21OfficialEvaluationUnavailableError(
                "V21_OFFICIAL_SELECTOR_UNAVAILABLE"
            )

        # From this point forward every side effect consumes exactly the selected
        # decision and its committed authority projection.
        critic_review = self.action_critic.review(event, decision)
        approval = self.approval_service.create_for_decision(
            event,
            decision,
            requesting_principal_id=requesting_principal_id,
            decision_authority=authority,
            approval_release_directive=None,
        )
        if not (self.v21_pipeline is not None and self.v21_pipeline.product_active):
            approval = self.approval_service.auto_review_with_llm(approval)
        memory_change = self._record_memory_change(
            event, decision, requesting_principal_id=requesting_principal_id
        )
        audit_event = self.audit_service.record_evaluation(
            event,
            decision,
            policy_bundle=bundle,
            # W1 修复：同源同时点冻结值（str 形态 → 审计契约 int），
            # 不在事务内重读 policy 面（避免并发策略滚动时
            # "revision N+1 × digest(bundle N)" TOCTOU 矛盾组合）。
            policy_revision=(
                int(materials.policy_revision)
                if materials.policy_revision is not None
                else None
            ),
            approval_id=approval.approval_id if approval is not None else None,
            critic_review=critic_review,
            memory_change_id=(
                memory_change.change_id if memory_change is not None else None
            ),
            extra_metadata={
                "request_digest": request_digest,
                "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
                **finalize_metadata,
                **semantic_metadata,
                **product_authority_metadata,
                **self._context_manifest_metadata(context_manifest),
            },
            decision_dump=decision.model_dump(mode="json"),
            v21_evidence=v21_evidence,
            state_delta_evidence=state_delta_evidence,
            # CT-PR-03b D4：facts 信封随同一条审计记录原子提交。
            ct_facts_evidence=(ct_plan.envelope if ct_plan is not None else None),
            decision_authority_evidence=authority_evidence,
            decision_authority=authority,
            # D7-5：pipeline 路径确定性审计身份（replay 同输入同身份）；
            # plan 缺态（stale/降级）时沿用 AuditEvent 默认工厂。
            audit_id=(phase_c_plan.audit_id if phase_c_plan is not None else None),
        )
        committed_context_plan = self._record_context_manifest(
            audit_event, context_manifest
        )
        binding = self._save_enforcement_binding(
            event,
            approval=approval,
            audit=audit_event,
            materials=materials,
            phase_b_outcome=phase_b_outcome,
            requesting_principal_id=requesting_principal_id,
            selected_decision=decision,
            decision_authority=authority,
            approval_release_directive=None,
        )
        return (
            GuardEvaluationResponse(
                decision=decision,
                approval=self._approval_summary(approval),
                policy_audit_id=audit_event.audit_id,
                enforcement_binding=binding,
                context_plan=committed_context_plan,
                decision_authority=authority,
            ),
            audit_event,
            phase_c_plan,
        )

    def _select_competition_authority(
        self,
        event: GuardEvent,
        *,
        materials: "V21PipelineMaterials",
        outcome: "V21PhaseBOutcome",
    ) -> V21SelectionResult | None:
        activation = self.competition_activation
        if activation is None:
            return None
        if self.v21_pipeline is None:
            raise V21OfficialEvaluationUnavailableError(
                "V21_OFFICIAL_PIPELINE_UNAVAILABLE"
            )
        raw_mode = self.v21_pipeline.mode
        if raw_mode not in {"shadow", "limited_enable", "active"}:
            raise V21OfficialEvaluationUnavailableError("V21_OFFICIAL_MODE_INVALID")
        mode = cast(
            Literal["shadow", "limited_enable", "active"],
            raw_mode,
        )
        manifest = activation.manifest
        auth = materials.auth_context
        expected_binding = f"binding:{auth.principal_id}" if auth is not None else None
        scope = materials.snapshot.scope if materials.snapshot is not None else None
        scope_identity_valid = bool(
            scope is None
            or (
                scope.principal_id == manifest.principal_id
                and scope.runtime == manifest.runtime
                and scope.runtime_binding_id == manifest.runtime_binding_id
            )
        )
        trusted_identity_valid = bool(
            auth is not None
            and auth.principal_id == manifest.principal_id
            and auth.runtime == manifest.runtime == event.runtime
            and auth.agent_id == manifest.agent_id
            and auth.agent_id == event.security_context.agent_id
            and expected_binding == manifest.runtime_binding_id
            and scope_identity_valid
        )
        action_ir = materials.action_ir
        action_ir_consistent = bool(
            materials.snapshot is None
            or action_ir is None
            or (
                action_ir.event_id == event.event_id
                and action_ir.action_id == materials.assessment.action_id
                and action_ir.authorization_fingerprint
                == materials.assessment.authorization_fingerprint
                and action_ir.audit_fingerprint
                == materials.assessment.audit_fingerprint
                and action_ir.principal_id == manifest.principal_id
                and action_ir.runtime_binding_id == manifest.runtime_binding_id
                and action_ir.agent_id == manifest.agent_id
            )
        )
        action_ir_complete = bool(
            materials.snapshot is not None
            and action_ir is not None
            and action_ir_consistent
        )
        ownership_valid = bool(
            trusted_identity_valid
            and scope is not None
            and scope.principal_id == manifest.principal_id
            and scope.runtime == manifest.runtime
            and scope.runtime_binding_id == manifest.runtime_binding_id
            and (
                action_ir is None
                or (
                    action_ir.principal_id == scope.principal_id
                    and action_ir.scope_digest == scope.scope_digest
                )
            )
        )
        eligibility = V21SelectionEligibility(
            activation_valid=True,
            trusted_identity_valid=trusted_identity_valid,
            profile_valid=(
                manifest.profile_id == "competition-langgraph-v2"
                and manifest.runtime == "langgraph"
            ),
            revalidation_valid=outcome.revalidation.status == "valid",
            pipeline_complete=(
                outcome.raw_v21_decision is not None
                and materials.degraded_kind != "component_failure"
                and action_ir_consistent
            ),
            ownership_valid=ownership_valid,
            action_ir_complete=action_ir_complete,
            task_fact_present=bool(
                materials.task_id is not None and materials.snapshot is not None
            ),
            approval_binding_eligible=bool(
                event.pre_execution is True
                and event.event_type in _STRONG_BINDING_PRE_EXECUTION_EVENT_TYPES
            ),
        )
        snapshot_id = (
            materials.snapshot.snapshot_id
            if materials.snapshot is not None
            else ABSENT_SNAPSHOT_ID
        )
        try:
            return select_v21_authority(
                event_id=event.event_id,
                current_decision=materials.decision,
                raw_v21_decision=outcome.raw_v21_decision,
                assessment=materials.assessment,
                coverage=materials.coverage,
                mode=mode,
                activation=manifest,
                eligibility=eligibility,
                snapshot_id=snapshot_id,
                state_version=(
                    materials.state_version if materials.snapshot is not None else 0
                ),
            )
        except V21AuthoritySelectionError as exc:
            raise V21OfficialEvaluationUnavailableError(exc.code) from exc

    @staticmethod
    def _context_manifest_metadata(
        prepared: ContextManifestPrepared | None,
    ) -> dict[str, object]:
        if prepared is None:
            return {}
        return {"context_manifest_anchor": prepared.anchor.model_dump(mode="json")}

    def _record_context_manifest(
        self,
        policy_audit: AuditEvent,
        prepared: ContextManifestPrepared | None,
    ) -> "ContextAssemblyPlan | None":
        """Write/readback the Manifest before exposing its transient plan."""

        if prepared is None:
            return None
        anchor = context_manifest_anchor_from_policy(policy_audit)
        if anchor is None or anchor != prepared.anchor:
            raise RuntimeError("policy audit context manifest anchor mismatch")
        persisted = self.audit_service.record_context_manifest(prepared)
        strict = validate_context_manifest_audit_event(persisted)
        if (
            strict.audit_id != anchor.audit_id
            or strict.trace_id != policy_audit.trace_id
            or strict.links.event_id != anchor.event_id
            or strict.links.plan_id != anchor.plan_id
            or strict.links.context_ref != anchor.context_ref
            or context_manifest_record_digest(strict) != anchor.manifest_digest
            or not records_have_same_content(persisted, prepared.audit_record)
        ):
            raise RuntimeError("context manifest readback does not match its anchor")
        return prepared.plan

    def _context_plan_for_replay(
        self,
        policy_audit: AuditEvent,
        prepared: ContextManifestPrepared | None,
        *,
        context_requested: bool,
    ) -> "ContextAssemblyPlan | None":
        """Return a plan only when policy anchor, record and candidate agree.

        Evaluations written before CT04M deliberately remain plan-less on
        replay.  They are immutable and must not be backfilled from a newly
        reconstructed plan.  Once an anchor exists, any missing or drifting
        part is a same-event conflict rather than an availability downgrade.
        """

        if not context_requested:
            return None
        try:
            anchor = context_manifest_anchor_from_policy(policy_audit)
        except Exception as exc:  # noqa: BLE001 - malformed anchor is conflict.
            raise EvaluationConflictError(
                policy_audit.links.get("event_id", "")
            ) from exc
        if anchor is None:
            return None
        if prepared is None or anchor != prepared.anchor:
            raise EvaluationConflictError(anchor.event_id)
        persisted = self.audit_service.store.get_audit_event(anchor.audit_id)
        if persisted is None:
            raise EvaluationConflictError(anchor.event_id)
        try:
            strict = validate_context_manifest_audit_event(persisted)
            matches = bool(
                strict.trace_id == policy_audit.trace_id
                and strict.links.event_id == anchor.event_id
                and strict.links.plan_id == anchor.plan_id
                and strict.links.context_ref == anchor.context_ref
                and context_manifest_record_digest(strict) == anchor.manifest_digest
                and records_have_same_content(persisted, prepared.audit_record)
            )
        except Exception as exc:  # noqa: BLE001 - malformed immutable record.
            raise EvaluationConflictError(anchor.event_id) from exc
        if not matches:
            raise EvaluationConflictError(anchor.event_id)
        return prepared.plan

    def _replay_or_conflict(
        self,
        existing: AuditEvent | None,
        request_digest: str,
        event_id: str,
    ) -> GuardEvaluationResponse | None:
        if existing is None:
            return None
        if _stored_request_digest(existing) == request_digest:
            # AuditEvent 已经是权威幂等结果；重试仍需执行确定性 provenance
            # upsert，以修复此前 audit 成功而图写入失败的部分状态。
            self.audit_service.repair_provenance(existing)
            return self._rebuild_response(existing)
        raise EvaluationConflictError(event_id)

    def _rebuild_response(self, audit: AuditEvent) -> GuardEvaluationResponse:
        raw_decision = _stored_decision_dump(audit)
        if raw_decision is None:
            raise EvaluationConflictError(audit.links.get("event_id", ""))
        decision = GuardDecision.model_validate(raw_decision)
        authority: DecisionAuthority | None = None
        approval_release_directive: ApprovalReleaseDirectiveV2 | None = None
        evidence = audit.evidence if isinstance(audit.evidence, dict) else {}
        raw_authority_envelope = evidence.get("decision_authority")
        raw_top_authority = (audit.model_extra or {}).get("decision_authority")
        if raw_authority_envelope is not None or raw_top_authority is not None:
            if raw_authority_envelope is None or raw_top_authority is None:
                raise CriticalDecisionEvidenceError(
                    "historical authority carrier is incomplete"
                )
            try:
                authority = DecisionAuthority.model_validate(raw_top_authority)
                raw_v21 = evidence.get("decision_v21")
                if not isinstance(raw_v21, dict):
                    raise ValueError("historical DecisionEvidenceV21 is absent")
                self.audit_service._validate_decision_authority_commit(
                    audit,
                    expected_envelope={
                        "decision_authority": raw_authority_envelope,
                    },
                    expected_decision=decision,
                    expected_authority=authority,
                    expected_v21_evidence={"decision_v21": raw_v21},
                )
                parsed_authority_evidence = parse_decision_authority_evidence_payload(
                    {"decision_authority": raw_authority_envelope}
                )
                approval_release_directive = getattr(
                    parsed_authority_evidence,
                    "approval_release_directive",
                    None,
                )
            except CriticalDecisionEvidenceError:
                raise
            except Exception as exc:  # noqa: BLE001 - immutable carrier boundary.
                raise CriticalDecisionEvidenceError(
                    "historical decision authority cannot be reconstructed"
                ) from exc
        approval: ApprovalRequest | None = None
        approval_id = audit.links.get("approval_id")
        if approval_id:
            approval = self.approval_service.get_approval(approval_id)
        binding = None
        if approval is not None:
            stored_binding = self.audit_service.store.get_enforcement_binding(
                approval.approval_id
            )
            if stored_binding is not None:
                binding = self._public_binding(stored_binding)
        if authority is not None and authority.source == "v21":
            release_mode = (
                approval_release_directive.mode
                if approval_release_directive is not None
                else authority.approval_release
            )
            if release_mode in {"strong_binding_required", "strong_binding"} and (
                approval is None or binding is None
            ):
                raise CriticalDecisionEvidenceError(
                    "historical reviewable V2 ASK lacks approval or binding"
                )
            if release_mode == "restricted_allow_once" and (
                approval is None or binding is not None
            ):
                raise CriticalDecisionEvidenceError(
                    "historical restricted V2 ASK has invalid approval binding"
                )
            if release_mode in {"forbidden", "not_applicable"} and (
                approval is not None or binding is not None
            ):
                raise CriticalDecisionEvidenceError(
                    "historical unreleasable V2 ASK carries release authority"
                )
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
            policy_audit_id=audit.audit_id,
            enforcement_binding=binding,
            decision_authority=authority,
            approval_release_directive=approval_release_directive,
        )

    def _save_enforcement_binding(
        self,
        event: GuardEvent,
        *,
        approval: ApprovalRequest | None,
        audit: AuditEvent,
        materials: "V21PipelineMaterials",
        phase_b_outcome: "V21PhaseBOutcome | None",
        requesting_principal_id: str,
        selected_decision: GuardDecision,
        decision_authority: DecisionAuthority | None,
        approval_release_directive: ApprovalReleaseDirectiveV2 | None = None,
    ) -> EnforcementBinding | None:
        """Persist an eligible ASK ActionIR binding inside the evaluation txn."""

        directive_mode = (
            approval_release_directive.mode
            if approval_release_directive is not None
            else None
        )
        approval_release = (
            decision_authority.approval_release
            if decision_authority is not None and decision_authority.source == "v21"
            else None
        )
        if approval_release_directive is not None:
            try:
                if decision_authority is None:
                    raise ValueError("decision authority is absent")
                typed_authority = DecisionAuthority.model_validate(
                    (approval.evidence if approval is not None else {}).get(
                        "decision_authority"
                    )
                )
                typed_directive = ApprovalReleaseDirectiveV2.model_validate(
                    (approval.evidence if approval is not None else {}).get(
                        "approval_release_directive"
                    )
                )
            except (TypeError, ValueError) as exc:
                if directive_mode in {"strong_binding", "restricted_allow_once"}:
                    raise V21OfficialEvaluationUnavailableError(
                        "V21_PRODUCT_APPROVAL_RELEASE_EVIDENCE_INVALID"
                    ) from exc
                typed_authority = None
                typed_directive = None
            if directive_mode in {"strong_binding", "restricted_allow_once"}:
                if (
                    approval is None
                    or approval.approval_id != audit.links.get("approval_id")
                    or approval.trace_id != audit.trace_id
                    or approval.runtime != event.runtime
                    or approval.action_id != audit.links.get("action_id")
                    or typed_authority != decision_authority
                    or typed_directive != approval_release_directive
                ):
                    raise V21OfficialEvaluationUnavailableError(
                        "V21_PRODUCT_APPROVAL_RELEASE_IDENTITY_MISMATCH"
                    )
        release_forbidden = bool(
            directive_mode in {"forbidden", "not_applicable"}
            or (directive_mode is None and approval_release == "forbidden")
        )
        if release_forbidden:
            if approval is not None:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_FORBIDDEN_ASK_CREATED_APPROVAL"
                )
            return None
        if directive_mode == "restricted_allow_once":
            if approval is None:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_PRODUCT_RESTRICTED_ASK_APPROVAL_MISSING"
                )
            # C1 best-effort Host binding is not the C3 exact
            # ``EnforcementBinding`` contract.  The restricted lease/spool
            # hand-off is wired by the OpenClaw runtime batch; this layer only
            # preserves the signed release directive and human approval.
            return None
        binding_required = bool(
            directive_mode == "strong_binding"
            or (
                directive_mode is None and approval_release == "strong_binding_required"
            )
        )
        if not self.approval_service.settings.rte05_strong_binding_enabled:
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_DISABLED"
                )
            return None
        eligible = not (
            approval is None
            or event.pre_execution is not True
            or event.event_type not in _STRONG_BINDING_PRE_EXECUTION_EVENT_TYPES
            or selected_decision.decision != "ask"
            or "allow_once" not in approval.decision_options
            or phase_b_outcome is None
            or phase_b_outcome.revalidation.status != "valid"
            or materials.snapshot is None
            or materials.scope_digest is None
            or materials.degraded_kind is not None
        )
        if not eligible:
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_MATERIALS_INVALID"
                )
            return None

        assert approval is not None
        assessment = materials.assessment
        assert materials.snapshot is not None
        scope = materials.snapshot.scope
        agent_id = event.security_context.agent_id
        if (
            not assessment.action_id
            or not assessment.authorization_fingerprint
            or assessment.action_id != approval.action_id
            or scope.scope_digest != materials.scope_digest
            or scope.principal_id != requesting_principal_id
            or scope.principal_id != approval.requesting_principal_id
            or scope.runtime != event.runtime
            or scope.runtime != approval.runtime
            or not scope.runtime_binding_id
            or not agent_id
            or agent_id != approval.agent_id
        ):
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_IDENTITY_MISMATCH"
                )
            return None

        record = EnforcementBindingRecord(
            event_id=event.event_id,
            policy_audit_id=audit.audit_id,
            approval_id=approval.approval_id,
            action_id=assessment.action_id,
            action_type=_ACTION_TYPE_BY_EVENT.get(event.event_type, event.event_type),
            authorization_fingerprint=assessment.authorization_fingerprint,
            runtime_binding_id=scope.runtime_binding_id,
            scope_digest=scope.scope_digest,
            principal_id=scope.principal_id,
            runtime=scope.runtime,
            agent_id=agent_id,
            policy_revision=materials.snapshot.policy_revision,
            requires_execution_lease=True,
            grant_id=None,
            created_at=approval.created_at,
        )
        try:
            stored = self.audit_service.store.save_enforcement_binding(record)
        except EnforcementBindingConflictError:
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_CONFLICT"
                ) from None
            raise EvaluationConflictError(event.event_id) from None
        except Exception as exc:  # noqa: BLE001 - official write must be atomic.
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_SAVE_FAILED"
                ) from exc
            raise
        readback = self.audit_service.store.get_enforcement_binding(
            approval.approval_id
        )
        if readback != stored:
            if binding_required:
                raise V21OfficialEvaluationUnavailableError(
                    "V21_OFFICIAL_STRONG_BINDING_READBACK_FAILED"
                )
            raise EvaluationConflictError(event.event_id)
        return self._public_binding(stored)

    @staticmethod
    def _public_binding(record: EnforcementBindingRecord) -> EnforcementBinding:
        if record.requires_execution_lease is not True:
            raise EvaluationConflictError(record.event_id)
        return EnforcementBinding(
            action_id=record.action_id,
            authorization_fingerprint=record.authorization_fingerprint,
            runtime_binding_id=record.runtime_binding_id,
            requires_execution_lease=True,
        )

    def _approval_summary(
        self, approval: ApprovalRequest | None
    ) -> EvaluationApproval | None:
        if approval is None:
            return None
        return EvaluationApproval(
            approval_id=approval.approval_id,
            status=approval.status,
            decision_options=approval.decision_options,
            decision=approval.decision,
            resolution_source=approval.resolution_source,
            resolved_by=approval.resolved_by,
            resolution_reason=approval.resolution_reason,
            llm_review=approval.llm_review,
        )

    def _record_memory_change(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        requesting_principal_id: str,
    ) -> MemoryGuardChange | None:
        if self.memory_guard_service is None or not isinstance(
            event.payload, MemoryEventPayload
        ):
            return None
        memory = event.payload.memory
        if memory.operation.lower() != "write" or not event.payload.will_persist:
            return None
        return self.memory_guard_service.propose(
            MemoryGuardChange(
                trace_id=event.trace_id,
                namespace=memory.namespace,
                key=memory.key,
                value_preview=memory.value_preview,
                operation=memory.operation,
                source_trust=memory.source_trust,
                metadata={
                    "event_id": event.event_id,
                    "decision_id": decision.decision_id,
                    "decision": decision.decision,
                    "requires_approval": event.payload.requires_approval,
                },
            ),
            runtime=event.runtime,
            agent_id=event.security_context.agent_id,
            principal_id=requesting_principal_id,
        )
