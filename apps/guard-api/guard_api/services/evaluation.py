"""Guard evaluation orchestration service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentguard_core import (
    ActionCritic,
    AuditEvent,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    MemoryEventPayload,
    MemoryGuardChange,
)
from guard_api.models import (
    ApprovalRequest,
    EvaluationApproval,
    GuardEvaluationResponse,
)
from guard_api.storage.base import parse_audit_timestamp
from guard_api.storage.integrity import canonical_sha256

from .approval import ApprovalService
from .audit import AuditService
from .memory import MemoryGuardService
from .policy import PolicyService

if TYPE_CHECKING:
    from .v21_pipeline import V21PhaseCPlan, V21PipelineMaterials, V21PipelineService
    from .v21_shadow import V21ShadowService


class EvaluationConflictError(ValueError):
    """Raised when the same event_id is re-evaluated with different content."""


# SecurityContext 后续增补的会话身份字段（见 agentguard_core SecurityContext）。
_SESSION_IDENTITY_FIELDS: tuple[str, ...] = (
    "conversation_id",
    "session_key",
    "session_id",
)
# payload 契约扩展时增补的可选字段（见 MemoryEventPayload.action_id）。
_PAYLOAD_EXTENSION_FIELDS: tuple[str, ...] = ("action_id",)


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
    ) -> None:
        self.policy_service = policy_service
        self.audit_service = audit_service
        self.approval_service = approval_service
        self.memory_guard_service = memory_guard_service
        self.action_critic = action_critic or ActionCritic()
        # V21-08 shadow 旁路编排器（flag 默认关闭）。T5 在 audit 落盘前
        # 调用它旁路产出 decision_v21 信封；判定/审批主流程不使用它
        # （legacy = 唯一官方决策者，04 §1-§2）。V21-09 起它同时是
        # pipeline Phase A 彻底失败时的逐字节降级回退路径。
        self.v21_shadow_service = v21_shadow_service
        # V21-09 四段式编排器（D4；flag 门控与 V21ShadowService 同源）。
        # 就绪时 evaluate 编排切换为 pipeline：Phase A 事务外、Phase B
        # 短事务内消费材料；未就绪时既有路径逐字节不变。
        self.v21_pipeline = v21_pipeline

    def evaluate(
        self, event: GuardEvent, *, requesting_principal_id: str
    ) -> GuardEvaluationResponse:
        # Validate temporal identity before detectors or any approval/memory side
        # effects run; persistence uses the same parser for defense in depth.
        parse_audit_timestamp(event.timestamp)
        request_digest = canonical_sha256(canonical_request_dump(event))
        # V21-09 D4/D9：pipeline Phase A 在 evaluation_transaction 之前
        # 执行（事务外只读）；replay 不重算 assess——已存在幂等评估
        # 时直接走事务内 replay 检查，不跑 Phase A。
        materials = None
        if self.v21_pipeline is not None and self.v21_pipeline.enabled:
            existing = self.audit_service.store.get_policy_evaluation_by_event_id(
                event.event_id
            )
            if existing is not None:
                replayed = self._replay_or_conflict(
                    existing, request_digest, event.event_id
                )
                if replayed is not None:
                    # D9：事务外幂等补投影（不重算；五元组幂等键短路
                    # 保证重复安全；绝不外抛、不影响重放响应）。
                    self.v21_pipeline.backfill_projection(existing)
                    return replayed
            else:
                materials = self.v21_pipeline.run_phase_a(event)
        # 审批、memory change、审计与 provenance 是一次评估的原子结果。
        # 同 event_id 在事务开始时串行化，失败时不得遗留任何部分状态。
        backfill_audit: AuditEvent | None = None
        phase_c_plan: "V21PhaseCPlan | None" = None
        with self.audit_service.store.evaluation_transaction(event.event_id):
            existing = self.audit_service.store.get_policy_evaluation_by_event_id(
                event.event_id
            )
            replayed = self._replay_or_conflict(
                existing,
                request_digest,
                event.event_id,
            )
            if replayed is not None:
                response = replayed
                backfill_audit = existing
            else:
                response, backfill_audit, phase_c_plan = self._evaluate_once(
                    event,
                    request_digest=request_digest,
                    requesting_principal_id=requesting_principal_id,
                    materials=materials,
                )
        # D4 commit → project：投影在事务提交**之后**执行，绝不影响
        # 已 commit 的审计记录与已确定的响应；两者互斥：新评估走
        # Phase C，重放走 D9 补投影；失败一律收敛不外抛。
        if self.v21_pipeline is not None:
            if phase_c_plan is not None:
                self.v21_pipeline.run_phase_c(phase_c_plan)
            elif backfill_audit is not None:
                self.v21_pipeline.backfill_projection(backfill_audit)
        return response

    def _evaluate_once(
        self,
        event: GuardEvent,
        *,
        request_digest: str,
        requesting_principal_id: str,
        materials: "V21PipelineMaterials | None" = None,
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
            },
            decision_dump=decision.model_dump(mode="json"),
            v21_evidence=v21_evidence,
        )
        return (
            GuardEvaluationResponse(
                decision=decision,
                approval=self._approval_summary(approval),
                policy_audit_id=audit_event.audit_id,
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
    ) -> tuple[GuardEvaluationResponse, AuditEvent | None, "V21PhaseCPlan | None"]:
        """四段式编排路径（D4）：Phase A 产物已在事务外就绪。

        事务窗口内：legacy 链照常（decision/detections 直接消费 Phase A
        单跑结果，不双跑检测器）+ Phase B 短事务 revalidate 与证据构建；
        **无 snapshot/task 全量 I/O**（S8 消除）。legacy 决策与 flag off
        路径同源同实现（evaluate_with_results 同内核），官方响应不变。
        """
        snapshot_record = self.policy_service.current_snapshot_record()
        bundle = materials.bundle
        # Phase A 单跑的 legacy 官方决策（同源同实现，不双跑检测器）。
        decision = materials.decision
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
        # Phase B（事务内）：revalidate + 证据构建；失败收敛为 None，
        # legacy 主链不受影响。valid 时同步确定性构造 Phase C 计划与
        # state_delta_v21 引用信封（D2：信封随 audit commit 写入，
        # delta_digest 冻结时刻即真实）；stale → 无 Phase C、无信封。
        v21_evidence = None
        state_delta_evidence = None
        phase_c_plan: "V21PhaseCPlan | None" = None
        if self.v21_pipeline is not None:
            outcome = self.v21_pipeline.build_phase_b(event, materials)
            if outcome is not None:
                v21_evidence = outcome.envelope
                phase_c_plan = self.v21_pipeline.prepare_phase_c(outcome)
                if phase_c_plan is not None:
                    state_delta_evidence = phase_c_plan.envelope
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
            },
            decision_dump=decision.model_dump(mode="json"),
            v21_evidence=v21_evidence,
            state_delta_evidence=state_delta_evidence,
            # D7-5：pipeline 路径确定性审计身份（replay 同输入同身份）；
            # plan 缺态（stale/降级）时沿用 AuditEvent 默认工厂。
            audit_id=(
                phase_c_plan.audit_id if phase_c_plan is not None else None
            ),
        )
        return (
            GuardEvaluationResponse(
                decision=decision,
                approval=self._approval_summary(approval),
                policy_audit_id=audit_event.audit_id,
            ),
            audit_event,
            phase_c_plan,
        )

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
        approval: ApprovalRequest | None = None
        approval_id = audit.links.get("approval_id")
        if approval_id:
            approval = self.approval_service.get_approval(approval_id)
        return GuardEvaluationResponse(
            decision=decision,
            approval=self._approval_summary(approval),
            policy_audit_id=audit.audit_id,
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
