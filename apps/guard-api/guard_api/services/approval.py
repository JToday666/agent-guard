"""Human and LLM approval service.

V21-08（``11_决策记录_V21-08前置.md`` D5，承接 ``10_决策记录`` D4）：

1. **决策面收紧**：V2 flag（``settings.v21_shadow_enabled``）开启时
   LLM Reviewer 只能 deny 或保持 pending，不得生成 allow（
   ``_llm_can_allow_once`` 恒 False）；flag off 保持现状（legacy
   official）。投影层另有 fail-closed 双保险（capability.py
   ``compile_approval_to_grant`` 拒绝非 human 来源），接线侧不重复
   实现状态机。
2. **Grant 投影接线**：human ``allow_once`` 终态后经
   ``compile_approval_to_grant`` 投影单次 grant（usage_limit=1、
   delegable=false）并 commit + ``SecurityStateService.project_committed``
   （V21-08 首个权威记录生产者）。投影失败一律收敛为告警日志，
   审批决议与 provenance 写入不受影响（fail-closed 不投影）。

已知限制（见 ``_resolve_grant_scope`` / ``_project_allow_once_grant``
docstring）：approval 模型本身不携带 task 上下文，scope 只能经
approval evidence → policy_evaluation 审计记录 → 权威 TaskFact 的
确定性链路解析；任一环节缺失即 fail-closed 不投影。grant 的
resource/destination 约束与 expires_at 语义顺延至 lease consume
端点（DEFERRED）阶段的决策记录承接。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from agentguard_core import AuditEvent, GuardDecision, GuardEvent
from agentguard_core.actions.canonical_json import (
    canonical_json_bytes,
    canonical_sha256,
)
from agentguard_core.authority.models import TaskFact
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)
from agentguard_core.security_context.projection.capability import (
    ApprovalGrantProjection,
    GrantPolicyContext,
    compile_approval_to_grant,
)

from guard_api.llm_approval import LlmApprovalReviewer
from guard_api.models import ApprovalRequest, LlmApprovalReview, LlmApprovalReviewInput
from guard_api.security_state import SecurityStateService
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ControlPlaneStore

from .evidence import _approval_evidence, describe_guard_event
from .provenance import ProvenanceWriter
from .redaction import (
    SUMMARY_TEXT_LIMIT,
    bound_redacted_value,
    scrub_text,
    truncate_text,
)

logger = logging.getLogger(__name__)

#: Approval 权威记录无 revision 链（resolved 终态唯一）：投影身份
#: 五元组中的 source_revision 固定为 1（确定性，禁 uuid）。
_APPROVAL_SOURCE_REVISION = 1

#: V21-08 shadow 期 approval grant 编译的 policy_revision 锚点：
#: 冻结常量（approval grant 不绑定 policy bundle 版本，保证同输入
#: 重放 digest 恒定）；V21-09 接线消费侧时由决策记录承接正式口径。
_APPROVAL_GRANT_POLICY_REVISION = "v21-08:approval-grant"

#: approval grant authorization_fingerprint 的域分离标签：与 ActionIR
#: 指纹（``agentguard/v21/action-ir/v1``）输入空间互不碰撞。
_APPROVAL_GRANT_FINGERPRINT_TAG = "agentguard/v21-08/approval-grant/v1"

#: event_type → action_type 映射（与 core ``actions/builder.py``
#: ``_ACTION_TYPE_BY_EVENT`` 逐字一致；该映射属冻结语义，core 变更时
#: 本表必须同步）。缺省回退 event_type 自身，与 core 口径相同。
_ACTION_TYPE_BY_EVENT: dict[str, str] = {
    "tool_call_proposed": "tool_call",
    "context_assembled": "context_build",
    "model_input_prepared": "model_call",
    "model_output_produced": "model_call",
    "tool_result_produced": "tool_result",
    "memory_write_proposed": "memory_write",
    "message_send_proposed": "message_send",
}


class ApprovalService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        settings: GuardApiSettings,
        llm_reviewer: LlmApprovalReviewer | None = None,
        provenance_writer: ProvenanceWriter | None = None,
        state_service: SecurityStateService | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.llm_reviewer = llm_reviewer
        self.provenance_writer = provenance_writer or ProvenanceWriter(store=store)
        # V21-08 D5：grant 投影的安全状态门面（T4 已注册实例，复用注入）。
        # 缺省时 human allow_once 不投影（fail-closed 降级，审批面不受影响）。
        self.state_service = state_service

    def create_for_decision(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        requesting_principal_id: str,
        decision_authority: Any | None = None,
    ) -> ApprovalRequest | None:
        if decision.decision != "ask" or decision.approval_intent is None:
            return None
        description = describe_guard_event(event)
        resource = decision.approval_intent.resource.strip()
        if not resource and description.resource_targets:
            resource = description.resource_targets[0]
        safe_resource = bound_redacted_value(resource, text_limit=SUMMARY_TEXT_LIMIT)
        safe_action_name = truncate_text(
            scrub_text(description.action_name), SUMMARY_TEXT_LIMIT
        )
        approval_evidence = _approval_evidence(event, decision, description)
        if decision_authority is not None:
            raw_authority = (
                decision_authority.model_dump(mode="json")
                if hasattr(decision_authority, "model_dump")
                else decision_authority
            )
            if not isinstance(raw_authority, dict):
                raise ValueError("decision authority must be a typed projection")
            approval_evidence["decision_authority"] = dict(raw_authority)
        approval = ApprovalRequest(
            trace_id=event.trace_id,
            subject_id=description.subject_id,
            subject_type=description.subject_type,
            action_id=description.action_id,
            action_name=safe_action_name,
            requesting_principal_id=requesting_principal_id,
            runtime=event.runtime,
            agent_id=event.security_context.agent_id,
            resource=safe_resource if isinstance(safe_resource, str) else "",
            reason=truncate_text(scrub_text(decision.reason), SUMMARY_TEXT_LIMIT),
            risk_score=decision.risk_score,
            severity=decision.severity,
            evidence=approval_evidence,
            decision_options=decision.approval_intent.options,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(seconds=self.settings.approval_ttl_seconds)
            ).isoformat(),
        )
        return self.store.create_approval(approval)

    def auto_review_with_llm(
        self, approval: ApprovalRequest | None
    ) -> ApprovalRequest | None:
        if approval is None or not self.settings.llm_approval_enabled:
            return approval
        if self.llm_reviewer is None:
            return self._record_llm_review(
                approval,
                LlmApprovalReview(
                    status="error",
                    error="LLM approval configuration is incomplete.",
                ),
            )
        try:
            review = LlmApprovalReview.model_validate(
                self.llm_reviewer.review(LlmApprovalReviewInput.from_approval(approval))
            )
        except Exception as exc:
            return self._record_llm_review(
                approval,
                LlmApprovalReview(
                    status="error",
                    error=_llm_review_error(exc),
                ),
            )

        if review.decision == "deny":
            return self.resolve_approval(
                approval.approval_id,
                "deny",
                resolution_source="llm",
                resolved_by="llm-approval",
                resolution_reason=review.reason,
                llm_review=review.model_copy(update={"status": "resolved"}),
            )
        # D4/D5：V2 flag 开启时 LLM Reviewer 只能 deny 或保持 pending。
        if review.decision == "allow_once" and _llm_can_allow_once(
            approval, v2_enabled=self.settings.v21_enabled()
        ):
            return self.resolve_approval(
                approval.approval_id,
                "allow_once",
                resolution_source="llm",
                resolved_by="llm-approval",
                resolution_reason=review.reason,
                llm_review=review.model_copy(update={"status": "resolved"}),
            )
        return self._record_llm_review(
            approval, review.model_copy(update={"status": "kept_pending"})
        )

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return self.store.list_pending_approvals()

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.store.get_approval(approval_id)

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        resolution_source: str = "human",
        resolved_by: str | None = None,
        resolution_reason: str | None = None,
        llm_review: LlmApprovalReview | None = None,
    ) -> ApprovalRequest:
        resolved = self.store.resolve_approval(
            approval_id,
            decision,
            resolution_source=resolution_source,
            resolved_by=resolved_by,
            resolution_reason=resolution_reason,
            llm_review=llm_review,
        )
        self.provenance_writer.update_approval(resolved)
        self._maybe_project_allow_once_grant(resolved)
        return resolved

    def _record_llm_review(
        self, approval: ApprovalRequest, review: LlmApprovalReview
    ) -> ApprovalRequest:
        updated = approval.model_copy(update={"llm_review": review})
        stored = self.store.create_approval(updated)
        self.provenance_writer.update_approval(stored)
        return stored

    # ------------------------------------------------------------------
    # V21-08 D5：human allow_once → CapabilityGrant 投影接线
    # ------------------------------------------------------------------

    def _maybe_project_allow_once_grant(self, approval: ApprovalRequest) -> None:
        """human ``allow_once`` 终态后的 grant 投影入口（绝不外抛）。

        仅 V2 flag 开启时执行（flag off 与现状逐字节一致）；仅 human
        ``allow_once`` 触发。**任何失败收敛为告警日志**：审批决议已在
        存储层生效并完成 provenance 写入，投影失败不得反向影响审批面
        （fail-closed：不投影，不伪造 grant）。
        """

        if not self.settings.v21_enabled():
            return
        if approval.decision != "allow_once" or approval.resolution_source != "human":
            return
        if self.settings.rte05_strong_binding_enabled:
            binding = self.store.get_enforcement_binding(approval.approval_id)
            if binding is None:
                # A C1/degraded ASK deliberately has no strong binding and must
                # never be upgraded into a consumable grant after resolution.
                return
            try:
                self._project_strong_allow_once_grant(approval, binding)
            except Exception:  # noqa: BLE001 - resolution stays committed; consume 503.
                logger.warning(
                    "rte-05 approval grant registration unavailable for approval %s; "
                    "the bound action remains fail-closed",
                    approval.approval_id,
                )
            return
        try:
            self._project_allow_once_grant(approval)
        except Exception:  # noqa: BLE001 - 投影故障必须收敛，绝不上抛。
            logger.warning(
                "v21-08 approval grant projection failed for approval %s; "
                "approval decision is unaffected (fail-closed, no grant "
                "projected)",
                approval.approval_id,
                exc_info=True,
            )

    def _project_strong_allow_once_grant(
        self, approval: ApprovalRequest, binding: Any
    ) -> None:
        """Project and register a consumable grant from the private ActionIR binding.

        The projection must become visible in SecurityState before the runtime
        grant row is registered.  A failure at either stage leaves ``grant_id``
        unset on the private binding, so consume returns a retryable 503 instead
        of falling back to C1.
        """

        self._ensure_strong_grant_registered(approval, binding)

    def ensure_strong_approval_grant_registered(self, approval_id: str) -> bool:
        """Retry-safe registration/backfill used by the consume endpoint.

        A previous resolve may have projected state and then lost the runtime
        registration write.  This method recognizes that exact projected grant
        and registers it without creating a new projection.  It never upgrades
        non-human or unbound C1 approvals.
        """

        if not self.settings.rte05_strong_binding_enabled:
            return False
        approval = self.store.get_approval(approval_id)
        binding = self.store.get_enforcement_binding(approval_id)
        if (
            approval is None
            or binding is None
            or approval.status != "resolved"
            or approval.decision != "allow_once"
            or approval.resolution_source != "human"
        ):
            return False
        if binding.grant_id is not None:
            return True
        try:
            return self._ensure_strong_grant_registered(approval, binding)
        except Exception:  # noqa: BLE001 - caller maps incomplete registration to 503.
            return False

    def _ensure_strong_grant_registered(
        self, approval: ApprovalRequest, binding: Any
    ) -> bool:
        if self.state_service is None:
            return False
        if (
            approval.resolved_at is not None
            and approval.resolved_at >= approval.expires_at
        ):
            return False

        scope = self._resolve_grant_scope(approval)
        if scope is None:
            return False
        task_fact, audit_record = scope
        if (
            binding.approval_id != approval.approval_id
            or binding.event_id != audit_record.links.get("event_id")
            or binding.action_id != approval.action_id
            or binding.principal_id != approval.requesting_principal_id
            or binding.principal_id != task_fact.principal_id
            or binding.runtime != approval.runtime
            or binding.agent_id != approval.agent_id
            or binding.scope_digest != task_fact.scope_digest
            or not binding.authorization_fingerprint
            or not binding.runtime_binding_id
            or not binding.action_type
            or not binding.policy_revision
            or binding.requires_execution_lease is not True
        ):
            return False

        policy_revision = str(binding.policy_revision)
        grant = compile_approval_to_grant(
            ApprovalGrantProjection(
                approval_id=approval.approval_id,
                scope_digest=binding.scope_digest,
                principal_id=binding.principal_id,
                subject_agent_id=binding.agent_id,
                task_id=task_fact.task_id,
                action_types=[binding.action_type],
                resource_constraints=[],
                destination_constraints=[],
                argument_constraints=[],
                resolution_source="human",
                authorization_fingerprint=binding.authorization_fingerprint,
                resolved_sequence=None,
                expires_at=approval.expires_at,
                policy_revision=policy_revision,
            ),
            GrantPolicyContext(
                policy_revision=policy_revision,
                scope_digest=binding.scope_digest,
                principal_id=binding.principal_id,
            ),
        )

        exact_projected = False
        with self.state_service.store_access.scope_lock(binding.scope_digest):
            state = self.state_service.ensure_ready(binding.scope_digest)
            existing_grant = next(
                (
                    item
                    for item in state.active_grants
                    if item.grant_id == grant.grant_id
                ),
                None,
            )
            if existing_grant is not None:
                exact_projected = existing_grant == grant
            else:
                projection = self.state_service.store_access.get_projection(
                    binding.scope_digest,
                    "approval",
                    approval.approval_id,
                    _APPROVAL_SOURCE_REVISION,
                    PROJECTOR_VERSION,
                )
                delta = (
                    SecurityStateDeltaV21.model_validate(projection.delta_payload)
                    if projection is not None
                    else _build_approval_grant_delta(
                        approval,
                        grant,
                        scope_digest=binding.scope_digest,
                        base_state_version=state.state_version,
                    )
                )
                if not any(item == grant for item in delta.grant_upserts):
                    return False
                result = self.state_service.project_committed(
                    CommittedRecord(
                        record_id=f"approval-grant:{approval.approval_id}",
                        committed=True,
                        source_record_type="approval",
                        source_record_id=approval.approval_id,
                        source_revision=_APPROVAL_SOURCE_REVISION,
                        scope_digest=binding.scope_digest,
                        projector_version=PROJECTOR_VERSION,
                        delta=delta,
                    ),
                    scope_digest=binding.scope_digest,
                    verify_source_committed=self._verify_approval_committed,
                )
                if result.outcome in {"applied", "replayed_noop"}:
                    projected = self.state_service.ensure_ready(binding.scope_digest)
                    exact_projected = any(
                        item == grant for item in projected.active_grants
                    )
        if not exact_projected:
            return False
        self.store.register_approval_grant(binding, grant)
        logger.info(
            "rte-05 approval grant registered for approval %s",
            approval.approval_id,
        )
        return True

    def _project_allow_once_grant(self, approval: ApprovalRequest) -> None:
        """把已 commit 的 human ``allow_once`` 审批投影为单次 grant。

        编排（02 §3 commit → project 时序，V21-08 首个权威记录生产者）：

        1. 前置 fail-closed：state_service / server secret 缺失、scope
           不可解析（approval 无 task 上下文，见 ``_resolve_grant_scope``）、
           决议晚于过期时间（expired 防御）→ 不投影；
        2. 确定性构造 ``ApprovalGrantProjection``（authorization_fingerprint
           经 server secret HMAC 派生，禁 uuid）→ core
           ``compile_approval_to_grant``（投影层已 fail-closed：非 human
           拒绝、fingerprint/action 缺失拒绝）；
        3. 权威记录即存储层已 commit 的 resolved approval；构造
           ``SecurityStateDeltaV21``（仅 grant_upserts）+ ``CommittedRecord``
           → ``SecurityStateService.project_committed``（经注入的
           ``verify_source_committed`` 钩子复核审批终态，F0-8）。

        幂等：同 approval 重复触发且 scope 状态版本未变时，由 projector
        五元组幂等键（delta_digest 含 base_state_version）短路为
        replayed_noop；若 base_state_version 已被其他投影推进，重放时
        delta_digest 不同，不会命中 replayed_noop，而是命中
        digest-conflict fail-closed 路径（不得静默覆盖）。grant 携带
        usage_limit=1、remaining_uses=1、delegable=false（core 强制）；
        expires_at 置 None（单次消费 + fingerprint 精确绑定即授权边界；
        生命周期语义随 lease consume 端点决策记录承接，见模块 docstring
        限制）。
        """

        if self.state_service is None:
            logger.warning(
                "v21-08 approval grant projection skipped for approval %s: "
                "security state service not wired (fail-closed)",
                approval.approval_id,
            )
            return
        secret = self.settings.v21_shadow_server_secret_bytes()
        if secret is None:
            logger.warning(
                "v21-08 approval grant projection skipped for approval %s: "
                "shadow server secret not configured (fail-closed)",
                approval.approval_id,
            )
            return
        if (
            approval.resolved_at is not None
            and approval.resolved_at >= approval.expires_at
        ):
            # expired 防御：存储层状态机已拒绝过期审批的 allow_once，
            # 此处为投影侧纵深防御（不得投影已失效授权）。
            logger.warning(
                "v21-08 approval grant projection skipped for approval %s: "
                "resolution not earlier than expires_at (expired, fail-closed)",
                approval.approval_id,
            )
            return

        scope = self._resolve_grant_scope(approval)
        if scope is None:
            return
        task_fact, audit_record = scope
        scope_digest = task_fact.scope_digest

        action_type = _ACTION_TYPE_BY_EVENT.get(
            audit_record.event_type, audit_record.event_type
        )
        fingerprint = derive_approval_grant_fingerprint(secret, approval)
        projection_input = ApprovalGrantProjection(
            approval_id=approval.approval_id,
            scope_digest=scope_digest,
            principal_id=task_fact.principal_id,
            subject_agent_id=approval.agent_id,
            task_id=task_fact.task_id,
            action_types=[action_type],
            resource_constraints=[],
            destination_constraints=[],
            argument_constraints=[],
            resolution_source=approval.resolution_source or "human",
            authorization_fingerprint=fingerprint,
            resolved_sequence=None,
            expires_at=None,
            policy_revision=_APPROVAL_GRANT_POLICY_REVISION,
        )
        policy_context = GrantPolicyContext(
            policy_revision=_APPROVAL_GRANT_POLICY_REVISION,
            scope_digest=scope_digest,
            principal_id=task_fact.principal_id,
        )
        grant = compile_approval_to_grant(projection_input, policy_context)

        # commit → project：先经既有 rebuild 钩子确保 scope 状态就绪，
        # 再以读到的 state_version 为 CAS base 构造 delta。base 读取 →
        # delta 构造 → project_committed 整段必须持 per-scope 编排锁
        # （RLock，project_and_apply 内部重入无碍）：否则并发推进会
        # 使 base 陈旧 → CAS 版本冲突 / base_state_version_mismatch →
        # fail-closed 且置脏，grant 永久不投影。
        with self.state_service.store_access.scope_lock(scope_digest):
            self.state_service.ensure_ready(scope_digest)
            current = self.state_service.store_access.get_security_state(scope_digest)
            base_state_version = current.state_version if current is not None else 0
            delta = _build_approval_grant_delta(
                approval,
                grant,
                scope_digest=scope_digest,
                base_state_version=base_state_version,
            )
            committed_record = CommittedRecord(
                record_id=f"approval-grant:{approval.approval_id}",
                committed=True,
                source_record_type="approval",
                source_record_id=approval.approval_id,
                source_revision=_APPROVAL_SOURCE_REVISION,
                scope_digest=scope_digest,
                projector_version=PROJECTOR_VERSION,
                delta=delta,
            )
            result = self.state_service.project_committed(
                committed_record,
                scope_digest=scope_digest,
                verify_source_committed=self._verify_approval_committed,
            )
        logger.info(
            "v21-08 approval grant projection %s for approval %s "
            "(grant_id=%s, state_version=%s)",
            result.outcome,
            approval.approval_id,
            grant.grant_id,
            result.state_version,
        )

    def _resolve_grant_scope(
        self, approval: ApprovalRequest
    ) -> tuple[TaskFact, AuditEvent] | None:
        """确定性解析 grant 投影所需 scope；不可解析返回 None（不投影）。

        **已知限制（V21-08 契约缺口，待决策记录补充）**：
        ``ApprovalRequest`` 冻结模型本身不携带 task 上下文，scope 只能
        经 approval evidence → 关联 policy_evaluation 审计记录 →
        ``metadata.task_id`` → 权威 TaskFact 的只读链路解析；任一环节
        缺失（无 evidence event_id / 无审计记录 / 无 task_id claim /
        claim 无权威 TaskFact / task 非 active）即 fail-closed 不投影，
        绝不伪造 scope（01 §19/§25）。
        """

        reason = None
        evidence_event = approval.evidence.get("event")
        event_id = (
            evidence_event.get("event_id") if isinstance(evidence_event, dict) else None
        )
        if not isinstance(event_id, str) or not event_id:
            reason = "approval evidence carries no event_id"
        else:
            audit_record = self.store.get_policy_evaluation_by_event_id(event_id)
            if audit_record is None:
                reason = "no policy_evaluation audit record for the approval event"
            else:
                task_id = audit_record.metadata.get("task_id")
                if not isinstance(task_id, str) or not task_id.strip():
                    reason = "evaluation record carries no task_id"
                else:
                    record = self.store.get_task_fact(task_id)
                    if record is None:
                        reason = "task claim has no authoritative TaskFact"
                    elif record.task_fact.status != "active":
                        reason = f"task status is {record.task_fact.status!r}"
                    else:
                        return record.task_fact, audit_record
        logger.warning(
            "v21-08 approval grant projection skipped for approval %s: %s "
            "(fail-closed, no scope)",
            approval.approval_id,
            reason,
        )
        return None

    def _verify_approval_committed(self, record: CommittedRecord) -> bool:
        """``verify_source_committed`` 钩子（F0-8）：存储层复核审批终态。

        只有存储中确为 resolved + human ``allow_once`` 的审批才允许成为
        后续历史状态；查不到/状态不符即拒绝投影。
        """

        approval = self.store.get_approval(record.source_record_id)
        return (
            approval is not None
            and approval.status == "resolved"
            and approval.decision == "allow_once"
            and approval.resolution_source == "human"
        )


def _llm_can_allow_once(approval: ApprovalRequest, *, v2_enabled: bool = False) -> bool:
    """LLM Reviewer 是否可自动 ``allow_once``。

    D4/D5（``10_决策记录`` L116-134 / ``11_决策记录`` D5）：V2 flag
    开启时恒 False——LLM Reviewer V2 路径只能 deny 或保持 pending，不得
    生成 allow；flag off 保持现状（legacy official：low/medium 且选项含
    allow_once 时可自动批准）。
    """

    if v2_enabled:
        return False
    if "allow_once" not in approval.decision_options:
        return False
    return approval.severity.lower() in {"low", "medium"}


def approval_grant_fingerprint_projection(
    approval: ApprovalRequest,
) -> dict[str, Any]:
    """approval grant authorization_fingerprint 的白名单投影。

    只投影创建期即固定的身份字段（确定性、禁 uuid / 随机量）；
    ``kind`` 判别键与 ActionIR 指纹投影空间域分离。

    白名单字段均为 ``ApprovalRequest`` 创建期固定的身份字段，
    其中 ``action_id`` 有意参与：它是创建期绑定的动作身份（非运行期
    可变状态），剔除反而会放宽指纹绑定面、允许同 approval 被
    投影到非预期动作。
    """

    return {
        "kind": "human_approval_grant",
        "approval_id": approval.approval_id,
        "trace_id": approval.trace_id,
        "action_id": approval.action_id,
        "subject_id": approval.subject_id,
        "principal_id": approval.requesting_principal_id,
        "runtime": approval.runtime,
        "agent_id": approval.agent_id,
        "resource": approval.resource,
        "risk_score": approval.risk_score,
        "severity": approval.severity,
    }


def derive_approval_grant_fingerprint(
    server_secret: bytes, approval: ApprovalRequest
) -> str:
    """HMAC-SHA256 授权指纹：域分离标签 + 白名单投影的受限 JCS 字节。

    口径仿 core ``actions/fingerprints.py::authorization_fingerprint``
    （HMAC(server_secret, tag + JCS(白名单))，``hmac-sha256:`` 前缀），
    域分离标签独立（``_APPROVAL_GRANT_FINGERPRINT_TAG``）。确定性：
    同 secret 同审批记录恒同输出。
    """

    if not isinstance(server_secret, bytes) or not server_secret:
        raise ValueError("server_secret must be non-empty bytes")
    payload = _APPROVAL_GRANT_FINGERPRINT_TAG.encode("utf-8") + b"\x00"
    payload += canonical_json_bytes(approval_grant_fingerprint_projection(approval))
    digest = hmac_module.new(server_secret, payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def _build_approval_grant_delta(
    approval: ApprovalRequest,
    grant: Any,
    *,
    scope_digest: str,
    base_state_version: int,
) -> SecurityStateDeltaV21:
    """构造仅携带 ``grant_upserts`` 的确定性 delta（禁 uuid）。

    ``projection_id`` 由幂等键五元组确定性派生；``delta_digest`` 为
    白名单投影的受限 JCS sha256（同身份同 base 重放恒定）。
    """

    identity = ProjectionRecordIdentity(
        source_record_type="approval",
        source_record_id=approval.approval_id,
        source_revision=_APPROVAL_SOURCE_REVISION,
        source_sequence=None,
    )
    projection_key = projection_identity_key(
        scope_digest,
        "approval",
        approval.approval_id,
        _APPROVAL_SOURCE_REVISION,
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
        grant_upserts=[grant],
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


def _llm_review_error(exc: Exception) -> str:
    message = str(exc).strip()
    if len(message) > 240:
        message = f"{message[:240]}..."
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__
