"""Audit persistence and provenance service."""

from __future__ import annotations

from dataclasses import asdict
from typing import NoReturn

from agentguard_core import (
    ActionCriticReview,
    ApprovalReleaseDirectiveV2,
    AuditEvent,
    DecisionAuthority,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
    ProductDecisionAuthorityEvidenceV1,
    RuntimeOutcomeReceipt,
)
from pydantic import ValidationError
from agentguard_core.decisions.evidence import DecisionEvidenceV21

from guard_api.models import ApprovalRequest
from guard_api.storage.base import ControlPlaneStore
from guard_api.storage.integrity import CANONICALIZATION

from .audit_checkpoint import (
    AuditCheckpointService,
    disabled_audit_anchor_status,
)
from .context_manifest import (
    ContextManifestPrepared,
    context_manifest_audit_event,
    is_context_manifest_reserved_payload,
    records_have_same_content,
    validate_context_manifest_audit_event,
)
from .competition import (
    CriticalDecisionEvidenceError,
    parse_decision_authority_evidence_payload,
    strict_decision_authority_envelope,
)
from .evidence import build_audit_event
from .provenance import ProvenanceWriter
from .redaction import sanitize_audit_event

_RUNTIME_OUTCOME_AUDIT_ID_PREFIX = "audit_outcome_"
_BOUND_FAILURE_GATE_STATES = frozenset({"binding_failed", "timed_out", "blocked"})


class PolicyEvaluationWriteForbiddenError(ValueError):
    """Raised when an inbound record explicitly claims record_type=policy_evaluation.

    契约 §12.1：POST /v1/audit/events 不得重复提交 Guard API 已经写入的
    policy_evaluation；该记录只能由 POST /v1/guard/evaluate 内部唯一写入（§10）。
    record_type=None 的 0.3 兼容记录不受影响。
    """


class ContextManifestWriteForbiddenError(ValueError):
    """Raised when an external Audit producer claims a reserved Manifest marker."""


class RuntimeOutcomeReceiptError(ValueError):
    """Raised when a runtime receipt is invalid or conflicts with its parent."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuditService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        provenance_writer: ProvenanceWriter | None = None,
        checkpoint_service: AuditCheckpointService | None = None,
        evidence_content_preview_enabled: bool = False,
    ) -> None:
        self.store = store
        self.provenance_writer = provenance_writer or ProvenanceWriter(store=store)
        self.checkpoint_service = checkpoint_service
        self.evidence_content_preview_enabled = evidence_content_preview_enabled

    def prepare_submission(
        self,
        event: AuditEvent,
        *,
        raw_payload: dict[str, object] | None = None,
    ) -> AuditEvent:
        """Apply the strict producer contract before authorization/persistence."""

        candidate = (
            raw_payload if raw_payload is not None else event.model_dump(mode="json")
        )
        if is_context_manifest_reserved_payload(candidate) or (
            raw_payload is not None and is_context_manifest_reserved_payload(event)
        ):
            raise ContextManifestWriteForbiddenError(event.audit_id)
        if event.record_type != "runtime_outcome":
            return event
        try:
            return RuntimeOutcomeReceipt.model_validate(candidate)
        except ValidationError:
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_INVALID") from None

    def submit(self, event: AuditEvent) -> dict[str, str | bool]:
        # Defense in depth for callers that bypass prepare_submission().  The
        # only authorized path is record_context_manifest() below.
        if is_context_manifest_reserved_payload(event):
            raise ContextManifestWriteForbiddenError(event.audit_id)
        # §12.1 守卫：仅拒显式声明 policy_evaluation 的入站记录。
        if event.record_type == "policy_evaluation":
            raise PolicyEvaluationWriteForbiddenError(event.audit_id)
        if event.record_type != "runtime_outcome" and event.audit_id.startswith(
            _RUNTIME_OUTCOME_AUDIT_ID_PREFIX
        ):
            # Runtime receipt IDs are deterministic and caller-known. Reserve
            # their namespace so a generic audit placeholder cannot win the
            # immutable first write and permanently block the real receipt.
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_INVALID")
        if event.record_type == "runtime_outcome":
            receipt = (
                event
                if isinstance(event, RuntimeOutcomeReceipt)
                else self.prepare_submission(event)
            )
            if not isinstance(receipt, RuntimeOutcomeReceipt):  # pragma: no cover
                raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_INVALID")
            with self.store.runtime_outcome_transaction(receipt.links.approval_id):
                parent = self._validate_runtime_outcome_parent(receipt)
                # Live approval/lease state is authoritative for a first write.
                # The store context serializes this check and the audit insert
                # against the approval row / consume CAS. Exact replays bypass
                # live-state validation so later expiry or revocation cannot
                # invalidate evidence already committed to the immutable chain.
                if self.store.get_audit_event(receipt.audit_id) is None:
                    self._validate_runtime_outcome_authority(receipt, parent)
                event = sanitize_audit_event(
                    AuditEvent.model_validate(receipt.model_dump(mode="json"))
                )
                is_new = self.store.add_audit_event(event)
        else:
            event = sanitize_audit_event(event)
            is_new = self.store.add_audit_event(event)
        persisted = self.store.get_audit_event(event.audit_id) or event
        # 同内容重试也执行确定性 upsert，用于修复首次请求在 audit 已提交后
        # provenance 写入失败形成的可检测部分状态。
        self.provenance_writer.record_audit_event(persisted)
        # §12.3：首次写入与同内容重试都返回 200，用 created/idempotent_replay 区分。
        return {
            "ok": True,
            "audit_id": event.audit_id,
            "created": is_new,
            "idempotent_replay": not is_new,
        }

    def record_context_manifest(self, prepared: ContextManifestPrepared) -> AuditEvent:
        """Persist and read back one internal strict Manifest in the caller txn.

        EvaluationService invokes this only after the anchored policy Audit has
        been written inside ``evaluation_transaction``.  Any validation,
        persistence or readback failure escapes so the surrounding
        transaction rolls back and no unverified plan can reach the runtime.
        """

        candidate = context_manifest_audit_event(prepared.audit_record)
        candidate = sanitize_audit_event(candidate)
        validate_context_manifest_audit_event(candidate)
        self.store.add_audit_event(candidate)
        persisted = self.store.get_audit_event(candidate.audit_id)
        if persisted is None:
            raise RuntimeError("context manifest readback is unavailable")
        validate_context_manifest_audit_event(persisted)
        if not records_have_same_content(persisted, prepared.audit_record):
            raise RuntimeError("context manifest readback conflicts with prepared data")
        return persisted

    def _validate_runtime_outcome_parent(
        self, receipt: RuntimeOutcomeReceipt
    ) -> AuditEvent:
        parent = self.store.get_audit_event(receipt.links.policy_audit_id)
        if parent is None or parent.record_type != "policy_evaluation":
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_PARENT_NOT_FOUND")
        expected = {
            "trace_id": parent.trace_id,
            "case_id": parent.case_id,
            "runtime": parent.runtime,
            "event_id": parent.links.get("event_id"),
            "decision_id": parent.links.get("decision_id"),
            "action_id": parent.links.get("action_id"),
            "approval_id": parent.links.get("approval_id"),
            "decision": parent.decision,
            "risk_score": parent.risk_score,
            "severity": parent.severity,
            "blocked": parent.blocked,
            "is_malicious": parent.is_malicious,
            "agent_id": parent.metadata.get("agent_id"),
            "rule_hits": parent.rule_hits,
        }
        actual = {
            "trace_id": receipt.trace_id,
            "case_id": receipt.case_id,
            "runtime": receipt.runtime,
            "event_id": receipt.links.event_id,
            "decision_id": receipt.links.decision_id,
            "action_id": receipt.links.action_id,
            "approval_id": receipt.links.approval_id,
            "decision": receipt.decision,
            "risk_score": receipt.risk_score,
            "severity": receipt.severity,
            "blocked": receipt.blocked,
            "is_malicious": receipt.is_malicious,
            "agent_id": receipt.metadata.agent_id,
            "rule_hits": receipt.rule_hits,
        }
        if actual != expected:
            raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_PARENT_MISMATCH")
        return parent

    def _validate_runtime_outcome_authority(
        self,
        receipt: RuntimeOutcomeReceipt,
        parent: AuditEvent,
    ) -> None:
        """Validate authority-bearing adapter evidence against private state.

        Runtime receipts are observations, not authority. A receipt may copy
        display-safe binding/consume outcomes only when the immutable private
        binding, approval, and consumed lease prove the exact same action and
        identity. All failures intentionally collapse to the existing generic
        parent-mismatch code so fingerprints, grant IDs, and storage state are
        never reflected into an adapter-visible error.
        """

        parent_approval_id = parent.links.get("approval_id")
        approval_evidence = receipt.evidence.approval
        if approval_evidence.approval_id != parent_approval_id:
            self._runtime_outcome_authority_mismatch()

        binding = (
            self.store.get_enforcement_binding(parent_approval_id)
            if parent_approval_id is not None
            else None
        )
        enforcement = receipt.evidence.enforcement
        has_lease_links = receipt.links.lease_id is not None

        # An unbound/C1 parent can still produce a legacy approval-release
        # receipt, but it cannot claim strong binding or lease consumption.
        if binding is None:
            if enforcement is not None or has_lease_links:
                self._runtime_outcome_authority_mismatch()
            if receipt.metadata.outcome_kind == "approval_release":
                self._validate_released_approval(
                    receipt,
                    parent,
                    require_human=False,
                )
            return

        binding_facts = (
            binding.event_id,
            binding.policy_audit_id,
            binding.approval_id,
            binding.action_id,
            binding.runtime,
            binding.agent_id,
            binding.requires_execution_lease,
        )
        receipt_facts = (
            receipt.links.event_id,
            parent.audit_id,
            receipt.links.approval_id,
            receipt.links.action_id,
            receipt.runtime,
            receipt.metadata.agent_id,
            True,
        )
        if binding_facts != receipt_facts:
            self._runtime_outcome_authority_mismatch()

        approval = self.store.get_approval(binding.approval_id)
        if approval is None or (
            approval.approval_id,
            approval.action_id,
            approval.requesting_principal_id,
            approval.runtime,
            approval.agent_id,
        ) != (
            binding.approval_id,
            binding.action_id,
            binding.principal_id,
            binding.runtime,
            binding.agent_id,
        ):
            self._runtime_outcome_authority_mismatch()

        # A strong-binding parent makes every runtime outcome an RTE-05 claim.
        # Omitting enforcement must not downgrade it to the legacy/C1 contract
        # or reserve the deterministic receipt identity with forged approval
        # evidence.
        if enforcement is None:
            self._runtime_outcome_authority_mismatch()
        self._validate_bound_outcome_shape(receipt)
        self._validate_bound_approval_evidence(receipt, approval)

        if not has_lease_links:
            # A pre-consume failure may arrive after the approval row resolves,
            # but it cannot win the deterministic terminal identity after this
            # binding's single-use authority has actually been consumed.  The
            # immutable-replay short circuit in submit() deliberately runs
            # before this live-state check.
            if self.store.approval_execution_was_consumed(binding.approval_id):
                self._runtime_outcome_authority_mismatch()
            return

        released_consume = (
            enforcement.gate_state == "approval_released"
            and enforcement.binding_check_status == "passed"
            and enforcement.lease_consume_outcome == "consumed"
        )
        # A runtime may fail closed after the server atomically consumes the
        # lease but before invocation begins (final input drift, local
        # deadline/lease expiry, or an invalid lease response).  Such a denial
        # must retain the exact lease pair and use one of the frozen bounded
        # shapes below so that single-use authority is never hidden behind a
        # generic failure claim.
        post_consume_deny_shape = (
            enforcement.gate_state,
            enforcement.binding_check_status,
            frozenset(enforcement.reason_codes),
        )
        blocked_after_consume = (
            receipt.metadata.outcome_kind == "pre_execution_deny"
            and enforcement.lease_consume_outcome == "consumed"
            and post_consume_deny_shape
            in {
                (
                    "binding_failed",
                    "failed",
                    frozenset({"rte-05:binding_mismatch", "rte-05:lease_consumed"}),
                ),
                (
                    "timed_out",
                    "passed",
                    frozenset(
                        {
                            "rte-05:binding_exact",
                            "rte-05:lease_consume_timed_out",
                        }
                    ),
                ),
                (
                    "binding_failed",
                    "passed",
                    frozenset({"rte-05:binding_exact", "rte-05:lease_expired"}),
                ),
                (
                    "binding_failed",
                    "passed",
                    frozenset(
                        {
                            "rte-05:binding_exact",
                            "rte-05:lease_response_invalid",
                        }
                    ),
                ),
                (
                    "binding_failed",
                    "failed",
                    frozenset({"rte-05:multiple_binding_conflict"}),
                ),
            }
        )
        if not (released_consume or blocked_after_consume):
            self._runtime_outcome_authority_mismatch()
        self._validate_released_approval(
            receipt,
            parent,
            require_human=True,
        )
        lease_id = receipt.links.lease_id
        if binding.grant_id is None or lease_id is None:
            self._runtime_outcome_authority_mismatch()
        lease = self.store.get_execution_lease(
            binding.scope_digest,
            lease_id,
        )
        # consumed -> expired/revoked is a legitimate later transition. The
        # immutable lease/consumption identity remains the authority proof for
        # a delayed receipt and must not cause post-execution evidence loss.
        if lease is None or (
            lease.lease_id,
            lease.consumption_id,
            lease.approval_id,
            lease.grant_id,
            lease.action_id,
            lease.authorization_fingerprint,
            lease.runtime_binding_id,
        ) != (
            lease_id,
            receipt.links.consumption_id,
            binding.approval_id,
            binding.grant_id,
            binding.action_id,
            binding.authorization_fingerprint,
            binding.runtime_binding_id,
        ):
            self._runtime_outcome_authority_mismatch()

    def _validate_bound_outcome_shape(
        self,
        receipt: RuntimeOutcomeReceipt,
    ) -> None:
        enforcement = receipt.evidence.enforcement
        if enforcement is None:  # narrowed by caller; defensive for direct use
            self._runtime_outcome_authority_mismatch()
        has_lease_links = receipt.links.lease_id is not None
        if receipt.metadata.outcome_kind == "pre_execution_deny":
            if (
                not has_lease_links
                and enforcement.gate_state not in _BOUND_FAILURE_GATE_STATES
            ):
                self._runtime_outcome_authority_mismatch()
            return
        # Every other bound outcome represents release or post-release runtime
        # activity, which is impossible without the exact consumed lease pair.
        if not has_lease_links:
            self._runtime_outcome_authority_mismatch()

    def _validate_bound_approval_evidence(
        self,
        receipt: RuntimeOutcomeReceipt,
        approval: ApprovalRequest,
    ) -> None:
        evidence = receipt.evidence.approval
        enforcement = receipt.evidence.enforcement
        if enforcement is None:  # narrowed by caller; defensive for direct use
            self._runtime_outcome_authority_mismatch()
        reason_codes = frozenset(enforcement.reason_codes)
        has_lease_links = receipt.links.lease_id is not None

        # These two observations are deliberately weaker than a terminal
        # approval claim.  Durable receipt delivery can occur after a pending
        # approval monotonically resolves, so validating them only against the
        # current row would discard legitimate pre-execution evidence.
        pending_observation = (
            evidence.status in {"pending", "unknown"}
            and evidence.decision is None
            and not has_lease_links
        )
        if pending_observation:
            return
        local_wait_timeout = (
            evidence.status == "expired"
            and evidence.decision is None
            and not has_lease_links
            and enforcement.gate_state == "timed_out"
            and enforcement.binding_check_status == "passed"
            and enforcement.lease_consume_outcome == "not_attempted"
            and "rte-05:approval_timed_out" in reason_codes
        )
        if local_wait_timeout:
            return

        # Stronger terminal claims must match authoritative private state.
        if approval.status == "expired":
            if (
                evidence.status != "expired"
                or evidence.decision is not None
                or enforcement.gate_state not in _BOUND_FAILURE_GATE_STATES
                or "rte-05:approval_expired" not in reason_codes
            ):
                self._runtime_outcome_authority_mismatch()
            return

        if approval.status != "resolved":
            self._runtime_outcome_authority_mismatch()
        if approval.decision == "deny":
            if (
                evidence.status != "denied"
                or evidence.decision != "deny"
                or has_lease_links
                or enforcement.gate_state not in _BOUND_FAILURE_GATE_STATES
                or "rte-05:approval_not_consumable" not in reason_codes
            ):
                self._runtime_outcome_authority_mismatch()
            return
        if approval.decision != "allow_once" or (
            evidence.status != "allowed" or evidence.decision != "allow_once"
        ):
            self._runtime_outcome_authority_mismatch()

        claims_non_human = "rte-05:approval_not_human" in reason_codes
        if approval.resolution_source != "human":
            if (
                has_lease_links
                or enforcement.gate_state != "binding_failed"
                or not claims_non_human
            ):
                self._runtime_outcome_authority_mismatch()
        elif claims_non_human:
            self._runtime_outcome_authority_mismatch()

    def _validate_released_approval(
        self,
        receipt: RuntimeOutcomeReceipt,
        parent: AuditEvent,
        *,
        require_human: bool,
    ) -> None:
        approval_id = parent.links.get("approval_id")
        approval = (
            self.store.get_approval(approval_id) if approval_id is not None else None
        )
        evidence = receipt.evidence.approval
        if approval is None or (
            approval.status != "resolved"
            or approval.decision != "allow_once"
            or evidence.approval_id != approval.approval_id
            or evidence.status != "allowed"
            or evidence.decision != "allow_once"
            or approval.action_id != receipt.links.action_id
            or approval.runtime != receipt.runtime
            or approval.agent_id != receipt.metadata.agent_id
            or (require_human and approval.resolution_source != "human")
        ):
            self._runtime_outcome_authority_mismatch()

    @staticmethod
    def _runtime_outcome_authority_mismatch() -> NoReturn:
        raise RuntimeOutcomeReceiptError("RUNTIME_OUTCOME_PARENT_MISMATCH")

    def record_evaluation(
        self,
        event: GuardEvent,
        decision: GuardDecision,
        *,
        policy_bundle: PolicyBundle,
        policy_revision: int | None,
        approval_id: str | None = None,
        critic_review: ActionCriticReview | None = None,
        memory_change_id: str | None = None,
        extra_metadata: dict[str, object] | None = None,
        decision_dump: dict[str, object] | None = None,
        v21_evidence: dict[str, object] | None = None,
        state_delta_evidence: dict[str, object] | None = None,
        ct_facts_evidence: dict[str, object] | None = None,
        decision_authority_evidence: dict[str, object] | None = None,
        decision_authority: DecisionAuthority | None = None,
        audit_id: str | None = None,
    ) -> AuditEvent:
        """写入 policy_evaluation 审计记录。

        ``v21_evidence``：V21-08 shadow 旁路信封透传（None 时与现状逐字节
        一致）；写入位置为同一条记录的 ``evidence.decision_v21``，不新增
        第二条审计记录（11_决策记录_V21-08前置.md D4）。

        ``state_delta_evidence``：V21-09 ``state_delta_v21`` 引用信封透传
        （None 时逐字节不变，仿 ``v21_evidence``）；只存投影身份引用，
        全量 delta 随 projection_records（12_决策记录_V21-09前置.md D2）。

        ``ct_facts_evidence``：CT-PR-03b ``ct_transient_facts`` 信封透传
        （None 时逐字节不变，仿 ``state_delta_evidence``）；facts 本体
        commit 载体寄生同一条审计记录 evidence（D4：零新表零迁移）。

        ``audit_id``：显式确定性审计身份（None 时沿用默认工厂，逐字节
        不变）；pipeline 路径以 ``derive_final_audit_id`` 产物显式赋值，
        保证 replay 同输入同身份（D7-5）。
        """

        audit_event = build_audit_event(
            event,
            decision,
            policy_bundle=policy_bundle,
            policy_revision=policy_revision,
            approval_id=approval_id,
            critic_review_id=(
                critic_review.review_id if critic_review is not None else None
            ),
            memory_change_id=memory_change_id,
            extra_metadata=extra_metadata,
            decision_dump=decision_dump,
            v21_evidence=v21_evidence,
            state_delta_evidence=state_delta_evidence,
            ct_facts_evidence=ct_facts_evidence,
            decision_authority_evidence=decision_authority_evidence,
            decision_authority=decision_authority,
            audit_id=audit_id,
            evidence_content_preview_enabled=self.evidence_content_preview_enabled,
        )
        audit_event = sanitize_audit_event(audit_event)
        self.store.add_audit_event(audit_event)
        persisted = self.store.get_audit_event(audit_event.audit_id) or audit_event
        if decision_authority_evidence is not None:
            self._validate_decision_authority_commit(
                persisted,
                expected_envelope=decision_authority_evidence,
                expected_decision=decision,
                expected_authority=decision_authority,
                expected_v21_evidence=v21_evidence,
            )
        if critic_review is not None:
            self.store.add_action_critic_review(critic_review)
        approval = (
            self.store.get_approval(approval_id) if approval_id is not None else None
        )
        self.provenance_writer.record_audit_event(
            persisted,
            approval=approval,
            critic_review=critic_review,
        )
        return persisted

    def _validate_decision_authority_commit(
        self,
        persisted: AuditEvent,
        *,
        expected_envelope: dict[str, object],
        expected_decision: GuardDecision,
        expected_authority: DecisionAuthority | None,
        expected_v21_evidence: dict[str, object] | None,
    ) -> None:
        if expected_authority is None:
            raise CriticalDecisionEvidenceError(
                "critical authority evidence requires a top-level authority"
            )
        expected = strict_decision_authority_envelope(expected_envelope)
        evidence = persisted.evidence
        actual_raw = (
            evidence.get("decision_authority") if isinstance(evidence, dict) else None
        )
        actual = strict_decision_authority_envelope({"decision_authority": actual_raw})
        if actual != expected:
            raise CriticalDecisionEvidenceError(
                "persisted authority evidence differs from the selected result"
            )
        # Both frozen authority evidence versions expose the same decision and
        # authority truth fields.  Parsing remains version-exact above; the
        # commit/readback parity checks below deliberately share one semantic
        # path so Product cannot receive weaker persistence guarantees.
        payload = parse_decision_authority_evidence_payload(actual)
        raw_top = (persisted.model_extra or {}).get("decision_authority")
        try:
            top = DecisionAuthority.model_validate(raw_top)
        except ValueError as exc:
            raise CriticalDecisionEvidenceError(
                "persisted top-level decision authority is invalid"
            ) from exc
        decision_dump = expected_decision.model_dump(mode="json")
        replay_dump = (
            evidence.get("guard_decision") if isinstance(evidence, dict) else None
        )
        raw_v21 = evidence.get("decision_v21") if isinstance(evidence, dict) else None
        if (
            expected_v21_evidence is None
            or not isinstance(raw_v21, dict)
            or set(expected_v21_evidence) != {"decision_v21"}
            or raw_v21 != expected_v21_evidence["decision_v21"]
        ):
            raise CriticalDecisionEvidenceError(
                "persisted DecisionEvidenceV21 differs from the selected result"
            )
        try:
            decision_evidence = DecisionEvidenceV21.model_validate(raw_v21["payload"])
        except (KeyError, ValueError) as exc:
            raise CriticalDecisionEvidenceError(
                "persisted DecisionEvidenceV21 is invalid"
            ) from exc
        exact_policy_projection = {
            "decision": persisted.decision,
            "risk_score": persisted.risk_score,
            "severity": persisted.severity,
            "blocked": persisted.blocked,
            "reason": persisted.reason,
            "decision_id": persisted.links.get("decision_id"),
        }
        expected_policy_projection = {
            "decision": expected_decision.decision,
            "risk_score": expected_decision.risk_score,
            "severity": expected_decision.severity,
            "blocked": expected_decision.blocked,
            "reason": expected_decision.reason,
            "decision_id": expected_decision.decision_id,
        }
        if not all(
            (
                top == expected_authority,
                payload.decision_authority == expected_authority,
                payload.selected_decision == expected_decision,
                decision_evidence.mode == expected_authority.mode,
                decision_evidence.final_decision == expected_decision.decision,
                replay_dump == decision_dump,
                exact_policy_projection == expected_policy_projection,
            )
        ):
            raise CriticalDecisionEvidenceError(
                "selected decision, authority, and audit projections lack exact parity"
            )
        if isinstance(payload, ProductDecisionAuthorityEvidenceV1):
            if not all(
                (
                    payload.runtime == persisted.runtime,
                    payload.event_type == persisted.event_type,
                    payload.event_id == persisted.links.get("event_id"),
                    payload.assessment_id == decision_evidence.assessment_id,
                    payload.assessment_digest == decision_evidence.assessment_digest,
                    payload.snapshot_id == decision_evidence.snapshot_id,
                    payload.snapshot_digest == decision_evidence.snapshot_digest,
                    payload.state_version == decision_evidence.state_version,
                    payload.policy_digest == persisted.metadata.get("policy_digest"),
                )
            ):
                raise CriticalDecisionEvidenceError(
                    "Product authority evidence is not bound to the persisted audit"
                )
            self._validate_product_approval_release_commit(persisted, payload)

    def _validate_product_approval_release_commit(
        self,
        persisted: AuditEvent,
        payload: ProductDecisionAuthorityEvidenceV1,
    ) -> None:
        """Bind Product release authority to the exact approval and audit action."""

        directive = payload.approval_release_directive
        approval_id = persisted.links.get("approval_id")
        releasable = directive.mode in {
            "strong_binding",
            "restricted_allow_once",
        }
        if not releasable:
            if approval_id is not None:
                raise CriticalDecisionEvidenceError(
                    "unreleasable Product authority carries an approval"
                )
            return
        if approval_id is None:
            raise CriticalDecisionEvidenceError(
                "releasable Product authority lacks an approval"
            )
        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise CriticalDecisionEvidenceError(
                "Product approval referenced by the audit is unavailable"
            )
        approval_evidence = approval.evidence
        try:
            approval_directive = ApprovalReleaseDirectiveV2.model_validate(
                approval_evidence.get("approval_release_directive")
            )
            approval_authority = DecisionAuthority.model_validate(
                approval_evidence.get("decision_authority")
            )
        except (TypeError, ValueError) as exc:
            raise CriticalDecisionEvidenceError(
                "Product approval release evidence is invalid"
            ) from exc
        raw_event = approval_evidence.get("event")
        raw_decision = approval_evidence.get("decision")
        if not isinstance(raw_event, dict) or not isinstance(raw_decision, dict):
            raise CriticalDecisionEvidenceError(
                "Product approval identity evidence is invalid"
            )
        if not all(
            (
                approval.approval_id == approval_id,
                approval.trace_id == persisted.trace_id,
                approval.runtime == persisted.runtime,
                approval.action_id == persisted.links.get("action_id"),
                raw_event.get("event_id") == payload.event_id,
                raw_event.get("event_type") == payload.event_type,
                raw_event.get("trace_id") == persisted.trace_id,
                raw_event.get("runtime") == payload.runtime,
                raw_decision.get("decision_id")
                == payload.selected_decision.decision_id,
                raw_decision.get("decision") == payload.selected_decision.decision,
                approval_directive == directive,
                approval_authority == payload.decision_authority,
            )
        ):
            raise CriticalDecisionEvidenceError(
                "Product approval release is not bound to the persisted authority"
            )

    def repair_provenance(self, event: AuditEvent) -> None:
        approval_id = event.links.get("approval_id")
        approval = self.store.get_approval(approval_id) if approval_id else None
        critic_review: ActionCriticReview | None = None
        critic_review_id = event.links.get("critic_review_id")
        if critic_review_id:
            critic_review = next(
                (
                    review
                    for review in self.store.list_action_critic_reviews(event.trace_id)
                    if review.review_id == critic_review_id
                ),
                None,
            )
        self.provenance_writer.record_audit_event(
            event,
            approval=approval,
            critic_review=critic_review,
        )

    def integrity(self) -> dict[str, object]:
        chain_status = self.store.verify_audit_integrity()
        anchor_status = (
            self.checkpoint_service.inspect(chain_status)
            if self.checkpoint_service is not None
            else disabled_audit_anchor_status()
        )
        return {
            **asdict(chain_status),
            "canonicalization": CANONICALIZATION,
            "anchor": asdict(anchor_status),
        }
