"""Replay isolated policy evidence with the candidate's production Core/API code.

This is an offline reader, never a producer of authority or host observations.
The explicitly synthetic activation is checked at the recorded evaluation time;
it cannot establish that the formal Product profile was activated. The coverage
kernel used below is also the kernel behind GuardEngine.assess and the API's
active pipeline. Neither a supplied assessment nor eligibility flags are inputs.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hmac
import os
import stat
from types import SimpleNamespace
from typing import Any, Literal, cast

from pydantic import BaseModel, Field, TypeAdapter

from agentguard_core import (
    ActivationAckV1,
    AuditEvent,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    ProductActivationBundleV1,
    ProductDecisionAuthorityEvidenceV1,
    RuntimeOutcomeReceipt,
    V21SelectionEligibility,
)
from agentguard_core.authority.models import (
    scope_digest_projection,
    task_digest_projection,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.product import (
    build_product_decision_authority_evidence,
    select_product_v21_authority,
    verify_activation_ack,
    verify_activation_ack_token,
    verify_product_activation_bundle,
)
from agentguard_core.decisions.revalidation import revalidate_assessment
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.security_context import ExecutionLease, SecuritySnapshot
from agentguard_core.security_context.assessment_overlay import AssessmentTransientFacts
from agentguard_core.security_context.snapshot import snapshot_digest_projection
from agentguard_core.security_context.projection.capability import (
    grant_digest_projection,
)
from guard_api.models import ApprovalRequest
from guard_api.runtime_status import (
    ProductActivationAckRecordV1,
    activation_ack_token_digest,
)
from guard_api.security_state.fact_builder import build_transient_facts
from guard_api.services.ct_projection import (
    CtProjectionService,
    decode_ct_transient_facts,
)
from guard_api.services.product_model_content import (
    CONTENT_KEY,
    build_product_model_content,
    read_product_model_content,
    verify_product_model_content,
    verify_product_tool_result,
    read_product_tool_result,
)
from guard_api.services.product_tool_catalog import ProductToolCatalog
from guard_api.storage.base import (
    AuditWindowQuery,
    ControlPlaneStore,
    EnforcementBindingRecord,
)

from .evidence import EvidenceStore, object_fields
from .models import AdmissionError, Digest, EvidenceRef, StrictModel, read_model


class PolicyServerCapture(StrictModel):
    """Fields captured from the original policy audit's fenced Phase-B check."""

    schema_version: Literal["agentguard-product-policy-server-capture/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    source: Literal["guard_api_phase_b"]
    runtime: Literal["langgraph", "openclaw"]
    checked_at: str = Field(min_length=1, max_length=64)
    event_id: str = Field(min_length=1, max_length=256)
    policy_audit_id: str = Field(min_length=1, max_length=256)
    event_digest: Digest
    snapshot_digest: Digest
    activation_ref_digest: Digest
    decision_authority_digest: Digest


class PolicyReplay(StrictModel):
    schema_version: Literal["agentguard-product-policy-replay/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    execution_scope: Literal["isolated_contract_fixture"]
    product_active_enabled: Literal[False]
    external_provider_requests: Literal[0]
    runtime: Literal["langgraph", "openclaw"]
    scope_id: str = Field(min_length=1, max_length=256)
    candidate_manifest_digest: Digest
    adapter_artifact_digest: Digest
    activation: EvidenceRef
    catalog: EvidenceRef
    snapshot: EvidenceRef
    current_snapshot: EvidenceRef
    history: EvidenceRef
    product_key: EvidenceRef
    assessment_key: EvidenceRef
    scope_key: EvidenceRef
    evaluation_ack: EvidenceRef
    revoked_grant_ids: list[str] = Field(max_length=256)
    coverage: dict[str, Any]
    transient_facts: dict[str, Any]
    product_data: dict[str, Any]
    prior_actions: list[EvidenceRef] = Field(max_length=4)
    server_capture: PolicyServerCapture


class PolicyHistory(StrictModel):
    schema_version: Literal["agentguard-product-policy-history/1"]
    authority_kind: Literal["synthetic_contract_fixture"]
    scope_id: str = Field(min_length=1, max_length=256)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=256)
    audits: list[dict[str, Any]] = Field(min_length=1, max_length=768)
    acknowledgements: list[dict[str, Any]] = Field(min_length=1, max_length=128)
    approvals: list[dict[str, Any]] = Field(max_length=64)
    bindings: list[dict[str, Any]] = Field(max_length=64)
    leases: list[dict[str, Any]] = Field(max_length=64)


def _require(
    condition: object, code: str = "conformance_policy_replay_invalid"
) -> None:
    if not condition:
        raise AdmissionError(code)


def _same(value: Any, expected: Any) -> None:
    _require(canonical_sha256(value) == canonical_sha256(expected))


def _typed(model: type[BaseModel], value: Any) -> Any:
    result = model.model_validate(value)
    _same(result.model_dump(mode="json"), value)
    return result


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None)
    return parsed


def _key(store: EvidenceStore, reference: EvidenceRef) -> bytes:
    file = store.read_file(reference, max_bytes=128)
    info = file.path.lstat()
    _require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid())
    _require(32 <= len(file.content) <= 128)
    return file.content


def _unique(rows: list[Any], name: str) -> dict[str, Any]:
    keys = [getattr(row, name) for row in rows]
    _require(len(keys) == len(set(keys)))
    return dict(zip(keys, rows, strict=True))


class _HistoryStore:
    """Only the bounded read methods used by the production proof readers."""

    def __init__(
        self,
        history: PolicyHistory,
        snapshot: SecuritySnapshot,
        activation: ProductActivationBundleV1,
        secret: bytes,
    ) -> None:
        self.snapshot = snapshot
        self.events = _unique(
            [_typed(GuardEvent, value) for value in history.events], "event_id"
        )
        self.audits = _unique(
            [_typed(AuditEvent, value) for value in history.audits], "audit_id"
        )
        policies = [
            row
            for row in self.audits.values()
            if row.record_type == "policy_evaluation"
        ]
        self.policies = _unique(policies, "audit_id")
        ids = [row.links.get("event_id") for row in policies]
        _require(None not in ids and len(ids) == len(set(ids)))
        for event in self.events.values():
            _require(
                event.runtime == snapshot.scope.runtime
                and event.trace_id == snapshot.scope.trace_id
            )
        for audit in self.audits.values():
            _require(
                audit.runtime == snapshot.scope.runtime
                and audit.trace_id == snapshot.scope.trace_id
            )
            _require(audit.record_type in {"policy_evaluation", "runtime_outcome"})
        self.acks: dict[str, ProductActivationAckRecordV1] = {}
        for value in history.acknowledgements:
            object_fields(value, {"ack", "record"}, "conformance_policy_ack_invalid")
            ack = _typed(ActivationAckV1, value["ack"])
            record = _typed(ProductActivationAckRecordV1, value["record"])
            _require(verify_activation_ack_token(ack, server_secret=secret))
            _require(record.token_digest == activation_ack_token_digest(ack.ack_token))
            _same(record.ack_projection, ack.token_projection())
            _require(record.token_digest not in self.acks)
            _require(record.principal_id == snapshot.scope.principal_id)
            _require(
                ack.runtime == snapshot.scope.runtime
                and ack.runtime_binding_id == snapshot.scope.runtime_binding_id
            )
            _require(ack.activation_ref_digest == activation.activation_ref_digest)
            self.acks[record.token_digest] = record
        self.approvals = _unique(
            [_typed(ApprovalRequest, value) for value in history.approvals],
            "approval_id",
        )
        bindings = []
        for value in history.bindings:
            binding = TypeAdapter(EnforcementBindingRecord).validate_python(value)
            _same(asdict(binding), value)
            _require(binding.scope_digest == snapshot.scope.scope_digest)
            _require(binding.runtime_binding_id == snapshot.scope.runtime_binding_id)
            bindings.append(binding)
        self.bindings = _unique(bindings, "approval_id")
        self.leases = _unique(
            [_typed(ExecutionLease, value) for value in history.leases], "lease_id"
        )
        _require(
            all(
                lease.runtime_binding_id == snapshot.scope.runtime_binding_id
                for lease in self.leases.values()
            )
        )

    def get_audit_event(self, audit_id: str) -> AuditEvent | None:
        return self.audits.get(audit_id)

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None:
        return next(
            (
                row
                for row in self.policies.values()
                if row.links.get("event_id") == event_id
            ),
            None,
        )

    def read_audit_events_bounded(self, query: AuditWindowQuery) -> list[AuditEvent]:
        _require(query.record_type == "policy_evaluation" and query.limit == 257)
        _require(
            query.runtime == self.snapshot.scope.runtime
            and query.trace_id == self.snapshot.scope.trace_id
        )
        return list(self.policies.values())[: query.limit]

    def get_product_activation_ack(
        self, token_digest: str
    ) -> ProductActivationAckRecordV1 | None:
        return self.acks.get(token_digest)

    def get_execution_lease(
        self, scope_digest: str, lease_id: str
    ) -> ExecutionLease | None:
        _require(scope_digest == self.snapshot.scope.scope_digest)
        return self.leases.get(lease_id)

    def get_enforcement_binding(
        self, approval_id: str
    ) -> EnforcementBindingRecord | None:
        return self.bindings.get(approval_id)

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self.approvals.get(approval_id)


def _snapshot(
    store: EvidenceStore, reference: EvidenceRef, policy: PolicyBundle, secret: bytes
) -> SecuritySnapshot:
    snapshot = _typed(SecuritySnapshot, store.read_json(reference).data)
    _require(
        snapshot.snapshot_digest
        == canonical_sha256(snapshot_digest_projection(snapshot))
    )
    _require(
        snapshot.scope.scope_digest
        == scope_digest_projection(snapshot.scope, server_key=secret)
    )
    _require(snapshot.policy_digest == canonical_sha256(policy.model_dump(mode="json")))
    _require(snapshot.task is not None and snapshot.task.status == "active")
    assert snapshot.task is not None
    _require(snapshot.task.task_digest == task_digest_projection(snapshot.task))
    _require(snapshot.task.scope_digest == snapshot.scope.scope_digest)
    _require(snapshot.task.principal_id == snapshot.scope.principal_id)
    _require(
        snapshot.task.producer == "guard_api_task_ingress"
        and snapshot.task.authority == "authoritative"
    )
    _require(len({grant.grant_id for grant in snapshot.grants}) == len(snapshot.grants))
    for grant in snapshot.grants:
        _require(grant.grant_digest == canonical_sha256(grant_digest_projection(grant)))
        _require(grant.scope_digest == snapshot.scope.scope_digest)
    _time(snapshot.evaluation_clock.evaluated_at)
    return snapshot


def verify_policy_evidence(
    row: dict[str, Any],
    *,
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
) -> ProductDecisionAuthorityEvidenceV1:
    """Reject omitted/changed material and recompute the complete target decision."""
    try:
        return _verify(
            row,
            runtime=runtime,
            scope_id=scope_id,
            policy=policy,
            store=store,
            candidate_manifest_digest=candidate_manifest_digest,
            adapter_artifact_digest=adapter_artifact_digest,
        )
    except AdmissionError:
        raise
    except Exception:
        # Validation exceptions can contain original model content or private ACKs.
        raise AdmissionError("conformance_policy_replay_invalid") from None


def _verify(
    row: dict[str, Any],
    *,
    runtime: str,
    scope_id: str,
    policy: PolicyBundle,
    store: EvidenceStore,
    candidate_manifest_digest: str,
    adapter_artifact_digest: str,
    depth: int = 0,
) -> ProductDecisionAuthorityEvidenceV1:
    _require(depth <= 1)
    replay = read_model(PolicyReplay, store.read_json(row["replay"]).data)
    _require(depth == 0 or not replay.prior_actions)
    _require(
        (
            replay.runtime,
            replay.scope_id,
            replay.candidate_manifest_digest,
            replay.adapter_artifact_digest,
        )
        == (runtime, scope_id, candidate_manifest_digest, adapter_artifact_digest)
    )
    product_secret, assessment_secret, scope_secret = (
        _key(store, getattr(replay, name))
        for name in ("product_key", "assessment_key", "scope_key")
    )
    _require(not hmac.compare_digest(product_secret, assessment_secret))
    event = _typed(GuardEvent, row["event"])
    supplied = _typed(ProductDecisionAuthorityEvidenceV1, row["authority"])
    snapshot = _snapshot(store, replay.snapshot, policy, scope_secret)
    current = _snapshot(store, replay.current_snapshot, policy, scope_secret)
    assert snapshot.task is not None and current.task is not None
    _require(snapshot.evaluation_clock.evaluated_at == event.timestamp)
    _same(current.scope.model_dump(mode="json"), snapshot.scope.model_dump(mode="json"))
    activation = _typed(
        ProductActivationBundleV1, store.read_json(replay.activation).data
    )
    _require(verify_product_activation_bundle(activation, server_secret=product_secret))
    _require(activation.candidate_artifact_manifest_digest == candidate_manifest_digest)
    _require(activation.policy_digest == snapshot.policy_digest)
    capture = replay.server_capture
    _require(
        (capture.runtime, capture.event_id, capture.policy_audit_id)
        == (runtime, event.event_id, row["policy_audit_id"])
    )
    _require(capture.event_digest == canonical_sha256(event.model_dump(mode="json")))
    _require(capture.snapshot_digest == snapshot.snapshot_digest)
    _require(capture.activation_ref_digest == activation.activation_ref_digest)
    _require(
        capture.decision_authority_digest
        == canonical_sha256(supplied.model_dump(mode="json"))
    )
    # Core deliberately keeps the event-anchored snapshot clock. Product ACKs
    # instead use the server's independent fenced Phase-B authority clock.
    when = _time(capture.checked_at)
    _require(_time(snapshot.evaluation_clock.evaluated_at) <= when)
    _require(_time(activation.issued_at) <= when < _time(activation.expires_at))
    entry = activation.runtime_entry(cast(Any, runtime))
    _require(
        entry.adapter_artifact_digest == adapter_artifact_digest
        and when < _time(entry.expires_at)
    )
    _require(
        (entry.runtime, entry.principal_id, entry.runtime_binding_id, entry.agent_id)
        == (
            event.runtime,
            snapshot.scope.principal_id,
            snapshot.scope.runtime_binding_id,
            event.security_context.agent_id,
        )
    )
    _require(
        event.trace_id == snapshot.scope.trace_id
        and event.metadata.get("task_id") == snapshot.task.task_id
    )
    ack = _typed(ActivationAckV1, store.read_json(replay.evaluation_ack).data)
    _require(verify_activation_ack(ack, server_secret=product_secret, now=when))
    history = read_model(PolicyHistory, store.read_json(replay.history).data)
    _require(history.scope_id == scope_id)
    records = _HistoryStore(history, snapshot, activation, product_secret)
    issued = records.get_product_activation_ack(
        activation_ack_token_digest(ack.ack_token)
    )
    _require(
        issued is not None
        and (issued.revoked_at is None or when < _time(issued.revoked_at))
    )
    assert issued is not None
    _same(issued.ack_projection, ack.token_projection())
    catalog_document = store.read_json(replay.catalog)
    catalog = ProductToolCatalog(str(catalog_document.file.path), activation)
    tool = catalog.resolve(event, activation=activation, activation_ack=ack)
    _require(tool is not None)
    assert tool is not None
    # Rebuild each original complete model-output commitment before its sealed
    # proof reader consumes the audit. No descriptor/proof supplied by a runner
    # can become a VerifiedProductTool/VerifiedProductData directly.
    for audit in records.policies.values():
        content = (audit.evidence or {}).get(CONTENT_KEY)
        if content is None:
            continue
        original = records.events.get(audit.links.get("event_id"))
        _require(original is not None)
        assert original is not None
        rebuilt = build_product_model_content(
            cast(ControlPlaneStore, records),
            original,
            snapshot=snapshot,
            catalog=catalog,
            activation=activation,
            decision_authority_evidence={
                "decision_authority": audit.evidence["decision_authority"]
            },
        )
        _require(rebuilt is not None)
        assert rebuilt is not None
        _same(
            rebuilt.model_dump(mode="json"),
            read_product_model_content(content).model_dump(mode="json"),
        )
    verified_reads: set[str] = set()
    for reference in replay.prior_actions:
        prior_row = store.read_json(reference).data
        _require(isinstance(prior_row, dict))
        prior_authority = _verify(
            prior_row,
            runtime=runtime,
            scope_id=scope_id,
            policy=policy,
            store=store,
            candidate_manifest_digest=candidate_manifest_digest,
            adapter_artifact_digest=adapter_artifact_digest,
            depth=depth + 1,
        )
        prior_replay = read_model(
            PolicyReplay, store.read_json(prior_row["replay"]).data
        )
        prior_snapshot = _snapshot(store, prior_replay.snapshot, policy, scope_secret)
        _same(
            prior_snapshot.scope.model_dump(mode="json"),
            snapshot.scope.model_dump(mode="json"),
        )
        assert prior_snapshot.task is not None
        _same(
            prior_snapshot.task.model_dump(mode="json"),
            snapshot.task.model_dump(mode="json"),
        )
        _require(
            prior_authority.decision_authority.activation_ref_digest
            == activation.activation_ref_digest
        )
        _require(
            prior_authority.selected_decision.decision == "allow"
            and prior_replay.product_data.get("tool_name") == "read"
        )
        audit_id = prior_row["policy_audit_id"]
        _require(audit_id not in verified_reads)
        parent = records.get_audit_event(audit_id)
        _require(parent is not None and parent.evidence is not None)
        assert parent is not None and parent.evidence is not None
        _same(
            parent.evidence["decision_authority"]["payload"],
            prior_authority.model_dump(mode="json"),
        )
        _require(
            parent.metadata.get("product_authority_initial_checked_at")
            == prior_replay.server_capture.checked_at
        )
        _same(parent.evidence["product_action_data"], prior_replay.product_data)
        _same(
            records.events[prior_authority.event_id].model_dump(mode="json"),
            prior_row["event"],
        )
        # A read is itself an invoked tool. Its original terminal bytes and the
        # LG confirmed start must be part of this ancestor's evidence, before
        # its output can justify a later command. Do not reconstruct private
        # transport from the token-stripped accepted audit.
        from guard_api.services.audit import AuditService
        from guard_api.services.product_model_content import (
            build_product_ack_validation,
        )
        from guard_api.services.redaction import sanitize_audit_event
        from .policy_start import verify_policy_start

        receipt = RuntimeOutcomeReceipt.model_validate(
            store.read_json(prior_row["receipt"]).data, strict=True
        )
        accepted = _typed(AuditEvent, store.read_json(prior_row["accepted"]).data)
        _require(records.audits.get(accepted.audit_id) == accepted)
        _require(receipt.audit_id == accepted.audit_id)
        _require(receipt.metadata.activation_ack is not None)
        assert receipt.metadata.activation_ack is not None
        _same(
            receipt.metadata.activation_ack.model_dump(mode="json"),
            store.read_json(prior_replay.evaluation_ack).data,
        )
        normalized = sanitize_audit_event(
            AuditEvent.model_validate(receipt.model_dump(mode="json"))
        )
        normalized.metadata["product_ack_validation"] = build_product_ack_validation(
            receipt, parent
        )
        _same(
            normalized.model_dump(mode="json", exclude={"integrity"}),
            accepted.model_dump(mode="json", exclude={"integrity"}),
        )
        audit_service = AuditService(store=cast(ControlPlaneStore, records))
        _require(audit_service._validate_runtime_outcome_parent(receipt) == parent)
        audit_service._validate_runtime_outcome_authority(receipt, parent)
        _require(
            receipt.decision == "allow"
            and receipt.metadata.outcome_kind == "execution_completed"
        )
        _require(receipt.evidence.execution.status == "executed")
        if runtime == "langgraph":
            _require(prior_row.get("start") is not None)
            verify_policy_start(
                prior_row["start"],
                row=prior_row,
                parent=parent,
                terminal=receipt,
                replay=prior_replay,
                store=store,
                records=records,
            )
        else:
            _require(prior_row.get("start") is None)
            _require(receipt.evidence.execution.invoked_at is None)
        verified_reads.add(audit_id)
    read_sources: set[str] = set()
    for audit in records.policies.values():
        if audit.event_type != "tool_result_produced":
            continue
        original = records.events.get(audit.links.get("event_id"))
        _require(original is not None)
        assert original is not None
        result = verify_product_tool_result(
            cast(ControlPlaneStore, records), original, snapshot
        )
        _same(
            result.model_dump(mode="json"),
            read_product_tool_result(audit).model_dump(mode="json"),
        )
        _, result_detections = GuardEngine().evaluate_with_results(original, policy)
        result_projection = object.__new__(CtProjectionService)
        result_projection._server_secret = assessment_secret
        result_inputs = result_projection._build_inputs(
            original,
            cast(
                Any,
                SimpleNamespace(
                    snapshot=snapshot,
                    detection_results=result_detections,
                    task_id=snapshot.task.task_id,
                    product_tool=None,
                    product_data=None,
                    product_result=result,
                ),
            ),
            snapshot.scope.scope_digest,
        )
        actual_facts = build_transient_facts(event=original, inputs=result_inputs)
        committed = decode_ct_transient_facts(audit)
        _require(committed.kind == "full" and committed.bundle is not None)
        assert committed.bundle is not None
        _same(
            [item.model_dump(mode="json") for item in committed.bundle.source_facts],
            [item.model_dump(mode="json") for item in actual_facts.source_facts],
        )
        _same(
            [item.model_dump(mode="json") for item in committed.bundle.flow_facts],
            [item.model_dump(mode="json") for item in actual_facts.flow_facts],
        )
        _require(not committed.bundle.degradations and not actual_facts.degradations)
        if result.parent_policy_audit_id in verified_reads:
            _require(result.native_tool_name == "read")
            read_sources.update(
                item.source_id
                for item in actual_facts.source_facts
                if item.source_type == "tool_result"
                and item.trust == "untrusted"
                and "UNTRUSTED" in item.taints
            )
    product_data = verify_product_model_content(
        cast(ControlPlaneStore, records), event, snapshot, tool
    )
    if tool.tool_name == "exec" and supplied.selected_decision.decision == "ask":
        _require(bool(read_sources & set(product_data.source_refs)))
    _same(product_data.model_dump(mode="json"), replay.product_data)
    engine = GuardEngine()
    actual_current, detections = engine.evaluate_with_results(event, policy)
    ignored = {"decision_id", "latency_ms"}
    _same(
        actual_current.model_dump(mode="json", exclude=ignored),
        supplied.current_decision.model_dump(mode="json", exclude=ignored),
    )
    projection = object.__new__(CtProjectionService)
    projection._server_secret = assessment_secret
    materials = SimpleNamespace(
        snapshot=snapshot,
        detection_results=detections,
        task_id=snapshot.task.task_id,
        product_tool=tool,
        product_data=product_data,
        product_result=None,
    )
    inputs = projection._build_inputs(
        event, cast(Any, materials), snapshot.scope.scope_digest
    )
    bundle = build_transient_facts(event=event, inputs=inputs)
    transient = AssessmentTransientFacts.model_validate(bundle.model_dump(mode="json"))
    _same(transient.model_dump(mode="json"), replay.transient_facts)
    _require(replay.revoked_grant_ids == sorted(set(replay.revoked_grant_ids)))
    outcome = shadow_assess_with_coverage(
        event,
        policy,
        snapshot,
        server_secret=assessment_secret,
        detection_results=detections,
        revoked_grant_ids=replay.revoked_grant_ids,
        transient_facts=transient,
        product_tool=tool,
        product_data=product_data,
    )
    _same(outcome.coverage.model_dump(mode="json"), replay.coverage)
    _same(outcome.assessment.model_dump(mode="json"), row["assessment"])
    action = outcome.action_ir
    _require(action is not None and inputs.action_ir is not None)
    assert action is not None and inputs.action_ir is not None
    _same(action.model_dump(mode="json"), inputs.action_ir.model_dump(mode="json"))
    # Match the active API selector's complete action identity predicate. A
    # present object alone is not evidence that the action belongs to this run.
    action_ir_consistent = bool(
        action.event_id == event.event_id
        and action.action_id == outcome.assessment.action_id
        and action.authorization_fingerprint
        == outcome.assessment.authorization_fingerprint
        and action.audit_fingerprint == outcome.assessment.audit_fingerprint
        and action.trace_id == event.trace_id
        and action.task_id == snapshot.task.task_id
        and action.task_revision == snapshot.task.revision
        and action.runtime == entry.runtime
        and action.principal_id == entry.principal_id
        and action.runtime_binding_id == entry.runtime_binding_id
        and action.agent_id == entry.agent_id
        and action.scope_digest == snapshot.scope.scope_digest
    )
    _require(action_ir_consistent)
    valid = revalidate_assessment(
        outcome.assessment,
        assessment_state_version=snapshot.state_version,
        current_state_version=current.state_version,
        current_task_digest=current.task.task_digest,
        current_policy_digest=current.policy_digest,
        current_snapshot_digest=current.snapshot_digest,
    )
    _require(valid.status == "valid")
    eligibility = V21SelectionEligibility(
        activation_valid=True,
        trusted_identity_valid=True,
        profile_valid=event.event_type in entry.event_types,
        revalidation_valid=valid.status == "valid",
        pipeline_complete=action_ir_consistent,
        ownership_valid=action_ir_consistent,
        action_ir_complete=action_ir_consistent,
        task_fact_present=snapshot.task is not None,
        approval_binding_eligible=event.pre_execution
        and event.event_type
        in {"tool_call_proposed", "memory_write_proposed", "message_send_proposed"},
    )
    selection, directive = select_product_v21_authority(
        event_id=event.event_id,
        current_decision=supplied.current_decision,
        raw_v21_decision=engine.finalize(outcome.assessment),
        assessment=outcome.assessment,
        coverage=outcome.coverage,
        activation=activation,
        runtime_entry=entry,
        eligibility=eligibility,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
        scope_digest=snapshot.scope.scope_digest,
        event_type=event.event_type,
        residual_boundaries=entry.residual_boundaries,
        product_data=product_data,
    )
    rebuilt = build_product_decision_authority_evidence(
        result=selection,
        directive=directive,
        assessment=outcome.assessment,
        activation=activation,
        runtime_entry=entry,
        event_type=event.event_type,
        snapshot_id=snapshot.snapshot_id,
        state_version=snapshot.state_version,
    )
    _same(rebuilt.model_dump(mode="json"), supplied.model_dump(mode="json"))
    store.recheck_reads()
    return rebuilt
