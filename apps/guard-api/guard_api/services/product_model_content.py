"""Server-only commitments for generated Product arguments; never a trust grant.

Only hashes and references are persisted. Actual arguments are compared with the
commitment made while the complete model output was evaluated. A recorded pair
of model receipts and the original, server-validated ACK issuance remain required.
"""

from __future__ import annotations

from datetime import datetime
import json
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from agentguard_core import (
    AuditEvent,
    GuardEvent,
    ModelCallPayload,
    RuntimeOutcomeReceipt,
)
from agentguard_core.actions import canonical_action_id
from agentguard_core.actions.canonical_json import canonical_json, canonical_sha256
from agentguard_core.actions.product_tools import VerifiedProductTool
from agentguard_core.decisions.product import ProductDecisionAuthorityEvidenceV1
from agentguard_core.security_context import SecuritySnapshot
from agentguard_core.security_context.product_data import (
    DataContentBinding,
    VerifiedProductData,
)
from agentguard_core.signals.models import TaintLabel
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.storage.base import AuditWindowQuery, ControlPlaneStore
from .competition import parse_decision_authority_evidence_payload

CONTENT_KEY = "product_model_content"
ACK_VALIDATION_KEY = "product_ack_validation"
_DIGEST = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
_SCOPE = Annotated[str, StringConstraints(pattern=r"^(?:hmac-)?sha256:[0-9a-f]{64}$")]
_REF = Annotated[
    str, StringConstraints(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f]+$")
]
_MAX_CONTENT_BYTES = 64 * 1024


class ProductModelContentUnavailable(ValueError):
    code = "V21_PRODUCT_MODEL_CONTENT_UNAVAILABLE"

    def __init__(self) -> None:
        super().__init__(self.code)


def _require(condition: object) -> None:
    if not condition:
        raise ProductModelContentUnavailable()


class ModelContentCommitment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    schema_version: Literal["1.0"] = "1.0"
    runtime: Literal["langgraph", "openclaw"]
    agent_id: _REF
    runtime_binding_id: _REF
    scope_digest: _SCOPE
    task_id: _REF
    task_revision: int = Field(ge=0, strict=True)
    trace_id: _REF
    model_input_event_id: _REF
    model_input_audit_id: _REF
    model_input_decision_id: _REF
    model_output_event_id: _REF
    model_output_digest: _DIGEST
    model_output_authority_digest: _DIGEST
    profile_id: _REF
    profile_digest: _DIGEST
    activation_ref_digest: _DIGEST
    tool_name: _REF
    call_id: _REF
    tool_descriptor_digest: _DIGEST
    input_schema_digest: _DIGEST
    inventory_digest: _DIGEST
    semantics_digest: _DIGEST
    original_arguments_digest: _DIGEST
    field_digests: dict[str, _DIGEST] = Field(min_length=1, max_length=256)
    visible_source_refs: tuple[_REF, ...] = Field(min_length=1, max_length=256)
    commitment_digest: str = ""

    @model_validator(mode="after")
    def _validate_digest(self) -> ModelContentCommitment:
        _require(len(set(self.visible_source_refs)) == len(self.visible_source_refs))
        _require(all(pointer.startswith("/") for pointer in self.field_digests))
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"commitment_digest"})
        )
        _require(not self.commitment_digest or self.commitment_digest == expected)
        object.__setattr__(self, "commitment_digest", expected)
        _require(
            len(canonical_json(self.model_dump(mode="json")).encode()) <= 24 * 1024
        )
        return self


def read_product_model_content(value: object) -> ModelContentCommitment:
    try:
        _require(type(value) is dict and bool(value.get("commitment_digest")))
        return ModelContentCommitment.model_validate(value)
    except Exception:
        raise ProductModelContentUnavailable() from None


def _leaves(value: object, pointer: str = "") -> dict[str, str]:
    if type(value) is dict:
        _require(bool(value))
        result: dict[str, str] = {}
        for key, child in value.items():
            _require(type(key) is str)
            escaped = key.replace("~", "~0").replace("/", "~1")
            result.update(_leaves(child, pointer + "/" + escaped))
        return result
    if type(value) is list:
        _require(bool(value))
        result = {}
        for index, child in enumerate(value):
            result.update(_leaves(child, pointer + "/" + str(index)))
        return result
    _require(bool(pointer) and (value is None or type(value) in {str, int, bool}))
    return {pointer: canonical_sha256(value)}


def _authority(
    audit: AuditEvent,
    event_type: str,
    *,
    require_allow: bool = True,
    require_unfloored: bool = True,
) -> ProductDecisionAuthorityEvidenceV1:
    _require(
        audit.record_type == "policy_evaluation" and audit.event_type == event_type
    )
    evidence = parse_decision_authority_evidence_payload(
        {"decision_authority": (audit.evidence or {}).get("decision_authority")}
    )
    _require(isinstance(evidence, ProductDecisionAuthorityEvidenceV1))
    assert isinstance(evidence, ProductDecisionAuthorityEvidenceV1)
    _require(
        evidence.event_type == event_type
        and evidence.event_id == audit.links.get("event_id")
    )
    _require(
        evidence.runtime == audit.runtime
        and evidence.selected_decision.decision == audit.decision
    )
    _require(not require_allow or audit.decision == "allow")
    _require(evidence.selected_decision.decision_id == audit.links.get("decision_id"))
    _require(
        not require_unfloored
        or evidence.decision_authority.legacy_floor_applied is False
    )
    _require(
        (audit.model_extra or {}).get("decision_authority")
        == evidence.decision_authority.model_dump(mode="json")
    )
    _require(
        (audit.evidence or {}).get("guard_decision")
        == evidence.selected_decision.model_dump(mode="json")
    )
    return evidence


def _same_parent(
    audit: AuditEvent,
    authority: ProductDecisionAuthorityEvidenceV1,
    event: GuardEvent,
    snapshot: SecuritySnapshot,
) -> None:
    task = snapshot.task
    _require(task is not None and task.status == "active")
    assert task is not None
    _require(audit.trace_id == event.trace_id == snapshot.scope.trace_id)
    _require(audit.runtime == event.runtime == snapshot.scope.runtime)
    _require(audit.metadata.get("agent_id") == event.security_context.agent_id)
    _require(
        audit.metadata.get("task_id") == task.task_id == event.metadata.get("task_id")
    )
    _require(
        authority.approval_release_directive.scope_digest
        == snapshot.scope.scope_digest
        == task.scope_digest
    )
    _require(task.principal_id == snapshot.scope.principal_id)
    # The actual TaskFact revision is committed below; stale source outputs do
    # not gain authority merely because the task retained the same identifier.
    _require(
        audit.metadata.get("product_model_task")
        == {
            "task_id": task.task_id,
            "task_revision": task.revision,
            "task_digest": task.task_digest,
            "scope_digest": task.scope_digest,
        }
    )


def build_product_model_content(
    store: ControlPlaneStore,
    event: GuardEvent,
    *,
    snapshot: SecuritySnapshot,
    catalog: Any,
    activation: Any,
    decision_authority_evidence: dict[str, object],
) -> ModelContentCommitment | None:
    """Compile hashes during the original complete output evaluation only."""
    try:
        _require(
            event.event_type == "model_output_produced"
            and isinstance(event.payload, ModelCallPayload)
        )
        assert isinstance(event.payload, ModelCallPayload)
        text = event.payload.content_preview
        _require(type(text) is str and len(text.encode("utf-8")) <= _MAX_CONTENT_BYTES)
        projection: dict[str, Any] = json.loads(text)
        _require(
            type(projection) is dict
            and set(projection) == {"content", "tool_calls", "invalid_tool_calls"}
        )
        _require(canonical_json(projection) == text)
        _require(
            type(projection["tool_calls"]) is list
            and projection["invalid_tool_calls"] == []
        )
        if not projection["tool_calls"]:
            return None
        _require(len(projection["tool_calls"]) == 1)
        call = cast(dict[str, Any], projection["tool_calls"][0])
        _require(
            type(call) is dict
            and set(call) == {"name", "id", "args", "type"}
            and call["type"] == "tool_call"
        )
        _require(type(call["args"]) is dict)
        fields = _leaves(call["args"])
        parent_id = event.metadata.get("product_model_input_audit_id")
        _require(type(parent_id) is str)
        assert isinstance(parent_id, str)
        parent = store.get_audit_event(parent_id)
        _require(parent is not None)
        assert parent is not None
        input_authority = _authority(parent, "model_input_prepared")
        _same_parent(parent, input_authority, event, snapshot)
        authority = parse_decision_authority_evidence_payload(
            decision_authority_evidence
        )
        _require(isinstance(authority, ProductDecisionAuthorityEvidenceV1))
        assert isinstance(authority, ProductDecisionAuthorityEvidenceV1)
        _require(
            authority.event_id == event.event_id
            and authority.event_type == event.event_type
            and authority.runtime == event.runtime
        )
        _require(
            authority.selected_decision.decision == "allow"
            and authority.decision_authority.legacy_floor_applied is False
        )
        _require(
            authority.profile_digest == input_authority.profile_digest
            and authority.profile_id == input_authority.profile_id
        )
        _require(
            authority.decision_authority.activation_ref_digest
            == input_authority.decision_authority.activation_ref_digest
        )
        _require(
            authority.approval_release_directive.scope_digest
            == snapshot.scope.scope_digest
        )
        visible = tuple(
            sorted(
                {
                    flow.source_ref
                    for flow in snapshot.flows
                    if flow.target_ref == f"model_input:{input_authority.event_id}"
                    and flow.relation in {"assembled_into", "loaded_from_memory"}
                    and flow.strength == "exact"
                    and flow.origin == "observed"
                }
            )
        )
        _require(
            visible
            and set(event.security_context.visible_source_refs or ()) == set(visible)
        )
        identities = catalog.describe_tool(
            event.runtime,
            call["name"],
            activation=activation,
            runtime_binding_id=snapshot.scope.runtime_binding_id,
        )
        task = snapshot.task
        assert task is not None
        return ModelContentCommitment(
            runtime=cast(Literal["langgraph", "openclaw"], event.runtime),
            agent_id=event.security_context.agent_id,
            runtime_binding_id=snapshot.scope.runtime_binding_id,
            scope_digest=snapshot.scope.scope_digest,
            task_id=task.task_id,
            task_revision=task.revision,
            trace_id=event.trace_id,
            model_input_event_id=input_authority.event_id,
            model_input_audit_id=parent.audit_id,
            model_input_decision_id=input_authority.selected_decision.decision_id,
            model_output_event_id=event.event_id,
            model_output_digest=canonical_sha256(projection),
            model_output_authority_digest=canonical_sha256(
                authority.model_dump(mode="json")
            ),
            profile_id=authority.profile_id,
            profile_digest=authority.profile_digest,
            activation_ref_digest=authority.decision_authority.activation_ref_digest,
            tool_name=call["name"],
            call_id=call["id"],
            tool_descriptor_digest=identities["descriptor_digest"],
            input_schema_digest=identities["input_schema_digest"],
            inventory_digest=identities["inventory_digest"],
            semantics_digest=identities["semantics_digest"],
            original_arguments_digest=canonical_sha256(call["args"]),
            field_digests=fields,
            visible_source_refs=visible,
        )
    except Exception:
        raise ProductModelContentUnavailable() from None


def build_product_ack_validation(
    receipt: RuntimeOutcomeReceipt, parent: AuditEvent
) -> dict[str, str]:
    """Called only after AuditService has cryptographically verified this ACK."""
    try:
        ack = receipt.metadata.activation_ack
        _require(ack is not None)
        assert ack is not None
        authority = parse_decision_authority_evidence_payload(
            {"decision_authority": (parent.evidence or {}).get("decision_authority")}
        )
        _require(isinstance(authority, ProductDecisionAuthorityEvidenceV1))
        return {
            "schema_version": "1.0",
            "token_digest": activation_ack_token_digest(ack.ack_token),
            "public_claims_digest": canonical_sha256(ack.token_projection()),
            "parent_authority_digest": canonical_sha256(
                authority.model_dump(mode="json")
            ),
        }
    except Exception:
        raise ProductModelContentUnavailable() from None


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None)
    return parsed


def _receipt(
    store: ControlPlaneStore,
    parent: AuditEvent,
    authority: ProductDecisionAuthorityEvidenceV1,
    snapshot: SecuritySnapshot,
) -> AuditEvent:
    receipt = store.get_audit_event(
        f"audit_outcome_{authority.event_id}_execution_completed"
    )
    _require(receipt is not None and receipt.record_type == "runtime_outcome")
    assert receipt is not None
    stamp = receipt.metadata.get(ACK_VALIDATION_KEY)
    _require(
        type(stamp) is dict
        and set(stamp)
        == {
            "schema_version",
            "token_digest",
            "public_claims_digest",
            "parent_authority_digest",
        }
    )
    stamp = cast(dict[str, Any], stamp)
    _require(
        stamp["schema_version"] == "1.0"
        and stamp["parent_authority_digest"]
        == canonical_sha256(authority.model_dump(mode="json"))
    )
    issuance = store.get_product_activation_ack(stamp["token_digest"])
    _require(issuance is not None)
    assert issuance is not None
    ack = issuance.unsigned_ack()
    _require(stamp["public_claims_digest"] == canonical_sha256(issuance.ack_projection))
    public = dict(receipt.metadata.get("activation_ack", {}))
    public.pop("ack_token", None)
    _require(public == issuance.ack_projection)
    anchor = _time(cast(str, parent.metadata["product_authority_initial_checked_at"]))
    _require(_time(ack.issued_at) <= anchor < _time(ack.expires_at))
    _require(issuance.revoked_at is None or anchor < _time(issuance.revoked_at))
    _require(issuance.principal_id == snapshot.scope.principal_id)
    _require(
        ack.runtime == parent.runtime
        and ack.agent_id == parent.metadata.get("agent_id")
    )
    _require(
        ack.runtime_binding_id == snapshot.scope.runtime_binding_id
        and ack.profile_id == authority.profile_id
    )
    _require(
        ack.activation_ref_digest == authority.decision_authority.activation_ref_digest
        and ack.capability_digest
        == authority.approval_release_directive.capability_digest
    )
    wire = receipt.model_dump(mode="json")
    wire.pop("integrity", None)  # Server audit-chain wrapper, not receipt wire.
    wire["metadata"].pop(ACK_VALIDATION_KEY)
    wire["metadata"]["activation_ack"] = ack.model_dump(mode="json")
    strict = RuntimeOutcomeReceipt.model_validate(wire)
    _require(strict.trace_id == parent.trace_id and strict.runtime == parent.runtime)
    _require(
        strict.links.event_id == authority.event_id
        and strict.links.policy_audit_id == parent.audit_id
        and strict.links.decision_id == parent.links.get("decision_id")
    )
    _require(
        strict.links.action_id == parent.links.get("action_id")
        and strict.links.approval_id is None
    )
    _require(strict.decision == parent.decision == "allow" and strict.blocked is False)
    _require(
        strict.evidence.execution.status == "executed"
        and strict.evidence.result.disposition == "passed_through"
    )
    return receipt


def _committed_artifacts(
    store: ControlPlaneStore,
    event: GuardEvent,
    snapshot: SecuritySnapshot,
) -> tuple[set[str], set[str], set[str]]:
    """Resolve identities from bounded immutable, same-scope CT policy records.

    A runtime supplied reference, including a cyclic chain of references, is
    never an identity declaration. Only a typed original policy's own event or
    action identity and its complete server CT bundle can declare an artifact.
    """
    from .ct_projection import decode_ct_transient_facts

    records = store.read_audit_events_bounded(
        AuditWindowQuery(
            record_type="policy_evaluation",
            trace_id=event.trace_id,
            runtime=event.runtime,
            limit=257,
        )
    )
    _require(len(records) <= 256)
    artifacts: set[str] = set()
    flows: set[str] = set()
    sources: set[str] = set()
    for record in records:
        decoded = decode_ct_transient_facts(record)
        if decoded.kind == "absent":
            continue
        _require(decoded.kind == "full" and decoded.bundle is not None)
        bundle = decoded.bundle
        assert bundle is not None
        _require(bundle.scope_digest == snapshot.scope.scope_digest)
        authority = _authority(
            record,
            record.event_type,
            require_allow=False,
            require_unfloored=record.event_type
            in {"model_input_prepared", "model_output_produced"},
        )
        _same_parent(record, authority, event, snapshot)
        _require(bundle.event_id == authority.event_id)
        prefix = {
            "model_input_prepared": "model_input",
            "model_output_produced": "model_output",
            "context_assembled": "context",
            "tool_result_produced": "context",
        }.get(record.event_type)
        if prefix is not None:
            artifacts.add(f"{prefix}:{authority.event_id}")
        action_id = record.links.get("action_id")
        if action_id:
            artifacts.add(f"action:{action_id}")
        for flow in bundle.flow_facts:
            _require(
                flow.scope_digest == snapshot.scope.scope_digest and bool(flow.producer)
            )
            flows.add(canonical_sha256(flow.model_dump(mode="json")))
            if (
                record.event_type == "model_output_produced"
                and flow.source_ref.startswith("credential:")
                and flow.target_ref == f"model_output:{authority.event_id}"
                and flow.relation == "derived_from"
                and flow.strength == "exact"
                and flow.origin == "deterministic"
                and {"CREDENTIAL", "SENSITIVE"} <= set(flow.taints)
            ):
                artifacts.add(flow.source_ref)
        sources.update(
            canonical_sha256(source.model_dump(mode="json"))
            for source in bundle.source_facts
        )
    return artifacts, flows, sources


def _verified_model_ancestors(
    store: ControlPlaneStore,
    ref: str,
    event: GuardEvent,
    snapshot: SecuritySnapshot,
) -> tuple[str, ...]:
    """Recognize a previous model identity only through its full accepted chain."""
    prefix = "source:model:"
    _require(ref.startswith(prefix))
    parent = store.get_policy_evaluation_by_event_id(ref[len(prefix) :])
    _require(parent is not None)
    assert parent is not None
    authority = _authority(parent, "model_output_produced")
    _same_parent(parent, authority, event, snapshot)
    commitment = read_product_model_content((parent.evidence or {}).get(CONTENT_KEY))
    task = snapshot.task
    assert task is not None
    _require(
        ref == f"source:model:{authority.event_id}"
        and commitment.model_output_event_id == authority.event_id
        and commitment.model_output_authority_digest
        == canonical_sha256(authority.model_dump(mode="json"))
        and commitment.runtime == event.runtime
        and commitment.runtime_binding_id == snapshot.scope.runtime_binding_id
        and commitment.agent_id == event.security_context.agent_id
        and commitment.scope_digest == snapshot.scope.scope_digest
        and commitment.task_id == task.task_id
        and commitment.task_revision == task.revision
        and commitment.trace_id == event.trace_id
        and commitment.profile_id == authority.profile_id
        and commitment.profile_digest == authority.profile_digest
        and commitment.activation_ref_digest
        == authority.decision_authority.activation_ref_digest
    )
    model_input = store.get_audit_event(commitment.model_input_audit_id)
    _require(model_input is not None)
    assert model_input is not None
    input_authority = _authority(model_input, "model_input_prepared")
    _same_parent(model_input, input_authority, event, snapshot)
    _require(
        input_authority.event_id == commitment.model_input_event_id
        and input_authority.selected_decision.decision_id
        == commitment.model_input_decision_id
        and input_authority.profile_id == authority.profile_id
        and input_authority.profile_digest == authority.profile_digest
        and input_authority.decision_authority.activation_ref_digest
        == commitment.activation_ref_digest
    )
    _receipt(store, parent, authority, snapshot)
    _receipt(store, model_input, input_authority, snapshot)
    return (
        f"model_output:{authority.event_id}",
        f"model_input:{input_authority.event_id}",
        *commitment.visible_source_refs,
    )


def verify_product_model_content(
    store: ControlPlaneStore,
    event: GuardEvent,
    snapshot: SecuritySnapshot,
    product_tool: VerifiedProductTool,
    *,
    transient_facts: object = None,
) -> VerifiedProductData:
    """Verify complete, original model data without accepting runtime claims."""
    del transient_facts  # Historical original-output facts must already be committed.
    try:
        _require(
            event.security_context.source_type == "model"
            and event.security_context.source_trust == "unknown"
        )
        origin = event.metadata.get("product_model_content")
        _require(
            type(origin) is dict
            and set(origin) == {"model_output_audit_id", "model_source_ref", "call_id"}
        )
        origin = cast(dict[str, Any], origin)
        product_tool.assert_matches(
            event, runtime_binding_id=snapshot.scope.runtime_binding_id
        )
        parent = store.get_audit_event(origin["model_output_audit_id"])
        _require(parent is not None)
        assert parent is not None
        authority = _authority(parent, "model_output_produced")
        _same_parent(parent, authority, event, snapshot)
        commitment = read_product_model_content(
            (parent.evidence or {}).get(CONTENT_KEY)
        )
        _require(
            commitment.model_output_authority_digest
            == canonical_sha256(authority.model_dump(mode="json"))
        )
        task = snapshot.task
        assert task is not None
        _require(
            commitment.runtime == event.runtime == product_tool.runtime
            and commitment.agent_id == event.security_context.agent_id
        )
        _require(
            commitment.runtime_binding_id
            == snapshot.scope.runtime_binding_id
            == product_tool.runtime_binding_id
        )
        _require(
            commitment.scope_digest == snapshot.scope.scope_digest
            and commitment.task_id == task.task_id
            and commitment.task_revision == task.revision
            and commitment.trace_id == event.trace_id
        )
        _require(
            commitment.model_output_event_id == authority.event_id
            and commitment.profile_digest == authority.profile_digest
            and commitment.profile_id == authority.profile_id
        )
        _require(
            commitment.activation_ref_digest
            == authority.decision_authority.activation_ref_digest
        )
        source_ref = f"source:model:{authority.event_id}"
        _require(
            origin["model_source_ref"] == source_ref
            and origin["call_id"] == commitment.call_id == product_tool.call_id
        )
        _require(
            commitment.tool_name == product_tool.tool_name
            and commitment.tool_descriptor_digest == product_tool.descriptor_digest
            and commitment.input_schema_digest == product_tool.input_schema_digest
            and commitment.inventory_digest == product_tool.inventory_digest
            and commitment.semantics_digest == product_tool.semantics_digest
        )
        arguments = product_tool.arguments()
        fields = _leaves(arguments)
        _require(
            commitment.original_arguments_digest
            == product_tool.original_arguments_digest
            == canonical_sha256(arguments)
        )
        _require(
            fields == commitment.field_digests
            and set(fields) == set(product_tool.required_argument_pointers())
        )
        expected_refs = {source_ref, *commitment.visible_source_refs}
        _require(set(event.security_context.visible_source_refs or ()) == expected_refs)
        model_input = store.get_audit_event(commitment.model_input_audit_id)
        _require(model_input is not None)
        assert model_input is not None
        input_authority = _authority(model_input, "model_input_prepared")
        _same_parent(model_input, input_authority, event, snapshot)
        _require(
            input_authority.event_id == commitment.model_input_event_id
            and input_authority.selected_decision.decision_id
            == commitment.model_input_decision_id
        )
        _require(
            input_authority.profile_digest == authority.profile_digest
            and input_authority.decision_authority.activation_ref_digest
            == authority.decision_authority.activation_ref_digest
        )
        output_receipt = _receipt(store, parent, authority, snapshot)
        input_receipt = _receipt(store, model_input, input_authority, snapshot)
        sources = {fact.source_id: fact for fact in snapshot.sources}
        _require(len(sources) == len(snapshot.sources))
        model_source = sources.get(source_ref)
        _require(
            model_source is not None
            and model_source.source_type == "model"
            and model_source.trust == "unknown"
            and model_source.authority == "model_judgment"
            and bool(model_source.producer)
        )
        artifacts, committed_flows, committed_sources = _committed_artifacts(
            store, event, snapshot
        )
        _require(f"model_output:{authority.event_id}" in artifacts)
        _require(f"model_input:{input_authority.event_id}" in artifacts)
        # Follow every incoming dependency, retaining possible-control taints.
        from agentguard_core.actions.canonical_resources import (
            RESOURCE_NORMALIZERS,
            ResourceNormalizationInput,
        )

        normalized_resources = []
        for resource in product_tool.resource_inputs():
            kind = resource["kind"]
            _require(kind in RESOURCE_NORMALIZERS)
            normalized = RESOURCE_NORMALIZERS[kind](
                ResourceNormalizationInput(
                    resource_id="product-resource",
                    target=resource["target"],
                    method=resource.get("method"),
                    memory_namespace=resource.get("memory_namespace"),
                )
            )
            _require(normalized.resolution_status != "unresolved")
            normalized_resources.append((kind, normalized))
        roots = [
            f"model_output:{authority.event_id}",
            f"model_input:{input_authority.event_id}",
            *expected_refs,
        ]
        if product_tool.tool_name == "agentguard_memory_read":
            roots.extend(
                resource.canonical_id
                for kind, resource in normalized_resources
                if kind == "memory"
            )
        pending = [(ref, False) for ref in roots]
        active: set[str] = set()
        visited: set[str] = set()
        source_refs: set[str] = set()
        memory_refs: set[str] = set()
        taints: set[TaintLabel] = set()
        _require(not snapshot.dirty_domains and len(snapshot.flows) <= 4096)
        while pending:
            ref, closing = pending.pop()
            if closing:
                active.remove(ref)
                visited.add(ref)
                continue
            _require(ref not in active)
            if ref in visited:
                continue
            active.add(ref)
            _require(len(visited | active) <= 256)
            pending.append((ref, True))
            source = sources.get(ref)
            if source is not None:
                _require(
                    source.scope_digest == snapshot.scope.scope_digest
                    and bool(source.producer)
                    and canonical_sha256(source.model_dump(mode="json"))
                    in committed_sources
                )
                if source.trust == "unknown" and ref != source_ref:
                    _require(
                        source.source_type == "model"
                        and source.authority == "model_judgment"
                    )
                    pending.extend(
                        (ancestor, False)
                        for ancestor in _verified_model_ancestors(
                            store, ref, event, snapshot
                        )
                    )
                source_refs.add(ref)
                taints.update(source.taints)
            if ref.startswith("memory://"):
                memory = next(
                    (item for item in snapshot.memory_facts if item.memory_id == ref),
                    None,
                )
                _require(memory is not None)
                assert memory is not None
                _require(
                    memory.change_status == "committed"
                    and bool(memory.change_id)
                    and bool(memory.source_refs)
                )
                memory_refs.add(ref)
                taints.update(memory.taints)
                pending.extend((ancestor, False) for ancestor in memory.source_refs)
            elif source is None:
                _require(ref in artifacts)
                if ref.startswith("credential:"):
                    taints.update(("CREDENTIAL", "SENSITIVE"))
            incoming = [flow for flow in snapshot.flows if flow.target_ref == ref]
            if source is None and not ref.startswith(("credential:", "memory://")):
                _require(bool(incoming))
            for flow in incoming:
                _require(
                    flow.scope_digest == snapshot.scope.scope_digest
                    and bool(flow.producer)
                    and canonical_sha256(flow.model_dump(mode="json"))
                    in committed_flows
                )
                taints.update(flow.taints)
                pending.append((flow.source_ref, False))
        _require(expected_refs <= source_refs)
        first_write_memory_ref = None
        artifact_refs = visited - source_refs - memory_refs
        for kind, normalized in normalized_resources:
            if kind == "memory":
                memory_refs.add(normalized.canonical_id)
                if event.event_type == "memory_write_proposed":
                    _require(
                        not any(
                            item.memory_id == normalized.canonical_id
                            for item in snapshot.memory_facts
                        )
                    )
                    first_write_memory_ref = normalized.canonical_id
            else:
                artifact_refs.add(normalized.canonical_id)
        action_id = canonical_action_id(event)
        content_fields = {
            "content",
            "value",
            "message",
            "newText",
            "oldText",
            "command",
        }
        bindings = tuple(
            DataContentBinding(
                source_ref=source_ref,
                source_json_pointer="/tool_calls/0/args" + pointer,
                value_digest=digest,
                action_id=action_id,
                argument_pointer=pointer,
                sink_role=(
                    "content"
                    if pointer.rsplit("/", 1)[-1] in content_fields
                    else "selector"
                ),
                resource_ref=first_write_memory_ref if pointer == "/value" else None,
            )
            for pointer, digest in sorted(fields.items())
        )
        evidence_digest = canonical_sha256(
            {
                "commitment": commitment.model_dump(mode="json"),
                "input_receipt": input_receipt.model_dump(mode="json"),
                "output_receipt": output_receipt.model_dump(mode="json"),
            }
        )
        return VerifiedProductData(
            event_id=event.event_id,
            action_id=action_id,
            runtime=cast(Literal["langgraph", "openclaw"], event.runtime),
            runtime_binding_id=snapshot.scope.runtime_binding_id,
            scope_digest=snapshot.scope.scope_digest,
            task_id=task.task_id,
            task_revision=task.revision,
            tool_name=product_tool.tool_name,
            tool_descriptor_digest=product_tool.descriptor_digest,
            input_schema_digest=product_tool.input_schema_digest,
            semantics_digest=product_tool.semantics_digest,
            argument_digest=product_tool.argument_digest,
            model_source_ref=source_ref,
            model_output_event_id=authority.event_id,
            model_output_audit_id=parent.audit_id,
            model_output_digest=commitment.model_output_digest,
            content_evidence_digest=evidence_digest,
            required_argument_pointers=tuple(sorted(fields)),
            bindings=bindings,
            direct_source_refs=tuple(sorted(expected_refs)),
            source_refs=tuple(sorted(source_refs)),
            first_write_memory_ref=first_write_memory_ref,
            memory_refs=tuple(sorted(memory_refs)),
            artifact_refs=tuple(sorted(artifact_refs)),
            taints=tuple(sorted(taints)),
            hostile_instruction="EXTERNAL_INSTRUCTION" in taints,
            closure_complete=True,
        )
    except Exception:
        raise ProductModelContentUnavailable() from None


def read_product_action_data(audit: AuditEvent) -> VerifiedProductData:
    """Resolve the assessment's logical product_action_data record by event ID."""
    try:
        value = (audit.evidence or {}).get("product_action_data")
        _require(type(value) is dict and bool(value.get("proof_digest")))
        proof = VerifiedProductData.model_validate(value)
        _require(
            proof.event_id == audit.links.get("event_id")
            and proof.action_id == audit.links.get("action_id")
            and proof.runtime == audit.runtime
        )
        _authority(
            audit, audit.event_type, require_allow=False, require_unfloored=False
        )
        envelope = (audit.evidence or {}).get("decision_v21")
        _require(type(envelope) is dict and type(envelope.get("payload")) is dict)
        refs = cast(dict[str, Any], cast(dict[str, Any], envelope)["payload"]).get(
            "evidence_refs"
        )
        _require(type(refs) is list)
        matches = [
            ref
            for ref in cast(list[dict[str, Any]], refs)
            if isinstance(ref, dict) and ref.get("record_type") == "product_action_data"
        ]
        _require(len(matches) == 1)
        ref = matches[0]
        _require(
            ref.get("kind") == "guard_event"
            and ref.get("record_id") == proof.event_id
            and ref.get("json_pointer") == "/evidence/product_action_data"
            and ref.get("digest") == proof.proof_digest
            and ref.get("redaction_state") == "summary_only"
        )
        return proof
    except Exception:
        raise ProductModelContentUnavailable() from None
