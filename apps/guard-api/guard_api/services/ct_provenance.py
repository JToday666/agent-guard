"""Materialize committed CT facts as strict, browser-safe provenance."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from agentguard_core import AuditEvent, ProvenanceEdge, ProvenanceNode
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.signals.models import EvidenceRef, FactAuthority, TaintLabel

from guard_api.storage.base import ControlPlaneStore, ProvenanceConflictError

from .ct_projection import CtEnvelopeDecodeResult, decode_ct_transient_facts

logger = logging.getLogger(__name__)

CT_PROVENANCE_CONTRACT = "ct-provenance/1.0"
Coverage = Literal["complete", "partial", "stale", "unknown", "not_applicable"]


class CtNodeRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref_type: Literal["source", "context", "model_input", "memory", "action", "other"]
    ref_id: str = Field(min_length=1, max_length=512)


class _CtNodeMetadataBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: Literal["ct-provenance/1.0"] = CT_PROVENANCE_CONTRACT
    kind: Literal["node"] = "node"
    node_kind: str
    node_ref: CtNodeRef
    taints: list[TaintLabel] = Field(max_length=32)
    coverage: Coverage
    evidence_refs: list[EvidenceRef] = Field(min_length=1, max_length=32)


class CtSourceNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["source"] = "source"
    source_type: Literal[
        "user",
        "web",
        "email",
        "tool_result",
        "mcp",
        "rag",
        "memory",
        "file",
        "model",
        "runtime",
        "other",
    ]
    trust: Literal["trusted", "untrusted", "unknown"]
    verification_state: Literal["verified", "unverified", "not_applicable"]
    fact_authority: FactAuthority


class CtContextNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["context"] = "context"
    scope_digest: str = Field(min_length=1, max_length=256)
    manifest_event_id: str | None = Field(default=None, max_length=256)


class CtModelInputNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["model_input"] = "model_input"
    event_id: str = Field(min_length=1, max_length=256)
    context_ref: str = Field(min_length=1, max_length=512)
    model_call_ref: str | None = Field(default=None, max_length=512)


class CtMemoryNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["memory"] = "memory"
    memory_ref: str = Field(min_length=1, max_length=512)
    trust: Literal["trusted", "untrusted", "unknown"]
    fact_authority: FactAuthority


class CtActionNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["action"] = "action"
    action_id: str = Field(min_length=1, max_length=256)


class CtOtherNodeMetadata(_CtNodeMetadataBase):
    node_kind: Literal["other"] = "other"
    coverage: Literal["unknown", "not_applicable"]


CtNodeMetadata = Annotated[
    Union[
        CtSourceNodeMetadata,
        CtContextNodeMetadata,
        CtModelInputNodeMetadata,
        CtMemoryNodeMetadata,
        CtActionNodeMetadata,
        CtOtherNodeMetadata,
    ],
    Field(discriminator="node_kind"),
]
_NODE_METADATA_ADAPTER = TypeAdapter(CtNodeMetadata)


class CtEdgeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract: Literal["ct-provenance/1.0"] = CT_PROVENANCE_CONTRACT
    kind: Literal["edge"] = "edge"
    flow_id: str = Field(min_length=1, max_length=512)
    flow_relation: Literal[
        "received_from",
        "read_from",
        "derived_from",
        "assembled_into",
        "influenced_by",
        "returned_by",
        "written_to",
        "persisted_to",
        "loaded_from_memory",
        "sent_to",
    ]
    source_ref: str = Field(min_length=1, max_length=512)
    target_ref: str = Field(min_length=1, max_length=512)
    flow_strength: Literal["exact", "strong", "possible"]
    flow_origin: Literal["observed", "deterministic", "semantic_inferred"]
    coverage: Coverage
    evidence_refs: list[EvidenceRef] = Field(min_length=1, max_length=32)


@dataclass(frozen=True, slots=True)
class CtProvenanceWriteOutcome:
    status: Literal["absent", "written", "skipped", "degraded"]
    node_count: int = 0
    edge_count: int = 0
    reason_codes: tuple[str, ...] = ()


class CtProvenanceWriter:
    """Write CT facts after legacy provenance, without changing wire schemas."""

    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def record_policy_evaluation(self, audit: AuditEvent) -> CtProvenanceWriteOutcome:
        decoded = decode_ct_transient_facts(audit)
        if decoded.kind == "absent":
            return CtProvenanceWriteOutcome(status="absent")
        if decoded.kind != "full":
            return CtProvenanceWriteOutcome(
                status="skipped", reason_codes=decoded.issues or (decoded.kind,)
            )
        try:
            nodes, edges = _materialize(audit, decoded)
        except Exception:  # noqa: BLE001 - malformed committed evidence is contained.
            logger.warning(
                "ct provenance materialization rejected for audit %s",
                audit.audit_id,
                exc_info=True,
            )
            return CtProvenanceWriteOutcome(
                status="degraded",
                reason_codes=("ct-provenance:materialization_invalid",),
            )
        try:
            written_nodes, written_edges = self.store.write_ct_provenance_batch(
                nodes, edges
            )
        except ProvenanceConflictError:
            logger.warning(
                "ct provenance batch conflicted for audit %s; legacy evidence retained",
                audit.audit_id,
                exc_info=True,
            )
            return CtProvenanceWriteOutcome(
                status="degraded",
                reason_codes=("ct-provenance:flow_or_identity_conflict",),
            )
        return CtProvenanceWriteOutcome(
            status="written",
            node_count=len(written_nodes),
            edge_count=len(written_edges),
        )


def _materialize(
    audit: AuditEvent, decoded: CtEnvelopeDecodeResult
) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]:
    assert decoded.bundle is not None
    bundle = decoded.bundle
    if not isinstance(audit.evidence, dict):
        raise ValueError("full CT envelope requires audit evidence")
    envelope = audit.evidence.get("ct_transient_facts")
    if not isinstance(envelope, dict):
        raise ValueError("full CT envelope is missing from audit evidence")
    evidence_ref = EvidenceRef(
        ref_id=f"ct-envelope:{audit.audit_id}",
        kind="audit_event",
        record_type="policy_evaluation",
        record_id=audit.audit_id,
        json_pointer="/evidence/ct_transient_facts",
        digest=canonical_sha256(envelope),
        redaction_state="summary_only",
    )
    partial = bool(bundle.degradations) or decoded.projection_eligible is False
    base_coverage: Coverage = "partial" if partial else "complete"

    node_kind_by_ref: dict[str, str] = {}
    node_payload_by_ref: dict[str, dict[str, object]] = {}
    node_taints: dict[str, set[str]] = {}

    for fact in bundle.source_facts:
        node_kind_by_ref[fact.source_id] = "source"
        node_payload_by_ref[fact.source_id] = {
            "source_type": fact.source_type,
            "trust": fact.trust,
            "verification_state": fact.verification_state,
            "fact_authority": fact.authority,
        }
        node_taints[fact.source_id] = set(fact.taints)
    for fact in bundle.memory_facts:
        ref = f"memory:{fact.memory_id}"
        node_kind_by_ref[ref] = "memory"
        node_payload_by_ref[ref] = {
            "memory_ref": ref,
            "trust": (
                "untrusted"
                if fact.trust_state in {"tainted", "quarantined"}
                else "unknown"
            ),
            # MemoryFact has no authority field.  Use the conservative floor;
            # never upgrade a persisted memory claim to authoritative here.
            "fact_authority": "untrusted_claim",
        }
        node_taints[ref] = set(fact.taints)
    if bundle.current_action is not None:
        ref = f"action:{bundle.current_action.action_id}"
        node_kind_by_ref[ref] = "action"
        node_payload_by_ref[ref] = {"action_id": bundle.current_action.action_id}
        node_taints[ref] = set()

    for flow in bundle.flow_facts:
        for ref in (flow.source_ref, flow.target_ref):
            if ref not in node_kind_by_ref:
                if ref.startswith("context:"):
                    node_kind_by_ref[ref] = "context"
                    node_payload_by_ref[ref] = {
                        "scope_digest": bundle.scope_digest,
                        "manifest_event_id": None,
                    }
                elif ref.startswith("action:"):
                    node_kind_by_ref[ref] = "action"
                    node_payload_by_ref[ref] = {
                        "action_id": ref.removeprefix("action:")
                    }
                else:
                    node_kind_by_ref[ref] = "other"
                    node_payload_by_ref[ref] = {}
                node_taints[ref] = set()
            node_taints[ref].update(str(item) for item in flow.taints)

    nodes: list[ProvenanceNode] = []
    node_id_by_ref: dict[str, str] = {}
    for ref in sorted(node_kind_by_ref):
        node_kind = node_kind_by_ref[ref]
        coverage: Coverage = "unknown" if node_kind == "other" else base_coverage
        metadata = _NODE_METADATA_ADAPTER.validate_python(
            {
                "contract": CT_PROVENANCE_CONTRACT,
                "kind": "node",
                "node_kind": node_kind,
                "node_ref": {"ref_type": node_kind, "ref_id": ref},
                "taints": sorted(node_taints[ref]),
                "coverage": coverage,
                "evidence_refs": [evidence_ref.model_dump(mode="json")],
                **node_payload_by_ref[ref],
            }
        )
        node_ref = metadata.node_ref.model_dump(mode="json")
        node_id = "ctnode:" + canonical_sha256(
            {"trace_id": audit.trace_id, "node_ref": node_ref}
        )
        node_id_by_ref[ref] = node_id
        nodes.append(
            ProvenanceNode(
                node_id=node_id,
                trace_id=audit.trace_id,
                kind=node_kind,
                ref_id=ref,
                label=_node_label(node_kind, node_payload_by_ref[ref]),
                timestamp=audit.timestamp,
                metadata=metadata.model_dump(mode="json"),
            )
        )

    edges: list[ProvenanceEdge] = []
    for flow in sorted(bundle.flow_facts, key=lambda item: item.flow_id):
        endpoint_unknown = any(
            node_kind_by_ref[ref] == "other"
            for ref in (flow.source_ref, flow.target_ref)
        )
        edge_metadata = CtEdgeMetadata.model_validate(
            {
                "flow_id": flow.flow_id,
                "flow_relation": flow.relation,
                "source_ref": flow.source_ref,
                "target_ref": flow.target_ref,
                "flow_strength": flow.strength,
                "flow_origin": flow.origin,
                "coverage": "unknown" if endpoint_unknown else base_coverage,
                "evidence_refs": [evidence_ref.model_dump(mode="json")],
            }
        )
        edge_id = "ctedge:" + canonical_sha256(
            {
                "trace_id": audit.trace_id,
                "flow_id": flow.flow_id,
                "source_ref": flow.source_ref,
                "target_ref": flow.target_ref,
                "flow_relation": flow.relation,
            }
        )
        edges.append(
            ProvenanceEdge(
                edge_id=edge_id,
                trace_id=audit.trace_id,
                source_node_id=node_id_by_ref[flow.source_ref],
                target_node_id=node_id_by_ref[flow.target_ref],
                relation=flow.relation,
                timestamp=audit.timestamp,
                metadata=edge_metadata.model_dump(mode="json"),
            )
        )
    return nodes, edges


def _node_label(kind: str, payload: dict[str, object]) -> str:
    if kind == "source":
        return f"source · {payload.get('source_type', 'other')}"
    if kind == "action":
        return "guarded action"
    if kind == "memory":
        return "memory fact"
    if kind == "context":
        return "assembled context"
    if kind == "model_input":
        return "model input"
    return "unresolved reference"


__all__ = [
    "CT_PROVENANCE_CONTRACT",
    "CtEdgeMetadata",
    "CtNodeMetadata",
    "CtProvenanceWriteOutcome",
    "CtProvenanceWriter",
]
