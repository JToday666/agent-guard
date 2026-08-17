"""Strict, bounded audit carrier for ephemeral context assembly plans.

The Context Builder plan remains a transient runtime authority.  This module
derives the only persistent display projection allowed by CT-PR-04-M and binds
it to the policy evaluation that produced it.  The projection never contains a
full prompt and is intentionally independent of generic audit redaction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from agentguard_core import (
    AuditEvent,
    AuditIntegrityMetadata,
    ContextBuildPayload,
    ContextSource,
    GuardEvent,
)
from agentguard_core.security_context import (
    ContextAssemblyPlan,
    ContextChunk,
    ContextTransformation,
    compute_context_plan_digest,
)
from agentguard_core.signals.models import EvidenceRef
from pydantic import BaseModel, ConfigDict, Field, model_validator

from guard_api.storage.integrity import canonical_json_bytes, canonical_sha256

from .redaction import MAX_EVIDENCE_BYTES, evidence_serialized_size, scrub_text

CONTEXT_MANIFEST_AUDIT_CONTRACT = "context-manifest-audit/1.0"
CONTEXT_MANIFEST_SCHEMA_VERSION = "1.0"
CONTEXT_MANIFEST_PRODUCER = "guard_api_context_builder"
CONTEXT_MANIFEST_PRODUCER_BINDING_ID = "guard-api:context-builder:1"
CONTEXT_MANIFEST_AUDIT_ID_PREFIX = "audit_context_manifest_"
CONTEXT_MANIFEST_EVENT_TYPE = "context_manifest_recorded"
CONTEXT_MANIFEST_MAX_CHUNKS = 20
CONTEXT_MANIFEST_PREVIEW_LIMIT = 240

_DISPLAY_UNSAFE_PREVIEW_FIELD = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"nonce|"
    r"authorization[ _-]*fingerprint|"
    r"runtime[ _-]*binding[ _-]*id|"
    r"enforcement[ _-]*binding|"
    r"lease[ _-]*token|"
    r"token[ _-]*digest|"
    r"credentials?|passwords?|secrets?|api[ _-]*keys?"
    r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_DISPLAY_UNSAFE_PREVIEW_VALUE = re.compile(
    r"(?<![A-Za-z0-9])(?:hmac-sha256|lease-v1):[0-9a-f]{64}(?![0-9a-f])|"
    r"(?<![A-Za-z0-9_])agt_tok_[0-9a-f]{32}(?![0-9a-f])|"
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)

Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
ScopeDigest = Annotated[str, Field(pattern=r"^(?:sha256|hmac-sha256):[0-9a-f]{64}$")]
ContextManifestAuditId = Annotated[
    str, Field(pattern=r"^audit_context_manifest_[0-9a-f]{64}$")
]
NonEmptyString = Annotated[str, Field(min_length=1, max_length=512)]


class ContextManifestCounts(BaseModel):
    """Global plan counts, including chunks outside the returned window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total: int = Field(ge=0)
    returned: int = Field(ge=0, le=CONTEXT_MANIFEST_MAX_CHUNKS)
    included: int = Field(ge=0)
    excluded: int = Field(ge=0)
    quarantined: int = Field(ge=0)
    sensitive: int = Field(ge=0)
    untrusted: int = Field(ge=0)
    by_source_type: dict[str, int]

    @model_validator(mode="after")
    def validate_counts(self) -> "ContextManifestCounts":
        if self.returned > self.total:
            raise ValueError("returned must not exceed total")
        if self.included + self.excluded != self.total:
            raise ValueError("included + excluded must equal total")
        if self.quarantined > self.excluded:
            raise ValueError("quarantined must be a subset of excluded")
        if self.sensitive > self.total or self.untrusted > self.total:
            raise ValueError("global subset counts must not exceed total")
        if not all(key and value >= 0 for key, value in self.by_source_type.items()):
            raise ValueError("by_source_type must contain non-negative named counts")
        if sum(self.by_source_type.values()) != self.total:
            raise ValueError("by_source_type counts must sum to total")
        return self


class ContextManifestCompleteness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["complete", "partial"]
    truncated: bool
    omitted_digest: Sha256Digest | None

    @model_validator(mode="after")
    def validate_completeness(self) -> "ContextManifestCompleteness":
        if self.truncated:
            if self.status != "partial" or self.omitted_digest is None:
                raise ValueError("truncated manifests require a partial omitted digest")
        elif self.status != "complete" or self.omitted_digest is not None:
            raise ValueError("untruncated manifests must be complete")
        return self


class ContextManifestEnvelope(BaseModel):
    """Strict bounded projection of one verified ContextAssemblyPlan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    plan_id: NonEmptyString
    event_id: NonEmptyString
    scope_digest: ScopeDigest
    runtime: NonEmptyString
    context_ref: NonEmptyString
    plan_digest: Sha256Digest
    manifest_digest: Sha256Digest
    counts: ContextManifestCounts
    chunks: tuple[ContextChunk, ...] = Field(
        default=(), max_length=CONTEXT_MANIFEST_MAX_CHUNKS
    )
    transformations: tuple[ContextTransformation, ...] = Field(
        default=(), max_length=CONTEXT_MANIFEST_MAX_CHUNKS
    )
    excluded_chunk_ids: tuple[str, ...] = Field(
        default=(), max_length=CONTEXT_MANIFEST_MAX_CHUNKS
    )
    reason_codes: tuple[str, ...] = Field(default=(), max_length=64)
    evidence_refs: tuple[EvidenceRef, ...] = Field(default=(), max_length=64)
    completeness: ContextManifestCompleteness

    @model_validator(mode="after")
    def validate_envelope(self) -> "ContextManifestEnvelope":
        if self.counts.returned != len(self.chunks):
            raise ValueError("returned must equal chunks length")
        if self.completeness.truncated != (self.counts.returned < self.counts.total):
            raise ValueError("truncated state must match returned/total")

        chunk_ids = [chunk.chunk_id for chunk in self.chunks]
        if len(chunk_ids) != len(set(chunk_ids)):
            raise ValueError("chunk IDs must be unique")
        if len(self.excluded_chunk_ids) != len(set(self.excluded_chunk_ids)):
            raise ValueError("excluded chunk IDs must be unique")
        expected_excluded = {
            chunk.chunk_id
            for chunk in self.chunks
            if chunk.transform_state in {"quarantined", "excluded"}
        }
        if set(self.excluded_chunk_ids) != expected_excluded:
            raise ValueError("returned excluded_chunk_ids do not match chunks")

        expected_actions = {
            "annotated": "annotate",
            "quarantined": "quarantine",
            "excluded": "exclude",
        }
        transformation_ids: set[str] = set()
        transformed_chunk_ids: set[str] = set()
        chunk_by_id = {chunk.chunk_id: chunk for chunk in self.chunks}
        for transformation in self.transformations:
            if transformation.transformation_id in transformation_ids:
                raise ValueError("transformation IDs must be unique")
            transformation_ids.add(transformation.transformation_id)
            if transformation.chunk_id in transformed_chunk_ids:
                raise ValueError("a returned chunk may have only one transformation")
            transformed_chunk_ids.add(transformation.chunk_id)
            chunk = chunk_by_id.get(transformation.chunk_id)
            if chunk is None:
                raise ValueError("transformations may reference only returned chunks")
            expected_action = expected_actions.get(chunk.transform_state)
            if expected_action is None or transformation.action != expected_action:
                raise ValueError("transformation action does not match chunk state")
            if transformation.input_digest != chunk.content_digest:
                raise ValueError("transformation input digest does not match chunk")
            expected_output = (
                chunk.content_digest if transformation.action == "annotate" else None
            )
            if transformation.output_digest != expected_output:
                raise ValueError("transformation output digest does not match action")
            if (
                transformation.mechanism_id != "ct-context-builder"
                or transformation.mechanism_version != "1.0"
            ):
                raise ValueError("transformation mechanism is not the CT builder")
            if transformation.declassification_id is not None:
                raise ValueError("CT04M does not persist declassification claims")
        expected_transformed = {
            chunk.chunk_id
            for chunk in self.chunks
            if chunk.transform_state != "preserved"
        }
        if transformed_chunk_ids != expected_transformed:
            raise ValueError(
                "every returned transformed chunk needs one transformation"
            )

        for index, chunk in enumerate(self.chunks):
            if chunk.scope_digest != self.scope_digest:
                raise ValueError("chunk scope does not match manifest")
            if chunk.context_ref != self.context_ref:
                raise ValueError("chunk context_ref does not match manifest")
            if chunk.sequence is None or (
                chunk.sequence.domain != "runtime"
                or chunk.sequence.producer_binding_id != f"runtime:{self.runtime}"
                or chunk.sequence.value != index
            ):
                raise ValueError("returned chunk sequence must match plan order")
            if chunk.content_preview is not None:
                if len(chunk.content_preview) > CONTEXT_MANIFEST_PREVIEW_LIMIT:
                    raise ValueError("content preview exceeds the frozen bound")
                if _preview_must_be_empty(chunk):
                    raise ValueError("restricted chunks cannot carry a preview")
                if scrub_text(chunk.content_preview) != chunk.content_preview:
                    raise ValueError("content preview contains credential material")
            if len(chunk.evidence_refs) > 64:
                raise ValueError("chunk evidence refs exceed the typed bound")
            if len(chunk.taints) != len(set(chunk.taints)):
                raise ValueError("chunk taints must not contain duplicates")
            _validate_chunk_security_semantics(chunk)
            _validate_evidence_refs(chunk.evidence_refs)
        for item in self.transformations:
            if len(item.evidence_refs) > 64:
                raise ValueError("transformation evidence refs exceed the typed bound")
            if len(item.reason_codes) != len(set(item.reason_codes)):
                raise ValueError("transformation reasons must not contain duplicates")
            if len(item.reason_codes) > 64 or any(
                not reason for reason in item.reason_codes
            ):
                raise ValueError("transformation reasons exceed the typed bound")
            _validate_evidence_refs(item.evidence_refs)

        if len(self.reason_codes) != len(set(self.reason_codes)) or any(
            not reason for reason in self.reason_codes
        ):
            raise ValueError("reason_codes must not contain duplicates")
        _validate_evidence_refs(self.evidence_refs)
        expected_digest = compute_manifest_digest(self)
        if self.manifest_digest != expected_digest:
            raise ValueError("manifest_digest does not match the canonical envelope")
        return self


class ContextManifestBudgetDroppedRef(BaseModel):
    """The only allowed whole-envelope budget degradation."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    budget_dropped: Literal[True] = Field(alias="_budget_dropped")
    manifest_sha256: Sha256Digest = Field(alias="_manifest_sha256")
    reason: Literal["audit_evidence_budget"]


class ContextManifestLinks(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: NonEmptyString
    plan_id: NonEmptyString
    context_ref: NonEmptyString


class ContextManifestMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["context-manifest-audit/1.0"]
    producer: Literal["guard_api_context_builder"]
    producer_binding_id: Literal["guard-api:context-builder:1"]


class ContextManifestEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    context_manifest: ContextManifestEnvelope | ContextManifestBudgetDroppedRef


class ContextManifestAuditRecord(BaseModel):
    """Strict Audit 0.4 runtime_observation carrier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: ContextManifestAuditId
    schema_version: Literal["0.4"] = "0.4"
    record_type: Literal["runtime_observation"] = "runtime_observation"
    trace_id: NonEmptyString
    case_id: str | None = None
    runtime: NonEmptyString
    timestamp: NonEmptyString
    stage: Literal["context_build"] = "context_build"
    event_type: Literal["context_manifest_recorded"] = CONTEXT_MANIFEST_EVENT_TYPE
    attack_type: None = None
    is_malicious: None = None
    summary: Literal["Bounded context manifest recorded"] = (
        "Bounded context manifest recorded"
    )
    decision: None = None
    risk_score: None = None
    severity: None = None
    blocked: None = None
    resource_targets: tuple[str, ...] = ()
    rule_hits: tuple[str, ...] = ()
    reason: Literal["context_manifest_projection"] = "context_manifest_projection"
    links: ContextManifestLinks
    latency_ms: None = None
    metadata: ContextManifestMetadata
    evidence: ContextManifestEvidence
    integrity: AuditIntegrityMetadata | None = None

    @model_validator(mode="after")
    def validate_record(self) -> "ContextManifestAuditRecord":
        if self.resource_targets or self.rule_hits:
            raise ValueError("context manifest audit lists must remain empty")
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("timestamp must be RFC3339") from None
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone")

        payload = self.evidence.context_manifest
        if isinstance(payload, ContextManifestEnvelope):
            if (
                self.runtime != payload.runtime
                or self.links.event_id != payload.event_id
                or self.links.plan_id != payload.plan_id
                or self.links.context_ref != payload.context_ref
            ):
                raise ValueError("audit links do not match the manifest payload")
            if self.audit_id != derive_context_manifest_audit_id(
                trace_id=self.trace_id,
                event_id=payload.event_id,
                plan_id=payload.plan_id,
                plan_digest=payload.plan_digest,
            ):
                raise ValueError("audit_id does not match the manifest identity")
        return self


class ContextManifestAnchor(BaseModel):
    """Typed policy-Audit link to its immutable manifest record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["context-manifest-audit/1.0"] = CONTEXT_MANIFEST_AUDIT_CONTRACT
    audit_id: ContextManifestAuditId
    event_id: NonEmptyString
    plan_id: NonEmptyString
    plan_digest: Sha256Digest
    context_ref: NonEmptyString
    manifest_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class ContextManifestPrepared:
    """Validated plan paired with its deterministic anchor and Audit record."""

    plan: ContextAssemblyPlan
    anchor: ContextManifestAnchor
    audit_record: ContextManifestAuditRecord


def derive_context_manifest_audit_id(
    *, trace_id: str, event_id: str, plan_id: str, plan_digest: str
) -> str:
    identity_digest = canonical_sha256(
        {
            "trace_id": trace_id,
            "event_id": event_id,
            "plan_id": plan_id,
            "plan_digest": plan_digest,
            "manifest_schema_version": CONTEXT_MANIFEST_SCHEMA_VERSION,
        }
    ).removeprefix("sha256:")
    return CONTEXT_MANIFEST_AUDIT_ID_PREFIX + identity_digest


def compute_manifest_digest(envelope: ContextManifestEnvelope) -> str:
    projection = envelope.model_dump(mode="json")
    projection.pop("manifest_digest", None)
    return canonical_sha256(projection)


def prepare_context_manifest(
    event: GuardEvent,
    plan: ContextAssemblyPlan,
    *,
    max_evidence_bytes: int = MAX_EVIDENCE_BYTES,
) -> ContextManifestPrepared:
    """Strictly bind and bound one ephemeral plan before any audit write."""

    sources = _validate_plan_event_binding(event, plan)
    preview_by_index = [
        _safe_preview(source=source, chunk=chunk)
        for source, chunk in zip(sources, plan.chunks, strict=True)
    ]
    envelope = _build_envelope(plan, preview_by_index=preview_by_index)
    if _manifest_evidence_size(envelope) > max_evidence_bytes:
        envelope = _build_envelope(
            plan,
            preview_by_index=[None] * len(plan.chunks),
        )

    manifest_payload: ContextManifestEnvelope | ContextManifestBudgetDroppedRef
    if _manifest_evidence_size(envelope) <= max_evidence_bytes:
        manifest_payload = envelope
    else:
        manifest_payload = ContextManifestBudgetDroppedRef(
            _budget_dropped=True,
            _manifest_sha256=envelope.manifest_digest,
            reason="audit_evidence_budget",
        )

    audit_id = derive_context_manifest_audit_id(
        trace_id=event.trace_id,
        event_id=plan.event_id,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
    )
    anchor = ContextManifestAnchor(
        audit_id=audit_id,
        event_id=plan.event_id,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        context_ref=plan.context_ref,
        manifest_digest=envelope.manifest_digest,
    )
    record = ContextManifestAuditRecord(
        audit_id=audit_id,
        trace_id=event.trace_id,
        case_id=event.case_id,
        runtime=event.runtime,
        timestamp=event.timestamp,
        links=ContextManifestLinks(
            event_id=plan.event_id,
            plan_id=plan.plan_id,
            context_ref=plan.context_ref,
        ),
        metadata=ContextManifestMetadata(
            contract=CONTEXT_MANIFEST_AUDIT_CONTRACT,
            producer=CONTEXT_MANIFEST_PRODUCER,
            producer_binding_id=CONTEXT_MANIFEST_PRODUCER_BINDING_ID,
        ),
        evidence=ContextManifestEvidence(context_manifest=manifest_payload),
    )
    # Defense in depth: a full strict round trip catches aliases and defaults.
    record = ContextManifestAuditRecord.model_validate(
        record.model_dump(mode="json", by_alias=True)
    )
    return ContextManifestPrepared(plan=plan, anchor=anchor, audit_record=record)


def context_manifest_audit_event(record: ContextManifestAuditRecord) -> AuditEvent:
    payload = record.model_dump(mode="json", by_alias=True, exclude={"integrity"})
    return AuditEvent.model_validate(payload)


def validate_context_manifest_audit_event(
    event: AuditEvent,
) -> ContextManifestAuditRecord:
    """Strictly parse a pre-write or persisted Context Manifest AuditEvent."""

    return ContextManifestAuditRecord.model_validate(
        event.model_dump(mode="json", by_alias=True)
    )


def context_manifest_record_digest(
    record: ContextManifestAuditRecord,
) -> str:
    payload = record.evidence.context_manifest
    if isinstance(payload, ContextManifestEnvelope):
        return payload.manifest_digest
    return payload.manifest_sha256


def context_manifest_anchor_from_policy(
    policy_audit: AuditEvent,
) -> ContextManifestAnchor | None:
    raw = policy_audit.metadata.get("context_manifest_anchor")
    if raw is None:
        return None
    return ContextManifestAnchor.model_validate(raw)


def records_have_same_content(
    stored: AuditEvent, candidate: ContextManifestAuditRecord
) -> bool:
    stored_dump = stored.model_dump(mode="json", by_alias=True)
    stored_dump.pop("integrity", None)
    candidate_dump = candidate.model_dump(
        mode="json", by_alias=True, exclude={"integrity"}
    )
    return canonical_json_bytes(stored_dump) == canonical_json_bytes(candidate_dump)


def is_context_manifest_reserved_payload(payload: object) -> bool:
    """Detect every server-reserved Manifest marker on the external Audit API."""

    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json", by_alias=True)  # type: ignore[attr-defined]
    if not isinstance(payload, dict):
        return False
    audit_id = payload.get("audit_id")
    if isinstance(audit_id, str) and audit_id.startswith(
        CONTEXT_MANIFEST_AUDIT_ID_PREFIX
    ):
        return True
    if payload.get("event_type") == CONTEXT_MANIFEST_EVENT_TYPE:
        return True
    evidence = payload.get("evidence")
    if isinstance(evidence, dict) and "context_manifest" in evidence:
        return True
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return False
    if "context_manifest_anchor" in metadata:
        return True
    return any(
        metadata.get(key) == value
        for key, value in (
            ("contract", CONTEXT_MANIFEST_AUDIT_CONTRACT),
            ("producer", CONTEXT_MANIFEST_PRODUCER),
            ("producer_binding_id", CONTEXT_MANIFEST_PRODUCER_BINDING_ID),
        )
    )


def _validate_plan_event_binding(
    event: GuardEvent, plan: ContextAssemblyPlan
) -> list[ContextSource]:
    if event.event_type != "context_assembled" or not isinstance(
        event.payload, ContextBuildPayload
    ):
        raise ValueError("context manifest requires context_assembled")
    if (
        plan.event_id != event.event_id
        or plan.runtime != event.runtime
        or plan.context_ref != f"context:{event.event_id}"
    ):
        raise ValueError("context plan identity does not match the event")
    if compute_context_plan_digest(plan) != plan.plan_digest:
        raise ValueError("context plan digest is invalid")
    sources = event.payload.sources
    if len(sources) != len(plan.chunks):
        raise ValueError("context plan does not cover every source")
    if len(plan.excluded_chunk_ids) != len(set(plan.excluded_chunk_ids)):
        raise ValueError("plan excluded chunk IDs must be unique")
    if (
        len(plan.reason_codes) > 64
        or len(plan.reason_codes) != len(set(plan.reason_codes))
        or any(not reason for reason in plan.reason_codes)
    ):
        raise ValueError("plan reason codes are not a bounded set")
    if len(plan.evidence_refs) > 64:
        raise ValueError("plan evidence refs exceed the typed bound")
    _validate_evidence_refs(plan.evidence_refs)
    chunk_ids = [chunk.chunk_id for chunk in plan.chunks]
    if len(chunk_ids) != len(set(chunk_ids)):
        raise ValueError("plan chunk IDs must be unique")
    expected_excluded = {
        chunk.chunk_id
        for chunk in plan.chunks
        if chunk.transform_state in {"quarantined", "excluded"}
    }
    if set(plan.excluded_chunk_ids) != expected_excluded:
        raise ValueError("plan excluded chunk IDs do not match dispositions")

    transformation_by_chunk: dict[str, ContextTransformation] = {}
    for transformation in plan.transformations:
        if transformation.chunk_id in transformation_by_chunk:
            raise ValueError("plan contains duplicate chunk transformations")
        transformation_by_chunk[transformation.chunk_id] = transformation

    action_by_state = {
        "annotated": "annotate",
        "quarantined": "quarantine",
        "excluded": "exclude",
    }
    for index, (source, chunk) in enumerate(zip(sources, plan.chunks, strict=True)):
        if (
            source.content_digest is None
            or chunk.content_digest != source.content_digest
            or source.sequence_index != index
            or chunk.scope_digest != plan.scope_digest
            or chunk.context_ref != plan.context_ref
            or chunk.sequence is None
            or chunk.sequence.domain != "runtime"
            or chunk.sequence.producer_binding_id != f"runtime:{event.runtime}"
            or chunk.sequence.value != index
        ):
            raise ValueError("context chunk binding does not match the source")
        expected_ref = (
            f"memory:{event.event_id}:{index}"
            if chunk.source_type == "memory"
            else f"source:{chunk.source_type}:{event.event_id}:{index}"
        )
        if chunk.source_ref != expected_ref:
            raise ValueError("context source reference is not server-derived")
        if chunk.transform_state not in {
            "preserved",
            "annotated",
            "quarantined",
            "excluded",
        }:
            raise ValueError("CT04M cannot persist an unsupported transformation")
        if len(chunk.evidence_refs) > 64 or len(chunk.taints) != len(set(chunk.taints)):
            raise ValueError("context chunk collections are not bounded sets")
        _validate_chunk_security_semantics(chunk)
        _validate_evidence_refs(chunk.evidence_refs)
        transformation = transformation_by_chunk.get(chunk.chunk_id)
        expected_action = action_by_state.get(chunk.transform_state)
        if expected_action is None:
            if transformation is not None:
                raise ValueError("preserved chunks cannot carry a transformation")
        elif (
            transformation is None
            or transformation.action != expected_action
            or transformation.input_digest != chunk.content_digest
            or transformation.declassification_id is not None
        ):
            raise ValueError("context transformation does not match the chunk")
        if transformation is not None:
            expected_output = (
                chunk.content_digest if transformation.action == "annotate" else None
            )
            if (
                transformation.output_digest != expected_output
                or transformation.mechanism_id != "ct-context-builder"
                or transformation.mechanism_version != "1.0"
                or len(transformation.reason_codes) > 64
                or len(transformation.reason_codes)
                != len(set(transformation.reason_codes))
                or any(not reason for reason in transformation.reason_codes)
                or len(transformation.evidence_refs) > 64
            ):
                raise ValueError("context transformation is not a bounded CT result")
            _validate_evidence_refs(transformation.evidence_refs)
    if set(transformation_by_chunk) != {
        chunk.chunk_id for chunk in plan.chunks if chunk.transform_state != "preserved"
    }:
        raise ValueError("plan transformations do not exactly cover changed chunks")
    return list(sources)


def _build_envelope(
    plan: ContextAssemblyPlan,
    *,
    preview_by_index: list[str | None],
) -> ContextManifestEnvelope:
    returned_chunks = tuple(
        chunk.model_copy(update={"content_preview": preview_by_index[index]})
        for index, chunk in enumerate(plan.chunks[:CONTEXT_MANIFEST_MAX_CHUNKS])
    )
    returned_ids = {chunk.chunk_id for chunk in returned_chunks}
    transformations = tuple(
        transformation
        for transformation in plan.transformations
        if transformation.chunk_id in returned_ids
    )
    excluded_chunk_ids = tuple(
        chunk_id for chunk_id in plan.excluded_chunk_ids if chunk_id in returned_ids
    )
    total = len(plan.chunks)
    excluded = len(plan.excluded_chunk_ids)
    truncated = len(returned_chunks) < total
    omitted_digest = (
        canonical_sha256(
            {
                "chunks": [
                    chunk.model_dump(mode="json")
                    for chunk in plan.chunks[CONTEXT_MANIFEST_MAX_CHUNKS:]
                ],
                "transformations": [
                    transformation.model_dump(mode="json")
                    for transformation in plan.transformations
                    if transformation.chunk_id not in returned_ids
                ],
                "excluded_chunk_ids": [
                    chunk_id
                    for chunk_id in plan.excluded_chunk_ids
                    if chunk_id not in returned_ids
                ],
            }
        )
        if truncated
        else None
    )
    by_source_type: dict[str, int] = {}
    for chunk in plan.chunks:
        by_source_type[chunk.source_type] = by_source_type.get(chunk.source_type, 0) + 1
    pending = ContextManifestEnvelope.model_construct(
        schema_version="1.0",
        plan_id=plan.plan_id,
        event_id=plan.event_id,
        scope_digest=plan.scope_digest,
        runtime=plan.runtime,
        context_ref=plan.context_ref,
        plan_digest=plan.plan_digest,
        manifest_digest="sha256:" + "0" * 64,
        counts=ContextManifestCounts(
            total=total,
            returned=len(returned_chunks),
            included=total - excluded,
            excluded=excluded,
            quarantined=sum(
                chunk.transform_state == "quarantined" for chunk in plan.chunks
            ),
            sensitive=sum(chunk.sensitive for chunk in plan.chunks),
            untrusted=sum(chunk.trust == "untrusted" for chunk in plan.chunks),
            by_source_type=by_source_type,
        ),
        chunks=returned_chunks,
        transformations=transformations,
        excluded_chunk_ids=excluded_chunk_ids,
        reason_codes=plan.reason_codes,
        evidence_refs=plan.evidence_refs,
        completeness=ContextManifestCompleteness(
            status="partial" if truncated else "complete",
            truncated=truncated,
            omitted_digest=omitted_digest,
        ),
    )
    digest = compute_manifest_digest(pending)
    return ContextManifestEnvelope.model_validate(
        pending.model_copy(update={"manifest_digest": digest}).model_dump(mode="json")
    )


def _safe_preview(*, source: ContextSource, chunk: ContextChunk) -> str | None:
    if (
        source.role == "system"
        or source.contains_sensitive_data
        or _preview_must_be_empty(chunk)
    ):
        return None
    candidate = source.summary
    if not isinstance(candidate, str) or not candidate:
        return None
    if (
        _DISPLAY_UNSAFE_PREVIEW_FIELD.search(candidate) is not None
        or _DISPLAY_UNSAFE_PREVIEW_VALUE.search(candidate) is not None
    ):
        return None
    if scrub_text(candidate) != candidate:
        return None
    return candidate[:CONTEXT_MANIFEST_PREVIEW_LIMIT]


def _preview_must_be_empty(chunk: ContextChunk) -> bool:
    return bool(
        chunk.sensitive
        or "CREDENTIAL" in chunk.taints
        or chunk.compartment in {"authority", "trusted_runtime_fact", "model_derived"}
        or chunk.transform_state in {"quarantined", "excluded"}
    )


def _manifest_evidence_size(envelope: ContextManifestEnvelope) -> int:
    return evidence_serialized_size(
        {"context_manifest": envelope.model_dump(mode="json", by_alias=True)}
    )


def _validate_evidence_refs(refs: tuple[EvidenceRef, ...]) -> None:
    canonical = [
        canonical_json_bytes(reference.model_dump(mode="json")) for reference in refs
    ]
    if len(canonical) != len(set(canonical)):
        raise ValueError("evidence refs must not contain duplicates")
    if any(
        not reference.digest.startswith("sha256:")
        or len(reference.digest) != len("sha256:") + 64
        or any(
            character not in "0123456789abcdef"
            for character in reference.digest.removeprefix("sha256:")
        )
        for reference in refs
    ):
        raise ValueError("evidence refs require canonical sha256 digests")


def _validate_chunk_security_semantics(chunk: ContextChunk) -> None:
    if chunk.sensitive and chunk.transform_state != "excluded":
        raise ValueError("sensitive chunks must be excluded")
    if chunk.compartment == "untrusted_evidence" and (
        chunk.trust != "untrusted"
        or chunk.fact_authority in {"authoritative", "trusted_claim"}
        or (
            chunk.instruction_like
            and chunk.transform_state not in {"quarantined", "excluded"}
        )
    ):
        raise ValueError("untrusted evidence cannot gain authority")
    if chunk.fact_authority == "authoritative" and (
        chunk.trust != "trusted"
        or chunk.compartment not in {"authority", "authenticated_task"}
    ):
        raise ValueError("authoritative chunks require a trusted authority compartment")
    if chunk.compartment == "trusted_runtime_fact" and (
        chunk.source_type != "runtime"
        or chunk.trust != "trusted"
        or chunk.fact_authority != "trusted_claim"
    ):
        raise ValueError("trusted runtime facts require the server-owned binding")
    if (
        chunk.compartment == "model_derived"
        and chunk.fact_authority != "model_judgment"
    ):
        raise ValueError("model-derived chunks cannot claim external authority")
