"""Deterministic, ephemeral context-assembly contracts.

These models implement the frozen CT-PR-04 contract.  They intentionally do
not carry full prompt content: ``content_preview`` is an optional audit/display
field and is excluded from the chunk semantic digest.  The live evaluate
response emitted by Guard API always leaves it ``None``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import canonical_sha256
from ..signals.models import EvidenceRef, FactAuthority, SequenceRef, TaintLabel

__all__ = [
    "ContextAssemblyPlan",
    "ContextChunk",
    "ContextCompartment",
    "ContextTransformState",
    "ContextTransformation",
    "ContextTransformationAction",
    "compute_context_chunk_digest",
    "compute_context_plan_digest",
    "context_chunk_digest_projection",
    "context_plan_digest_projection",
]


ContextCompartment = Literal[
    "authority",
    "authenticated_task",
    "trusted_runtime_fact",
    "untrusted_evidence",
    "memory_context",
    "model_derived",
]
ContextTransformState = Literal[
    "preserved",
    "annotated",
    "redacted",
    "quarantined",
    "summarized",
    "excluded",
]
ContextTransformationAction = Literal[
    "annotate", "redact", "quarantine", "summarize", "exclude"
]


class ContextChunk(BaseModel):
    """A content-addressed source selected for one model context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    chunk_id: str
    scope_digest: str
    context_ref: str
    source_ref: str
    source_type: str
    compartment: ContextCompartment
    trust: Literal["trusted", "untrusted", "unknown"]
    fact_authority: FactAuthority
    taints: tuple[TaintLabel, ...] = ()
    content_digest: str
    content_preview: str | None = None
    instruction_like: bool
    sensitive: bool
    transform_state: ContextTransformState
    sequence: SequenceRef | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()


class ContextTransformation(BaseModel):
    """A deterministic disposition applied to a context chunk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transformation_id: str
    chunk_id: str
    action: ContextTransformationAction
    input_digest: str
    output_digest: str | None
    mechanism_id: str
    mechanism_version: str
    declassification_id: str | None = None
    reason_codes: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()


class ContextAssemblyPlan(BaseModel):
    """Ephemeral, deterministic plan consumed by a runtime adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    plan_id: str
    event_id: str
    scope_digest: str
    runtime: str
    context_ref: str
    chunks: tuple[ContextChunk, ...] = ()
    transformations: tuple[ContextTransformation, ...] = ()
    excluded_chunk_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    plan_digest: str


def context_chunk_digest_projection(chunk: ContextChunk) -> dict[str, Any]:
    """Project a chunk for semantic hashing, excluding display-only preview."""

    projection = chunk.model_dump(mode="json")
    projection.pop("content_preview", None)
    return projection


def compute_context_chunk_digest(chunk: ContextChunk) -> str:
    """Return the restricted-canonical semantic digest of ``chunk``."""

    return canonical_sha256(context_chunk_digest_projection(chunk))


def context_plan_digest_projection(plan: ContextAssemblyPlan) -> dict[str, Any]:
    """Project the exact wire plan excluding only its self-referential digest."""

    projection = plan.model_dump(mode="json")
    projection.pop("plan_digest", None)
    return projection


def compute_context_plan_digest(plan: ContextAssemblyPlan) -> str:
    """Return ``sha256(JCS(context_plan without plan_digest))``."""

    return canonical_sha256(context_plan_digest_projection(plan))
