"""Gate A current-event assessment overlay.

The overlay is deliberately separate from :class:`SecuritySnapshot`: current
event facts may participate in the current decision, but they are not
historical state until an authoritative record is committed and projected.
Every function in this module is deterministic and returns a new value; no
snapshot or online-state object is mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal, Sequence, TypeVar

from pydantic import BaseModel, ConfigDict, model_validator

from ..actions.canonical_json import canonical_sha256
from ..signals.models import EvaluationDegradation, EvidenceRef, SecuritySignal
from .facts import (
    DeclassificationFact,
    FlowFact,
    MemoryFact,
    RecentActionFact,
    SourceFact,
)
from .projection.provenance_lookup import (
    MAX_LOOKUP_INPUT_FLOWS,
    bounded_relevant_flow_lookup_many,
)
from .state import OnlineSecurityState

__all__ = [
    "ASSESSMENT_OVERLAY_COMPONENT_ID",
    "ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS",
    "ASSESSMENT_OVERLAY_VERSION",
    "AssessmentOverlay",
    "AssessmentOverlayError",
    "AssessmentTransientFacts",
    "build_assessment_overlay",
    "compute_overlay_digest",
    "overlay_digest_projection",
]

ASSESSMENT_OVERLAY_VERSION = "gate-a-overlay-1"
ASSESSMENT_OVERLAY_COMPONENT_ID = "gate-a.assessment_overlay"

#: Hard per-container input bound for the ephemeral overlay. It deliberately
#: matches the lookup's maximum indexable flow count; source, memory, and action
#: containers use the same conservative ceiling so no merge can allocate from
#: an unbounded sticky history. The bound is checked on raw historical plus
#: transient counts before any list/dict merge allocation.
ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS = MAX_LOOKUP_INPUT_FLOWS


class AssessmentOverlayError(ValueError):
    """Invalid or conflicting current-event overlay input."""


class AssessmentTransientFacts(BaseModel):
    """Core-owned current-event assessment input.

    The field names intentionally match Guard API's ``TransientSecurityFacts``
    so the API boundary can use ``model_validate(bundle.model_dump())`` without
    importing an application model into Core. ``overlay_digest`` covers the
    complete assessment overlay, unlike the projection-oriented
    ``bundle_digest`` whose historical whitelist is intentionally narrower.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    event_id: str
    scope_digest: str
    source_facts: tuple[SourceFact, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    memory_facts: tuple[MemoryFact, ...] = ()
    declassifications: tuple[DeclassificationFact, ...] = ()
    current_action: RecentActionFact | None = None
    signals: tuple[SecuritySignal, ...] = ()
    degradations: tuple[EvaluationDegradation, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    bundle_digest: str = ""
    overlay_digest: str = ""

    @model_validator(mode="after")
    def _validate_and_bind_digest(self) -> "AssessmentTransientFacts":
        for fact in (*self.source_facts, *self.flow_facts):
            if fact.scope_digest != self.scope_digest:
                raise ValueError(
                    "assessment transient fact scope does not match bundle scope"
                )
        if (
            self.current_action is not None
            and self.current_action.event_id != self.event_id
        ):
            raise ValueError(
                "assessment transient current_action event does not match bundle event"
            )

        expected = compute_overlay_digest(self)
        if self.overlay_digest and self.overlay_digest != expected:
            raise ValueError("assessment transient overlay_digest mismatch")
        if not self.overlay_digest:
            # Pydantic's frozen contract applies after validation. Binding the
            # derived field here gives every successfully constructed instance
            # a verified digest without exposing a second mutable build phase.
            object.__setattr__(self, "overlay_digest", expected)
        return self

    @classmethod
    def from_primitives(
        cls,
        *,
        event_id: str,
        scope_digest: str,
        source_facts: Sequence[SourceFact] = (),
        flow_facts: Sequence[FlowFact] = (),
        memory_facts: Sequence[MemoryFact] = (),
        declassifications: Sequence[DeclassificationFact] = (),
        current_action: RecentActionFact | None = None,
        signals: Sequence[SecuritySignal] = (),
        degradations: Sequence[EvaluationDegradation] = (),
        evidence_refs: Sequence[EvidenceRef] = (),
        bundle_digest: str = "",
    ) -> "AssessmentTransientFacts":
        """Build the immutable DTO from typed primitives."""
        return cls(
            event_id=event_id,
            scope_digest=scope_digest,
            source_facts=tuple(source_facts),
            flow_facts=tuple(flow_facts),
            memory_facts=tuple(memory_facts),
            declassifications=tuple(declassifications),
            current_action=current_action,
            signals=tuple(signals),
            degradations=tuple(degradations),
            evidence_refs=tuple(evidence_refs),
            bundle_digest=bundle_digest,
        )


def overlay_digest_projection(bundle: AssessmentTransientFacts) -> dict[str, Any]:
    """Complete deterministic projection of current assessment inputs."""
    return {
        "assessment_overlay_version": ASSESSMENT_OVERLAY_VERSION,
        "schema_version": bundle.schema_version,
        "event_id": bundle.event_id,
        "scope_digest": bundle.scope_digest,
        "source_facts": [fact.model_dump(mode="json") for fact in bundle.source_facts],
        "flow_facts": [fact.model_dump(mode="json") for fact in bundle.flow_facts],
        "memory_facts": [fact.model_dump(mode="json") for fact in bundle.memory_facts],
        "declassifications": [
            fact.model_dump(mode="json") for fact in bundle.declassifications
        ],
        "current_action": (
            bundle.current_action.model_dump(mode="json")
            if bundle.current_action is not None
            else None
        ),
        "signals": [signal.model_dump(mode="json") for signal in bundle.signals],
        "degradations": [
            degradation.model_dump(mode="json") for degradation in bundle.degradations
        ],
        "evidence_refs": [
            evidence.model_dump(mode="json") for evidence in bundle.evidence_refs
        ],
    }


def compute_overlay_digest(bundle: AssessmentTransientFacts) -> str:
    """Digest all transient inputs consumed by the current assessment."""
    return canonical_sha256(overlay_digest_projection(bundle))


@dataclass(frozen=True)
class AssessmentOverlay:
    """Ephemeral state view plus bounded-lookup metadata."""

    state: OnlineSecurityState
    relevant_flows: tuple[FlowFact, ...]
    stable_source_refs: tuple[str, ...]
    truncated: bool


_FactT = TypeVar("_FactT", bound=BaseModel)


def _merge_by_identity(
    historical: Sequence[_FactT],
    transient: Iterable[_FactT],
    *,
    identity_field: str,
) -> list[_FactT]:
    """Stable append with exact replay and conflict detection."""
    merged = list(historical)
    by_identity = {str(getattr(item, identity_field)): item for item in historical}
    for item in transient:
        identity = str(getattr(item, identity_field))
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = item
            merged.append(item)
            continue
        if existing != item:
            raise AssessmentOverlayError(
                f"conflicting {identity_field} in assessment overlay: {identity}"
            )
    return merged


def _ensure_container_budget(
    name: str, *, historical_count: int, transient_count: int
) -> None:
    """Reject an oversized merge before allocating its list or identity map."""

    if historical_count + transient_count > ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS:
        raise AssessmentOverlayError(
            f"assessment overlay {name} exceeds "
            f"{ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS} item limit"
        )


def _merge_current_action(
    historical: Sequence[RecentActionFact],
    current: RecentActionFact | None,
) -> list[RecentActionFact]:
    if current is None:
        return list(historical)
    return _merge_by_identity(historical, (current,), identity_field="action_id")


def build_assessment_overlay(
    state: OnlineSecurityState,
    transient_facts: AssessmentTransientFacts,
    *,
    target_refs: Sequence[str],
) -> AssessmentOverlay:
    """Compose historical state with current facts in an ephemeral view.

    ``target_refs`` must identify the current action and its normalized sinks.
    Only their bounded relevant flow subgraph is exposed to FlowVerdict,
    Behavior, and Fusion. Current action facts are never returned as a delta and
    therefore cannot be persisted by this function.
    """
    if transient_facts.declassifications:
        raise AssessmentOverlayError(
            "current-event declassification is outside the Gate A overlay contract"
        )

    # Check every state container that Gate A merges before _merge_by_identity
    # allocates a list/dict. Raw-count rejection is intentionally conservative:
    # duplicate replay entries do not earn permission to exceed the hard input
    # budget because proving that would itself require an unbounded index.
    _ensure_container_budget(
        "sources",
        historical_count=len(state.source_index),
        transient_count=len(transient_facts.source_facts),
    )
    _ensure_container_budget(
        "flows",
        historical_count=len(state.relevant_flows),
        transient_count=len(transient_facts.flow_facts),
    )
    _ensure_container_budget(
        "memory",
        historical_count=len(state.memory_index),
        transient_count=len(transient_facts.memory_facts),
    )
    _ensure_container_budget(
        "actions",
        historical_count=len(state.recent_actions),
        transient_count=int(transient_facts.current_action is not None),
    )

    sources = _merge_by_identity(
        state.source_index,
        transient_facts.source_facts,
        identity_field="source_id",
    )
    flows = _merge_by_identity(
        state.relevant_flows,
        transient_facts.flow_facts,
        identity_field="flow_id",
    )
    memory = _merge_by_identity(
        state.memory_index,
        transient_facts.memory_facts,
        identity_field="memory_id",
    )
    actions = _merge_current_action(
        state.recent_actions, transient_facts.current_action
    )

    complete_view = state.model_copy(
        update={
            "source_index": sources,
            "relevant_flows": flows,
            "memory_index": memory,
            "recent_actions": actions,
        },
    )
    relevant_flows, truncated = bounded_relevant_flow_lookup_many(
        complete_view,
        target_refs=tuple(target_refs),
    )
    bounded_view = complete_view.model_copy(update={"relevant_flows": relevant_flows})

    source_ids = {source.source_id for source in sources}
    action_refs = (
        transient_facts.current_action.data_refs
        if transient_facts.current_action is not None
        else ()
    )
    stable_source_refs = tuple(
        sorted({ref for ref in action_refs if ref in source_ids})
    )
    return AssessmentOverlay(
        state=bounded_view,
        relevant_flows=tuple(relevant_flows),
        stable_source_refs=stable_source_refs,
        truncated=truncated,
    )
