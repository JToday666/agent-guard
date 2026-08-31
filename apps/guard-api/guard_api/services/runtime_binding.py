"""Server-owned runtime binding resolution.

The caller may claim a runtime binding only for equality checking.  The value
returned by this module is always derived from an authenticated server-side
identity (legacy modes) or read from the process-frozen Product activation
bundle (Product Active).  In particular, an adapter-provided binding is never
used as a lookup key or copied into an authoritative scope.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from agentguard_core import GuardEvent

from guard_api.auth import AuthContext

if TYPE_CHECKING:
    from .product_activation import FrozenProductActivation

LEGACY_RUNTIME_IDENTITY_MISMATCH = "RUNTIME_IDENTITY_MISMATCH"
PRODUCT_ACTIVATION_NOT_CURRENT = "V21_PRODUCT_ACTIVATION_NOT_CURRENT"
PRODUCT_RUNTIME_IDENTITY_MISMATCH = "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH"
PRODUCT_TASK_IDENTITY_MISMATCH = "V21_PRODUCT_TASK_IDENTITY_MISMATCH"
PRODUCT_TASK_SCOPE_INVALID = "V21_PRODUCT_TASK_SCOPE_INVALID"

RuntimeBindingSource = Literal["legacy_derived", "product_activation"]


class RuntimeBindingResolutionError(RuntimeError):
    """A server-owned runtime identity could not be resolved exactly."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ResolvedRuntimeBinding:
    """Immutable subject identity used to construct an authoritative scope."""

    runtime: str
    principal_id: str
    agent_id: str | None
    runtime_binding_id: str
    actor_principal_id: str
    activation_ref_digest: str | None
    source: RuntimeBindingSource


@dataclass(frozen=True, slots=True)
class _FrozenProductBindingEntry:
    runtime: str
    principal_id: str
    agent_id: str
    runtime_binding_id: str
    expires_at: datetime


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Product activation time must be timezone-aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class RuntimeBindingResolver:
    """Resolve legacy or Product Active runtime identities without caller trust.

    ``product_activation is None`` deliberately preserves the existing
    derivation:

    * runtime-bound credentials use ``binding:{principal_id}``;
    * the control task-ingress identity uses
      ``binding:control:{principal_id}``;
    * evaluation scope reconstruction uses the authoritative TaskFact
      principal and ``binding:{task_principal_id}``.

    With a Product activation, every call re-checks its validity window.  A
    runtime credential is matched by its authenticated runtime/principal/agent
    tuple.  The control-plane task writer may select only the signed runtime
    entry by ``request.runtime``; the subject principal, agent, and binding all
    come from that entry.
    """

    product_activation: FrozenProductActivation | None = None
    clock: Callable[[], datetime] = _now_utc
    _product_entries: tuple[_FrozenProductBindingEntry, ...] = field(
        init=False,
        default=(),
        repr=False,
    )
    _activation_ref_digest: str | None = field(
        init=False,
        default=None,
        repr=False,
    )
    _issued_at: datetime | None = field(init=False, default=None, repr=False)
    _expires_at: datetime | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        activation = self.product_activation
        if activation is None:
            return
        activation.assert_unchanged()
        bundle = activation.bundle
        entries = tuple(
            _FrozenProductBindingEntry(
                runtime=entry.runtime,
                principal_id=entry.principal_id,
                agent_id=entry.agent_id,
                runtime_binding_id=entry.runtime_binding_id,
                expires_at=_parse_utc(entry.expires_at),
            )
            for entry in bundle.runtimes
        )
        if tuple(entry.runtime for entry in entries) != ("langgraph", "openclaw"):
            raise ValueError("Product activation runtime entries are incomplete")
        object.__setattr__(self, "_product_entries", entries)
        object.__setattr__(
            self,
            "_activation_ref_digest",
            bundle.activation_ref_digest,
        )
        object.__setattr__(self, "_issued_at", _parse_utc(bundle.issued_at))
        object.__setattr__(self, "_expires_at", _parse_utc(bundle.expires_at))

    @property
    def product_active(self) -> bool:
        """Whether resolution is bound to one verified Product activation."""

        return self.product_activation is not None

    def resolve_task_ingress(
        self,
        auth_context: AuthContext,
        *,
        runtime: str,
        claimed_runtime_binding_id: str | None = None,
    ) -> ResolvedRuntimeBinding:
        """Resolve the subject for one Task Ingress create/revise request.

        ``claimed_runtime_binding_id`` is comparison-only.  It never
        participates in lookup or construction of the returned identity.
        """

        if self.product_activation is None:
            resolved = self._resolve_legacy_task(auth_context, runtime=runtime)
            self._verify_claim(
                resolved,
                claimed_runtime_binding_id,
                code=LEGACY_RUNTIME_IDENTITY_MISMATCH,
            )
            return resolved

        self._require_current_product_activation()
        if auth_context.runtime is None:
            # Only the authenticated control-plane identity may delegate task
            # creation to one of the two signed Product runtime subjects.
            if auth_context.role != "control" or auth_context.agent_id is not None:
                raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)
            entry = self._product_entry(runtime)
        else:
            # Select by the credential-owned runtime first.  request.runtime is
            # merely an equality assertion and cannot redirect the lookup.
            entry = self._product_entry(auth_context.runtime)
            if not all(
                (
                    runtime == entry.runtime,
                    auth_context.runtime == entry.runtime,
                    auth_context.principal_id == entry.principal_id,
                    auth_context.agent_id == entry.agent_id,
                )
            ):
                raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)

        resolved = ResolvedRuntimeBinding(
            runtime=entry.runtime,
            principal_id=entry.principal_id,
            agent_id=entry.agent_id,
            runtime_binding_id=entry.runtime_binding_id,
            actor_principal_id=auth_context.principal_id,
            activation_ref_digest=self._activation_ref_digest,
            source="product_activation",
        )
        self._verify_claim(
            resolved,
            claimed_runtime_binding_id,
            # A caller-supplied binding is an authentication-boundary claim.
            # Even in Product Active, disagreement remains the existing 403
            # RUNTIME_IDENTITY_MISMATCH rather than an authority-availability
            # 503.  The claimed value is still never adopted.
            code=LEGACY_RUNTIME_IDENTITY_MISMATCH,
        )
        return resolved

    def resolve_evaluation(
        self,
        auth_context: AuthContext | None,
        *,
        event: GuardEvent,
        task_principal_id: str,
    ) -> ResolvedRuntimeBinding:
        """Reconstruct the runtime identity for an authoritative TaskFact scope.

        In Product Active, the activation entry is selected by the
        credential-owned runtime.  Event runtime/agent and persisted TaskFact
        principal are comparison-only inputs; all must exactly match the signed
        entry before its binding can enter a reconstructed scope.
        """

        if self.product_activation is None:
            return ResolvedRuntimeBinding(
                runtime=event.runtime,
                principal_id=task_principal_id,
                agent_id=event.security_context.agent_id,
                runtime_binding_id=f"binding:{task_principal_id}",
                actor_principal_id=(
                    auth_context.principal_id
                    if auth_context is not None
                    else task_principal_id
                ),
                activation_ref_digest=None,
                source="legacy_derived",
            )

        self._require_current_product_activation()
        if auth_context is None or auth_context.runtime is None:
            raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)
        entry = self._product_entry(auth_context.runtime)
        event_agent_explicit = "agent_id" in event.security_context.model_fields_set
        if not all(
            (
                event_agent_explicit,
                auth_context.runtime == entry.runtime,
                auth_context.principal_id == entry.principal_id,
                auth_context.agent_id == entry.agent_id,
                event.runtime == entry.runtime,
                event.security_context.agent_id == entry.agent_id,
                task_principal_id == entry.principal_id,
            )
        ):
            raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)
        return ResolvedRuntimeBinding(
            runtime=entry.runtime,
            principal_id=entry.principal_id,
            agent_id=entry.agent_id,
            runtime_binding_id=entry.runtime_binding_id,
            actor_principal_id=auth_context.principal_id,
            activation_ref_digest=self._activation_ref_digest,
            source="product_activation",
        )

    def revalidate(self, resolved: ResolvedRuntimeBinding) -> None:
        """Recheck the Product activation immediately before a later phase.

        Legacy derivation has no external activation to revalidate and is a
        deliberate no-op.  Product resolution rechecks both the time window and
        every signed subject field, including the activation reference carried
        with the immutable result.
        """

        if self.product_activation is None:
            return
        self._require_current_product_activation()
        if resolved.source != "product_activation":
            raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)
        entry = self._product_entry(resolved.runtime)
        if not all(
            (
                resolved.runtime == entry.runtime,
                resolved.principal_id == entry.principal_id,
                resolved.agent_id == entry.agent_id,
                resolved.runtime_binding_id == entry.runtime_binding_id,
                resolved.activation_ref_digest == self._activation_ref_digest,
            )
        ):
            raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)

    def _resolve_legacy_task(
        self, auth_context: AuthContext, *, runtime: str
    ) -> ResolvedRuntimeBinding:
        if auth_context.runtime is not None:
            if runtime != auth_context.runtime:
                raise RuntimeBindingResolutionError(LEGACY_RUNTIME_IDENTITY_MISMATCH)
            binding_id = f"binding:{auth_context.principal_id}"
        else:
            binding_id = f"binding:control:{auth_context.principal_id}"
        return ResolvedRuntimeBinding(
            runtime=runtime,
            principal_id=auth_context.principal_id,
            agent_id=auth_context.agent_id,
            runtime_binding_id=binding_id,
            actor_principal_id=auth_context.principal_id,
            activation_ref_digest=None,
            source="legacy_derived",
        )

    def _require_current_product_activation(self) -> None:
        activation = self.product_activation
        assert activation is not None
        try:
            activation.assert_unchanged()
            current = self.clock().astimezone(timezone.utc)
        except Exception as exc:  # noqa: BLE001 - collapse clock/validity failures.
            raise RuntimeBindingResolutionError(PRODUCT_ACTIVATION_NOT_CURRENT) from exc
        if (
            self._issued_at is None
            or self._expires_at is None
            or not self._issued_at <= current < self._expires_at
            or any(current >= entry.expires_at for entry in self._product_entries)
        ):
            raise RuntimeBindingResolutionError(PRODUCT_ACTIVATION_NOT_CURRENT)

    def _product_entry(self, runtime: str) -> _FrozenProductBindingEntry:
        for entry in self._product_entries:
            if entry.runtime == runtime:
                return entry
        raise RuntimeBindingResolutionError(PRODUCT_RUNTIME_IDENTITY_MISMATCH)

    @staticmethod
    def _verify_claim(
        resolved: ResolvedRuntimeBinding,
        claimed_runtime_binding_id: str | None,
        *,
        code: str,
    ) -> None:
        if (
            claimed_runtime_binding_id is not None
            and claimed_runtime_binding_id != resolved.runtime_binding_id
        ):
            raise RuntimeBindingResolutionError(code)


__all__ = [
    "LEGACY_RUNTIME_IDENTITY_MISMATCH",
    "PRODUCT_ACTIVATION_NOT_CURRENT",
    "PRODUCT_RUNTIME_IDENTITY_MISMATCH",
    "PRODUCT_TASK_IDENTITY_MISMATCH",
    "PRODUCT_TASK_SCOPE_INVALID",
    "ResolvedRuntimeBinding",
    "RuntimeBindingResolutionError",
    "RuntimeBindingResolver",
]
