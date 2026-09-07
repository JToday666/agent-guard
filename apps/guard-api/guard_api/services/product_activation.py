"""Process-frozen Product V2 activation and runtime ACK authority.

This module owns activation loading, short-lived heartbeat acknowledgements,
and the request gate consumed before Product evaluation or release.  The
selector remains in ``EvaluationService``/Core; this service proves that the
calling runtime and both frozen runtime observations are current first.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NoReturn, cast

from agentguard_core import (
    ActivationAckV1,
    GuardEvent,
    ProductActivationBundleV1,
    ProductDecisionAuthorityEvidenceV1,
    RuntimeActivationEntryV1,
    RuntimeOutcomeReceipt,
    build_activation_ack,
    verify_activation_ack,
    verify_activation_ack_token,
    verify_product_activation_bundle,
)

from guard_api.auth import AuthContext
from guard_api.runtime_status import (
    ProductActivationAckRecordV1,
    ProductRuntime,
    ProductRuntimeHeartbeatV2,
    ProductRuntimeStatusIdentityV1,
    ProductRuntimeStatusV2,
    activation_ack_matches_runtime_status,
    activation_ack_token_digest,
)
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import ControlPlaneStore
from guard_api.storage.integrity import canonical_sha256

from .runtime_binding import (
    PRODUCT_ACTIVATION_NOT_CURRENT as ACTIVATION_NOT_CURRENT,
    PRODUCT_RUNTIME_IDENTITY_MISMATCH as RUNTIME_IDENTITY_MISMATCH,
)
from .v21_pipeline import V21OfficialEvaluationUnavailableError

_MAX_ACTIVATION_BYTES = 64 * 1024
_PRODUCT_RUNTIMES = ("langgraph", "openclaw")
_SIGNER_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

RUNTIME_OBSERVATION_MISMATCH = "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH"
ACTIVATION_ACK_REQUIRED = "V21_PRODUCT_ACTIVATION_ACK_REQUIRED"
ACTIVATION_ACK_NOT_CURRENT = "V21_PRODUCT_ACTIVATION_ACK_NOT_CURRENT"
ACTIVATION_ACK_TTL_SECONDS = 120
# Compatibility-only symbol for direct callers from the pre-01d API.  The
# public composition root no longer constructs this fuse.
SELECTOR_NOT_WIRED = "V21_PRODUCT_SELECTOR_NOT_WIRED"


@dataclass(frozen=True, slots=True)
class FrozenProductActivation:
    """Verified Product activation bytes captured once during construction."""

    bundle: ProductActivationBundleV1
    source_path: str
    content_digest: str

    def __post_init__(self) -> None:
        current_digest = canonical_sha256(self.bundle.model_dump(mode="json"))
        if not hmac.compare_digest(current_digest, self.content_digest):
            raise ValueError(
                "frozen Product activation content digest does not match bundle"
            )

    def assert_unchanged(self) -> None:
        """Fail if a shallow-frozen nested model was mutated in process."""

        current_digest = canonical_sha256(self.bundle.model_dump(mode="json"))
        if not hmac.compare_digest(current_digest, self.content_digest):
            raise ValueError("frozen Product activation changed after verification")


@dataclass(frozen=True, slots=True)
class ProductRuntimeObservationReconciliation:
    """Non-sensitive result of comparing both exact runtime observations."""

    matched: bool
    reason_codes: tuple[str, ...]
    observation_digest: str | None = None
    authority_observation_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ProductHeartbeatAcceptance:
    """Persisted Product heartbeat and its private server-signed ACK."""

    runtime_status: ProductRuntimeStatusV2
    activation_ack: ActivationAckV1 = field(repr=False)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)


def _parse_utc(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    return _aware_utc(parsed, label=label)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _read_owned_read_only_json(path_value: str) -> object:
    """Read one bounded, owner-controlled, non-symlink JSON file."""

    path = Path(path_value)
    if not path.is_absolute():
        raise GuardApiConfigurationError(
            "Product activation bundle path must be absolute"
        )
    try:
        before = path.lstat()
    except (OSError, ValueError) as exc:
        raise GuardApiConfigurationError(
            "Product activation bundle is unavailable"
        ) from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise GuardApiConfigurationError(
            "Product activation bundle must be a regular non-symlink file"
        )
    if before.st_uid != os.geteuid():
        raise GuardApiConfigurationError(
            "Product activation bundle must be owned by the Guard API user"
        )
    if before.st_mode & 0o222:
        raise GuardApiConfigurationError("Product activation bundle must be read-only")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise GuardApiConfigurationError(
                "Product activation bundle changed while opening"
            )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o222
        ):
            raise GuardApiConfigurationError(
                "Product activation bundle file security changed while opening"
            )
        if opened.st_size <= 0 or opened.st_size > _MAX_ACTIVATION_BYTES:
            raise GuardApiConfigurationError(
                "Product activation bundle has an invalid size"
            )

        chunks: list[bytes] = []
        remaining = _MAX_ACTIVATION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(16 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or len(payload) != opened.st_size
        ):
            raise GuardApiConfigurationError(
                "Product activation bundle changed while reading"
            )
    except GuardApiConfigurationError:
        raise
    except (OSError, ValueError) as exc:
        raise GuardApiConfigurationError(
            "Product activation bundle could not be read"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise GuardApiConfigurationError(
            "Product activation bundle is invalid JSON"
        ) from exc


def load_frozen_product_activation(
    settings: GuardApiSettings,
    *,
    clock: Callable[[], datetime] = _now_utc,
) -> FrozenProductActivation | None:
    """Load one strict, signed, currently valid Product activation bundle."""

    values = (
        settings.v21_product_activation_path,
        settings.v21_product_activation_server_secret,
        settings.v21_product_activation_signer_key_id,
    )
    present = tuple(value is not None and bool(value.strip()) for value in values)
    if not any(present):
        return None
    if not all(present):
        raise GuardApiConfigurationError(
            "Product activation path, secret, and signer key id must be configured "
            "together"
        )
    if settings.effective_v21_mode() != "active":
        raise GuardApiConfigurationError(
            "Product activation bundle requires AGENTGUARD_V21_MODE=active"
        )
    if (
        settings.v21_competition_activation_path
        and settings.v21_competition_activation_path.strip()
    ):
        raise GuardApiConfigurationError(
            "Product and competition V2.1 activation paths are mutually exclusive"
        )

    path_value = settings.v21_product_activation_path
    signer_key_id = settings.v21_product_activation_signer_key_id
    assert path_value is not None
    assert signer_key_id is not None
    if not _SIGNER_KEY_ID_PATTERN.fullmatch(signer_key_id):
        raise GuardApiConfigurationError(
            "Product activation signer key id must contain 1-64 safe characters"
        )
    raw = _read_owned_read_only_json(path_value)
    try:
        bundle = ProductActivationBundleV1.model_validate(raw)
    except (RecursionError, ValueError) as exc:
        raise GuardApiConfigurationError(
            "Product activation bundle is invalid"
        ) from exc
    if raw != bundle.model_dump(mode="json"):
        raise GuardApiConfigurationError(
            "Product activation bundle is not a strict contract document"
        )

    signer_ids = (
        bundle.signer_key_id,
        bundle.rollout_admission_record.signer_key_id,
        bundle.residual_risk_acceptance.signer_key_id,
    )
    if any(value != signer_key_id for value in signer_ids):
        raise GuardApiConfigurationError(
            "Product activation bundle signer identity does not match configuration"
        )
    secret = settings.v21_product_activation_server_secret_bytes()
    shadow_secret = settings.v21_shadow_server_secret_bytes()
    if (
        secret is not None
        and shadow_secret is not None
        and hmac.compare_digest(secret, shadow_secret)
    ):
        raise GuardApiConfigurationError(
            "Product activation and V2.1 shadow must use independent secrets"
        )
    if secret is None or not verify_product_activation_bundle(
        bundle,
        server_secret=secret,
    ):
        raise GuardApiConfigurationError(
            "Product activation bundle signature is invalid"
        )
    if not bundle.valid_at(clock()):
        raise GuardApiConfigurationError(
            "Product activation bundle is not currently valid"
        )
    return FrozenProductActivation(
        bundle=bundle,
        source_path=str(Path(path_value)),
        content_digest=canonical_sha256(raw),
    )


def _status_matches_entry(
    status: ProductRuntimeStatusV2,
    *,
    activation: FrozenProductActivation,
    runtime: str,
) -> bool:
    entry = activation.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
    report = status.capability_report
    return bool(
        status.runtime == entry.runtime
        and status.principal_id == entry.principal_id
        and status.agent_id == entry.agent_id
        and status.runtime_binding_id == entry.runtime_binding_id
        and status.profile_id == entry.profile_id
        and status.runtime_version == entry.runtime_version
        and status.plugin_version == entry.plugin_version
        and status.profile_digest == entry.profile_digest
        and status.adapter_artifact_digest == entry.adapter_artifact_digest
        and status.reported_activation_ref_digest
        == activation.bundle.activation_ref_digest
        and status.host_inventory_digest == entry.host_inventory_digest
        and status.plugin_inventory_digest == entry.plugin_inventory_digest
        and status.plugin_order_inventory_digest == entry.plugin_order_inventory_digest
        and status.tool_inventory_digest == entry.tool_inventory_digest
        and status.status == "loaded"
        and status.loaded
        and status.enforcement_mode == "enforce"
        and report is not None
        and report.runtime == entry.runtime
        and report.agent_id == entry.agent_id
        and report.runtime_binding_id == entry.runtime_binding_id
        and report.profile_id == entry.profile_id
        and report.report_digest == entry.capability_report_digest
        and report.supported
        and report.active
        and all(event.supported and event.active for event in report.events)
    )


def _entry_identity(
    activation: FrozenProductActivation,
    runtime: ProductRuntime,
) -> ProductRuntimeStatusIdentityV1:
    entry = activation.bundle.runtime_entry(runtime)
    return ProductRuntimeStatusIdentityV1(
        runtime=entry.runtime,
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        profile_id=entry.profile_id,
    )


def _ack_matches_entry(
    ack: ActivationAckV1,
    *,
    activation: FrozenProductActivation,
    runtime: ProductRuntime,
) -> bool:
    entry = activation.bundle.runtime_entry(runtime)
    return bool(
        ack.runtime == entry.runtime
        and ack.runtime_version == entry.runtime_version
        and ack.plugin_version == entry.plugin_version
        and ack.agent_id == entry.agent_id
        and ack.runtime_binding_id == entry.runtime_binding_id
        and ack.profile_id == entry.profile_id
        and ack.activation_ref_digest == activation.bundle.activation_ref_digest
        and ack.capability_digest == entry.capability_report_digest
        and ack.host_inventory_digest == entry.host_inventory_digest
        and ack.plugin_inventory_digest == entry.plugin_inventory_digest
        and ack.plugin_order_inventory_digest == entry.plugin_order_inventory_digest
        and ack.tool_inventory_digest == entry.tool_inventory_digest
    )


def _signed_ack_from_record(
    record: ProductActivationAckRecordV1,
    *,
    server_secret: bytes,
) -> ActivationAckV1:
    """Recompute one issuance token from its durable non-secret projection."""

    claims = record.unsigned_ack()
    return build_activation_ack(
        server_secret=server_secret,
        runtime=claims.runtime,
        runtime_version=claims.runtime_version,
        plugin_version=claims.plugin_version,
        agent_id=claims.agent_id,
        runtime_binding_id=claims.runtime_binding_id,
        profile_id=claims.profile_id,
        activation_ref_digest=claims.activation_ref_digest,
        capability_digest=claims.capability_digest,
        host_inventory_digest=claims.host_inventory_digest,
        plugin_inventory_digest=claims.plugin_inventory_digest,
        plugin_order_inventory_digest=claims.plugin_order_inventory_digest,
        tool_inventory_digest=claims.tool_inventory_digest,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )


def reconcile_product_runtime_observations(
    activation: FrozenProductActivation,
    store: ControlPlaneStore,
    *,
    server_secret: bytes,
    reference_time: datetime,
) -> ProductRuntimeObservationReconciliation:
    """Compare both exact Product status rows and fresh private ACKs."""

    try:
        activation.assert_unchanged()
        current = _aware_utc(reference_time, label="reference_time")
        if not activation.bundle.valid_at(current):
            raise ValueError("Product activation is not current")
        observations: list[dict[str, object]] = []
        authority_observations: list[dict[str, object]] = []
        for runtime in _PRODUCT_RUNTIMES:
            product_runtime = cast(ProductRuntime, runtime)
            entry = activation.bundle.runtime_entry(product_runtime)
            identity = _entry_identity(activation, product_runtime)
            stored = store.get_product_runtime_status(identity)
            if stored is None:
                return ProductRuntimeObservationReconciliation(
                    matched=False,
                    reason_codes=(RUNTIME_OBSERVATION_MISMATCH,),
                )
            status = ProductRuntimeStatusV2.model_validate(
                stored.model_dump(mode="json")
            )
            if not _status_matches_entry(
                status,
                activation=activation,
                runtime=runtime,
            ):
                return ProductRuntimeObservationReconciliation(
                    matched=False,
                    reason_codes=(RUNTIME_OBSERVATION_MISMATCH,),
                )
            issuance = store.get_latest_product_activation_ack(identity)
            ack = (
                None
                if issuance is None or issuance.revoked_at is not None
                else _signed_ack_from_record(
                    issuance,
                    server_secret=server_secret,
                )
            )
            if (
                ack is None
                or issuance is None
                or issuance.principal_id != entry.principal_id
                or not hmac.compare_digest(
                    issuance.token_digest,
                    activation_ack_token_digest(ack.ack_token),
                )
                or not activation_ack_matches_runtime_status(ack, status)
                or not _ack_matches_entry(
                    ack,
                    activation=activation,
                    runtime=product_runtime,
                )
                or not verify_activation_ack(
                    ack,
                    server_secret=server_secret,
                    now=current,
                )
            ):
                return ProductRuntimeObservationReconciliation(
                    matched=False,
                    reason_codes=(RUNTIME_OBSERVATION_MISMATCH,),
                )
            status_dump = status.model_dump(mode="json")
            observations.append(
                {
                    "runtime_status": status_dump,
                    "activation_ack": {
                        "token_digest": issuance.token_digest,
                        "projection": ack.token_projection(),
                    },
                }
            )
            # A new valid heartbeat may refresh the timestamp/token without
            # changing replay-stable identity, capability, or inventory facts.
            authority_observations.append(
                {
                    key: value
                    for key, value in status_dump.items()
                    if key != "last_heartbeat_at"
                }
            )
    except Exception:
        return ProductRuntimeObservationReconciliation(
            matched=False,
            reason_codes=(RUNTIME_OBSERVATION_MISMATCH,),
        )
    return ProductRuntimeObservationReconciliation(
        matched=True,
        reason_codes=(),
        observation_digest=canonical_sha256(
            {
                "activation_ref_digest": activation.bundle.activation_ref_digest,
                "observations": observations,
            }
        ),
        authority_observation_digest=canonical_sha256(
            {
                "activation_ref_digest": activation.bundle.activation_ref_digest,
                "observations": authority_observations,
            }
        ),
    )


@dataclass(frozen=True, slots=True)
class ProductActivationAuthorityService:
    """Mint and validate Product ACKs without exposing the server HMAC key."""

    activation: FrozenProductActivation
    store: ControlPlaneStore
    server_secret: bytes = field(repr=False)
    clock: Callable[[], datetime] = _now_utc

    def __post_init__(self) -> None:
        if not isinstance(self.server_secret, bytes) or len(self.server_secret) < 32:
            raise ValueError("Product activation ACK secret must be at least 32 bytes")

    def _current(self, reference_time: datetime | None = None) -> datetime:
        return _aware_utc(
            self.clock() if reference_time is None else reference_time,
            label="Product activation clock",
        )

    def _require_current_activation(self, current: datetime) -> None:
        try:
            self.activation.assert_unchanged()
        except ValueError as exc:
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT) from exc
        if not self.activation.bundle.valid_at(current):
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT)

    def _runtime_entry(
        self,
        runtime: str | None,
    ) -> tuple[ProductRuntime, RuntimeActivationEntryV1]:
        try:
            product_runtime = cast(ProductRuntime, runtime)
            entry = self.activation.bundle.runtime_entry(product_runtime)
        except (KeyError, TypeError):
            raise V21OfficialEvaluationUnavailableError(
                RUNTIME_IDENTITY_MISMATCH
            ) from None
        return product_runtime, entry

    @staticmethod
    def _auth_matches_entry(
        auth_context: AuthContext | None,
        entry: object,
    ) -> bool:
        return bool(
            auth_context is not None
            and auth_context.principal_id == getattr(entry, "principal_id")
            and auth_context.runtime == getattr(entry, "runtime")
            and auth_context.agent_id == getattr(entry, "agent_id")
        )

    def accept_heartbeat(
        self,
        runtime: str,
        heartbeat: ProductRuntimeHeartbeatV2,
        auth_context: AuthContext,
    ) -> ProductHeartbeatAcceptance:
        """Persist a server-timed heartbeat and mint exactly one 120s ACK."""

        current = self._current()
        try:
            self.activation.assert_unchanged()
        except ValueError as exc:
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT) from exc
        product_runtime, entry = self._runtime_entry(runtime)
        # Only the activated principal/agent may update or revoke this runtime
        # entry. An unrelated adapter must not invalidate another agent's ACKs.
        if not self._auth_matches_entry(auth_context, entry):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_IDENTITY_MISMATCH)
        status = ProductRuntimeStatusV2.model_validate(
            {
                **heartbeat.model_dump(mode="json"),
                "runtime": runtime,
                "principal_id": auth_context.principal_id,
                "last_heartbeat_at": current.isoformat(),
            }
        )
        identity = _entry_identity(self.activation, product_runtime)
        activation_current = self.activation.bundle.valid_at(current)
        status_matches = _status_matches_entry(
            status,
            activation=self.activation,
            runtime=runtime,
        )
        if not activation_current or not status_matches:
            # A drift heartbeat immediately revokes the previous exact-row ACK,
            # including when the caller moved to a different composite key.
            self.store.save_product_runtime_status(
                status,
                revoke_activation_acks_for=identity,
                revoked_at=current.isoformat(),
            )
            if not activation_current:
                raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT)
            raise V21OfficialEvaluationUnavailableError(RUNTIME_OBSERVATION_MISMATCH)

        bundle_expiry = _parse_utc(
            self.activation.bundle.expires_at,
            label="activation.expires_at",
        )
        entry_expiry = _parse_utc(
            getattr(entry, "expires_at"),
            label="runtime_entry.expires_at",
        )
        expires = min(
            current + timedelta(seconds=ACTIVATION_ACK_TTL_SECONDS),
            bundle_expiry,
            entry_expiry,
        )
        report = status.capability_report
        assert report is not None
        ack = build_activation_ack(
            server_secret=self.server_secret,
            runtime=product_runtime,
            runtime_version=status.runtime_version,
            plugin_version=status.plugin_version,
            agent_id=status.agent_id,
            runtime_binding_id=status.runtime_binding_id,
            profile_id=status.profile_id,
            activation_ref_digest=self.activation.bundle.activation_ref_digest,
            capability_digest=report.report_digest,
            host_inventory_digest=cast(str, status.host_inventory_digest),
            plugin_inventory_digest=status.plugin_inventory_digest,
            plugin_order_inventory_digest=status.plugin_order_inventory_digest,
            tool_inventory_digest=cast(str, status.tool_inventory_digest),
            issued_at=current.isoformat(),
            expires_at=expires.isoformat(),
        )
        persisted = self.store.save_product_runtime_status(
            status,
            activation_ack=ack,
        )
        return ProductHeartbeatAcceptance(
            runtime_status=persisted,
            activation_ack=ack,
        )

    def _enforce_fresh_runtime(
        self,
        auth_context: AuthContext | None,
        activation_ack_token: str | None,
        *,
        event: GuardEvent | None = None,
        reference_time: datetime | None = None,
    ) -> tuple[ActivationAckV1, ProductRuntimeObservationReconciliation]:
        current = self._current(reference_time)
        self._require_current_activation(current)
        runtime = None if auth_context is None else auth_context.runtime
        product_runtime, entry = self._runtime_entry(runtime)
        if not self._auth_matches_entry(auth_context, entry) or (
            event is not None
            and not all(
                (
                    event.runtime == getattr(entry, "runtime"),
                    event.security_context.agent_id == getattr(entry, "agent_id"),
                )
            )
        ):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_IDENTITY_MISMATCH)
        if activation_ack_token is None:
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_ACK_REQUIRED)

        reconciliation = reconcile_product_runtime_observations(
            self.activation,
            self.store,
            server_secret=self.server_secret,
            reference_time=current,
        )
        if not reconciliation.matched:
            raise V21OfficialEvaluationUnavailableError(RUNTIME_OBSERVATION_MISMATCH)
        identity = _entry_identity(self.activation, product_runtime)
        try:
            issuance = self.store.get_product_activation_ack(
                activation_ack_token_digest(activation_ack_token)
            )
            if issuance is None or issuance.revoked_at is not None:
                raise ValueError("activation ACK issuance is unavailable")
            ack = issuance.rebuild(activation_ack_token)
            status = self.store.get_product_runtime_status(identity)
            if status is None or not all(
                (
                    issuance.principal_id == entry.principal_id,
                    issuance.identity() == identity,
                    activation_ack_matches_runtime_status(
                        ack,
                        status,
                        require_heartbeat_time=False,
                    ),
                    _ack_matches_entry(
                        ack,
                        activation=self.activation,
                        runtime=product_runtime,
                    ),
                    verify_activation_ack(
                        ack,
                        server_secret=self.server_secret,
                        now=current,
                    ),
                )
            ):
                raise ValueError("activation ACK is not current")
        except (TypeError, ValueError):
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_ACK_NOT_CURRENT)
        except Exception:
            # Backend failures are retryable authority unavailability, not
            # malformed caller evidence.  Never expose private backend text.
            raise V21OfficialEvaluationUnavailableError(
                "V21_PRODUCT_ACTIVATION_ACK_VERIFIER_UNAVAILABLE"
            ) from None
        return ack, reconciliation

    def enforce_evaluation(
        self,
        event: GuardEvent,
        auth_context: AuthContext | None,
        activation_ack_token: str | None,
        *,
        reference_time: datetime | None = None,
    ) -> ActivationAckV1:
        ack, _ = self._enforce_fresh_runtime(
            auth_context,
            activation_ack_token,
            event=event,
            reference_time=reference_time,
        )
        return ack

    def enforce_evaluation_with_observation(
        self,
        event: GuardEvent,
        auth_context: AuthContext | None,
        activation_ack_token: str | None,
        *,
        reference_time: datetime | None = None,
    ) -> tuple[ActivationAckV1, ProductRuntimeObservationReconciliation]:
        """Validate one caller ACK and return its locked dual-runtime view."""

        return self._enforce_fresh_runtime(
            auth_context,
            activation_ack_token,
            event=event,
            reference_time=reference_time,
        )

    def enforce_release(
        self,
        auth_context: AuthContext,
        activation_ack_token: str | None,
        *,
        reference_time: datetime | None = None,
    ) -> ActivationAckV1:
        ack, _ = self._enforce_fresh_runtime(
            auth_context,
            activation_ack_token,
            reference_time=reference_time,
        )
        return ack

    def reconcile(
        self,
        *,
        reference_time: datetime | None = None,
    ) -> ProductRuntimeObservationReconciliation:
        """Return the current dual-runtime ACK/status authority observation."""

        current = self._current(reference_time)
        self._require_current_activation(current)
        return reconcile_product_runtime_observations(
            self.activation,
            self.store,
            server_secret=self.server_secret,
            reference_time=current,
        )

    def enforce_receipt(
        self,
        receipt: RuntimeOutcomeReceipt,
        auth_context: AuthContext | None,
        *,
        parent_authority: ProductDecisionAuthorityEvidenceV1,
        reference_time: datetime,
    ) -> ActivationAckV1:
        """Verify historical ACK evidence against immutable server authority.

        The caller supplies the policy evaluation time or consumed lease issue
        time, never the runtime's terminal timestamp. Delivery can follow ACK
        expiry, revocation, or activation replacement. This proves authority at
        evaluation/release; it does not assert an authoritative invocation start.
        Permanent carrier failures are ValueError; storage failures propagate.
        """

        ack = receipt.metadata.activation_ack
        if ack is None:
            raise ValueError("Product receipt requires an activation ACK")
        issuance = self.store.get_product_activation_ack(
            activation_ack_token_digest(ack.ack_token)
        )
        if issuance is None:
            raise ValueError("Product receipt ACK issuance is unavailable")
        anchor = _aware_utc(reference_time, label="receipt authority time")
        directive = parent_authority.approval_release_directive
        if not all(
            (
                auth_context is not None,
                auth_context is not None
                and auth_context.principal_id == issuance.principal_id
                and auth_context.runtime == ack.runtime
                and auth_context.agent_id == ack.agent_id,
                issuance.rebuild(ack.ack_token) == ack,
                receipt.runtime == ack.runtime == parent_authority.runtime,
                receipt.metadata.agent_id == ack.agent_id,
                receipt.links.event_id == parent_authority.event_id,
                ack.profile_id == parent_authority.profile_id,
                ack.activation_ref_digest == directive.activation_ref_digest,
                ack.capability_digest == directive.capability_digest,
                verify_activation_ack_token(
                    ack,
                    server_secret=self.server_secret,
                ),
                _parse_utc(ack.issued_at, label="activation_ack.issued_at")
                <= anchor
                < _parse_utc(ack.expires_at, label="activation_ack.expires_at"),
                issuance.revoked_at is None
                or anchor < _parse_utc(issuance.revoked_at, label="ACK revoked_at"),
            )
        ):
            raise ValueError("Product receipt ACK does not match historical authority")
        return ack


@dataclass(frozen=True, slots=True)
class ProductActivePreSelectorFuse:
    """Deprecated compatibility facade; never used by the public app."""

    activation: FrozenProductActivation
    store: ControlPlaneStore
    clock: Callable[[], datetime] = _now_utc

    def enforce(self, event: GuardEvent, auth_context: AuthContext | None) -> NoReturn:
        try:
            self.activation.assert_unchanged()
            current = _aware_utc(self.clock(), label="Product activation clock")
            if not self.activation.bundle.valid_at(current):
                raise ValueError("Product activation is not current")
        except ValueError as exc:
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT) from exc
        runtime = cast(
            ProductRuntime,
            None if auth_context is None else auth_context.runtime,
        )
        try:
            entry = self.activation.bundle.runtime_entry(runtime)
        except (KeyError, TypeError):
            raise V21OfficialEvaluationUnavailableError(
                RUNTIME_IDENTITY_MISMATCH
            ) from None
        auth_matches = bool(
            auth_context is not None
            and auth_context.principal_id == entry.principal_id
            and auth_context.runtime == entry.runtime
            and auth_context.agent_id == entry.agent_id
        )
        if not auth_matches or not all(
            (
                event.runtime == entry.runtime,
                event.security_context.agent_id == entry.agent_id,
            )
        ):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_IDENTITY_MISMATCH)
        for observed_runtime in _PRODUCT_RUNTIMES:
            product_runtime = cast(ProductRuntime, observed_runtime)
            status = self.store.get_product_runtime_status(
                _entry_identity(self.activation, product_runtime)
            )
            if status is None or not _status_matches_entry(
                status,
                activation=self.activation,
                runtime=observed_runtime,
            ):
                raise V21OfficialEvaluationUnavailableError(
                    RUNTIME_OBSERVATION_MISMATCH
                )
        raise V21OfficialEvaluationUnavailableError(SELECTOR_NOT_WIRED)


__all__ = [
    "ACTIVATION_NOT_CURRENT",
    "ACTIVATION_ACK_NOT_CURRENT",
    "ACTIVATION_ACK_REQUIRED",
    "ACTIVATION_ACK_TTL_SECONDS",
    "FrozenProductActivation",
    "ProductActivationAuthorityService",
    "ProductActivePreSelectorFuse",
    "ProductHeartbeatAcceptance",
    "ProductRuntimeObservationReconciliation",
    "RUNTIME_IDENTITY_MISMATCH",
    "RUNTIME_OBSERVATION_MISMATCH",
    "SELECTOR_NOT_WIRED",
    "load_frozen_product_activation",
    "reconcile_product_runtime_observations",
]
