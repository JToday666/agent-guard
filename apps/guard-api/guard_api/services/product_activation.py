"""Process-frozen Product V2 activation and pre-selector safety checks.

This module deliberately stops before authority selection.  A valid signed
bundle and matching runtime observations are necessary inputs, but are not by
themselves permission to evaluate or release an action.  Until the Product V2
selector is wired, :class:`ProductActivePreSelectorFuse` therefore terminates
every request with a stable 503 reason code after completing the read-only
checks below.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from agentguard_core import GuardEvent, ProductActivationBundleV1
from agentguard_core import verify_product_activation_bundle

from guard_api.auth import AuthContext
from guard_api.runtime_status import (
    ProductRuntimeStatusIdentityV1,
    ProductRuntimeStatusV2,
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


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


def reconcile_product_runtime_observations(
    activation: FrozenProductActivation,
    store: ControlPlaneStore,
) -> ProductRuntimeObservationReconciliation:
    """Compare both exact Product status rows without legacy/freshness/ACK input."""

    try:
        activation.assert_unchanged()
        observations: list[dict[str, object]] = []
        for runtime in _PRODUCT_RUNTIMES:
            entry = activation.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
            identity = ProductRuntimeStatusIdentityV1(
                runtime=entry.runtime,
                agent_id=entry.agent_id,
                runtime_binding_id=entry.runtime_binding_id,
                profile_id=entry.profile_id,
            )
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
            observations.append(status.model_dump(mode="json"))
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
    )


@dataclass(frozen=True, slots=True)
class ProductActivePreSelectorFuse:
    """Read-only top-of-evaluate fuse for the not-yet-wired Product selector."""

    activation: FrozenProductActivation
    store: ControlPlaneStore
    clock: Callable[[], datetime] = _now_utc

    def enforce(self, event: GuardEvent, auth_context: AuthContext | None) -> NoReturn:
        try:
            self.activation.assert_unchanged()
        except ValueError as exc:
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT) from exc
        current = self.clock()
        if not self.activation.bundle.valid_at(current):
            raise V21OfficialEvaluationUnavailableError(ACTIVATION_NOT_CURRENT)

        runtime = None if auth_context is None else auth_context.runtime
        try:
            entry = self.activation.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
        except (KeyError, TypeError):
            raise V21OfficialEvaluationUnavailableError(
                RUNTIME_IDENTITY_MISMATCH
            ) from None
        if auth_context is None or not all(
            (
                auth_context.principal_id == entry.principal_id,
                auth_context.runtime == entry.runtime,
                auth_context.agent_id == entry.agent_id,
                event.runtime == entry.runtime,
                event.security_context.agent_id == entry.agent_id,
            )
        ):
            raise V21OfficialEvaluationUnavailableError(RUNTIME_IDENTITY_MISMATCH)

        reconciliation = reconcile_product_runtime_observations(
            self.activation,
            self.store,
        )
        if not reconciliation.matched:
            raise V21OfficialEvaluationUnavailableError(RUNTIME_OBSERVATION_MISMATCH)
        raise V21OfficialEvaluationUnavailableError(SELECTOR_NOT_WIRED)


__all__ = [
    "ACTIVATION_NOT_CURRENT",
    "FrozenProductActivation",
    "ProductActivePreSelectorFuse",
    "ProductRuntimeObservationReconciliation",
    "RUNTIME_IDENTITY_MISMATCH",
    "RUNTIME_OBSERVATION_MISMATCH",
    "SELECTOR_NOT_WIRED",
    "load_frozen_product_activation",
    "reconcile_product_runtime_observations",
]
