"""Process-frozen LangGraph competition activation loading and validation."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentguard_core import (
    CompetitionActivationManifestV1,
    DecisionAuthorityEvidenceV1,
    verify_competition_activation_manifest,
)

from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.integrity import canonical_sha256

_MAX_ACTIVATION_BYTES = 64 * 1024


class CriticalDecisionEvidenceError(RuntimeError):
    """Critical authority evidence could not be preserved byte-for-byte."""


def strict_decision_authority_envelope(value: object) -> dict[str, Any]:
    """Validate and normalize the critical sibling without truncation/drop."""

    if not isinstance(value, dict) or set(value) != {"decision_authority"}:
        raise CriticalDecisionEvidenceError(
            "decision authority evidence must use its reserved sibling key"
        )
    raw_envelope = value.get("decision_authority")
    if not isinstance(raw_envelope, dict) or set(raw_envelope) != {
        "schema_version",
        "payload",
    }:
        raise CriticalDecisionEvidenceError(
            "decision authority evidence envelope is malformed"
        )
    if raw_envelope.get("schema_version") != "1.0":
        raise CriticalDecisionEvidenceError(
            "decision authority evidence schema version is unsupported"
        )
    try:
        payload = DecisionAuthorityEvidenceV1.model_validate(
            raw_envelope.get("payload")
        )
    except ValueError as exc:
        raise CriticalDecisionEvidenceError(
            "decision authority evidence payload is invalid"
        ) from exc
    return {
        "decision_authority": {
            "schema_version": "1.0",
            "payload": payload.model_dump(mode="json"),
        }
    }


@dataclass(frozen=True, slots=True)
class FrozenCompetitionActivation:
    """Verified activation bytes captured once during process construction."""

    manifest: CompetitionActivationManifestV1
    source_path: str
    content_digest: str


def load_frozen_competition_activation(
    settings: GuardApiSettings,
) -> FrozenCompetitionActivation | None:
    """Load one strict server-owned activation without following symlinks.

    Off and legacy-reference shadow profiles need no competition activation.
    When a path is supplied, every mode validates the exact same immutable
    manifest contract.  Official modes require a path through startup settings.
    """

    path_value = settings.v21_competition_activation_path
    mode = settings.effective_v21_mode()
    if path_value is None:
        if mode in {"limited_enable", "active"}:
            raise GuardApiConfigurationError(
                "competition V2.1 official mode requires an activation manifest"
            )
        return None
    path = Path(path_value)
    if not path.is_absolute():
        raise GuardApiConfigurationError(
            "competition activation path must be absolute"
        )
    try:
        before = path.lstat()
    except OSError as exc:
        raise GuardApiConfigurationError(
            "competition activation manifest is unavailable"
        ) from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise GuardApiConfigurationError(
            "competition activation manifest must be a regular non-symlink file"
        )
    if before.st_uid != os.geteuid():
        raise GuardApiConfigurationError(
            "competition activation manifest must be owned by the Guard API user"
        )
    if before.st_mode & 0o222:
        raise GuardApiConfigurationError(
            "competition activation manifest must be read-only"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise GuardApiConfigurationError(
                    "competition activation manifest changed while opening"
                )
            payload = os.read(descriptor, _MAX_ACTIVATION_BYTES + 1)
        finally:
            os.close(descriptor)
    except GuardApiConfigurationError:
        raise
    except OSError as exc:
        raise GuardApiConfigurationError(
            "competition activation manifest could not be read"
        ) from exc
    if not payload or len(payload) > _MAX_ACTIVATION_BYTES:
        raise GuardApiConfigurationError(
            "competition activation manifest has an invalid size"
        )
    try:
        raw = json.loads(payload)
        manifest = CompetitionActivationManifestV1.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GuardApiConfigurationError(
            "competition activation manifest is invalid"
        ) from exc
    secret = settings.v21_shadow_server_secret_bytes()
    if secret is None or not verify_competition_activation_manifest(
        manifest,
        server_secret=secret,
    ):
        raise GuardApiConfigurationError(
            "competition activation manifest signature is invalid"
        )
    expected_basis = {
        "limited_enable": "path_allowlist",
        "active": "profile_all",
    }.get(mode)
    if expected_basis is not None and manifest.selection_basis != expected_basis:
        raise GuardApiConfigurationError(
            "competition activation selection basis does not match V2.1 mode"
        )
    return FrozenCompetitionActivation(
        manifest=manifest,
        source_path=str(path),
        content_digest=canonical_sha256(raw),
    )


__all__ = [
    "CriticalDecisionEvidenceError",
    "FrozenCompetitionActivation",
    "load_frozen_competition_activation",
    "strict_decision_authority_envelope",
]
