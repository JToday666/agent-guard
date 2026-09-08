"""Protected local expectations and independently observed LangGraph identity."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from .activation_ack import DIGEST_PATTERN, IDENTIFIER_PATTERN, ProductActivationError

PRODUCT_EVENT_TYPES = (
    "context_assembled",
    "memory_write_proposed",
    "message_send_proposed",
    "model_input_prepared",
    "model_output_produced",
    "tool_call_proposed",
    "tool_result_produced",
)
_ENFORCEMENT = {
    "context_assembled": "pre_execution_c1",
    "memory_write_proposed": "pre_execution_c3",
    "message_send_proposed": "pre_execution_c3",
    "model_input_prepared": "pre_execution_c1",
    "model_output_produced": "post_execution_isolation",
    "tool_call_proposed": "pre_execution_c3",
    "tool_result_produced": "post_execution_isolation",
}
_MAX_MANIFEST_BYTES = 128 * 1024


def canonical_sha256(value: Any) -> str:
    """Match the repository's restricted canonical JSON, without Core imports."""

    def validate(item: Any) -> None:
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for entry in item:
                validate(entry)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for entry in item.values():
                validate(entry)
            return
        raise ProductActivationError("invalid_canonical_value")

    try:
        validate(value)
        body = json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
    except ProductActivationError:
        raise
    except Exception:
        raise ProductActivationError("invalid_canonical_value") from None


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )


class LangGraphEventCapabilityV2(_FrozenModel):
    event_type: str
    supported: bool
    active: bool
    enforcement: str
    residual_boundaries: tuple[str, ...]

    @field_validator("residual_boundaries", mode="before")
    @classmethod
    def _freeze_residual(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class LangGraphCapabilityReportV2(_FrozenModel):
    schema_version: Literal["2.0"]
    runtime: Literal["langgraph"]
    agent_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    runtime_binding_id: str = Field(
        min_length=1, max_length=256, pattern=IDENTIFIER_PATTERN
    )
    profile_id: Literal["agentguard-langgraph-v2"]
    supported: bool
    active: bool
    c0_registration: bool
    c1_pre_execution_interception: bool
    c2_correlation: bool
    c3_atomic_replace_and_seal: bool
    c4_outcome_receipts: bool
    events: tuple[LangGraphEventCapabilityV2, ...]
    residual_boundaries: tuple[str, ...]
    report_digest: str = Field(pattern=DIGEST_PATTERN)

    @field_validator("events", "residual_boundaries", mode="before")
    @classmethod
    def _freeze_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _validate_profile(self) -> LangGraphCapabilityReportV2:
        if tuple(event.event_type for event in self.events) != PRODUCT_EVENT_TYPES:
            raise ValueError("capability event set/order differs from frozen profile")
        if not all(
            (
                self.c0_registration,
                self.c1_pre_execution_interception,
                self.c2_correlation,
                self.c3_atomic_replace_and_seal,
                self.c4_outcome_receipts,
            )
        ):
            raise ValueError("capability levels differ from frozen LangGraph profile")
        if self.active and not self.supported:
            raise ValueError("active capability requires support")
        if self.residual_boundaries or any(
            event.residual_boundaries for event in self.events
        ):
            raise ValueError("LangGraph cannot carry residual boundaries")
        if any(
            not event.supported
            or event.active != self.active
            or event.enforcement != _ENFORCEMENT[event.event_type]
            for event in self.events
        ):
            raise ValueError("event enforcement differs from frozen LangGraph profile")
        if (
            canonical_sha256(self.model_dump(mode="json", exclude={"report_digest"}))
            != self.report_digest
        ):
            raise ValueError("capability report digest mismatch")
        return self


class ProductRuntimeObservation(_FrozenModel):
    runtime: Literal["langgraph"]
    runtime_version: str
    plugin_version: str
    loaded: bool
    enforcement_mode: Literal["enforce", "observe", "disabled"]
    adapter_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    host_inventory_digest: str = Field(pattern=DIGEST_PATTERN)
    tool_inventory_digest: str = Field(pattern=DIGEST_PATTERN)
    capability_report: LangGraphCapabilityReportV2


class ProductActivationManifest(_FrozenModel):
    schema_version: Literal["1.0"]
    runtime: Literal["langgraph"]
    runtime_version: Literal["1.2.7"]
    plugin_version: Literal["0.1.0rc1"]
    principal_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    agent_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    runtime_binding_id: str = Field(
        min_length=1, max_length=256, pattern=IDENTIFIER_PATTERN
    )
    profile_id: Literal["agentguard-langgraph-v2"]
    profile_digest: str = Field(pattern=DIGEST_PATTERN)
    activation_ref_digest: str = Field(pattern=DIGEST_PATTERN)
    adapter_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    capability_report_digest: str = Field(pattern=DIGEST_PATTERN)
    host_inventory_digest: str = Field(pattern=DIGEST_PATTERN)
    tool_inventory_digest: str = Field(pattern=DIGEST_PATTERN)

    _source_path: Path | None = PrivateAttr(default=None)
    _source_fingerprint: tuple[Any, ...] | None = PrivateAttr(default=None)

    @classmethod
    def from_file(cls, path: str | Path) -> ProductActivationManifest:
        normalized = _manifest_path(path)
        body, fingerprint = _read_protected_manifest(normalized)
        try:
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
            result = cls.model_validate(payload)
        except Exception:
            raise ProductActivationError("manifest_invalid") from None
        result._source_path = normalized
        result._source_fingerprint = fingerprint
        return result

    def assert_unchanged(self) -> None:
        if self._source_path is None or self._source_fingerprint is None:
            raise ProductActivationError("manifest_not_file_backed")
        try:
            _, fingerprint = _read_protected_manifest(self._source_path)
            if fingerprint != self._source_fingerprint:
                raise ProductActivationError("manifest_changed")
        except Exception:
            raise ProductActivationError("manifest_changed") from None

    def make_heartbeat(self, observation: ProductRuntimeObservation) -> dict[str, Any]:
        try:
            observed = ProductRuntimeObservation.model_validate(observation)
        except Exception:
            raise ProductActivationError("observation_invalid") from None
        report = observed.capability_report
        pairs = (
            (observed.runtime, self.runtime),
            (observed.runtime_version, self.runtime_version),
            (observed.plugin_version, self.plugin_version),
            (observed.adapter_artifact_digest, self.adapter_artifact_digest),
            (observed.host_inventory_digest, self.host_inventory_digest),
            (observed.tool_inventory_digest, self.tool_inventory_digest),
            (report.agent_id, self.agent_id),
            (report.runtime_binding_id, self.runtime_binding_id),
            (report.profile_id, self.profile_id),
            (report.report_digest, self.capability_report_digest),
        )
        if (
            not observed.loaded
            or observed.enforcement_mode != "enforce"
            or not report.supported
            or not report.active
            or any(actual != expected for actual, expected in pairs)
        ):
            raise ProductActivationError("observation_drift")
        return {
            "schema_version": "2.0",
            "status": "loaded",
            "loaded": True,
            "runtime_id": "langgraph",
            "agent_id": self.agent_id,
            "runtime_binding_id": self.runtime_binding_id,
            "profile_id": self.profile_id,
            "runtime_version": observed.runtime_version,
            "plugin_version": observed.plugin_version,
            "profile_digest": self.profile_digest,
            "adapter_artifact_digest": observed.adapter_artifact_digest,
            "reported_activation_ref_digest": self.activation_ref_digest,
            "host_inventory_digest": observed.host_inventory_digest,
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
            "tool_inventory_digest": observed.tool_inventory_digest,
            "capability_report": report.model_dump(mode="json"),
            "source": "agentguard-langgraph-adapter",
            "enforcement_mode": "enforce",
        }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _manifest_path(value: str | Path) -> Path:
    try:
        raw = os.fspath(value)
        if (
            not isinstance(raw, str)
            or not os.path.isabs(raw)
            or os.path.normpath(raw) != raw
        ):
            raise ValueError
        return Path(raw)
    except (ValueError, TypeError):
        raise ProductActivationError("manifest_invalid_path") from None


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_protected_manifest(path: Path) -> tuple[bytes, tuple[Any, ...]]:
    descriptor: int | None = None
    try:
        owner = os.getuid()
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != owner
            or stat.S_IMODE(parent.st_mode) != 0o700
            or path.resolve(strict=True) != path
        ):
            raise ProductActivationError("manifest_insecure")
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise ProductActivationError("manifest_insecure")
        if before.st_size > _MAX_MANIFEST_BYTES:
            raise ProductActivationError("manifest_too_large")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, _MAX_MANIFEST_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_MANIFEST_BYTES:
                raise ProductActivationError("manifest_too_large")
        after = os.fstat(descriptor)
        parent_after = path.parent.lstat()
        if (
            _stat_identity(before) != _stat_identity(after)
            or _stat_identity(path.lstat()) != _stat_identity(after)
            or (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode)
            != (
                parent_after.st_dev,
                parent_after.st_ino,
                parent_after.st_uid,
                parent_after.st_mode,
            )
            or path.resolve(strict=True) != path
        ):
            raise ProductActivationError("manifest_changed")
        body = b"".join(chunks)
        return body, (
            (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode),
            _stat_identity(after),
            hashlib.sha256(body).hexdigest(),
        )
    except ProductActivationError:
        raise
    except Exception:
        raise ProductActivationError("manifest_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
