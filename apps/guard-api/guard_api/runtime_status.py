"""Strict Product V2 runtime heartbeat and persisted status contracts.

The existing :class:`guard_api.models.AdapterStatusRecord` is intentionally a
legacy, latest-per-runtime telemetry shape.  The models in this module carry a
complete product identity and must be used for any identity-keyed runtime
state.  Heartbeat callers cannot provide server-owned runtime, principal, ACK,
or receipt-time facts; the route constructs ``ProductRuntimeStatusV2`` only
after authenticating the caller.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentguard_core import RuntimeCapabilityReportV2

from guard_api.models import AdapterStatus, AdapterStatusRecord

ProductRuntime = Literal["langgraph", "openclaw"]
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]

_IDENTIFIER = r"^[!-~]+$"
_RUNTIME_PROFILE_IDS: dict[ProductRuntime, str] = {
    "langgraph": "agentguard-langgraph-v2",
    "openclaw": "agentguard-openclaw-v2-restricted",
}


def _canonical_unique(values: list[str], *, label: str) -> None:
    if values != sorted(set(values)):
        raise ValueError(f"{label} must be unique and canonically sorted")


def _utc_timestamp(value: str, *, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


class ProductRuntimeStatusIdentityV1(BaseModel):
    """Complete storage key for one product runtime status row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime: ProductRuntime
    agent_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    runtime_binding_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=_IDENTIFIER,
    )
    profile_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        expected = _RUNTIME_PROFILE_IDS[self.runtime]
        if self.profile_id != expected:
            raise ValueError(
                f"{self.runtime} runtime status identity requires profile_id={expected}"
            )
        return self


class ProductRuntimeHeartbeatV2(BaseModel):
    """Caller-supplied Product V2 heartbeat without server-owned facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"]
    status: AdapterStatus
    loaded: bool
    runtime_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    agent_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    runtime_binding_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=_IDENTIFIER,
    )
    profile_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    runtime_version: str = Field(min_length=1, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=64)
    profile_digest: Sha256Digest
    adapter_artifact_digest: Sha256Digest
    reported_activation_ref_digest: Sha256Digest | None = None
    host_inventory_digest: Sha256Digest | None = None
    plugin_inventory_digest: Sha256Digest | None = None
    plugin_order_inventory_digest: Sha256Digest | None = None
    tool_inventory_digest: Sha256Digest | None = None
    capability_report: RuntimeCapabilityReportV2 | None = None
    source: str = Field(min_length=1, max_length=128)
    error: str | None = Field(default=None, min_length=1, max_length=1024)
    hook_count: int | None = Field(default=None, ge=0)
    expected_hook_count: int | None = Field(default=None, ge=0)
    hooks: list[str] = Field(default_factory=list)
    fail_closed_stages: list[str] = Field(default_factory=list)
    enforcement_mode: Literal["enforce", "observe", "disabled"]

    @field_validator("hooks", "fail_closed_stages")
    @classmethod
    def validate_canonical_lists(cls, value: list[str]) -> list[str]:
        _canonical_unique(value, label="runtime status list")
        if any(not item for item in value):
            raise ValueError("runtime status list entries must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_heartbeat(self) -> Self:
        if self.loaded != (self.status == "loaded"):
            raise ValueError("status=loaded must exactly match loaded=true")
        if self.status == "error" and self.error is None:
            raise ValueError("status=error requires an error reason")
        if self.status == "loaded" and self.error is not None:
            raise ValueError("status=loaded cannot carry an error reason")

        if self.hook_count is not None and self.hook_count != len(self.hooks):
            raise ValueError("hook_count must equal the number of hooks")
        if self.expected_hook_count is not None and self.expected_hook_count < len(
            self.hooks
        ):
            raise ValueError("expected_hook_count cannot be smaller than hooks")

        report = self.capability_report
        if report is not None:
            identity_checks = (
                (self.agent_id, report.agent_id, "agent_id"),
                (
                    self.runtime_binding_id,
                    report.runtime_binding_id,
                    "runtime_binding_id",
                ),
                (self.profile_id, report.profile_id, "profile_id"),
            )
            for outer, inner, label in identity_checks:
                if outer != inner:
                    raise ValueError(f"capability_report differs from {label}")

            runtime = report.runtime
            expected_profile = _RUNTIME_PROFILE_IDS[runtime]
            if self.profile_id != expected_profile:
                raise ValueError(
                    f"{runtime} product heartbeat requires profile_id="
                    f"{expected_profile}"
                )
            if report.active and (
                not self.loaded or self.enforcement_mode != "enforce"
            ):
                raise ValueError(
                    "an active capability report requires loaded status and "
                    "enforcement_mode=enforce"
                )

        if self.loaded:
            required_observations = (
                (self.host_inventory_digest, "host_inventory_digest"),
                (self.tool_inventory_digest, "tool_inventory_digest"),
                (report, "capability_report"),
            )
            missing = [label for value, label in required_observations if value is None]
            if missing:
                raise ValueError(
                    "loaded product heartbeat requires " + ", ".join(missing)
                )
            if report is not None and report.runtime == "openclaw":
                plugin_inventories = (
                    self.plugin_inventory_digest,
                    self.plugin_order_inventory_digest,
                )
                if any(value is None for value in plugin_inventories):
                    raise ValueError(
                        "loaded OpenClaw product heartbeat requires plugin inventories"
                    )
        return self


class ProductRuntimeStatusV2(ProductRuntimeHeartbeatV2):
    """Server-enriched, persistable Product V2 runtime status."""

    runtime: ProductRuntime
    principal_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    last_heartbeat_at: str

    @field_validator("last_heartbeat_at")
    @classmethod
    def normalize_last_heartbeat_at(cls, value: str) -> str:
        return _utc_timestamp(value, label="last_heartbeat_at")

    @model_validator(mode="after")
    def validate_server_identity(self) -> Self:
        if (
            self.capability_report is not None
            and self.runtime != self.capability_report.runtime
        ):
            raise ValueError("runtime differs from capability_report.runtime")
        expected_profile = _RUNTIME_PROFILE_IDS[self.runtime]
        if self.profile_id != expected_profile:
            raise ValueError(
                f"{self.runtime} persisted runtime status requires profile_id="
                f"{expected_profile}"
            )
        return self

    def identity(self) -> ProductRuntimeStatusIdentityV1:
        """Return the complete composite storage identity."""

        return ProductRuntimeStatusIdentityV1(
            runtime=self.runtime,
            agent_id=self.agent_id,
            runtime_binding_id=self.runtime_binding_id,
            profile_id=self.profile_id,
        )

    def to_legacy_adapter_status(self) -> AdapterStatusRecord:
        """Project telemetry into the existing non-authoritative wire shape.

        Product identity, inventories, activation observations, and future ACK
        facts deliberately remain absent from the top-level legacy record.
        """

        product_capabilities = {
            "event_types": (
                []
                if self.capability_report is None
                else [event.event_type for event in self.capability_report.events]
            )
        }
        return AdapterStatusRecord(
            status=self.status,
            loaded=self.loaded,
            hook_count=self.hook_count,
            expected_hook_count=self.expected_hook_count,
            last_heartbeat_at=self.last_heartbeat_at,
            error=self.error,
            source=self.source,
            runtime_id=self.runtime_id,
            agent_id=self.agent_id,
            plugin_version=self.plugin_version,
            runtime_version=self.runtime_version,
            capabilities=product_capabilities,
            hooks=list(self.hooks),
            fail_closed_stages=list(self.fail_closed_stages),
            enforcement_mode=self.enforcement_mode,
        )


__all__ = [
    "ProductRuntime",
    "ProductRuntimeHeartbeatV2",
    "ProductRuntimeStatusIdentityV1",
    "ProductRuntimeStatusV2",
]
