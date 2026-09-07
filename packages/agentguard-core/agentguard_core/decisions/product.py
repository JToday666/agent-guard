"""Runtime-neutral product V2 activation and release contracts.

The competition activation contract is intentionally not reused here.  Product
activation binds one immutable candidate to both supported runtimes while the
competition manifest remains frozen to its original LangGraph profile.

All signatures use the repository's restricted canonical JSON implementation
and a domain-separated HMAC-SHA256.  The models are pure and perform no file,
environment, clock, network, or store access.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Sequence, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..actions.canonical_json import canonical_hmac_sha256, canonical_sha256
from ..events.payloads import GuardEventType
from .activation_ack import ActivationAckV1, ProductRuntime
from .competition import (
    DecisionAuthority,
    V21AuthoritySelectionError,
    V21SelectionEligibility,
    V21SelectionResult,
    decision_semantic_projection,
)
from .evidence import CoverageMap, FastAssessment
from .models import ApprovalIntent, Decision, GuardDecision

__all__ = [
    "ACTIVATION_ACK_SIGNATURE_DOMAIN",
    "PRODUCT_ACTIVATION_SIGNATURE_DOMAIN",
    "RESIDUAL_RISK_SIGNATURE_DOMAIN",
    "ROLLOUT_ADMISSION_SIGNATURE_DOMAIN",
    "OPENCLAW_RESIDUAL_BOUNDARIES",
    "PRODUCT_EVENT_TYPES",
    "ActivationAckV1",
    "ApprovalReleaseDirectiveV2",
    "ProductActivationBundleV1",
    "ProductDecisionAuthorityEvidenceV1",
    "ResidualRiskAcceptanceV1",
    "RolloutAdmissionRecordV1",
    "RuntimeActivationEntryV1",
    "RuntimeCapabilityReportV2",
    "RuntimeEventCapabilityV2",
    "OpenClawFrozenToolV1",
    "OpenClawInventoryDigestsV1",
    "build_activation_ack",
    "build_approval_release_directive",
    "build_product_activation_bundle",
    "build_product_decision_authority_evidence",
    "build_residual_risk_acceptance",
    "build_rollout_admission_record",
    "build_runtime_capability_report",
    "build_openclaw_inventory_digests",
    "openclaw_tool_event_type",
    "openclaw_event_residual_boundaries",
    "legacy_approval_release_projection",
    "product_decision_authority_envelope",
    "select_product_v21_authority",
    "verify_activation_ack",
    "verify_activation_ack_token",
    "verify_product_activation_bundle",
    "verify_residual_risk_acceptance",
    "verify_rollout_admission_record",
]

PRODUCT_ACTIVATION_SIGNATURE_DOMAIN = "agentguard/product-activation/v1"
ROLLOUT_ADMISSION_SIGNATURE_DOMAIN = "agentguard/rollout-admission/v1"
RESIDUAL_RISK_SIGNATURE_DOMAIN = "agentguard/residual-risk-acceptance/v1"
ACTIVATION_ACK_SIGNATURE_DOMAIN = "agentguard/activation-ack/v1"

PRODUCT_EVENT_TYPES: tuple[GuardEventType, ...] = tuple(
    sorted(
        (
            "tool_call_proposed",
            "context_assembled",
            "model_input_prepared",
            "model_output_produced",
            "tool_result_produced",
            "memory_write_proposed",
            "message_send_proposed",
        )
    )
)  # type: ignore[assignment]

OpenClawResidualBoundary = Literal[
    "openclaw_has_no_authoritative_invocation_start_hook",
    "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
    "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
    "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
    "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
]

OPENCLAW_RESIDUAL_BOUNDARIES: tuple[OpenClawResidualBoundary, ...] = (
    "openclaw_has_no_authoritative_invocation_start_hook",
    "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
    "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
    "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
    "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
)
_OPENCLAW_EVENT_RESIDUAL_BOUNDARIES: dict[
    GuardEventType, tuple[OpenClawResidualBoundary, ...]
] = {
    "context_assembled": (),
    "memory_write_proposed": (
        OPENCLAW_RESIDUAL_BOUNDARIES[0],
        OPENCLAW_RESIDUAL_BOUNDARIES[1],
        OPENCLAW_RESIDUAL_BOUNDARIES[3],
    ),
    "message_send_proposed": (
        OPENCLAW_RESIDUAL_BOUNDARIES[0],
        OPENCLAW_RESIDUAL_BOUNDARIES[1],
        OPENCLAW_RESIDUAL_BOUNDARIES[2],
    ),
    "model_input_prepared": (),
    "model_output_produced": (),
    "tool_call_proposed": (
        OPENCLAW_RESIDUAL_BOUNDARIES[0],
        OPENCLAW_RESIDUAL_BOUNDARIES[1],
    ),
    "tool_result_produced": (OPENCLAW_RESIDUAL_BOUNDARIES[4],),
}

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE = r"^hmac-sha256:[0-9a-f]{64}$"
_RUNTIME_ORDER = {"langgraph": 0, "openclaw": 1}
_RUNTIME_PROFILE_IDS = {
    "langgraph": "agentguard-langgraph-v2",
    "openclaw": "agentguard-openclaw-v2-restricted",
}
_RUNTIME_EVENT_ENFORCEMENT: dict[
    str,
    dict[GuardEventType, str],
] = {
    "langgraph": {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c3",
        "message_send_proposed": "pre_execution_c3",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c3",
        "tool_result_produced": "post_execution_isolation",
    },
    "openclaw": {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": "pre_execution_c1",
        "message_send_proposed": "pre_execution_c1",
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": "pre_execution_c1",
        "tool_result_produced": "post_execution_isolation",
    },
}
_DECISION_RANK: dict[Decision, int] = {"allow": 0, "ask": 1, "deny": 2}
_MEMORY_WRITE_PATTERNS = (
    re.compile(
        r"(?:^|[._:-])memory[._:-]"
        r"(?:write|add|append|create|save|set|update|upsert)(?:$|[._:-])"
    ),
    re.compile(
        r"(?:^|[._:-])(?:write|add|append|create|save|set|update|upsert)"
        r"[._:-]memory(?:$|[._:-])"
    ),
)

ApprovalReleaseModeV2 = Literal[
    "not_applicable", "forbidden", "strong_binding", "restricted_allow_once"
]


def _canonical_unique(values: Sequence[str], *, label: str) -> None:
    if list(values) != sorted(set(values)):
        raise ValueError(f"{label} must be unique and canonically sorted")


def _parse_utc(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_window(
    issued_at: str,
    expires_at: str,
    *,
    maximum: timedelta | None,
) -> None:
    issued = _parse_utc(issued_at, label="issued_at")
    expires = _parse_utc(expires_at, label="expires_at")
    if expires <= issued:
        raise ValueError("expires_at must be later than issued_at")
    if maximum is not None and expires - issued > maximum:
        raise ValueError("validity window exceeds the contract maximum")


def _require_secret(secret: bytes, *, label: str) -> None:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError(f"{label} must be at least 32 bytes")


def openclaw_event_residual_boundaries(
    event_type: GuardEventType,
) -> tuple[OpenClawResidualBoundary, ...]:
    """Return the frozen residual-risk projection for one OpenClaw boundary."""

    return _OPENCLAW_EVENT_RESIDUAL_BOUNDARIES[event_type]


def _runtime_capability_events_json_schema(runtime: ProductRuntime) -> dict[str, Any]:
    return {
        "minItems": len(PRODUCT_EVENT_TYPES),
        "maxItems": len(PRODUCT_EVENT_TYPES),
        "prefixItems": [
            {
                "properties": {
                    "event_type": {"const": event_type},
                    "supported": {"const": True},
                    "enforcement": {
                        "const": _RUNTIME_EVENT_ENFORCEMENT[runtime][event_type]
                    },
                    "residual_boundaries": {
                        "const": (
                            list(openclaw_event_residual_boundaries(event_type))
                            if runtime == "openclaw"
                            else []
                        )
                    },
                },
                "required": [
                    "event_type",
                    "supported",
                    "active",
                    "enforcement",
                    "residual_boundaries",
                ],
            }
            for event_type in PRODUCT_EVENT_TYPES
        ],
    }


class RuntimeEventCapabilityV2(BaseModel):
    """One runtime's truthful capability at a concrete GuardEvent boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: GuardEventType
    supported: bool
    active: bool
    enforcement: Literal[
        "observation",
        "pre_execution_c1",
        "pre_execution_c3",
        "post_execution_isolation",
        "not_supported",
    ]
    residual_boundaries: list[OpenClawResidualBoundary]

    @model_validator(mode="after")
    def validate_semantics(self) -> "RuntimeEventCapabilityV2":
        _canonical_unique(self.residual_boundaries, label="residual_boundaries")
        if self.active and not self.supported:
            raise ValueError("an active event capability must be supported")
        if self.supported == (self.enforcement == "not_supported"):
            raise ValueError("supported and enforcement are inconsistent")
        return self


class RuntimeCapabilityReportV2(BaseModel):
    """Runtime capability report separating support from activation state."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra=cast(
            dict[str, Any],
            {
                "allOf": [
                    {
                        "if": {
                            "properties": {"runtime": {"const": "langgraph"}},
                            "required": ["runtime"],
                        },
                        "then": {
                            "properties": {
                                "profile_id": {"const": "agentguard-langgraph-v2"},
                                "c0_registration": {"const": True},
                                "c1_pre_execution_interception": {"const": True},
                                "c2_correlation": {"const": True},
                                "c3_atomic_replace_and_seal": {"const": True},
                                "c4_outcome_receipts": {"const": True},
                                "events": _runtime_capability_events_json_schema(
                                    "langgraph"
                                ),
                                "residual_boundaries": {"const": []},
                            },
                            "required": ["residual_boundaries"],
                        },
                    },
                    {
                        "if": {
                            "properties": {"runtime": {"const": "openclaw"}},
                            "required": ["runtime"],
                        },
                        "then": {
                            "properties": {
                                "profile_id": {
                                    "const": "agentguard-openclaw-v2-restricted"
                                },
                                "c0_registration": {"const": True},
                                "c1_pre_execution_interception": {"const": True},
                                "c2_correlation": {"const": True},
                                "c3_atomic_replace_and_seal": {"const": False},
                                "c4_outcome_receipts": {"const": True},
                                "events": _runtime_capability_events_json_schema(
                                    "openclaw"
                                ),
                                "residual_boundaries": {
                                    "const": list(OPENCLAW_RESIDUAL_BOUNDARIES)
                                },
                            },
                            "required": ["residual_boundaries"],
                        },
                    },
                    {
                        "if": {
                            "properties": {"active": {"const": True}},
                            "required": ["active"],
                        },
                        "then": {
                            "properties": {
                                "supported": {"const": True},
                                "events": {
                                    "items": {
                                        "properties": {"active": {"const": True}},
                                        "required": ["active"],
                                    }
                                },
                            }
                        },
                    },
                    {
                        "if": {
                            "properties": {"active": {"const": False}},
                            "required": ["active"],
                        },
                        "then": {
                            "properties": {
                                "events": {
                                    "items": {
                                        "properties": {"active": {"const": False}},
                                        "required": ["active"],
                                    }
                                }
                            }
                        },
                    },
                ]
            },
        ),
    )

    schema_version: Literal["2.0"] = "2.0"
    runtime: ProductRuntime
    agent_id: str = Field(min_length=1, max_length=128)
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    profile_id: str = Field(min_length=1, max_length=128)
    supported: bool
    active: bool
    c0_registration: bool
    c1_pre_execution_interception: bool
    c2_correlation: bool
    c3_atomic_replace_and_seal: bool
    c4_outcome_receipts: bool
    events: list[RuntimeEventCapabilityV2]
    residual_boundaries: list[OpenClawResidualBoundary]
    report_digest: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def validate_report(self) -> "RuntimeCapabilityReportV2":
        event_types = [item.event_type for item in self.events]
        if event_types != list(PRODUCT_EVENT_TYPES):
            raise ValueError(
                "events must contain all product event types in canonical order"
            )
        _canonical_unique(self.residual_boundaries, label="residual_boundaries")
        expected_profile_id = _RUNTIME_PROFILE_IDS[self.runtime]
        if self.profile_id != expected_profile_id:
            raise ValueError(
                f"{self.runtime} capability report requires profile_id="
                f"{expected_profile_id}"
            )
        if self.active and not self.supported:
            raise ValueError("an active runtime must be supported")
        if self.runtime == "openclaw" and self.c3_atomic_replace_and_seal:
            raise ValueError("OpenClaw must not claim C3 atomic replace-and-seal")
        expected_capabilities = (
            True,
            True,
            True,
            self.runtime == "langgraph",
            True,
        )
        actual_capabilities = (
            self.c0_registration,
            self.c1_pre_execution_interception,
            self.c2_correlation,
            self.c3_atomic_replace_and_seal,
            self.c4_outcome_receipts,
        )
        if actual_capabilities != expected_capabilities:
            raise ValueError(
                f"{self.runtime} capability report does not match the frozen C0-C4 profile"
            )
        expected_enforcement = _RUNTIME_EVENT_ENFORCEMENT[self.runtime]
        for event in self.events:
            if not event.supported:
                raise ValueError(
                    f"{self.runtime} product profile requires support for "
                    f"{event.event_type}"
                )
            if event.active != self.active:
                raise ValueError(
                    "event active state must match the runtime active state for "
                    f"{event.event_type}"
                )
            if event.enforcement != expected_enforcement[event.event_type]:
                raise ValueError(
                    f"{self.runtime} enforcement for {event.event_type} must be "
                    f"{expected_enforcement[event.event_type]}"
                )
        if self.runtime == "openclaw":
            if tuple(self.residual_boundaries) != OPENCLAW_RESIDUAL_BOUNDARIES:
                raise ValueError(
                    "OpenClaw capability report requires the frozen residual boundaries"
                )
            for event in self.events:
                if tuple(event.residual_boundaries) != (
                    openclaw_event_residual_boundaries(event.event_type)
                ):
                    raise ValueError(
                        "OpenClaw event capability residual boundaries do not match "
                        f"{event.event_type}"
                    )
        elif self.residual_boundaries or any(
            event.residual_boundaries for event in self.events
        ):
            raise ValueError(
                "LangGraph capability report cannot carry residual boundaries"
            )
        expected = canonical_sha256(self.digest_projection())
        if not hmac.compare_digest(expected, self.report_digest):
            raise ValueError("report_digest does not match capability report")
        return self

    def digest_projection(self) -> dict[str, Any]:
        dumped = self.model_dump(mode="json", exclude={"report_digest"})
        return {key: dumped[key] for key in sorted(dumped)}


def openclaw_tool_event_type(
    tool_id: str,
) -> Literal["tool_call_proposed", "memory_write_proposed"]:
    """Return the legacy name heuristic for non-official callers.

    Official activation never uses this helper: the signed frozen inventory
    carries an explicit ``event_type`` for every tool.  Keeping the helper
    preserves the pre-RC API without allowing a tool name to become an
    authority input.
    """

    normalized = tool_id.strip().lower()
    if any(pattern.search(normalized) for pattern in _MEMORY_WRITE_PATTERNS):
        return "memory_write_proposed"
    return "tool_call_proposed"


class OpenClawFrozenToolV1(BaseModel):
    """One complete, fixture-backed tool in the signed OpenClaw inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=256)
    source_plugin_id: str = Field(min_length=1, max_length=256)
    input_schema_digest: str = Field(pattern=_DIGEST)
    event_type: Literal["tool_call_proposed", "memory_write_proposed"]
    fixture_id: str = Field(min_length=1, max_length=320)

    @model_validator(mode="after")
    def validate_tool(self) -> "OpenClawFrozenToolV1":
        expected_fixture = f"openclaw:{self.tool_id}:restricted-v1"
        if self.fixture_id != expected_fixture:
            raise ValueError("fixture_id must use the frozen restricted-v1 identity")
        return self


class OpenClawInventoryDigestsV1(BaseModel):
    """The four canonical digests required by OpenClaw activation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    host_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_order_inventory_digest: str = Field(pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)


def build_openclaw_inventory_digests(
    *,
    tools: Sequence[OpenClawFrozenToolV1],
    plugin_order: Sequence[str],
) -> OpenClawInventoryDigestsV1:
    """Build the frozen Host/plugin/order/tool inventory digest quartet.

    Arrays are semantic: callers must supply tools in ``tool_id`` order and the
    exact first-seen catalog group order.  Duplicate tool IDs are rejected even
    when their source is otherwise identical.
    """

    tool_ids = [item.tool_id for item in tools]
    if (
        not tool_ids
        or tool_ids != sorted(tool_ids)
        or len(tool_ids) != len(set(tool_ids))
    ):
        raise ValueError("OpenClaw tools must be unique and sorted by tool_id")
    canonical_order = list(plugin_order)
    if (
        not canonical_order
        or len(canonical_order) != len(set(canonical_order))
        or any(not item for item in canonical_order)
    ):
        raise ValueError("OpenClaw plugin_order must be non-empty and unique")
    plugin_ids = sorted({item.source_plugin_id for item in tools})
    if set(canonical_order) != set(plugin_ids):
        raise ValueError("plugin_order must contain every source plugin exactly once")
    host_payload = {
        "schema_version": "1.0",
        "runtime": "openclaw",
        "tools": [
            {
                "tool_id": item.tool_id,
                "source_plugin_id": item.source_plugin_id,
            }
            for item in tools
        ],
    }
    host_digest = canonical_sha256(host_payload)
    plugin_payload = {
        "schema_version": "1.0",
        "runtime": "openclaw",
        "plugin_ids": plugin_ids,
    }
    order_payload = {
        "schema_version": "1.0",
        "runtime": "openclaw",
        "plugin_order": canonical_order,
    }
    tool_payload = {
        "schema_version": "1.0",
        "runtime": "openclaw",
        "host_inventory_digest": host_digest,
        "tools": [item.model_dump(mode="json") for item in tools],
    }
    return OpenClawInventoryDigestsV1(
        host_inventory_digest=host_digest,
        plugin_inventory_digest=canonical_sha256(plugin_payload),
        plugin_order_inventory_digest=canonical_sha256(order_payload),
        tool_inventory_digest=canonical_sha256(tool_payload),
    )


class ResidualRiskAcceptanceV1(BaseModel):
    """Signed, short-lived acceptance of explicitly named runtime boundaries."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra=cast(
            dict[str, Any],
            {
                "allOf": [
                    {
                        "properties": {
                            "residual_boundaries": {
                                "const": list(OPENCLAW_RESIDUAL_BOUNDARIES)
                            }
                        },
                        "required": ["residual_boundaries"],
                    }
                ]
            },
        ),
    )

    schema_version: Literal["1.0"] = "1.0"
    runtime: Literal["openclaw"] = "openclaw"
    runtime_version: Literal["2026.7.1-2"]
    plugin_version: Literal["0.1.0-rc.1"]
    release_scope: Literal["internal_rc_canary"] = "internal_rc_canary"
    reviewer_id: str = Field(min_length=1, max_length=128)
    candidate_artifact_digest: str = Field(pattern=_DIGEST)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_digest: str = Field(pattern=_DIGEST)
    agent_id: str = Field(min_length=1, max_length=128)
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    host_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_order_inventory_digest: str = Field(pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)
    canary_cohort: str = Field(min_length=1, max_length=128)
    environment: Literal["internal_rc_canary"]
    residual_boundaries: list[OpenClawResidualBoundary] = Field(min_length=1)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(min_length=1, max_length=64)
    acceptance_ref_digest: str = Field(pattern=_DIGEST)
    server_signature: str = Field(pattern=_SIGNATURE)

    @model_validator(mode="after")
    def validate_acceptance(self) -> "ResidualRiskAcceptanceV1":
        _canonical_unique(self.residual_boundaries, label="residual_boundaries")
        if tuple(self.residual_boundaries) != OPENCLAW_RESIDUAL_BOUNDARIES:
            raise ValueError(
                "OpenClaw risk acceptance requires the frozen residual boundaries"
            )
        _require_window(
            self.issued_at,
            self.expires_at,
            maximum=timedelta(days=14),
        )
        expected = canonical_sha256(self.digest_projection())
        if not hmac.compare_digest(expected, self.acceptance_ref_digest):
            raise ValueError("acceptance_ref_digest does not match acceptance")
        return self

    def digest_projection(self) -> dict[str, Any]:
        dumped = self.model_dump(
            mode="json", exclude={"acceptance_ref_digest", "server_signature"}
        )
        return {key: dumped[key] for key in sorted(dumped)}


class RuntimeActivationEntryV1(BaseModel):
    """One runtime identity and immutable candidate inventory activation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra=cast(
            dict[str, Any],
            {
                "allOf": [
                    {
                        "properties": {
                            "event_types": {"const": list(PRODUCT_EVENT_TYPES)}
                        },
                        "required": ["event_types"],
                    },
                    {
                        "if": {
                            "properties": {"runtime": {"const": "langgraph"}},
                            "required": ["runtime"],
                        },
                        "then": {
                            "properties": {
                                "runtime_version": {"const": "1.2.7"},
                                "plugin_version": {"const": "0.1.0rc1"},
                                "profile_id": {"const": "agentguard-langgraph-v2"},
                                "ask_release_mode": {"const": "strong_binding"},
                                "plugin_inventory_digest": {"type": "null"},
                                "plugin_order_inventory_digest": {"type": "null"},
                                "residual_risk_acceptance_digest": {"type": "null"},
                                "residual_boundaries": {"const": []},
                            },
                            "required": ["residual_boundaries"],
                        },
                    },
                    {
                        "if": {
                            "properties": {"runtime": {"const": "openclaw"}},
                            "required": ["runtime"],
                        },
                        "then": {
                            "properties": {
                                "runtime_version": {"const": "2026.7.1-2"},
                                "plugin_version": {"const": "0.1.0-rc.1"},
                                "profile_id": {
                                    "const": "agentguard-openclaw-v2-restricted"
                                },
                                "ask_release_mode": {"const": "restricted_allow_once"},
                                "plugin_inventory_digest": {
                                    "type": "string",
                                    "pattern": _DIGEST,
                                },
                                "plugin_order_inventory_digest": {
                                    "type": "string",
                                    "pattern": _DIGEST,
                                },
                                "residual_risk_acceptance_digest": {
                                    "type": "string",
                                    "pattern": _DIGEST,
                                },
                                "residual_boundaries": {
                                    "const": list(OPENCLAW_RESIDUAL_BOUNDARIES)
                                },
                            },
                            "required": [
                                "plugin_inventory_digest",
                                "plugin_order_inventory_digest",
                                "residual_risk_acceptance_digest",
                                "residual_boundaries",
                            ],
                        },
                    },
                ],
            },
        ),
    )

    runtime: ProductRuntime
    runtime_version: str = Field(min_length=1, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=64)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_digest: str = Field(pattern=_DIGEST)
    principal_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    event_types: list[GuardEventType]
    adapter_artifact_digest: str = Field(pattern=_DIGEST)
    capability_report_digest: str = Field(pattern=_DIGEST)
    host_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_inventory_digest: str | None = Field(default=None, pattern=_DIGEST)
    plugin_order_inventory_digest: str | None = Field(default=None, pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)
    ask_release_mode: Literal["strong_binding", "restricted_allow_once"]
    residual_risk_acceptance_digest: str | None = Field(default=None, pattern=_DIGEST)
    residual_boundaries: list[OpenClawResidualBoundary]
    canary_cohort: str = Field(min_length=1, max_length=128)
    environment: Literal["internal_rc_canary"] = "internal_rc_canary"
    expires_at: str

    @model_validator(mode="after")
    def validate_runtime_entry(self) -> "RuntimeActivationEntryV1":
        if self.event_types != list(PRODUCT_EVENT_TYPES):
            raise ValueError(
                "event_types must contain all product event types in canonical order"
            )
        _parse_utc(self.expires_at, label="expires_at")
        _canonical_unique(self.residual_boundaries, label="residual_boundaries")
        expected_runtime_version = {
            "langgraph": "1.2.7",
            "openclaw": "2026.7.1-2",
        }[self.runtime]
        if self.runtime_version != expected_runtime_version:
            raise ValueError(
                f"{self.runtime} activation requires runtime_version="
                f"{expected_runtime_version}"
            )
        expected_profile_id = _RUNTIME_PROFILE_IDS[self.runtime]
        if self.profile_id != expected_profile_id:
            raise ValueError(
                f"{self.runtime} activation requires profile_id={expected_profile_id}"
            )
        expected_plugin_version = {
            "langgraph": "0.1.0rc1",
            "openclaw": "0.1.0-rc.1",
        }[self.runtime]
        if self.plugin_version != expected_plugin_version:
            raise ValueError(
                f"{self.runtime} activation requires plugin_version="
                f"{expected_plugin_version}"
            )
        if self.runtime == "langgraph":
            if self.ask_release_mode != "strong_binding":
                raise ValueError("LangGraph activation requires strong_binding")
            if any(
                value is not None
                for value in (
                    self.plugin_inventory_digest,
                    self.plugin_order_inventory_digest,
                    self.residual_risk_acceptance_digest,
                )
            ):
                raise ValueError(
                    "LangGraph activation cannot carry OpenClaw plugin or residual fields"
                )
            if self.residual_boundaries:
                raise ValueError(
                    "LangGraph activation cannot carry residual boundaries"
                )
        else:
            if self.ask_release_mode != "restricted_allow_once":
                raise ValueError("OpenClaw activation requires restricted_allow_once")
            if any(
                value is None
                for value in (
                    self.plugin_inventory_digest,
                    self.plugin_order_inventory_digest,
                    self.residual_risk_acceptance_digest,
                )
            ):
                raise ValueError(
                    "OpenClaw activation requires plugin, order, and residual digests"
                )
            if tuple(self.residual_boundaries) != OPENCLAW_RESIDUAL_BOUNDARIES:
                raise ValueError(
                    "OpenClaw activation requires the frozen residual boundaries"
                )
        return self


class RolloutAdmissionRecordV1(BaseModel):
    """Signed proof that a fixed candidate passed the named admission evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    candidate_artifact_manifest_digest: str = Field(pattern=_DIGEST)
    source_revision: str = Field(min_length=7, max_length=128)
    policy_digest: str = Field(pattern=_DIGEST)
    dataset_digest: str = Field(pattern=_DIGEST)
    contract_digest: str = Field(pattern=_DIGEST)
    langgraph_conformance_digest: str = Field(pattern=_DIGEST)
    openclaw_conformance_digest: str = Field(pattern=_DIGEST)
    capability_matrix_digest: str = Field(pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(min_length=1, max_length=64)
    admission_ref_digest: str = Field(pattern=_DIGEST)
    server_signature: str = Field(pattern=_SIGNATURE)

    @model_validator(mode="after")
    def validate_admission(self) -> "RolloutAdmissionRecordV1":
        _require_window(self.issued_at, self.expires_at, maximum=None)
        expected = canonical_sha256(self.digest_projection())
        if not hmac.compare_digest(expected, self.admission_ref_digest):
            raise ValueError("admission_ref_digest does not match admission")
        return self

    def digest_projection(self) -> dict[str, Any]:
        dumped = self.model_dump(
            mode="json", exclude={"admission_ref_digest", "server_signature"}
        )
        return {key: dumped[key] for key in sorted(dumped)}


class ProductActivationBundleV1(BaseModel):
    """Strict dual-runtime product activation for one immutable candidate."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra=cast(
            dict[str, Any],
            {
                "allOf": [
                    {
                        "properties": {
                            "runtimes": {
                                "minItems": 2,
                                "maxItems": 2,
                                "prefixItems": [
                                    {
                                        "properties": {
                                            "runtime": {"const": "langgraph"}
                                        },
                                        "required": ["runtime"],
                                    },
                                    {
                                        "properties": {
                                            "runtime": {"const": "openclaw"}
                                        },
                                        "required": ["runtime"],
                                    },
                                ],
                            }
                        },
                        "required": ["runtimes"],
                    }
                ]
            },
        ),
    )

    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["active"] = "active"
    candidate_artifact_manifest_digest: str = Field(pattern=_DIGEST)
    rollout_admission_digest: str = Field(pattern=_DIGEST)
    rollout_admission_record: RolloutAdmissionRecordV1
    residual_risk_acceptance: ResidualRiskAcceptanceV1
    policy_digest: str = Field(pattern=_DIGEST)
    dataset_digest: str = Field(pattern=_DIGEST)
    contract_digest: str = Field(pattern=_DIGEST)
    runtimes: list[RuntimeActivationEntryV1]
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(min_length=1, max_length=64)
    activation_ref_digest: str = Field(pattern=_DIGEST)
    server_signature: str = Field(pattern=_SIGNATURE)

    @model_validator(mode="after")
    def validate_activation(self) -> "ProductActivationBundleV1":
        if [item.runtime for item in self.runtimes] != ["langgraph", "openclaw"]:
            raise ValueError("runtimes must contain langgraph then openclaw")
        _require_window(self.issued_at, self.expires_at, maximum=timedelta(days=14))
        bundle_issued = _parse_utc(self.issued_at, label="issued_at")
        bundle_expiry = _parse_utc(self.expires_at, label="expires_at")
        if any(
            not (
                bundle_issued
                < _parse_utc(item.expires_at, label="runtime expires_at")
                <= bundle_expiry
            )
            for item in self.runtimes
        ):
            raise ValueError(
                "runtime activation must expire after bundle issuance and not outlive it"
            )
        admission = self.rollout_admission_record
        risk = self.residual_risk_acceptance
        openclaw = self.runtime_entry("openclaw")
        if self.rollout_admission_digest != admission.admission_ref_digest:
            raise ValueError("rollout admission digest does not match signed record")
        if openclaw.residual_risk_acceptance_digest != risk.acceptance_ref_digest:
            raise ValueError("residual risk digest does not match signed record")
        if any(
            (
                self.candidate_artifact_manifest_digest
                != admission.candidate_artifact_manifest_digest,
                self.candidate_artifact_manifest_digest
                != risk.candidate_artifact_digest,
                self.policy_digest != admission.policy_digest,
                self.dataset_digest != admission.dataset_digest,
                self.contract_digest != admission.contract_digest,
                openclaw.host_inventory_digest != risk.host_inventory_digest,
                openclaw.plugin_inventory_digest != risk.plugin_inventory_digest,
                openclaw.plugin_order_inventory_digest
                != risk.plugin_order_inventory_digest,
                openclaw.tool_inventory_digest != risk.tool_inventory_digest,
                openclaw.tool_inventory_digest != admission.tool_inventory_digest,
                openclaw.residual_boundaries != risk.residual_boundaries,
                openclaw.runtime_version != risk.runtime_version,
                openclaw.plugin_version != risk.plugin_version,
                openclaw.profile_id != risk.profile_id,
                openclaw.profile_digest != risk.profile_digest,
                openclaw.agent_id != risk.agent_id,
                openclaw.runtime_binding_id != risk.runtime_binding_id,
                openclaw.canary_cohort != risk.canary_cohort,
                openclaw.environment != risk.environment,
            )
        ):
            raise ValueError("activation proof records do not match bundle inventories")
        admission_issued = _parse_utc(admission.issued_at, label="admission issued_at")
        admission_expiry = _parse_utc(
            admission.expires_at, label="admission expires_at"
        )
        risk_issued = _parse_utc(risk.issued_at, label="risk issued_at")
        risk_expiry = _parse_utc(risk.expires_at, label="risk expires_at")
        if not (
            admission_issued <= bundle_issued
            and risk_issued <= bundle_issued
            and bundle_expiry <= admission_expiry
            and bundle_expiry <= risk_expiry
        ):
            raise ValueError("activation must remain inside signed proof windows")
        expected = canonical_sha256(self.digest_projection())
        if not hmac.compare_digest(expected, self.activation_ref_digest):
            raise ValueError("activation_ref_digest does not match bundle")
        return self

    def digest_projection(self) -> dict[str, Any]:
        dumped = self.model_dump(
            mode="json", exclude={"activation_ref_digest", "server_signature"}
        )
        return {key: dumped[key] for key in sorted(dumped)}

    def runtime_entry(self, runtime: ProductRuntime) -> RuntimeActivationEntryV1:
        return self.runtimes[_RUNTIME_ORDER[runtime]]

    def valid_at(self, now: datetime) -> bool:
        """Return whether the bundle and every runtime entry are time-valid."""

        current = now.astimezone(timezone.utc)
        if not (
            _parse_utc(self.issued_at, label="issued_at")
            <= current
            < _parse_utc(self.expires_at, label="expires_at")
        ):
            return False
        return all(
            current < _parse_utc(item.expires_at, label="runtime expires_at")
            for item in self.runtimes
        )


class ApprovalReleaseDirectiveV2(BaseModel):
    """New-reader release authority with a deliberately safe legacy projection."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra=cast(
            dict[str, Any],
            {
                "allOf": [
                    {
                        "if": {
                            "properties": {"mode": {"const": mode}},
                            "required": ["mode"],
                        },
                        "then": {
                            "properties": {
                                "required_runtime_profile": (
                                    {"type": "null"}
                                    if runtime_profile is None
                                    else {"const": runtime_profile}
                                ),
                                "action_binding": {"const": action_binding},
                                "receipt_requirement": {"const": receipt_requirement},
                                "residual_boundaries": residual_schema,
                            },
                            "required": ["residual_boundaries"],
                        },
                    }
                    for (
                        mode,
                        runtime_profile,
                        action_binding,
                        receipt_requirement,
                        residual_schema,
                    ) in (
                        (
                            "not_applicable",
                            None,
                            "none",
                            "not_applicable",
                            {"maxItems": 0},
                        ),
                        ("forbidden", None, "none", "not_applicable", {"maxItems": 0}),
                        (
                            "strong_binding",
                            "C3",
                            "exact",
                            "required_durable",
                            {"maxItems": 0},
                        ),
                        (
                            "restricted_allow_once",
                            "C1",
                            "best_effort_host",
                            "required_durable",
                            {"const": list(OPENCLAW_RESIDUAL_BOUNDARIES)},
                        ),
                    )
                ]
            },
        ),
    )

    schema_version: Literal["2.0"] = "2.0"
    mode: ApprovalReleaseModeV2
    required_runtime_profile: Literal["C1", "C3"] | None
    human_only: Literal[True] = True
    single_use: Literal[True] = True
    action_binding: Literal["exact", "best_effort_host", "none"]
    receipt_requirement: Literal["not_applicable", "required_durable"]
    activation_ref_digest: str = Field(pattern=_DIGEST)
    scope_digest: str = Field(pattern=r"^(?:sha256|hmac-sha256):[0-9a-f]{64}$")
    capability_digest: str = Field(pattern=_DIGEST)
    residual_boundaries: list[OpenClawResidualBoundary]

    @model_validator(mode="after")
    def validate_directive(self) -> "ApprovalReleaseDirectiveV2":
        _canonical_unique(self.residual_boundaries, label="residual_boundaries")
        expected = {
            "not_applicable": (None, "none", "not_applicable"),
            "forbidden": (None, "none", "not_applicable"),
            "strong_binding": ("C3", "exact", "required_durable"),
            "restricted_allow_once": (
                "C1",
                "best_effort_host",
                "required_durable",
            ),
        }[self.mode]
        if (
            self.required_runtime_profile,
            self.action_binding,
            self.receipt_requirement,
        ) != expected:
            raise ValueError("approval release fields do not match mode")
        if self.mode == "restricted_allow_once" and tuple(
            self.residual_boundaries
        ) != tuple(OPENCLAW_RESIDUAL_BOUNDARIES):
            raise ValueError(
                "restricted_allow_once requires frozen residual boundaries"
            )
        if self.mode != "restricted_allow_once" and self.residual_boundaries:
            raise ValueError("only restricted_allow_once may carry residual boundaries")
        return self


class ProductDecisionAuthorityEvidenceV1(BaseModel):
    """Critical/no-drop evidence for a product authority selection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = "2.0"
    persistence_requirement: Literal["critical_no_drop"] = "critical_no_drop"
    runtime: ProductRuntime
    profile_id: str = Field(min_length=1, max_length=128)
    event_type: GuardEventType
    event_id: str = Field(min_length=1)
    assessment_id: str = Field(min_length=1)
    assessment_digest: str = Field(pattern=_DIGEST)
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(pattern=_DIGEST)
    state_version: int = Field(ge=0)
    policy_digest: str = Field(pattern=_DIGEST)
    dataset_digest: str = Field(pattern=_DIGEST)
    profile_digest: str = Field(pattern=_DIGEST)
    current_decision: GuardDecision
    current_decision_digest: str = Field(pattern=_DIGEST)
    raw_v21_decision: GuardDecision
    raw_v21_decision_digest: str = Field(pattern=_DIGEST)
    selected_decision: GuardDecision
    selected_decision_digest: str = Field(pattern=_DIGEST)
    decision_authority: DecisionAuthority
    approval_release_directive: ApprovalReleaseDirectiveV2

    @model_validator(mode="after")
    def validate_parity(self) -> "ProductDecisionAuthorityEvidenceV1":
        if self.profile_id != _RUNTIME_PROFILE_IDS[self.runtime]:
            raise ValueError(
                "product authority evidence profile does not match runtime"
            )
        decisions = (
            (self.current_decision, self.current_decision_digest, "current"),
            (self.raw_v21_decision, self.raw_v21_decision_digest, "raw_v21"),
            (self.selected_decision, self.selected_decision_digest, "selected"),
        )
        for decision, digest, label in decisions:
            expected = canonical_sha256(decision.model_dump(mode="json"))
            if not hmac.compare_digest(expected, digest):
                raise ValueError(f"{label}_decision_digest does not match decision")
        if self.decision_authority.source != "v21":
            raise ValueError("product authority evidence requires V2 authority")
        if self.decision_authority.mode != "active" or (
            self.decision_authority.selection_basis != "profile_all"
        ):
            raise ValueError("product authority evidence requires active profile_all")
        if not hmac.compare_digest(
            self.decision_authority.activation_ref_digest,
            self.approval_release_directive.activation_ref_digest,
        ):
            raise ValueError("authority and release activation refs differ")
        if (
            self.decision_authority.approval_release
            != legacy_approval_release_projection(self.approval_release_directive)
        ):
            raise ValueError("legacy approval release projection is unsafe")
        if self.selected_decision.decision == "ask":
            release = self.approval_release_directive.mode
            intent = self.selected_decision.approval_intent
            releasable = release in {"strong_binding", "restricted_allow_once"}
            if (intent is not None) != releasable:
                raise ValueError("ASK approval intent does not match release directive")
            if releasable and (intent is None or "allow_once" not in intent.options):
                raise ValueError(
                    "releasable ASK approval intent must include allow_once"
                )
            if releasable and any(
                decision.decision == "ask"
                and decision.approval_intent is not None
                and "allow_once" not in decision.approval_intent.options
                for decision in (self.current_decision, self.raw_v21_decision)
            ):
                raise ValueError(
                    "releasable ASK cannot override an explicit deny-only intent"
                )
        elif self.approval_release_directive.mode != "not_applicable":
            raise ValueError("non-ASK decision requires not_applicable release")
        if self.runtime == "langgraph" and (
            self.approval_release_directive.mode == "restricted_allow_once"
        ):
            raise ValueError("LangGraph cannot use restricted_allow_once")
        if self.runtime == "openclaw" and (
            self.approval_release_directive.mode == "strong_binding"
        ):
            raise ValueError("OpenClaw cannot claim strong_binding")
        if self.event_type not in {
            "tool_call_proposed",
            "memory_write_proposed",
            "message_send_proposed",
        } and self.approval_release_directive.mode in {
            "strong_binding",
            "restricted_allow_once",
        }:
            raise ValueError("event type does not permit approval release")
        return self


def build_runtime_capability_report(**values: Any) -> RuntimeCapabilityReportV2:
    """Build a self-digested capability report from typed event capabilities."""

    normalized = dict(values)
    raw_events = normalized.get("events")
    if isinstance(raw_events, (list, tuple)):
        normalized["events"] = [
            RuntimeEventCapabilityV2.model_validate(item) for item in raw_events
        ]
    unsigned = RuntimeCapabilityReportV2.model_construct(
        **normalized,
        report_digest="sha256:" + "0" * 64,
    )
    payload = unsigned.digest_projection()
    return RuntimeCapabilityReportV2.model_validate(
        {**payload, "report_digest": canonical_sha256(payload)}
    )


def _signature(secret: bytes, *, domain: str, ref_name: str, ref: str) -> str:
    return canonical_hmac_sha256(
        secret,
        {"domain": domain, ref_name: ref},
    )


def build_residual_risk_acceptance(
    *, server_secret: bytes, **values: Any
) -> ResidualRiskAcceptanceV1:
    _require_secret(server_secret, label="residual risk server_secret")
    unsigned = ResidualRiskAcceptanceV1.model_construct(
        **values,
        acceptance_ref_digest="sha256:" + "0" * 64,
        server_signature="hmac-sha256:" + "0" * 64,
    )
    payload = unsigned.digest_projection()
    ref = canonical_sha256(payload)
    return ResidualRiskAcceptanceV1.model_validate(
        {
            **payload,
            "acceptance_ref_digest": ref,
            "server_signature": _signature(
                server_secret,
                domain=RESIDUAL_RISK_SIGNATURE_DOMAIN,
                ref_name="acceptance_ref_digest",
                ref=ref,
            ),
        }
    )


def verify_residual_risk_acceptance(
    value: ResidualRiskAcceptanceV1, *, server_secret: bytes
) -> bool:
    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        return False
    ref = canonical_sha256(value.digest_projection())
    expected = _signature(
        server_secret,
        domain=RESIDUAL_RISK_SIGNATURE_DOMAIN,
        ref_name="acceptance_ref_digest",
        ref=ref,
    )
    return hmac.compare_digest(
        ref, value.acceptance_ref_digest
    ) and hmac.compare_digest(expected, value.server_signature)


def build_rollout_admission_record(
    *, server_secret: bytes, **values: Any
) -> RolloutAdmissionRecordV1:
    _require_secret(server_secret, label="rollout admission server_secret")
    unsigned = RolloutAdmissionRecordV1.model_construct(
        **values,
        admission_ref_digest="sha256:" + "0" * 64,
        server_signature="hmac-sha256:" + "0" * 64,
    )
    payload = unsigned.digest_projection()
    ref = canonical_sha256(payload)
    return RolloutAdmissionRecordV1.model_validate(
        {
            **payload,
            "admission_ref_digest": ref,
            "server_signature": _signature(
                server_secret,
                domain=ROLLOUT_ADMISSION_SIGNATURE_DOMAIN,
                ref_name="admission_ref_digest",
                ref=ref,
            ),
        }
    )


def verify_rollout_admission_record(
    value: RolloutAdmissionRecordV1, *, server_secret: bytes
) -> bool:
    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        return False
    ref = canonical_sha256(value.digest_projection())
    expected = _signature(
        server_secret,
        domain=ROLLOUT_ADMISSION_SIGNATURE_DOMAIN,
        ref_name="admission_ref_digest",
        ref=ref,
    )
    return hmac.compare_digest(ref, value.admission_ref_digest) and hmac.compare_digest(
        expected, value.server_signature
    )


def build_product_activation_bundle(
    *,
    server_secret: bytes,
    rollout_admission_record: RolloutAdmissionRecordV1,
    residual_risk_acceptance: ResidualRiskAcceptanceV1,
    **values: Any,
) -> ProductActivationBundleV1:
    _require_secret(server_secret, label="product activation server_secret")
    if not verify_rollout_admission_record(
        rollout_admission_record, server_secret=server_secret
    ):
        raise ValueError("rollout admission record signature is invalid")
    if not verify_residual_risk_acceptance(
        residual_risk_acceptance, server_secret=server_secret
    ):
        raise ValueError("residual risk acceptance signature is invalid")
    unsigned = ProductActivationBundleV1.model_construct(
        **values,
        rollout_admission_record=rollout_admission_record,
        residual_risk_acceptance=residual_risk_acceptance,
        activation_ref_digest="sha256:" + "0" * 64,
        server_signature="hmac-sha256:" + "0" * 64,
    )
    payload = unsigned.digest_projection()
    ref = canonical_sha256(payload)
    return ProductActivationBundleV1.model_validate(
        {
            **payload,
            "activation_ref_digest": ref,
            "server_signature": _signature(
                server_secret,
                domain=PRODUCT_ACTIVATION_SIGNATURE_DOMAIN,
                ref_name="activation_ref_digest",
                ref=ref,
            ),
        }
    )


def verify_product_activation_bundle(
    value: ProductActivationBundleV1, *, server_secret: bytes
) -> bool:
    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        return False
    ref = canonical_sha256(value.digest_projection())
    expected = _signature(
        server_secret,
        domain=PRODUCT_ACTIVATION_SIGNATURE_DOMAIN,
        ref_name="activation_ref_digest",
        ref=ref,
    )
    return bool(
        hmac.compare_digest(ref, value.activation_ref_digest)
        and hmac.compare_digest(expected, value.server_signature)
        and verify_rollout_admission_record(
            value.rollout_admission_record, server_secret=server_secret
        )
        and verify_residual_risk_acceptance(
            value.residual_risk_acceptance, server_secret=server_secret
        )
    )


def build_activation_ack(
    *,
    server_secret: bytes,
    runtime: ProductRuntime,
    runtime_version: str,
    plugin_version: str,
    agent_id: str,
    runtime_binding_id: str,
    profile_id: str,
    activation_ref_digest: str,
    capability_digest: str,
    host_inventory_digest: str,
    plugin_inventory_digest: str | None,
    plugin_order_inventory_digest: str | None,
    tool_inventory_digest: str,
    issued_at: str,
    expires_at: str,
) -> ActivationAckV1:
    _require_secret(server_secret, label="activation ack server_secret")
    payload = {
        "schema_version": "1.0",
        "runtime": runtime,
        "runtime_version": runtime_version,
        "plugin_version": plugin_version,
        "agent_id": agent_id,
        "runtime_binding_id": runtime_binding_id,
        "profile_id": profile_id,
        "activation_ref_digest": activation_ref_digest,
        "capability_digest": capability_digest,
        "host_inventory_digest": host_inventory_digest,
        "plugin_inventory_digest": plugin_inventory_digest,
        "plugin_order_inventory_digest": plugin_order_inventory_digest,
        "tool_inventory_digest": tool_inventory_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    token = canonical_hmac_sha256(
        server_secret,
        {"domain": ACTIVATION_ACK_SIGNATURE_DOMAIN, "ack": payload},
    )
    return ActivationAckV1.model_validate({**payload, "ack_token": token})


def verify_activation_ack(
    value: ActivationAckV1,
    *,
    server_secret: bytes,
    now: datetime | None = None,
) -> bool:
    if not verify_activation_ack_token(value, server_secret=server_secret):
        return False
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued = _parse_utc(value.issued_at, label="issued_at")
    expires = _parse_utc(value.expires_at, label="expires_at")
    return issued <= current < expires


def verify_activation_ack_token(
    value: ActivationAckV1,
    *,
    server_secret: bytes,
) -> bool:
    """Verify the opaque ACK token without applying wall-clock freshness.

    Authority-bearing requests must use :func:`verify_activation_ack`, which
    also enforces ``issued_at <= now < expires_at``.  Runtime outcome receipts
    are durable historical facts and may arrive after that short window; they
    use this signature-only primitive and separately bind the signed ACK to
    the receipt, authenticated runtime, and frozen activation.
    """

    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        return False
    expected = canonical_hmac_sha256(
        server_secret,
        {"domain": ACTIVATION_ACK_SIGNATURE_DOMAIN, "ack": value.token_projection()},
    )
    return hmac.compare_digest(expected, value.ack_token)


def legacy_approval_release_projection(
    directive: ApprovalReleaseDirectiveV2,
) -> Literal["not_applicable", "strong_binding_required", "forbidden"]:
    """Project new release authority safely for pre-V2 readers."""

    return {
        "not_applicable": "not_applicable",
        "forbidden": "forbidden",
        "strong_binding": "strong_binding_required",
        "restricted_allow_once": "forbidden",
    }[
        directive.mode
    ]  # type: ignore[return-value]


def build_approval_release_directive(
    *,
    runtime: ProductRuntime,
    decision: Decision,
    reviewable: bool,
    activation_ref_digest: str,
    scope_digest: str,
    capability_digest: str,
    residual_boundaries: Sequence[str] = (),
    release_applicable: bool = True,
) -> ApprovalReleaseDirectiveV2:
    if runtime not in _RUNTIME_ORDER:
        raise ValueError("unsupported product runtime")
    if not release_applicable or decision != "ask":
        mode: ApprovalReleaseModeV2 = "not_applicable"
    elif not reviewable:
        mode = "forbidden"
    elif runtime == "langgraph":
        mode = "strong_binding"
    else:
        mode = "restricted_allow_once"
    fields = {
        "not_applicable": (None, "none", "not_applicable", []),
        "forbidden": (None, "none", "not_applicable", []),
        "strong_binding": ("C3", "exact", "required_durable", []),
        "restricted_allow_once": (
            "C1",
            "best_effort_host",
            "required_durable",
            list(residual_boundaries),
        ),
    }[mode]
    return ApprovalReleaseDirectiveV2(
        mode=mode,
        required_runtime_profile=fields[0],  # type: ignore[arg-type]
        action_binding=fields[1],  # type: ignore[arg-type]
        receipt_requirement=fields[2],  # type: ignore[arg-type]
        activation_ref_digest=activation_ref_digest,
        scope_digest=scope_digest,
        capability_digest=capability_digest,
        residual_boundaries=fields[3],
    )


def _reviewable(
    assessment: FastAssessment,
    coverage: CoverageMap,
    eligibility: V21SelectionEligibility,
) -> bool:
    fingerprints_complete = bool(
        assessment.authorization_fingerprint.startswith("hmac-sha256:")
        and len(assessment.authorization_fingerprint) == 76
        and assessment.audit_fingerprint.startswith("sha256:")
        and len(assessment.audit_fingerprint) == 71
    )
    task_complete = bool(
        assessment.task_digest is not None
        and assessment.task_digest.startswith("sha256:")
        and len(assessment.task_digest) == 71
    )
    required_state_complete = not any(
        item.required_for_action for item in assessment.degradations
    ) and all(
        getattr(coverage, domain).status in {"complete", "not_applicable"}
        for domain in assessment.required_check_plan.required_domains
    )
    return all(
        (
            eligibility.approval_binding_eligible,
            eligibility.action_ir_complete,
            eligibility.task_fact_present,
            fingerprints_complete,
            task_complete,
            required_state_complete,
        )
    )


def select_product_v21_authority(
    *,
    event_id: str,
    current_decision: GuardDecision,
    raw_v21_decision: GuardDecision | None,
    assessment: FastAssessment,
    coverage: CoverageMap,
    activation: ProductActivationBundleV1,
    runtime_entry: RuntimeActivationEntryV1,
    eligibility: V21SelectionEligibility,
    snapshot_id: str,
    state_version: int,
    scope_digest: str,
    event_type: GuardEventType,
    residual_boundaries: Sequence[str] = (),
) -> tuple[V21SelectionResult, ApprovalReleaseDirectiveV2]:
    """Select product V2 authority in active mode with no legacy fallback."""

    if event_type not in PRODUCT_EVENT_TYPES:
        raise V21AuthoritySelectionError("v21-product:unsupported_event_type")
    if event_id != assessment.event_id:
        raise V21AuthoritySelectionError("v21-product:event_mismatch")
    if runtime_entry.runtime not in _RUNTIME_ORDER or (
        activation.runtime_entry(runtime_entry.runtime) != runtime_entry
    ):
        raise V21AuthoritySelectionError("v21-product:activation_runtime_mismatch")
    if not eligibility.active_authority_valid:
        raise V21AuthoritySelectionError(
            "v21-product:active_authority_precondition_failed"
        )
    if not hmac.compare_digest(assessment.policy_digest, activation.policy_digest):
        raise V21AuthoritySelectionError("v21-product:policy_digest_mismatch")
    expected_raw = {
        "CLEAR_ALLOW": "allow",
        "DEFER": "ask",
        "CLEAR_DENY": "deny",
    }[assessment.disposition]
    if raw_v21_decision is None or raw_v21_decision.decision != expected_raw:
        raise V21AuthoritySelectionError("v21-product:raw_v21_unavailable")
    if tuple(residual_boundaries) != tuple(runtime_entry.residual_boundaries):
        raise V21AuthoritySelectionError("v21-product:residual_boundaries_mismatch")

    legacy_floor = (
        _DECISION_RANK[current_decision.decision]
        > _DECISION_RANK[raw_v21_decision.decision]
    )
    base = current_decision if legacy_floor else raw_v21_decision
    directive_residual_boundaries: Sequence[str] = ()
    if runtime_entry.runtime == "openclaw":
        directive_residual_boundaries = runtime_entry.residual_boundaries
    # A pre-existing ASK intent may deliberately be deny-only.  Product Active
    # must never advertise a human allow-once release that either same-rank ASK
    # explicitly forbids merely because the raw V2 object wins the tie. Missing
    # intent is safe to synthesize only when neither authority input carries an
    # explicit deny-only intent.
    explicit_deny_only_ask = any(
        decision.decision == "ask"
        and decision.approval_intent is not None
        and "allow_once" not in decision.approval_intent.options
        for decision in (current_decision, raw_v21_decision)
    )
    intent_allows_once = bool(
        not explicit_deny_only_ask
        and (
            base.approval_intent is None or "allow_once" in base.approval_intent.options
        )
    )
    directive = build_approval_release_directive(
        runtime=runtime_entry.runtime,
        decision=base.decision,
        reviewable=(
            _reviewable(assessment, coverage, eligibility) and intent_allows_once
        ),
        activation_ref_digest=activation.activation_ref_digest,
        scope_digest=scope_digest,
        capability_digest=runtime_entry.capability_report_digest,
        residual_boundaries=directive_residual_boundaries,
        release_applicable=event_type
        in {
            "tool_call_proposed",
            "memory_write_proposed",
            "message_send_proposed",
        },
    )
    approval_intent: ApprovalIntent | None = None
    if directive.mode in {"strong_binding", "restricted_allow_once"}:
        approval_intent = base.approval_intent or ApprovalIntent(
            resource=f"action:{assessment.action_id}"
        )
    authority = DecisionAuthority(
        source="v21",
        mode="active",
        selection_basis="profile_all",
        matched_path_ids=[],
        legacy_floor_applied=legacy_floor,
        activation_ref_digest=activation.activation_ref_digest,
        approval_release=legacy_approval_release_projection(directive),
    )
    identity = {
        "schema_version": "2.0",
        "event_type": event_type,
        "event_id": event_id,
        "assessment_id": assessment.assessment_id,
        "assessment_digest": assessment.assessment_digest,
        "current_decision": decision_semantic_projection(current_decision),
        "raw_v21_decision": decision_semantic_projection(raw_v21_decision),
        "selected_decision": base.decision,
        "mode": "active",
        "selection_basis": "profile_all",
        "runtime": runtime_entry.runtime,
        "profile_id": runtime_entry.profile_id,
        "profile_digest": runtime_entry.profile_digest,
        "activation_ref_digest": activation.activation_ref_digest,
        "approval_release_directive": directive.model_dump(mode="json"),
        "snapshot_id": snapshot_id,
        "state_version": state_version,
    }
    decision_id = "dec:v21-product:" + canonical_sha256(identity).removeprefix(
        "sha256:"
    )
    selected = base.model_copy(
        update={
            "decision_id": decision_id,
            "approval_intent": approval_intent,
            "latency_ms": None,
        }
    )
    return (
        V21SelectionResult(
            selected_decision=selected,
            selected_decision_digest=canonical_sha256(selected.model_dump(mode="json")),
            current_decision=current_decision,
            raw_v21_decision=raw_v21_decision,
            authority=authority,
        ),
        directive,
    )


def build_product_decision_authority_evidence(
    *,
    result: V21SelectionResult,
    directive: ApprovalReleaseDirectiveV2,
    assessment: FastAssessment,
    activation: ProductActivationBundleV1,
    runtime_entry: RuntimeActivationEntryV1,
    event_type: GuardEventType,
    snapshot_id: str,
    state_version: int,
) -> ProductDecisionAuthorityEvidenceV1:
    """Build the critical product sibling persisted with the selected decision."""

    if result.raw_v21_decision is None:
        raise ValueError("product authority evidence requires raw_v21_decision")
    return ProductDecisionAuthorityEvidenceV1(
        runtime=runtime_entry.runtime,
        profile_id=runtime_entry.profile_id,
        event_type=event_type,
        event_id=assessment.event_id,
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
        snapshot_id=snapshot_id,
        snapshot_digest=assessment.snapshot_digest,
        state_version=state_version,
        policy_digest=assessment.policy_digest,
        dataset_digest=activation.dataset_digest,
        profile_digest=runtime_entry.profile_digest,
        current_decision=result.current_decision,
        current_decision_digest=canonical_sha256(
            result.current_decision.model_dump(mode="json")
        ),
        raw_v21_decision=result.raw_v21_decision,
        raw_v21_decision_digest=canonical_sha256(
            result.raw_v21_decision.model_dump(mode="json")
        ),
        selected_decision=result.selected_decision,
        selected_decision_digest=result.selected_decision_digest,
        decision_authority=result.authority,
        approval_release_directive=directive,
    )


def product_decision_authority_envelope(
    evidence: ProductDecisionAuthorityEvidenceV1,
) -> dict[str, Any]:
    return {
        "decision_authority": {
            "schema_version": "2.0",
            "payload": evidence.model_dump(mode="json"),
        }
    }
