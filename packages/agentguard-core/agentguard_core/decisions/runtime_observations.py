"""Strict runtime observations produced before Guard evaluation is available."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import AuditEvent

__all__ = [
    "PreEvaluationBlockDiagnostic",
    "PreEvaluationBlockFailureCode",
]

PreEvaluationBlockFailureCode = Literal[
    "activation_authority_unavailable",
    "guard_api_unavailable",
    "wrong_binding",
    "wrong_profile",
]
_PreEvaluationRecordType = Literal["runtime_observation"]
_EmptyStringTuple = Annotated[tuple[str, ...], Field(max_length=0)]

_FAILURE_CODES: tuple[PreEvaluationBlockFailureCode, ...] = (
    "activation_authority_unavailable",
    "guard_api_unavailable",
    "wrong_binding",
    "wrong_profile",
)
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_RFC3339_WITH_TIMEZONE = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_RUNTIME_SECRET_MATERIAL = re.compile(r"(?:hmac-sha256|lease-v1):[0-9a-f]{64}")


def _failure_code_equality_schema() -> dict[str, Any]:
    return {
        "oneOf": [
            {
                "properties": {
                    "reason": {"const": code},
                    "metadata": {
                        "properties": {"failure_code": {"const": code}},
                        "required": ["failure_code"],
                    },
                    "evidence": {
                        "properties": {"failure_code": {"const": code}},
                        "required": ["failure_code"],
                    },
                },
                "required": ["reason", "metadata", "evidence"],
            }
            for code in _FAILURE_CODES
        ]
    }


def _runtime_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


class PreEvaluationBlockLinks(BaseModel):
    """Frozen action and activation identity at the local fail-closed boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=160)
    action_id: str = Field(min_length=1, max_length=160)
    activation_ref_digest: str = Field(pattern=_DIGEST)


class PreEvaluationBlockMetadata(BaseModel):
    """Exact OpenClaw host and inventory identity observed by the plugin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(min_length=1, max_length=128)
    runtime_version: Literal["2026.7.1-2"]
    plugin_version: Literal["0.1.0-rc.1"]
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    profile_id: str = Field(min_length=1, max_length=128)
    profile_digest: str = Field(pattern=_DIGEST)
    activation_ref_digest: str = Field(pattern=_DIGEST)
    capability_digest: str = Field(pattern=_DIGEST)
    host_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_order_inventory_digest: str = Field(pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)
    action_digest: str = Field(pattern=_DIGEST)
    failure_code: PreEvaluationBlockFailureCode


class PreEvaluationBlockEvidence(BaseModel):
    """Bounded non-authority evidence that the side effect was not invoked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_stage: Literal["pre_evaluation_blocked"]
    execution_state: Literal["not_invoked"]
    required_durable_spool: bool = Field(
        strict=True,
        json_schema_extra={"const": True},
    )
    tool_replay_permitted: bool = Field(
        strict=True,
        json_schema_extra={"const": False},
    )
    failure_code: PreEvaluationBlockFailureCode

    @model_validator(mode="after")
    def _validate_fixed_evidence(self) -> "PreEvaluationBlockEvidence":
        if self.required_durable_spool is not True:
            raise ValueError("pre-evaluation block requires durable spool evidence")
        if self.tool_replay_permitted is not False:
            raise ValueError("pre-evaluation blocked tools cannot be replayed")
        return self


class PreEvaluationBlockDiagnostic(AuditEvent):
    """Action-bound fact for an OpenClaw side effect blocked before evaluate.

    This runtime observation is not a policy decision, activation ACK, approval,
    release directive, lease, or invocation authority.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        title="PreEvaluationBlockDiagnosticV1",
        json_schema_extra=_failure_code_equality_schema(),
    )

    # All canonical wire fields are required; no authority field is synthesized.
    audit_id: str = Field(  # pyright: ignore[reportGeneralTypeIssues]
        min_length=1,
        max_length=256,
        pattern=r"^audit_execution_blocked_.+$",
    )
    schema_version: Literal["0.4"]  # pyright: ignore[reportGeneralTypeIssues]
    record_type: _PreEvaluationRecordType  # pyright: ignore[reportGeneralTypeIssues]
    trace_id: str = Field(min_length=1, max_length=160)
    case_id: str | None = Field(  # pyright: ignore[reportGeneralTypeIssues]
        min_length=1,
        max_length=160,
    )
    runtime: Literal["openclaw"]  # pyright: ignore[reportGeneralTypeIssues]
    timestamp: str = Field(  # pyright: ignore[reportGeneralTypeIssues]
        pattern=_RFC3339_WITH_TIMEZONE, json_schema_extra={"format": "date-time"}
    )
    stage: Literal["pre_evaluation_blocked"]  # pyright: ignore[reportGeneralTypeIssues]
    event_type: Literal["execution_blocked"]  # pyright: ignore[reportGeneralTypeIssues]
    attack_type: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    is_malicious: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    summary: Literal["OpenClaw blocked a side effect before Guard evaluation"]
    decision: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    risk_score: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    severity: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    blocked: bool = Field(  # pyright: ignore[reportGeneralTypeIssues]
        strict=True,
        json_schema_extra={"const": True},
    )
    resource_targets: _EmptyStringTuple  # pyright: ignore[reportGeneralTypeIssues]
    rule_hits: _EmptyStringTuple  # pyright: ignore[reportGeneralTypeIssues]
    reason: PreEvaluationBlockFailureCode
    links: PreEvaluationBlockLinks  # pyright: ignore[reportGeneralTypeIssues]
    latency_ms: Literal[None]  # pyright: ignore[reportGeneralTypeIssues]
    metadata: PreEvaluationBlockMetadata  # pyright: ignore[reportGeneralTypeIssues]
    evidence: PreEvaluationBlockEvidence  # pyright: ignore[reportGeneralTypeIssues]

    @model_validator(mode="after")
    def _validate_diagnostic(self) -> "PreEvaluationBlockDiagnostic":
        occurred_at = _runtime_timestamp(self.timestamp, "timestamp")
        object.__setattr__(self, "timestamp", occurred_at.isoformat())
        if self.blocked is not True:
            raise ValueError("pre-evaluation block must be blocked")
        expected_audit_id = f"audit_execution_blocked_{self.links.event_id}"
        if self.audit_id != expected_audit_id:
            raise ValueError("audit_id does not match pre-evaluation block identity")
        if not (
            self.reason == self.metadata.failure_code == self.evidence.failure_code
        ):
            raise ValueError("pre-evaluation block failure codes must match")
        if self.links.activation_ref_digest != self.metadata.activation_ref_digest:
            raise ValueError("pre-evaluation block activation identity does not match")
        if _RUNTIME_SECRET_MATERIAL.search(self.model_dump_json()) is not None:
            raise ValueError("pre-evaluation block cannot contain runtime secrets")
        return self
