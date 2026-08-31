"""Shared product activation acknowledgement contract.

This module intentionally has no dependency on the broader product decision
models.  Runtime outcome contracts can therefore reuse the exact
``ActivationAckV1`` type without creating a ``product``/``models`` import
cycle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

ProductRuntime = Literal["langgraph", "openclaw"]

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE = r"^hmac-sha256:[0-9a-f]{64}$"
_RUNTIME_PROFILE_IDS = {
    "langgraph": "agentguard-langgraph-v2",
    "openclaw": "agentguard-openclaw-v2-restricted",
}


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


class ActivationAckV1(BaseModel):
    """Short-lived server acknowledgement of exact runtime activation identity."""

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
                                "runtime_version": {"const": "1.2.7"},
                                "plugin_version": {"const": "0.1.0rc1"},
                                "profile_id": {"const": "agentguard-langgraph-v2"},
                                "plugin_inventory_digest": {"type": "null"},
                                "plugin_order_inventory_digest": {"type": "null"},
                            }
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
                                "plugin_inventory_digest": {
                                    "type": "string",
                                    "pattern": _DIGEST,
                                },
                                "plugin_order_inventory_digest": {
                                    "type": "string",
                                    "pattern": _DIGEST,
                                },
                            },
                            "required": [
                                "plugin_inventory_digest",
                                "plugin_order_inventory_digest",
                            ],
                        },
                    },
                ]
            },
        ),
    )

    schema_version: Literal["1.0"] = "1.0"
    runtime: ProductRuntime
    runtime_version: str = Field(min_length=1, max_length=64)
    plugin_version: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=1, max_length=128)
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    profile_id: str = Field(min_length=1, max_length=128)
    activation_ref_digest: str = Field(pattern=_DIGEST)
    capability_digest: str = Field(pattern=_DIGEST)
    host_inventory_digest: str = Field(pattern=_DIGEST)
    plugin_inventory_digest: str | None = Field(default=None, pattern=_DIGEST)
    plugin_order_inventory_digest: str | None = Field(default=None, pattern=_DIGEST)
    tool_inventory_digest: str = Field(pattern=_DIGEST)
    issued_at: str
    expires_at: str
    ack_token: str = Field(pattern=_SIGNATURE)

    @model_validator(mode="after")
    def validate_ack(self) -> "ActivationAckV1":
        _require_window(
            self.issued_at,
            self.expires_at,
            maximum=timedelta(seconds=120),
        )
        expected_runtime_version = {
            "langgraph": "1.2.7",
            "openclaw": "2026.7.1-2",
        }[self.runtime]
        if self.runtime_version != expected_runtime_version:
            raise ValueError(
                f"{self.runtime} activation ack requires runtime_version="
                f"{expected_runtime_version}"
            )
        expected_plugin_version = {
            "langgraph": "0.1.0rc1",
            "openclaw": "0.1.0-rc.1",
        }[self.runtime]
        if self.plugin_version != expected_plugin_version:
            raise ValueError(
                f"{self.runtime} activation ack requires plugin_version="
                f"{expected_plugin_version}"
            )
        expected_profile_id = _RUNTIME_PROFILE_IDS[self.runtime]
        if self.profile_id != expected_profile_id:
            raise ValueError(
                f"{self.runtime} activation ack requires profile_id="
                f"{expected_profile_id}"
            )
        if self.runtime == "openclaw" and any(
            value is None
            for value in (
                self.plugin_inventory_digest,
                self.plugin_order_inventory_digest,
            )
        ):
            raise ValueError("OpenClaw activation ack requires plugin inventories")
        if self.runtime == "langgraph" and any(
            value is not None
            for value in (
                self.plugin_inventory_digest,
                self.plugin_order_inventory_digest,
            )
        ):
            raise ValueError("LangGraph activation ack has no plugin inventories")
        return self

    def token_projection(self) -> dict[str, Any]:
        dumped = self.model_dump(mode="json", exclude={"ack_token"})
        return {key: dumped[key] for key in sorted(dumped)}
