"""Secret-safe transport reader for the frozen LangGraph activation ACK."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from typing import Any, Literal, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from .product_manifest import ProductActivationManifest

DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$",
    re.ASCII,
)
_EPOCH = datetime(1970, 1, 1)
_NS_PER_SECOND = 1_000_000_000


class ProductActivationError(RuntimeError):
    """Fixed error code only; never retain a token, response, or private path."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Product activation unavailable: {code}")


def timestamp_nanoseconds(value: str) -> int:
    """Parse RFC3339 without rounding a sub-microsecond validity boundary."""
    try:
        match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            raise ValueError
        year, month, day, hour, minute, second = map(int, match.group(1, 2, 3, 4, 5, 6))
        base = datetime(year, month, day, hour, minute, second)
        offset = 0
        if match.group(8) != "Z":
            offset_hour, offset_minute = int(match.group(10)), int(match.group(11))
            if offset_hour > 23 or offset_minute > 59:
                raise ValueError
            offset = (offset_hour * 60 + offset_minute) * 60
            if match.group(9) == "-":
                offset = -offset
        elapsed = base - _EPOCH
        seconds = elapsed.days * 86400 + elapsed.seconds - offset
        fraction = int((match.group(7) or "").ljust(9, "0"))
        return seconds * _NS_PER_SECOND + fraction
    except (ValueError, TypeError, OverflowError):
        raise ProductActivationError("invalid_timestamp") from None


def datetime_nanoseconds(value: datetime) -> int:
    try:
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise ValueError
        elapsed = value.astimezone(timezone.utc).replace(tzinfo=None) - _EPOCH
        return (
            elapsed.days * 86400 + elapsed.seconds
        ) * _NS_PER_SECOND + elapsed.microseconds * 1000
    except (ValueError, TypeError, OverflowError):
        raise ProductActivationError("invalid_clock") from None


def _max_age_nanoseconds(value: float) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value <= 120
        or not math.isfinite(value)
    ):
        raise ProductActivationError("invalid_max_age")
    return int(value * _NS_PER_SECOND)


class ActivationAckV1(BaseModel):
    """One immutable ACK; only explicit transport methods expose its token."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )

    schema_version: Literal["1.0"]
    runtime: Literal["langgraph"]
    runtime_version: Literal["1.2.7"]
    plugin_version: Literal["0.1.0rc1"]
    agent_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    runtime_binding_id: str = Field(
        min_length=1, max_length=256, pattern=IDENTIFIER_PATTERN
    )
    profile_id: Literal["agentguard-langgraph-v2"]
    activation_ref_digest: str = Field(pattern=DIGEST_PATTERN)
    capability_digest: str = Field(pattern=DIGEST_PATTERN)
    host_inventory_digest: str = Field(pattern=DIGEST_PATTERN)
    plugin_inventory_digest: None
    plugin_order_inventory_digest: None
    tool_inventory_digest: str = Field(pattern=DIGEST_PATTERN)
    issued_at: str
    expires_at: str
    ack_token: str = Field(
        pattern=r"^hmac-sha256:[0-9a-f]{64}$", exclude=True, repr=False
    )

    @model_validator(mode="after")
    def _validate_window(self) -> ActivationAckV1:
        issued = timestamp_nanoseconds(self.issued_at)
        expires = timestamp_nanoseconds(self.expires_at)
        if not 0 < expires - issued <= 120 * _NS_PER_SECOND:
            raise ProductActivationError("invalid_validity_window")
        return self

    @classmethod
    def read(
        cls,
        value: object,
        *,
        expected: ProductActivationManifest,
        now: datetime,
        max_age_seconds: float = 120.0,
    ) -> ActivationAckV1:
        try:
            # Copy/parse actual wire data; constructed instances cannot bypass validation.
            if not isinstance(value, dict):
                raise ProductActivationError("invalid_ack")
            ack = cls.model_validate(value)
        except ProductActivationError:
            raise
        except Exception:
            raise ProductActivationError("invalid_ack") from None
        pairs = (
            (ack.runtime, expected.runtime),
            (ack.runtime_version, expected.runtime_version),
            (ack.plugin_version, expected.plugin_version),
            (ack.agent_id, expected.agent_id),
            (ack.runtime_binding_id, expected.runtime_binding_id),
            (ack.profile_id, expected.profile_id),
            (ack.activation_ref_digest, expected.activation_ref_digest),
            (ack.capability_digest, expected.capability_report_digest),
            (ack.host_inventory_digest, expected.host_inventory_digest),
            (ack.tool_inventory_digest, expected.tool_inventory_digest),
        )
        if any(actual != wanted for actual, wanted in pairs):
            raise ProductActivationError("ack_identity_mismatch")
        ack.remaining_seconds(now=now, max_age_seconds=max_age_seconds)
        return ack

    def remaining_seconds(
        self, *, now: datetime, max_age_seconds: float = 120.0
    ) -> float:
        age_limit = _max_age_nanoseconds(max_age_seconds)
        current = datetime_nanoseconds(now)
        issued = timestamp_nanoseconds(self.issued_at)
        expires = timestamp_nanoseconds(self.expires_at)
        if current < issued:
            raise ProductActivationError("ack_not_yet_valid")
        if current >= expires:
            raise ProductActivationError("ack_expired")
        if current - issued > age_limit:
            raise ProductActivationError("ack_too_old")
        return max(0, min(expires, issued + age_limit) - current) / _NS_PER_SECOND

    def header_value(self) -> str:
        return self.ack_token

    def to_wire(self) -> dict[str, Any]:
        return {**self.model_dump(mode="json"), "ack_token": self.ack_token}
