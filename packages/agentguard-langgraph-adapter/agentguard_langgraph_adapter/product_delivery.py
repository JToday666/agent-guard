"""Explicit Product receipt facts; local durability is not server acknowledgement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ProductTransportStatus = Literal[
    "recorded", "retryable", "permanent_rejected", "failed"
]
ProductDeliveryStatus = Literal[
    "recorded", "queued_durable", "permanent_rejected", "failed"
]


@dataclass(frozen=True, slots=True)
class ProductReceiptTransportResult:
    """One bounded HTTP attempt, with no response body or credential fields."""

    status: ProductTransportStatus
    audit_id: str | None = None
    http_status: int | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class ProductReceiptDeliveryResult:
    """The durable delivery result exposed independently of the legacy API."""

    status: ProductDeliveryStatus
    audit_id: str | None = None
    http_status: int | None = None
    error_code: str | None = None

    def compatibility_response(self) -> dict[str, Any]:
        return {
            "ok": self.status == "recorded",
            "audit_id": self.audit_id,
            "delivery_status": self.status,
            **(
                {"error": self.error_code or self.status}
                if self.status != "recorded"
                else {}
            ),
        }
