"""Bind a receipt journal to its producer's fixed Guard endpoint and identity."""

from __future__ import annotations

import hashlib
import json

from .activation_ack import ProductActivationError
from .endpoint_policy import validate_guard_api_base_url
from .product_envelope_store import ProductStoreNamespace


def product_transport_binding_digest(
    *,
    base_url: str,
    namespace: ProductStoreNamespace,
    api_mode: str = "guard-api-v0.3",
) -> str:
    """Return a raw SHA-256; credentials and expiring authority are excluded.

    This binds the configured destination, not the remote server's database.
    Server acknowledgement and independent database evidence remain necessary.
    """
    try:
        if type(namespace) is not ProductStoreNamespace or api_mode != "guard-api-v0.3":
            raise ValueError
        url = validate_guard_api_base_url(base_url)
        value = {
            "schema_version": "agentguard-product-receipt-transport/1",
            "api_mode": api_mode,
            "base_url": url,
            "namespace": {
                "runtime": namespace.runtime,
                "agent_id": namespace.agent_id,
                "principal_id": namespace.principal_id,
                "runtime_binding_id": namespace.runtime_binding_id,
            },
        }
        wire = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(wire).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        raise ProductActivationError("receipt_transport_binding_invalid") from None
