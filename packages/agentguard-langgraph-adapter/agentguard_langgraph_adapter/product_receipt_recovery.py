"""Open an existing receipt journal without starting a runtime or ACK session."""

from __future__ import annotations

from dataclasses import fields, replace
import json
from pathlib import Path
import stat

from .activation_ack import ProductActivationError
from .config import (
    AgentGuardLangGraphConfig,
    validate_product_configuration,
    validate_product_receipt_paths,
)
from .core_client import AgentGuardCoreClient
from .product_delivery import (
    ProductReceiptDeliveryResult,
    ProductReceiptReconciliationSnapshot,
)
from .product_envelope_store import ProductEnvelopeStore, ProductStoreNamespace
from .product_manifest import (
    _manifest_path,
    _read_protected_manifest,
    _unique_object,
)
from .product_outbox import ProductOutboxStatus, ProductReceiptOutbox

RECOVERY_CONFIG_SCHEMA = "agentguard-product-receipt-recovery/1"


def _invalid_constant(_value: str) -> None:
    raise ValueError


def load_product_recovery_config(path: str | Path) -> AgentGuardLangGraphConfig:
    """Read a 0600 configuration in its owner's 0700 directory; never log it."""
    try:
        body, _fingerprint = _read_protected_manifest(_manifest_path(path))
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "runtime", "config"}
            or value["schema_version"] != RECOVERY_CONFIG_SCHEMA
            or value["runtime"] != "langgraph"
            or type(value["config"]) is not dict
        ):
            raise ValueError
        raw = value["config"]
        required = {
            "core_base_url",
            "token",
            "runtime",
            "agent_id",
            "runtime_binding_id",
            "api_mode",
            "fail_closed",
            "defense_enabled",
            "context_isolation_mode",
            "runtime_receipt_mode",
            "product_manifest_path",
            "product_receipt_directory",
            "product_receipt_key_path",
            "product_execution_enabled",
        }
        if (
            not required.issubset(raw)
            or not set(raw).issubset(
                {item.name for item in fields(AgentGuardLangGraphConfig)}
            )
            or raw["product_execution_enabled"] is not False
        ):
            raise ValueError
        config = AgentGuardLangGraphConfig(**raw)
        validate_product_configuration(config)
        validate_product_receipt_paths(config, required=True)
        return config
    except ProductActivationError as error:
        code = (
            "receipt_recovery_config_unavailable"
            if error.code == "manifest_unavailable"
            else "receipt_recovery_config_invalid"
        )
        raise ProductActivationError(code) from None
    except Exception:
        raise ProductActivationError("receipt_recovery_config_invalid") from None


class ProductReceiptRecovery:
    """A receipts-only facade. It exposes no sender, ticket or runtime callbacks."""

    __slots__ = ("_outbox",)

    def __init__(self, outbox: ProductReceiptOutbox) -> None:
        self._outbox = outbox

    def __repr__(self) -> str:
        return "ProductReceiptRecovery(<private>)"

    def status(self) -> ProductOutboxStatus:
        return self._outbox.status()

    def drain_once(self) -> tuple[ProductReceiptDeliveryResult, ...]:
        return self._outbox.drain_once()

    def reconcile_rejected_receipt(
        self, audit_id: str, expected_wire_digest: str
    ) -> ProductReceiptDeliveryResult:
        return self._outbox.reconcile_rejected_receipt(audit_id, expected_wire_digest)

    def reconciliation_snapshot(
        self, audit_id: str, expected_wire_digest: str
    ) -> ProductReceiptReconciliationSnapshot:
        return self._outbox.reconciliation_snapshot(audit_id, expected_wire_digest)

    def close(self) -> ProductOutboxStatus:
        # The outbox retains ownership while an existing send is finishing.
        # In particular, there is no unconditional store.close() here.
        return self._outbox.close()

    def __enter__(self) -> ProductReceiptRecovery:
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()


def _require_existing_storage(config: AgentGuardLangGraphConfig) -> None:
    try:
        assert config.product_receipt_directory is not None
        assert config.product_receipt_key_path is not None
        directory = Path(config.product_receipt_directory)
        key = Path(config.product_receipt_key_path)
        if (
            directory.resolve(strict=True) != directory
            or key.resolve(strict=True) != key
            or not stat.S_ISDIR(directory.lstat().st_mode)
            or not stat.S_ISREG(key.lstat().st_mode)
            or not any(directory.glob("*.agq"))
        ):
            raise ValueError
    except Exception:
        raise ProductActivationError("receipt_recovery_storage_missing") from None


def open_product_receipt_recovery(
    config: AgentGuardLangGraphConfig,
) -> ProductReceiptRecovery:
    """Use the original endpoint binding; no current ACK is requested or required."""
    if type(config) is not AgentGuardLangGraphConfig:
        raise ProductActivationError("receipt_recovery_config_invalid")
    store: ProductEnvelopeStore | None = None
    outbox: ProductReceiptOutbox | None = None
    try:
        # Copy the configuration before capturing transport. A normal producer's
        # execution opt-in never enables any execution in this recovery object.
        frozen_config = replace(config, product_execution_enabled=False)
        validate_product_configuration(frozen_config)
        validate_product_receipt_paths(frozen_config, required=True)
        _require_existing_storage(frozen_config)
        client = AgentGuardCoreClient(frozen_config)
        manifest = client._product_manifest
        if manifest is None:
            raise ProductActivationError("receipt_recovery_config_invalid")
        binding = client.product_receipt_transport_binding_digest
        assert frozen_config.product_receipt_directory is not None
        assert frozen_config.product_receipt_key_path is not None
        store = ProductEnvelopeStore(
            frozen_config.product_receipt_directory,
            frozen_config.product_receipt_key_path,
            existing_only=True,
            namespace=ProductStoreNamespace(
                runtime=manifest.runtime,
                agent_id=manifest.agent_id,
                principal_id=manifest.principal_id,
                runtime_binding_id=manifest.runtime_binding_id,
            ),
        )
        outbox = ProductReceiptOutbox(
            store,
            send_receipt=client.submit_product_receipt_wire,
            receipts_only=True,
            transport_binding_digest=binding,
        )
        if outbox.transport_binding_digest != binding:
            raise ProductActivationError("receipt_recovery_binding_missing")
        return ProductReceiptRecovery(outbox)
    except Exception as error:
        # Initialization cannot start a sender or worker. After construction,
        # only the outbox closes its store, including any deferred close.
        if outbox is not None:
            outbox.close()
        elif store is not None:
            store.close()
        if isinstance(error, ProductActivationError):
            raise ProductActivationError(error.code) from None
        raise ProductActivationError("receipt_recovery_unavailable") from None
