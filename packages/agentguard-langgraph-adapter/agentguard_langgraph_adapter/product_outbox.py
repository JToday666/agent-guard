"""Encrypted Product receipt journal; persistence precedes every HTTP attempt."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from threading import Event, RLock, Thread, current_thread
import time
from typing import Any, Callable

from .activation_ack import (
    ActivationAckV1,
    ProductActivationError,
    timestamp_nanoseconds,
)
from .event_models import AuditEvent, RuntimeOutcomeReceipt
from .product_delivery import (
    ProductReceiptDeliveryResult,
    ProductReceiptTransportResult,
)
from .product_envelope_store import ProductEnvelopeStore, StoredEnvelope

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SECRET = re.compile(r"(?:hmac-sha256|lease-v1):[0-9a-f]+", re.IGNORECASE)
_CONTROL_ID = "barrier_control"
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "action_id",
        "event_id",
        "phase",
        "start",
        "terminal",
        "start_acknowledged",
        "attempts",
        "next_attempt_at_ms",
        "error_code",
        "http_status",
    }
)
_TOMBSTONE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "action_id",
        "event_id",
        "owner_kind",
        "start_audit_id",
        "start_digest",
        "terminal_audit_id",
        "terminal_digest",
    }
)
_ITEM_FIELDS = frozenset({"audit_id", "wire", "wire_digest", "activation_ack"})


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class ProductOutboxStatus:
    pending_count: int
    completed_count: int
    unknown_action_count: int
    breaker_open: bool
    record_count: int
    stored_bytes: int
    error_code: str | None = None


class ProductReceiptOutbox:
    """One owning process; never replay an action or expose decrypted status."""

    def __init__(
        self,
        store: ProductEnvelopeStore,
        *,
        send_receipt: Callable[[bytes], ProductReceiptTransportResult],
        retry_base_seconds: float = 0.25,
        retry_max_seconds: float = 30.0,
        drain_interval_seconds: float = 1.0,
    ) -> None:
        if not isinstance(store, ProductEnvelopeStore) or not callable(send_receipt):
            raise ProductActivationError("outbox_invalid_configuration")
        for value in (retry_base_seconds, retry_max_seconds, drain_interval_seconds):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 < value <= 60
                or not math.isfinite(value)
            ):
                raise ProductActivationError("outbox_invalid_configuration")
        if retry_base_seconds > retry_max_seconds:
            raise ProductActivationError("outbox_invalid_configuration")
        self._store = store
        self._send = send_receipt
        self._retry_base_ms = max(1, int(retry_base_seconds * 1000))
        self._retry_max_ms = max(1, int(retry_max_seconds * 1000))
        self._drain_interval = float(drain_interval_seconds)
        self._mutex = RLock()
        self._stop = Event()
        self._worker: Thread | None = None
        self._closed = False
        self._failure: str | None = None
        self._sending: set[str] = set()
        self._starting: str | None = None
        self._active: str | None = None
        self._records: dict[str, tuple[StoredEnvelope, dict[str, Any]]] = {}
        self._control: StoredEnvelope | None = None
        self._last_status = ProductOutboxStatus(0, 0, 0, False, 0, 0)
        try:
            with self._mutex:
                self._load_locked()
                if self._control is None:
                    self._control = store.create(
                        _CONTROL_ID,
                        _encode(
                            {
                                "schema_version": "1.0",
                                "record_type": "breaker",
                                "tripped": False,
                                "code": None,
                            }
                        ),
                        kind="breaker",
                    )
                if self._unknown_count_locked():
                    self._trip_locked("action_outcome_unknown")
        except Exception:
            store.close()
            raise ProductActivationError("outbox_recovery_failed") from None

    def __repr__(self) -> str:
        return f"ProductReceiptOutbox(closed={self._closed})"

    def start(self) -> None:
        with self._mutex:
            self._assert_open()
            if self._worker is None:
                self._worker = Thread(
                    target=self._loop, name="agentguard-product-outbox", daemon=True
                )
                self._worker.start()

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._starting = None
            self._active = None
            self.status()
            self._closed = True
            self._stop.set()
            worker = self._worker
        if worker is not None and worker is not current_thread():
            worker.join(timeout=1.0)
        # A late HTTP success cannot delete or change the durable journal.
        self._store.close()

    def status(self) -> ProductOutboxStatus:
        with self._mutex:
            if self._closed:
                return ProductOutboxStatus(
                    self._last_status.pending_count,
                    self._last_status.completed_count,
                    self._last_status.unknown_action_count,
                    True,
                    self._last_status.record_count,
                    self._last_status.stored_bytes,
                    "outbox_closed",
                )
            try:
                self._load_locked()
                usage = self._store.usage()
                pending = sum(
                    data["record_type"] != "tombstone"
                    and self._pending_item(data) is not None
                    for _, data in self._records.values()
                )
                unknown = self._unknown_count_locked()
                self._last_status = ProductOutboxStatus(
                    pending,
                    sum(
                        data["record_type"] == "tombstone"
                        for _, data in self._records.values()
                    ),
                    unknown,
                    bool(self._failure or unknown),
                    usage.record_count,
                    usage.stored_bytes,
                    self._failure or ("action_outcome_unknown" if unknown else None),
                )
            except Exception:
                self._trip_locked("outbox_storage_failed")
                previous = self._last_status
                self._last_status = ProductOutboxStatus(
                    previous.pending_count,
                    previous.completed_count,
                    previous.unknown_action_count,
                    True,
                    previous.record_count,
                    previous.stored_bytes,
                    "outbox_storage_failed",
                )
            return self._last_status

    def submit(
        self,
        receipt: AuditEvent | RuntimeOutcomeReceipt,
        *,
        activation_ack: ActivationAckV1 | None = None,
    ) -> ProductReceiptDeliveryResult:
        if (
            isinstance(receipt, AuditEvent)
            and receipt.event_type == "tool_call_started"
        ):
            return _failed("action_barrier_required")
        try:
            item, action_id, event_id = self._receipt_item(receipt, activation_ack)
            record_id = _record_id("receipt", item["audit_id"])
            with self._mutex:
                self._assert_open()
                self._load_locked()
                previous = self._records.get(record_id)
                if previous is None:
                    data = _new_record(
                        "receipt", action_id, event_id, start=None, terminal=item
                    )
                    self._create_locked(record_id, data, "receipt")
                else:
                    data = previous[1]
                    if not self._matches_terminal(data, item):
                        self._trip_locked("outbox_receipt_conflict")
                        return _failed("outbox_receipt_conflict", item["audit_id"])
                    if data["record_type"] == "tombstone":
                        return ProductReceiptDeliveryResult(
                            "recorded", item["audit_id"]
                        )
            return self._deliver(record_id)
        except ProductActivationError as exc:
            return _failed(_safe_local_code(exc.code))
        except Exception:
            with self._mutex:
                self._trip_locked("outbox_storage_failed")
            return _failed("outbox_storage_failed")

    def drain_once(self) -> tuple[ProductReceiptDeliveryResult, ...]:
        with self._mutex:
            self._assert_open()
            try:
                self._load_locked()
                selected = [
                    record_id
                    for record_id, (_, data) in self._records.items()
                    if data["record_type"] != "tombstone"
                    and data["phase"] not in {"failed", "permanent_rejected"}
                    and self._pending_item(data) is not None
                    and data["next_attempt_at_ms"] <= _now_ms()
                ]
            except Exception:
                self._trip_locked("outbox_storage_failed")
                return (_failed("outbox_storage_failed"),)
        return tuple(self._deliver(record_id) for record_id in selected)

    def _assert_ready(self) -> None:
        with self._mutex:
            self._assert_open()
            status = self.status()
            if status.breaker_open:
                raise ProductActivationError(status.error_code or "outbox_barrier_open")
            if self._starting is not None or self._active is not None:
                raise ProductActivationError("action_already_active")
            if status.pending_count:
                raise ProductActivationError("outbox_pending_receipts")

    def _begin(
        self,
        action_id: str,
        event_id: str,
        receipt: AuditEvent,
        activation_ack: ActivationAckV1 | None,
        on_created: Callable[[str], None] | None = None,
    ) -> tuple[ProductReceiptDeliveryResult, str | None]:
        reserved = False
        try:
            if (
                not _identifier(action_id)
                or not _identifier(event_id)
                or not isinstance(receipt, AuditEvent)
                or isinstance(receipt, RuntimeOutcomeReceipt)
                or receipt.record_type != "runtime_observation"
            ):
                raise ProductActivationError("action_identity_invalid")
            item, actual_action, actual_event = self._receipt_item(
                receipt, activation_ack
            )
            if actual_action != action_id or actual_event != event_id:
                raise ProductActivationError("action_identity_invalid")
            record_id = _record_id("action", action_id)
            with self._mutex:
                self._assert_ready()
                if record_id in self._records:
                    return _failed("action_already_known", item["audit_id"]), None
                self._starting = record_id
                reserved = True
                self._create_locked(
                    record_id,
                    _new_record(
                        "action", action_id, event_id, start=item, terminal=None
                    ),
                    "action",
                )
                if on_created is not None:
                    on_created(record_id)
            delivered = self._deliver(record_id)
            with self._mutex:
                self._starting = None
                if (
                    not self._closed
                    and self._failure is None
                    and delivered.status == "recorded"
                ):
                    self._active = record_id
                    return delivered, record_id
                return (
                    delivered
                    if delivered.status != "recorded"
                    else _failed("outbox_barrier_open", item["audit_id"])
                ), None
        except ProductActivationError as exc:
            with self._mutex:
                if reserved:
                    self._starting = None
            return _failed(_safe_local_code(exc.code)), None
        except Exception:
            with self._mutex:
                if reserved:
                    self._starting = None
                self._trip_locked("outbox_storage_failed")
            return _failed("outbox_storage_failed"), None

    def _publish_ticket(
        self, record_id: str, publish: Callable[[], None]
    ) -> str | None:
        # Linearize permission publication with close and the sticky breaker.
        with self._mutex:

            def refuse(code: str) -> str:
                if self._active == record_id:
                    self._active = None
                return code

            try:
                self._assert_open()
                self._load_locked()
                if self._failure is not None:
                    return refuse(self._failure)
                if any(
                    self._pending_item(item) is not None
                    for _, item in self._records.values()
                ):
                    return refuse("outbox_pending_receipts")
                _, data = self._records[record_id]
                if self._active != record_id or data["phase"] != "active":
                    return refuse("action_ticket_invalid")
                publish()
                return None
            except ProductActivationError as exc:
                return refuse(_safe_local_code(exc.code))
            except Exception:
                self._trip_locked("outbox_storage_failed")
                return refuse("outbox_storage_failed")

    def _finish(
        self, record_id: str, receipt: RuntimeOutcomeReceipt
    ) -> ProductReceiptDeliveryResult:
        try:
            if not isinstance(receipt, RuntimeOutcomeReceipt):
                raise ProductActivationError("terminal_receipt_required")
            if receipt.metadata.outcome_kind not in {
                "execution_completed",
                "execution_failed",
                "pre_execution_deny",
            }:
                raise ProductActivationError("terminal_receipt_required")
            item, action_id, event_id = self._receipt_item(receipt, None)
            with self._mutex:
                self._assert_open()
                self._load_locked()
                stored, data = self._records[record_id]
                if data["record_type"] == "tombstone":
                    if self._matches_terminal(data, item):
                        return ProductReceiptDeliveryResult(
                            "recorded", item["audit_id"]
                        )
                    self._trip_locked("outbox_receipt_conflict")
                    return _failed("outbox_receipt_conflict", item["audit_id"])
                if data["action_id"] != action_id or data["event_id"] != event_id:
                    raise ProductActivationError("action_identity_invalid")
                if data["terminal"] is not None:
                    if not self._matches_terminal(data, item):
                        self._trip_locked("outbox_receipt_conflict")
                        return _failed("outbox_receipt_conflict", item["audit_id"])
                else:
                    if self._active != record_id or data["phase"] != "active":
                        raise ProductActivationError("action_ticket_invalid")
                    self._validate_terminal_anchor(data, item)
                    updated = {
                        **data,
                        "terminal": item,
                        "phase": "terminal_pending",
                        "attempts": 0,
                        "next_attempt_at_ms": 0,
                        "error_code": None,
                        "http_status": None,
                    }
                    self._replace_locked(stored, updated)
                    self._active = None
            return self._deliver(record_id)
        except ProductActivationError as exc:
            with self._mutex:
                self._trip_locked("action_terminal_invalid")
            return _failed(_safe_local_code(exc.code))
        except Exception:
            with self._mutex:
                self._trip_locked("outbox_storage_failed")
            return _failed("outbox_storage_failed")

    def _mark_unknown(self, record_id: str) -> None:
        with self._mutex:
            self._assert_open()
            if self._active == record_id:
                self._active = None
            self._trip_locked("action_outcome_unknown")

    def _abort(
        self, record_id: str, receipt: RuntimeOutcomeReceipt
    ) -> ProductReceiptDeliveryResult:
        """Append a known not-invoked fact, even while the start is unconfirmed."""
        try:
            if not _not_invoked(receipt):
                raise ProductActivationError("terminal_receipt_required")
            item, action_id, event_id = self._receipt_item(receipt, None)
            with self._mutex:
                self._assert_open()
                self._load_locked()
                stored, data = self._records[record_id]
                if data["record_type"] == "tombstone":
                    if self._matches_terminal(data, item):
                        return ProductReceiptDeliveryResult(
                            "recorded", item["audit_id"]
                        )
                    raise ProductActivationError("outbox_receipt_conflict")
                if data["record_type"] != "action" or (
                    data["action_id"],
                    data["event_id"],
                ) != (action_id, event_id):
                    raise ProductActivationError("action_identity_invalid")
                self._validate_terminal_anchor(data, item)
                if data["terminal"] is not None:
                    if not self._matches_terminal(data, item):
                        raise ProductActivationError("outbox_receipt_conflict")
                else:
                    updated = {**data, "terminal": item}
                    if data["phase"] not in {"failed", "permanent_rejected"}:
                        updated["phase"] = "terminal_pending"
                    self._replace_locked(stored, updated)
                    if self._active == record_id:
                        self._active = None
            # At most two distinct attempts: original start, then original terminal.
            for _ in range(2):
                result = self._deliver(record_id)
                if result.status != "recorded":
                    return ProductReceiptDeliveryResult(
                        result.status,
                        item["audit_id"],
                        result.http_status,
                        result.error_code,
                    )
                if result.audit_id == item["audit_id"]:
                    return result
            return ProductReceiptDeliveryResult("queued_durable", item["audit_id"])
        except ProductActivationError as exc:
            with self._mutex:
                self._trip_locked("action_terminal_invalid")
            return _failed(_safe_local_code(exc.code))
        except Exception:
            with self._mutex:
                self._trip_locked("outbox_storage_failed")
            return _failed("outbox_storage_failed")

    def _deliver(self, record_id: str) -> ProductReceiptDeliveryResult:
        with self._mutex:
            if self._closed:
                return _failed("outbox_closed")
            try:
                self._load_locked()
                stored, data = self._records[record_id]
                if data["record_type"] == "tombstone":
                    return ProductReceiptDeliveryResult(
                        "recorded", data["terminal_audit_id"] or data["start_audit_id"]
                    )
                item = self._pending_item(data)
                if item is None:
                    return ProductReceiptDeliveryResult(
                        "recorded", data["start"]["audit_id"]
                    )
                if data["phase"] in {"failed", "permanent_rejected"}:
                    return ProductReceiptDeliveryResult(
                        data["phase"],
                        item["audit_id"],
                        data["http_status"],
                        data["error_code"],
                    )
                if self._sending or data["next_attempt_at_ms"] > _now_ms():
                    return ProductReceiptDeliveryResult(
                        "queued_durable",
                        item["audit_id"],
                        error_code="receipt_retry_pending",
                    )
                self._sending.add(record_id)
                wire = item["wire"].encode("utf-8")
            except Exception:
                self._trip_locked("outbox_storage_failed")
                return _failed("outbox_storage_failed")
        try:
            reply = self._send(wire)
        except Exception:
            reply = ProductReceiptTransportResult(
                "retryable", error_code="receipt_transport_unavailable"
            )
        with self._mutex:
            self._sending.discard(record_id)
            if self._closed:
                return _failed("outbox_closed", item["audit_id"])
            try:
                current = self._store.get(record_id)
                if current is not None and current.revision != stored.revision:
                    # A same-process abort may append a terminal while this exact
                    # start wire is in flight. Merge only that monotonic transition.
                    changed = json.loads(current.payload)
                    self._validate_record(current, changed)
                    expected = {
                        **data,
                        "terminal": changed.get("terminal"),
                        "phase": "terminal_pending",
                    }
                    if (
                        data["record_type"] == "action"
                        and not data["start_acknowledged"]
                        and data["terminal"] is None
                        and changed.get("terminal") is not None
                        and changed == expected
                    ):
                        stored, data = current, changed
                if current is None or current.revision != stored.revision:
                    self._trip_locked("outbox_receipt_conflict")
                    return _failed("outbox_receipt_conflict", item["audit_id"])
                status, http_status, error_code = _transport_fact(
                    reply, item["audit_id"]
                )
                if status == "recorded":
                    if (
                        data["record_type"] == "action"
                        and not data["start_acknowledged"]
                    ):
                        self._replace_locked(
                            stored,
                            {
                                **data,
                                "start_acknowledged": True,
                                "phase": (
                                    "terminal_pending" if data["terminal"] else "active"
                                ),
                                "attempts": 0,
                                "next_attempt_at_ms": 0,
                                "error_code": None,
                                "http_status": None,
                            },
                        )
                    else:
                        self._replace_locked(stored, _tombstone(data), kind="tombstone")
                    return ProductReceiptDeliveryResult(
                        "recorded", item["audit_id"], http_status
                    )
                if status == "retryable":
                    attempts = data["attempts"] + 1
                    delay = min(
                        self._retry_max_ms,
                        self._retry_base_ms * (2 ** min(attempts - 1, 16)),
                    )
                    self._replace_locked(
                        stored,
                        {
                            **data,
                            "attempts": attempts,
                            "next_attempt_at_ms": _now_ms() + delay,
                            "http_status": http_status,
                            "error_code": error_code,
                        },
                    )
                    return ProductReceiptDeliveryResult(
                        "queued_durable", item["audit_id"], http_status, error_code
                    )
                self._replace_locked(
                    stored,
                    {
                        **data,
                        "phase": status,
                        "http_status": http_status,
                        "error_code": error_code,
                    },
                )
                self._trip_locked(
                    "receipt_permanently_rejected"
                    if status == "permanent_rejected"
                    else "receipt_transport_failed"
                )
                return ProductReceiptDeliveryResult(
                    status, item["audit_id"], http_status, error_code
                )
            except Exception:
                self._trip_locked("outbox_storage_failed")
                return _failed("outbox_storage_failed", item["audit_id"])

    def _receipt_item(
        self,
        receipt: AuditEvent | RuntimeOutcomeReceipt,
        explicit: ActivationAckV1 | None,
    ) -> tuple[dict[str, Any], str | None, str]:
        try:
            if not isinstance(receipt, AuditEvent):
                raise ValueError
            carrier = (
                receipt.metadata.activation_ack
                if isinstance(receipt, RuntimeOutcomeReceipt)
                else getattr(receipt, "_product_activation_ack", None)
            )
            if explicit is not None and (
                not isinstance(explicit, ActivationAckV1)
                or carrier is not None
                and explicit.to_wire() != carrier.to_wire()
            ):
                raise ValueError
            ack = carrier if carrier is not None else explicit
            if not isinstance(ack, ActivationAckV1):
                raise ValueError
            ack = ActivationAckV1.model_validate(ack.to_wire())
            namespace = self._store.namespace
            if (ack.runtime, ack.agent_id, ack.runtime_binding_id) != (
                namespace.runtime,
                namespace.agent_id,
                namespace.runtime_binding_id,
            ):
                raise ValueError
            if isinstance(receipt, RuntimeOutcomeReceipt):
                if carrier is None:
                    raise ValueError
                validated = RuntimeOutcomeReceipt.model_validate(receipt.to_wire())
                payload = validated.to_wire()
            else:
                payload = receipt.model_dump(mode="json")
                if (
                    payload["record_type"] != "runtime_observation"
                    or "activation_ack" in payload["metadata"]
                    or _SECRET.search(_encode(payload).decode("utf-8"))
                ):
                    raise ValueError
            if payload["runtime"] != namespace.runtime or timestamp_nanoseconds(
                payload["timestamp"]
            ) < timestamp_nanoseconds(ack.issued_at):
                raise ValueError
            audit_id = payload["audit_id"]
            links = payload["links"]
            event_id = links.get("event_id")
            action_id = links.get("action_id")
            if (
                not _identifier(audit_id)
                or not _identifier(event_id)
                or not _identifier(links.get("policy_audit_id"))
                or action_id is not None
                and not _identifier(action_id)
            ):
                raise ValueError
            encoded = _encode(payload)
            return (
                {
                    "audit_id": audit_id,
                    "wire": encoded.decode("utf-8"),
                    "wire_digest": hashlib.sha256(encoded).hexdigest(),
                    "activation_ack": ack.to_wire(),
                },
                action_id,
                event_id,
            )
        except Exception:
            raise ProductActivationError("receipt_carrier_invalid") from None

    def _load_locked(self) -> None:
        records: dict[str, tuple[StoredEnvelope, dict[str, Any]]] = {}
        control = None
        for stored in self._store.records():
            data = json.loads(stored.payload)
            if _encode(data) != stored.payload:
                raise ValueError
            if stored.kind == "breaker":
                if (
                    stored.record_id != _CONTROL_ID
                    or set(data) != {"schema_version", "record_type", "tripped", "code"}
                    or data["schema_version"] != "1.0"
                    or data["record_type"] != "breaker"
                    or type(data["tripped"]) is not bool
                    or data["code"] is not None
                    and data["code"] not in _LOCAL_CODES
                ):
                    raise ValueError
                control = stored
                if data["tripped"]:
                    self._failure = data["code"] or "outbox_barrier_open"
                continue
            self._validate_record(stored, data)
            if data.get("phase") in {"failed", "permanent_rejected"}:
                self._failure = (
                    "receipt_permanently_rejected"
                    if data["phase"] == "permanent_rejected"
                    else "receipt_transport_failed"
                )
            records[stored.record_id] = stored, data
        if self._control is not None and control is None:
            raise ValueError
        self._records, self._control = records, control

    def _validate_record(self, stored: StoredEnvelope, data: dict[str, Any]) -> None:
        if not isinstance(data, dict) or data.get("schema_version") != "1.0":
            raise ValueError
        if stored.kind == "tombstone":
            if (
                set(data) != _TOMBSTONE_FIELDS
                or data["record_type"] != "tombstone"
                or data["owner_kind"] not in {"action", "receipt"}
            ):
                raise ValueError
            identity = (
                data["action_id"]
                if data["owner_kind"] == "action"
                else data["terminal_audit_id"]
            )
            if not _identifier(identity) or stored.record_id != _record_id(
                data["owner_kind"], identity
            ):
                raise ValueError
            if (
                not _identifier(data["event_id"])
                or not _identifier(data["terminal_audit_id"])
                or not _hex_digest(data["terminal_digest"])
            ):
                raise ValueError
            if data["owner_kind"] == "action":
                if not _identifier(data["start_audit_id"]) or not _hex_digest(
                    data["start_digest"]
                ):
                    raise ValueError
            elif data["start_audit_id"] is not None or data["start_digest"] is not None:
                raise ValueError
            return
        if (
            set(data) != _RECORD_FIELDS
            or stored.kind != data["record_type"]
            or stored.kind not in {"action", "receipt"}
            or not _identifier(data["event_id"])
            or data["phase"]
            not in {
                "intent",
                "active",
                "terminal_pending",
                "permanent_rejected",
                "failed",
            }
        ):
            raise ValueError
        for field in ("attempts", "next_attempt_at_ms"):
            if type(data[field]) is not int or data[field] < 0:
                raise ValueError
        if type(data["start_acknowledged"]) is not bool:
            raise ValueError
        if (
            data["error_code"] is not None
            and data["error_code"] not in _LOCAL_CODES | _DELIVERY_CODES
        ):
            raise ValueError
        if data["http_status"] is not None and (
            type(data["http_status"]) is not int
            or not 100 <= data["http_status"] <= 599
        ):
            raise ValueError
        for item in (data["start"], data["terminal"]):
            if item is None:
                continue
            if (
                not isinstance(item, dict)
                or set(item) != _ITEM_FIELDS
                or not isinstance(item["wire"], str)
                or hashlib.sha256(item["wire"].encode("utf-8")).hexdigest()
                != item["wire_digest"]
            ):
                raise ValueError
            payload = json.loads(item["wire"])
            ack = ActivationAckV1.model_validate(item["activation_ack"])
            model = (
                RuntimeOutcomeReceipt.model_validate(payload)
                if payload.get("record_type") == "runtime_outcome"
                else AuditEvent.model_validate(payload)
            )
            checked, action_id, event_id = self._receipt_item(model, ack)
            if (
                checked != item
                or event_id != data["event_id"]
                or action_id != data["action_id"]
            ):
                raise ValueError
        if stored.kind == "action":
            if (
                not _identifier(data["action_id"])
                or data["start"] is None
                or stored.record_id != _record_id("action", data["action_id"])
            ):
                raise ValueError
            if (
                json.loads(data["start"]["wire"])["record_type"]
                != "runtime_observation"
            ):
                raise ValueError
            if data["phase"] == "intent" and (
                data["start_acknowledged"] or data["terminal"] is not None
            ):
                raise ValueError
            if data["phase"] == "active" and (
                not data["start_acknowledged"] or data["terminal"] is not None
            ):
                raise ValueError
            if data["terminal"] is not None:
                if (
                    json.loads(data["terminal"]["wire"])["record_type"]
                    != "runtime_outcome"
                ):
                    raise ValueError
                terminal = RuntimeOutcomeReceipt.model_validate_json(
                    data["terminal"]["wire"]
                )
                if terminal.metadata.outcome_kind not in {
                    "execution_completed",
                    "execution_failed",
                    "pre_execution_deny",
                } or (not data["start_acknowledged"] and not _not_invoked(terminal)):
                    raise ValueError
                self._validate_terminal_anchor(data, data["terminal"])
            elif data["phase"] == "terminal_pending":
                raise ValueError
        elif (
            data["start"] is not None
            or data["terminal"] is None
            or stored.record_id != _record_id("receipt", data["terminal"]["audit_id"])
        ):
            raise ValueError
        elif data["start_acknowledged"] or data["phase"] in {"intent", "active"}:
            raise ValueError

    def _create_locked(self, record_id: str, data: dict[str, Any], kind: Any) -> None:
        stored = self._store.create(record_id, _encode(data), kind=kind)
        self._records[record_id] = stored, data

    def _replace_locked(
        self, stored: StoredEnvelope, data: dict[str, Any], *, kind: Any = None
    ) -> None:
        changed = self._store.replace(
            stored.record_id,
            _encode(data),
            expected_revision=stored.revision,
            kind=kind or stored.kind,
        )
        self._records[stored.record_id] = changed, data

    def _trip_locked(self, code: str) -> None:
        self._failure = code = _safe_local_code(code)
        if self._closed or self._control is None:
            return
        try:
            self._control = self._store.replace(
                _CONTROL_ID,
                _encode(
                    {
                        "schema_version": "1.0",
                        "record_type": "breaker",
                        "tripped": True,
                        "code": code,
                    }
                ),
                expected_revision=self._control.revision,
                kind="breaker",
            )
        except Exception:
            # No successful persistence claim is possible when storage fails.
            # Existing intent/terminal records remain the recovery boundary.
            pass

    def _unknown_count_locked(self) -> int:
        return sum(
            data["record_type"] == "action"
            and data["terminal"] is None
            and record_id not in {self._starting, self._active}
            for record_id, (_, data) in self._records.items()
        )

    @staticmethod
    def _pending_item(data: dict[str, Any]) -> dict[str, Any] | None:
        if data["record_type"] == "tombstone":
            return None
        if data["start"] is not None and not data["start_acknowledged"]:
            return data["start"]
        return data["terminal"]

    @staticmethod
    def _matches_terminal(data: dict[str, Any], item: dict[str, Any]) -> bool:
        if data["record_type"] == "tombstone":
            return (
                data["terminal_audit_id"] == item["audit_id"]
                and data["terminal_digest"] == item["wire_digest"]
            )
        return data["terminal"] == item

    @staticmethod
    def _validate_terminal_anchor(data: dict[str, Any], item: dict[str, Any]) -> None:
        start = data["start"]
        initial_links = json.loads(start["wire"])["links"]
        final_links = json.loads(item["wire"])["links"]
        for field in (
            "event_id",
            "action_id",
            "policy_audit_id",
            "decision_id",
            "approval_id",
            "lease_id",
            "consumption_id",
        ):
            if initial_links.get(field) != final_links.get(field):
                raise ProductActivationError("action_identity_invalid")
        if start["activation_ack"] != item["activation_ack"]:
            raise ProductActivationError("receipt_carrier_invalid")

    def _assert_open(self) -> None:
        if self._closed:
            raise ProductActivationError("outbox_closed")

    def _loop(self) -> None:
        while not self._stop.wait(self._drain_interval):
            try:
                self.drain_once()
            except Exception:
                with self._mutex:
                    if not self._closed:
                        self._trip_locked("outbox_storage_failed")


_LOCAL_CODES = frozenset(
    {
        "outbox_closed",
        "outbox_storage_failed",
        "outbox_recovery_failed",
        "outbox_receipt_conflict",
        "outbox_barrier_open",
        "outbox_pending_receipts",
        "action_outcome_unknown",
        "action_already_active",
        "action_already_known",
        "action_identity_invalid",
        "action_ticket_invalid",
        "action_terminal_invalid",
        "action_checkpoint_failed",
        "receipt_carrier_invalid",
        "terminal_receipt_required",
        "receipt_permanently_rejected",
        "receipt_transport_failed",
        "action_barrier_required",
    }
)
_DELIVERY_CODES = frozenset(
    {
        "receipt_retry_pending",
        "receipt_acknowledgement_invalid",
        "receipt_transport_invalid",
    }
)


def _safe_local_code(code: str) -> str:
    return (
        code
        if isinstance(code, str) and code in _LOCAL_CODES
        else "outbox_storage_failed"
    )


def _failed(code: str, audit_id: str | None = None) -> ProductReceiptDeliveryResult:
    return ProductReceiptDeliveryResult(
        "failed", audit_id=audit_id, error_code=_safe_local_code(code)
    )


def _not_invoked(receipt: Any) -> bool:
    return (
        isinstance(receipt, RuntimeOutcomeReceipt)
        and receipt.metadata.outcome_kind == "pre_execution_deny"
        and receipt.evidence.execution.get("status") == "not_invoked"
        and receipt.evidence.execution.get("invoked_at") is None
    )


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _hex_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _record_id(kind: str, identity: str) -> str:
    return f"{kind}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"


def _encode(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _new_record(
    kind: str,
    action_id: str | None,
    event_id: str,
    *,
    start: dict[str, Any] | None,
    terminal: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "record_type": kind,
        "action_id": action_id,
        "event_id": event_id,
        "phase": "intent" if start else "terminal_pending",
        "start": start,
        "terminal": terminal,
        "start_acknowledged": False,
        "attempts": 0,
        "next_attempt_at_ms": 0,
        "error_code": None,
        "http_status": None,
    }


def _tombstone(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "record_type": "tombstone",
        "owner_kind": data["record_type"],
        "action_id": data["action_id"],
        "event_id": data["event_id"],
        "start_audit_id": data["start"]["audit_id"] if data["start"] else None,
        "start_digest": data["start"]["wire_digest"] if data["start"] else None,
        "terminal_audit_id": data["terminal"]["audit_id"] if data["terminal"] else None,
        "terminal_digest": (
            data["terminal"]["wire_digest"] if data["terminal"] else None
        ),
    }


def _transport_fact(reply: Any, audit_id: str) -> tuple[Any, int | None, str | None]:
    if not isinstance(reply, ProductReceiptTransportResult) or reply.status not in {
        "recorded",
        "retryable",
        "permanent_rejected",
        "failed",
    }:
        return "failed", None, "receipt_transport_invalid"
    status = (
        reply.http_status
        if type(reply.http_status) is int and 100 <= reply.http_status <= 599
        else None
    )
    if reply.status == "recorded":
        if reply.audit_id != audit_id or status is not None and not 200 <= status < 300:
            return "failed", status, "receipt_acknowledgement_invalid"
        return "recorded", status, None
    code = {
        "retryable": "receipt_retry_pending",
        "permanent_rejected": "receipt_permanently_rejected",
        "failed": "receipt_transport_failed",
    }[reply.status]
    return reply.status, status, code
