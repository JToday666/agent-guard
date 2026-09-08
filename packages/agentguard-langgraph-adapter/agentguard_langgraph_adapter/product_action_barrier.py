"""Explicit single-action permits backed by the encrypted Product journal."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from .activation_ack import ActivationAckV1, ProductActivationError
from .event_models import AuditEvent, RuntimeOutcomeReceipt
from .product_delivery import ProductReceiptDeliveryResult
from .product_outbox import ProductOutboxStatus, ProductReceiptOutbox

_CONSTRUCTION_KEY = object()


class ProductActionTicket:
    """Opaque same-process permission; never recover or serialize an invocation."""

    __slots__ = ("_owner", "_record_id")

    def __init__(self, key: object, owner: object, record_id: str) -> None:
        if key is not _CONSTRUCTION_KEY:
            raise ProductActivationError("action_ticket_invalid")
        self._owner = owner
        self._record_id = record_id

    def __repr__(self) -> str:
        return "ProductActionTicket(<private>)"

    def __reduce__(self) -> Any:
        raise ProductActivationError("action_ticket_invalid")


@dataclass(frozen=True, slots=True)
class BeginActionResult:
    delivery: ProductReceiptDeliveryResult
    ticket: ProductActionTicket | None = field(default=None, repr=False)


class ProductActionBarrier:
    def __init__(self, outbox: ProductReceiptOutbox) -> None:
        if not isinstance(outbox, ProductReceiptOutbox):
            raise ProductActivationError("outbox_invalid_configuration")
        self._outbox = outbox
        self._mutex = RLock()
        self._tickets: dict[ProductActionTicket, str] = {}

    def assert_ready(self) -> None:
        self._outbox._assert_ready()

    def recover(self) -> ProductOutboxStatus:
        # Recovery reports durable facts only; it never creates a ticket.
        return self._outbox.status()

    def begin_action(
        self,
        *,
        action_id: str,
        event_id: str,
        start_receipt: AuditEvent,
        activation_ack: ActivationAckV1 | None = None,
    ) -> BeginActionResult:
        delivered, record_id = self._outbox._begin(
            action_id, event_id, start_receipt, activation_ack
        )
        if delivered.status != "recorded" or record_id is None:
            return BeginActionResult(delivered)
        ticket: ProductActionTicket | None = None

        def publish() -> None:
            nonlocal ticket
            with self._mutex:
                ticket = ProductActionTicket(_CONSTRUCTION_KEY, self, record_id)
                self._tickets[ticket] = record_id

        error_code = self._outbox._publish_ticket(record_id, publish)
        if error_code is not None:
            return BeginActionResult(
                ProductReceiptDeliveryResult(
                    "failed", audit_id=delivered.audit_id, error_code=error_code
                )
            )
        return BeginActionResult(delivered, ticket)

    def finish_action(
        self, ticket: ProductActionTicket, terminal_receipt: RuntimeOutcomeReceipt
    ) -> ProductReceiptDeliveryResult:
        with self._mutex:
            record_id = (
                self._tickets.get(ticket)
                if isinstance(ticket, ProductActionTicket)
                else None
            )
            if (
                record_id is None
                or ticket._owner is not self
                or ticket._record_id != record_id
            ):
                return ProductReceiptDeliveryResult(
                    "failed", error_code="action_ticket_invalid"
                )
        return self._outbox._finish(record_id, terminal_receipt)
