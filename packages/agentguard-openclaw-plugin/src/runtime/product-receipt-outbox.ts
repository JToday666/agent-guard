import { createHash } from "node:crypto";
import {
  ProductContentCheckpoint,
  type ProductCheckpointRole,
} from "../mapping/product-content-receipts.js";
import { inspect, types } from "node:util";

import type { RuntimeOutcomeReceipt } from "../types.js";
import {
  readHistoricalOpenClawActivationAck,
  type OpenClawActivationAckV1,
} from "./activation-ack.js";
import {
  isOpenClawActivationAckHandle,
  type OpenClawActivationAckHandle,
} from "./activation-ack-handle.js";
import { restrictedCanonicalJson } from "./canonical.js";
import type { RuntimeOutcomeWire } from "./product-authority-context.js";
import type {
  ProductReceiptDeliveryResult,
  ProductReceiptTransportResult,
} from "./product-delivery.js";
import {
  OpenClawProductEnvelopeStore,
  type OpenClawProductRecordKind,
  type OpenClawStoredEnvelope,
} from "./product-envelope-store.js";
import { OpenClawProductActivationError } from "./product-manifest.js";
import {
  prepareProductReceipt,
  readHistoricalProductReceiptWire,
} from "./product-receipt-wire.js";

const CONTROL_ID = "barrier_control";
const TICKET_KEY = Symbol("product-action-ticket");
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const ACTION_TERMINAL_KINDS = new Set([
  "execution_completed",
  "execution_failed",
  "pre_execution_deny",
]);
const CODES = new Set([
  "outbox_closed",
  "outbox_storage_failed",
  "outbox_recovery_failed",
  "outbox_invalid_configuration",
  "outbox_receipt_conflict",
  "outbox_pending_receipts",
  "outbox_barrier_open",
  "receipt_invalid",
  "receipt_retry_pending",
  "receipt_transport_failed",
  "receipt_transport_invalid",
  "receipt_acknowledgement_invalid",
  "receipt_permanently_rejected",
  "action_already_active",
  "action_barrier_failed",
  "action_already_known",
  "action_identity_invalid",
  "action_ticket_invalid",
  "action_terminal_invalid",
  "action_outcome_unknown",
  "action_journal_required",
]);

export type OpenClawProductOutboxStatus = Readonly<{
  pendingCount: number;
  completedCount: number;
  unknownActionCount: number;
  breakerOpen: boolean;
  recordCount: number;
  storedBytes: number;
  errorCode?: string;
}>;

export type OpenClawProductReceiptOutboxOptions = {
  store: OpenClawProductEnvelopeStore;
  sendReceipt: (wire: string) => Promise<ProductReceiptTransportResult>;
  retryBaseMs?: number;
  retryMaxMs?: number;
  drainIntervalMs?: number;
  now?: () => number;
};

export type OpenClawProductActionPreparation = Readonly<{
  actionId: string;
  eventId: string;
  policyAuditId: string;
  decisionId: string;
  approvalId?: string;
  leaseId?: string;
  consumptionId?: string;
  activationAck: OpenClawActivationAckHandle;
}>;

/** Same-process correlation only: release never claims a Host invocation started. */
export class OpenClawProductActionTicket {
  #brand = true;
  constructor(key: symbol) {
    if (key !== TICKET_KEY) fail("action_ticket_invalid");
    Object.freeze(this);
  }
  static isTicket(value: unknown): value is OpenClawProductActionTicket {
    return typeof value === "object" && value !== null && #brand in value;
  }
  toJSON(): object {
    return { type: "OpenClawProductActionTicket" };
  }
  [inspect.custom](): object {
    return this.toJSON();
  }
}

type Anchor = {
  actionId: string;
  eventId: string;
  policyAuditId: string;
  decisionId: string;
  approvalId: string | null;
  leaseId: string | null;
  consumptionId: string | null;
  activationAck: Readonly<OpenClawActivationAckV1>;
};
type ReceiptItem = { auditId: string; wire: string; wireDigest: string };
type Pending = {
  version: 1 | 2;
  checkpointRole?: ProductCheckpointRole;
  type: "action" | "receipt";
  phase:
    | "prepared"
    | "released"
    | "terminal_pending"
    | "failed"
    | "permanent_rejected";
  anchor: Anchor | null;
  terminal: ReceiptItem | null;
  attempts: number;
  nextAttemptAt: number;
  errorCode: string | null;
  httpStatus: number | null;
};
type Tombstone = {
  version: 1 | 2;
  checkpointRole?: ProductCheckpointRole;
  type: "tombstone";
  ownerKind: "action" | "receipt";
  actionId: string | null;
  actionTerminal: boolean;
  auditId: string;
  wireDigest: string;
};
type JournalRecord = Pending | Tombstone;
type Loaded = { stored: OpenClawStoredEnvelope; record: JournalRecord };

/** Encrypted, bounded delivery. No hook registration, tool invocation or legacy fallback. */
export class OpenClawProductReceiptOutbox {
  #store: OpenClawProductEnvelopeStore;
  #send: OpenClawProductReceiptOutboxOptions["sendReceipt"];
  #now: () => number;
  #retryBaseMs: number;
  #retryMaxMs: number;
  #drainIntervalMs: number;
  #records = new Map<string, Loaded>();
  #control?: OpenClawStoredEnvelope;
  #failure?: string;
  #closed = false;
  #active?: string;
  #tickets = new WeakMap<OpenClawProductActionTicket, string>();
  #sending?: string;
  #drainPromise?: Promise<readonly ProductReceiptDeliveryResult[]>;
  #closePromise?: Promise<void>;
  #timer?: ReturnType<typeof setInterval>;
  #lastStatus: OpenClawProductOutboxStatus = Object.freeze({
    pendingCount: 0,
    completedCount: 0,
    unknownActionCount: 0,
    breakerOpen: false,
    recordCount: 0,
    storedBytes: 0,
  });

  constructor(options: OpenClawProductReceiptOutboxOptions) {
    if (
      !(options.store instanceof OpenClawProductEnvelopeStore) ||
      typeof options.sendReceipt !== "function" ||
      (options.now !== undefined && typeof options.now !== "function")
    ) {
      fail("outbox_invalid_configuration");
    }
    this.#store = options.store;
    this.#send = options.sendReceipt;
    this.#now = options.now ?? Date.now;
    this.#retryBaseMs = interval(options.retryBaseMs ?? 250);
    this.#retryMaxMs = interval(options.retryMaxMs ?? 30_000);
    this.#drainIntervalMs = interval(options.drainIntervalMs ?? 1_000);
    if (this.#retryBaseMs > this.#retryMaxMs)
      fail("outbox_invalid_configuration");
    try {
      this.#clock();
      this.#load();
      if (!this.#control) {
        this.#control = this.#store.create(
          CONTROL_ID,
          encode({
            version: 1,
            type: "breaker",
            tripped: false,
            errorCode: null,
          }),
          { kind: "breaker" },
        );
      }
      if (this.#unknownCount()) this.#trip("action_outcome_unknown");
      else if (this.#failure) this.#trip(this.#failure);
    } catch {
      this.#closed = true;
      void this.#store.close();
      fail("outbox_recovery_failed");
    }
  }

  toJSON(): object {
    return this.status();
  }
  [inspect.custom](): object {
    return this.toJSON();
  }

  start(): void {
    this.#assertOpen();
    if (this.#timer) return;
    this.#timer = setInterval(() => {
      void this.drain().catch(() => this.#trip("outbox_storage_failed"));
    }, this.#drainIntervalMs);
    this.#timer.unref();
  }

  close(): Promise<void> {
    if (this.#closePromise) return this.#closePromise;
    this.#active = undefined;
    this.status();
    this.#closed = true;
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    // Never wait for a network callback. Its eventual result cannot change disk.
    this.#closePromise = this.#store.close();
    return this.#closePromise;
  }

  status(): OpenClawProductOutboxStatus {
    if (this.#closed)
      return Object.freeze({
        ...this.#lastStatus,
        breakerOpen: true,
        errorCode: "outbox_closed",
      });
    try {
      this.#load();
      const usage = this.#store.usage();
      let pendingCount = 0;
      let completedCount = 0;
      for (const { record } of this.#records.values()) {
        if (record.type === "tombstone") completedCount += 1;
        else if (record.terminal) pendingCount += 1;
      }
      const unknownActionCount = this.#unknownCount();
      this.#lastStatus = Object.freeze({
        pendingCount,
        completedCount,
        unknownActionCount,
        breakerOpen: Boolean(this.#failure || unknownActionCount),
        ...usage,
        ...(this.#failure || unknownActionCount
          ? {
              errorCode: this.#failure ?? "action_outcome_unknown",
            }
          : {}),
      });
    } catch {
      this.#trip("outbox_storage_failed");
      this.#lastStatus = Object.freeze({
        ...this.#lastStatus,
        breakerOpen: true,
        errorCode: "outbox_storage_failed",
      });
    }
    return this.#lastStatus;
  }

  assertReady(): void {
    this.#assertOpen();
    const status = this.status();
    if (status.breakerOpen) fail(status.errorCode ?? "outbox_barrier_open");
    if (this.#active) fail("action_already_active");
    if (status.pendingCount) fail("outbox_pending_receipts");
  }

  async submit(
    receipt: RuntimeOutcomeReceipt,
  ): Promise<ProductReceiptDeliveryResult> {
    try {
      return await this.submitHistoricalWire(
        prepareProductReceipt(receipt, this.#store.namespace),
      );
    } catch {
      this.#trip("receipt_invalid");
      return failed("receipt_invalid");
    }
  }

  /** Explicit evidence-only sink; historical bytes never grant an execution ticket. */
  async submitHistoricalWire(
    encoded: string,
  ): Promise<ProductReceiptDeliveryResult> {
    return this.#submitWire(encoded);
  }

  /** A private builder-issued checkpoint can never release or complete an action. */
  async submitCheckpoint(
    checkpoint: ProductContentCheckpoint,
  ): Promise<ProductReceiptDeliveryResult> {
    try {
      const { wire, role } = ProductContentCheckpoint.read(
        checkpoint,
        this.#store.namespace,
      );
      return await this.#submitWire(wire, role);
    } catch {
      this.#trip("receipt_invalid");
      return failed("receipt_invalid");
    }
  }

  async #submitWire(
    encoded: string,
    role?: ProductCheckpointRole,
  ): Promise<ProductReceiptDeliveryResult> {
    let item: ReceiptItem;
    let wire: RuntimeOutcomeWire;
    try {
      wire = readHistoricalProductReceiptWire(encoded, this.#store.namespace);
      if (
        (checkpointStage(wire.stage) && !role) ||
        (role && wire.stage !== `product_${role}`)
      )
        fail("receipt_invalid");
      item = {
        auditId: wire.audit_id,
        wire: encoded,
        wireDigest: digest(encoded),
      };
    } catch {
      this.#trip("receipt_invalid");
      return failed("receipt_invalid");
    }
    try {
      this.#assertOpen();
      this.#load();
      if (
        !role &&
        ACTION_TERMINAL_KINDS.has(wire.metadata.outcome_kind) &&
        wire.links.action_id &&
        this.#records.has(recordId("action", wire.links.action_id))
      ) {
        return failed("action_journal_required", item.auditId);
      }
      const id = recordId("receipt", item.auditId);
      const previous = this.#records.get(id);
      if (previous) {
        if (
          previous.record.checkpointRole !== role ||
          !matches(previous.record, item)
        ) {
          this.#trip("outbox_receipt_conflict");
          return failed("outbox_receipt_conflict", item.auditId);
        }
        if (previous.record.type === "tombstone") return recorded(item.auditId);
      } else {
        this.#create(id, {
          ...pending("receipt", null, item),
          ...(role ? { version: 2 as const, checkpointRole: role } : {}),
        });
      }
      return await this.#deliver(id);
    } catch (error) {
      if (isClosed(error)) return failed("outbox_closed", item.auditId);
      this.#trip("outbox_storage_failed");
      return failed("outbox_storage_failed", item.auditId);
    }
  }

  /** A required native boundary failed; persist the breaker without inventing an outcome. */
  tripActionBarrier(): void {
    this.#assertOpen();
    this.#trip("action_barrier_failed");
  }

  /** Durable preparation occurs before returning any permission to the Host. */
  prepareAction(
    input: OpenClawProductActionPreparation,
  ): OpenClawProductActionTicket {
    this.assertReady();
    let anchor: Anchor;
    try {
      if (!isOpenClawActivationAckHandle(input.activationAck))
        fail("action_identity_invalid");
      anchor = this.#readAnchor({
        actionId: input.actionId,
        eventId: input.eventId,
        policyAuditId: input.policyAuditId,
        decisionId: input.decisionId,
        approvalId: input.approvalId ?? null,
        leaseId: input.leaseId ?? null,
        consumptionId: input.consumptionId ?? null,
        activationAck: input.activationAck.toWire(),
      });
    } catch {
      this.#trip("action_identity_invalid");
      fail("action_identity_invalid");
    }
    const id = recordId("action", anchor.actionId);
    if (
      this.#records.has(id) ||
      [...this.#records.values()].some(
        ({ record }) =>
          record.type === "tombstone" &&
          record.actionTerminal &&
          record.actionId === anchor.actionId,
      )
    )
      fail("action_already_known");
    try {
      this.#create(id, pending("action", anchor, null));
      const ticket = new OpenClawProductActionTicket(TICKET_KEY);
      this.#tickets.set(ticket, id);
      this.#active = id;
      return ticket;
    } catch {
      this.#trip("outbox_storage_failed");
      fail("outbox_storage_failed");
    }
  }

  /** A gate release is not an authoritative invocation-start observation. */
  releaseAction(ticket: OpenClawProductActionTicket): void {
    this.#assertOpen();
    const id = this.#ticketId(ticket);
    try {
      this.#load();
      if (this.#failure) fail(this.#failure);
      if (
        [...this.#records.values()].some(
          ({ record }) => record.type !== "tombstone" && record.terminal,
        )
      ) {
        fail("outbox_pending_receipts");
      }
      const loaded = this.#records.get(id);
      if (
        !loaded ||
        loaded.record.type !== "action" ||
        loaded.record.phase !== "prepared" ||
        this.#active !== id
      ) {
        fail("action_ticket_invalid");
      }
      this.#replace(loaded, { ...loaded.record, phase: "released" });
    } catch (error) {
      const code = errorCode(error);
      if (code) fail(code);
      this.#trip("outbox_storage_failed");
      fail("outbox_storage_failed");
    }
  }

  /** Host lifecycle ended without a correlated terminal callback. Never infer execution. */
  markActionUnknown(ticket: OpenClawProductActionTicket): void {
    this.#assertOpen();
    const id = this.#ticketId(ticket);
    try {
      this.#load();
      const record = this.#records.get(id)?.record;
      if (!record || record.type !== "action" || record.terminal)
        fail("action_ticket_invalid");
      if (this.#active === id) this.#active = undefined;
      this.#trip("action_outcome_unknown");
    } catch (error) {
      const code = errorCode(error);
      if (code) fail(code);
      this.#trip("outbox_storage_failed");
      fail("outbox_storage_failed");
    }
  }

  /** Persist the real terminal callback before attempting its HTTP submission. */
  async finishAction(
    ticket: OpenClawProductActionTicket,
    receipt: RuntimeOutcomeReceipt,
  ): Promise<ProductReceiptDeliveryResult> {
    let id: string;
    try {
      id = this.#ticketId(ticket);
    } catch {
      return failed("action_ticket_invalid");
    }
    let item: ReceiptItem;
    let wire: RuntimeOutcomeWire;
    try {
      ({ item, wire } = this.#prepareReceipt(receipt));
    } catch {
      this.#trip("action_terminal_invalid");
      return failed("action_terminal_invalid");
    }
    try {
      this.#assertOpen();
      this.#load();
      const loaded = this.#records.get(id);
      if (!loaded) fail("action_ticket_invalid");
      const record = loaded.record;
      if (record.type === "tombstone") {
        if (matches(record, item)) return recorded(item.auditId);
        this.#trip("outbox_receipt_conflict");
        return failed("outbox_receipt_conflict", item.auditId);
      }
      if (record.type !== "action" || !record.anchor)
        fail("action_ticket_invalid");
      if (!ACTION_TERMINAL_KINDS.has(wire.metadata.outcome_kind))
        fail("action_terminal_invalid");
      this.#assertAnchor(record.anchor, wire);
      if (record.terminal) {
        if (!matches(record, item)) {
          this.#trip("outbox_receipt_conflict");
          return failed("outbox_receipt_conflict", item.auditId);
        }
      } else {
        // A same-process late after callback may add evidence after markUnknown.
        // The breaker stays sticky; a restarted process has no valid ticket.
        if (
          !["prepared", "released"].includes(record.phase) ||
          (record.phase === "prepared" && this.#active !== id)
        )
          fail("action_ticket_invalid");
        if (wire.evidence.execution.status === "unknown")
          fail("action_terminal_invalid");
        if (
          record.phase === "prepared" &&
          wire.evidence.execution.status !== "not_invoked"
        )
          fail("action_terminal_invalid");
        this.#replace(loaded, {
          ...record,
          phase: "terminal_pending",
          terminal: item,
          attempts: 0,
          nextAttemptAt: 0,
          errorCode: null,
          httpStatus: null,
        });
        if (this.#active === id) this.#active = undefined;
      }
      return await this.#deliver(id);
    } catch (error) {
      if (isClosed(error)) return failed("outbox_closed", item.auditId);
      const code = errorCode(error);
      if (code) {
        this.#trip("action_terminal_invalid");
        return failed(code, item.auditId);
      }
      this.#trip("outbox_storage_failed");
      return failed("outbox_storage_failed", item.auditId);
    }
  }

  drain(): Promise<readonly ProductReceiptDeliveryResult[]> {
    if (this.#closed) return Promise.resolve([failed("outbox_closed")]);
    if (this.#drainPromise) return this.#drainPromise;
    const promise = this.#drainPending();
    this.#drainPromise = promise;
    void promise
      .finally(() => {
        if (this.#drainPromise === promise) this.#drainPromise = undefined;
      })
      .catch(() => undefined);
    return promise;
  }

  async #drainPending(): Promise<readonly ProductReceiptDeliveryResult[]> {
    let ids: string[];
    try {
      this.#load();
      const now = this.#clock();
      ids = [...this.#records]
        .filter(
          ([, { record }]) =>
            record.type !== "tombstone" &&
            record.terminal &&
            record.phase !== "failed" &&
            record.phase !== "permanent_rejected" &&
            record.nextAttemptAt <= now,
        )
        .map(([id]) => id);
    } catch {
      this.#trip("outbox_storage_failed");
      return [failed("outbox_storage_failed")];
    }
    const results: ProductReceiptDeliveryResult[] = [];
    for (const id of ids) results.push(await this.#deliver(id));
    return Object.freeze(results);
  }

  async #deliver(id: string): Promise<ProductReceiptDeliveryResult> {
    if (this.#closed) return failed("outbox_closed");
    let loaded: Loaded;
    let record: Pending;
    let item: ReceiptItem;
    try {
      this.#load();
      const found = this.#records.get(id);
      if (!found) fail("outbox_receipt_conflict");
      loaded = found;
      if (found.record.type === "tombstone")
        return recorded(found.record.auditId);
      record = found.record;
      if (!record.terminal) fail("action_terminal_invalid");
      item = record.terminal;
      if (record.phase === "failed" || record.phase === "permanent_rejected") {
        return result(
          record.phase,
          item.auditId,
          record.httpStatus,
          record.errorCode,
        );
      }
      if (this.#sending || record.nextAttemptAt > this.#clock()) {
        return result(
          "queued_durable",
          item.auditId,
          null,
          "receipt_retry_pending",
        );
      }
      this.#sending = id;
    } catch {
      this.#trip("outbox_storage_failed");
      return failed("outbox_storage_failed");
    }
    let reply: ProductReceiptTransportResult;
    try {
      reply = await this.#send(item.wire);
    } catch {
      reply = { status: "retryable" };
    }
    this.#sending = undefined;
    if (this.#closed) return failed("outbox_closed", item.auditId);
    try {
      const current = this.#store.get(id);
      if (
        !current ||
        current.revision !== loaded.stored.revision ||
        current.payload !== loaded.stored.payload
      ) {
        this.#trip("outbox_receipt_conflict");
        return failed("outbox_receipt_conflict", item.auditId);
      }
      const fact = transportFact(reply, item.auditId);
      if (fact.status === "recorded") {
        const confirmed = readHistoricalProductReceiptWire(
          item.wire,
          this.#store.namespace,
        );
        this.#replace(loaded, {
          version: record.version,
          ...(record.checkpointRole
            ? { checkpointRole: record.checkpointRole }
            : {}),
          type: "tombstone",
          ownerKind: record.type,
          actionId: confirmed.links.action_id ?? null,
          actionTerminal:
            !record.checkpointRole &&
            ACTION_TERMINAL_KINDS.has(confirmed.metadata.outcome_kind),
          auditId: item.auditId,
          wireDigest: item.wireDigest,
        });
        return result("recorded", item.auditId, fact.httpStatus, null);
      }
      if (fact.status === "retryable") {
        const attempts = record.attempts + 1;
        const delay = Math.min(
          this.#retryMaxMs,
          this.#retryBaseMs * 2 ** Math.min(attempts - 1, 16),
        );
        this.#replace(loaded, {
          ...record,
          attempts,
          nextAttemptAt: this.#clock() + delay,
          errorCode: fact.errorCode,
          httpStatus: fact.httpStatus,
        });
        return result(
          "queued_durable",
          item.auditId,
          fact.httpStatus,
          fact.errorCode,
        );
      }
      this.#replace(loaded, {
        ...record,
        phase: fact.status,
        errorCode: fact.errorCode,
        httpStatus: fact.httpStatus,
      });
      this.#trip(
        fact.status === "permanent_rejected"
          ? "receipt_permanently_rejected"
          : "receipt_transport_failed",
      );
      return result(fact.status, item.auditId, fact.httpStatus, fact.errorCode);
    } catch {
      this.#trip("outbox_storage_failed");
      return failed("outbox_storage_failed", item.auditId);
    }
  }

  #prepareReceipt(receipt: RuntimeOutcomeReceipt): {
    item: ReceiptItem;
    wire: RuntimeOutcomeWire;
  } {
    const encoded = prepareProductReceipt(receipt, this.#store.namespace);
    const wire = readHistoricalProductReceiptWire(
      encoded,
      this.#store.namespace,
    );
    return {
      item: {
        auditId: wire.audit_id,
        wire: encoded,
        wireDigest: digest(encoded),
      },
      wire,
    };
  }

  #readAnchor(value: unknown): Anchor {
    const data = object(value, [
      "actionId",
      "eventId",
      "policyAuditId",
      "decisionId",
      "approvalId",
      "leaseId",
      "consumptionId",
      "activationAck",
    ]);
    for (const field of ["actionId", "eventId", "policyAuditId", "decisionId"])
      identifier(data[field]);
    if (data.approvalId !== null) identifier(data.approvalId);
    if ((data.leaseId === null) !== (data.consumptionId === null))
      fail("action_identity_invalid");
    if (data.leaseId !== null) {
      identifier(data.leaseId);
      identifier(data.consumptionId);
    }
    const ack = readHistoricalOpenClawActivationAck(data.activationAck);
    if (
      ack.agent_id !== this.#store.namespace.agentId ||
      ack.runtime_binding_id !== this.#store.namespace.runtimeBindingId
    )
      fail("action_identity_invalid");
    return {
      actionId: data.actionId as string,
      eventId: data.eventId as string,
      policyAuditId: data.policyAuditId as string,
      decisionId: data.decisionId as string,
      approvalId: data.approvalId as string | null,
      leaseId: data.leaseId as string | null,
      consumptionId: data.consumptionId as string | null,
      activationAck: ack,
    };
  }

  #assertAnchor(anchor: Anchor, wire: RuntimeOutcomeWire): void {
    const links = wire.links;
    if (
      links.action_id !== anchor.actionId ||
      links.event_id !== anchor.eventId ||
      links.policy_audit_id !== anchor.policyAuditId ||
      links.decision_id !== anchor.decisionId ||
      (links.approval_id ?? null) !== anchor.approvalId ||
      (links.lease_id ?? null) !== anchor.leaseId ||
      (links.consumption_id ?? null) !== anchor.consumptionId ||
      encode(wire.metadata.activation_ack) !== encode(anchor.activationAck)
    )
      fail("action_identity_invalid");
  }

  #load(): void {
    const records = new Map<string, Loaded>();
    let control: OpenClawStoredEnvelope | undefined;
    for (const stored of this.#store.records()) {
      const value: unknown = JSON.parse(stored.payload);
      if (encode(value) !== stored.payload) fail("outbox_storage_failed");
      if (stored.kind === "breaker") {
        const data = object(value, ["version", "type", "tripped", "errorCode"]);
        if (
          stored.recordId !== CONTROL_ID ||
          data.version !== 1 ||
          data.type !== "breaker" ||
          typeof data.tripped !== "boolean" ||
          (data.errorCode !== null && !safeCode(data.errorCode)) ||
          (!data.tripped && data.errorCode !== null)
        )
          fail("outbox_storage_failed");
        control = stored;
        if (data.tripped)
          this.#failure ??=
            typeof data.errorCode === "string"
              ? data.errorCode
              : "outbox_barrier_open";
      } else {
        const record = this.#readRecord(stored, value);
        records.set(stored.recordId, { stored, record });
        // The record phase itself is durable failure evidence if a later
        // breaker-control update failed or the process crashed between writes.
        if (
          record.type !== "tombstone" &&
          ["failed", "permanent_rejected"].includes(record.phase)
        ) {
          this.#failure ??=
            record.phase === "permanent_rejected"
              ? "receipt_permanently_rejected"
              : "receipt_transport_failed";
        }
      }
    }
    if (this.#control && !control) fail("outbox_storage_failed");
    this.#records = records;
    this.#control = control;
  }

  #readRecord(stored: OpenClawStoredEnvelope, value: unknown): JournalRecord {
    const newer = (value as { version?: unknown })?.version === 2;
    const roleFields = newer ? ["checkpointRole"] : [];
    if (stored.kind === "tombstone") {
      const data = object(value, [
        "version",
        "type",
        "ownerKind",
        "actionId",
        "actionTerminal",
        "auditId",
        "wireDigest",
        ...roleFields,
      ]);
      if (
        (data.version !== 1 && data.version !== 2) ||
        data.type !== "tombstone" ||
        !["action", "receipt"].includes(data.ownerKind as string)
      )
        fail("outbox_storage_failed");
      if (
        newer &&
        (data.ownerKind !== "receipt" ||
          data.actionTerminal !== false ||
          !checkpointRole(data.checkpointRole))
      )
        fail("outbox_storage_failed");
      identifier(data.auditId);
      hex(data.wireDigest);
      if (data.actionId !== null) identifier(data.actionId);
      if (
        typeof data.actionTerminal !== "boolean" ||
        (data.ownerKind === "action" &&
          (!data.actionTerminal || data.actionId === null))
      )
        fail("outbox_storage_failed");
      if (
        stored.recordId !==
        recordId(
          data.ownerKind as string,
          (data.ownerKind === "action"
            ? data.actionId
            : data.auditId) as string,
        )
      )
        fail("outbox_storage_failed");
      return data as Tombstone;
    }
    const data = object(value, [
      "version",
      "type",
      "phase",
      "anchor",
      "terminal",
      "attempts",
      "nextAttemptAt",
      "errorCode",
      "httpStatus",
      ...roleFields,
    ]);
    if (
      (data.version !== 1 && data.version !== 2) ||
      !["action", "receipt"].includes(data.type as string) ||
      data.type !== stored.kind ||
      ![
        "prepared",
        "released",
        "terminal_pending",
        "failed",
        "permanent_rejected",
      ].includes(data.phase as string) ||
      !nonnegative(data.attempts) ||
      !nonnegative(data.nextAttemptAt) ||
      (data.errorCode !== null && !safeCode(data.errorCode)) ||
      (data.httpStatus !== null && !validHttpStatus(data.httpStatus))
    )
      fail("outbox_storage_failed");
    if (
      newer &&
      (data.type !== "receipt" || !checkpointRole(data.checkpointRole))
    )
      fail("outbox_storage_failed");
    const anchor = data.anchor === null ? null : this.#readAnchor(data.anchor);
    let terminal: ReceiptItem | null = null;
    let wire: RuntimeOutcomeWire | undefined;
    if (data.terminal !== null) {
      const item = object(data.terminal, ["auditId", "wire", "wireDigest"]);
      identifier(item.auditId);
      hex(item.wireDigest);
      if (
        typeof item.wire !== "string" ||
        digest(item.wire) !== item.wireDigest
      )
        fail("outbox_storage_failed");
      wire = readHistoricalProductReceiptWire(item.wire, this.#store.namespace);
      if (wire.audit_id !== item.auditId) fail("outbox_storage_failed");
      if (
        (newer && wire.stage !== `product_${data.checkpointRole}`) ||
        (!newer && checkpointStage(wire.stage))
      )
        fail("outbox_storage_failed");
      terminal = item as ReceiptItem;
    }
    if (data.type === "action") {
      if (!anchor || stored.recordId !== recordId("action", anchor.actionId))
        fail("outbox_storage_failed");
      if (wire) {
        this.#assertAnchor(anchor, wire);
        if (!ACTION_TERMINAL_KINDS.has(wire.metadata.outcome_kind))
          fail("action_terminal_invalid");
        if (wire.evidence.execution.status === "unknown")
          fail("action_terminal_invalid");
      }
    } else if (
      anchor !== null ||
      !terminal ||
      stored.recordId !== recordId("receipt", terminal.auditId)
    ) {
      fail("outbox_storage_failed");
    }
    if (["prepared", "released"].includes(data.phase as string)) {
      if (
        data.type !== "action" ||
        terminal !== null ||
        data.attempts !== 0 ||
        data.nextAttemptAt !== 0 ||
        data.errorCode !== null ||
        data.httpStatus !== null
      )
        fail("outbox_storage_failed");
    } else if (!terminal) fail("outbox_storage_failed");
    if (
      ["failed", "permanent_rejected"].includes(data.phase as string) &&
      data.errorCode === null
    )
      fail("outbox_storage_failed");
    return { ...data, anchor, terminal } as Pending;
  }

  #create(id: string, record: JournalRecord): void {
    const stored = this.#store.create(id, encode(record), {
      kind: record.type,
    });
    this.#records.set(id, { stored, record });
  }

  #replace(loaded: Loaded, record: JournalRecord): void {
    const stored = this.#store.replace(loaded.stored.recordId, encode(record), {
      expectedRevision: loaded.stored.revision,
      kind: record.type as OpenClawProductRecordKind,
    });
    this.#records.set(stored.recordId, { stored, record });
  }

  #trip(code: string): void {
    this.#failure ??= safeCode(code) ? code : "outbox_storage_failed";
    if (this.#closed || !this.#control) return;
    try {
      this.#control = this.#store.replace(
        CONTROL_ID,
        encode({
          version: 1,
          type: "breaker",
          tripped: true,
          errorCode: this.#failure,
        }),
        { kind: "breaker", expectedRevision: this.#control.revision },
      );
    } catch {
      /* Broken storage cannot be reported as durable success. */
    }
  }

  #unknownCount(): number {
    let count = 0;
    for (const [id, { record }] of this.#records) {
      if (
        record.type === "action" &&
        record.terminal === null &&
        this.#active !== id
      )
        count += 1;
    }
    return count;
  }

  #ticketId(ticket: OpenClawProductActionTicket): string {
    if (!OpenClawProductActionTicket.isTicket(ticket))
      fail("action_ticket_invalid");
    const id = this.#tickets.get(ticket);
    if (!id) fail("action_ticket_invalid");
    return id;
  }

  #clock(): number {
    const now = this.#now();
    if (!nonnegative(now)) fail("outbox_invalid_configuration");
    return now;
  }

  #assertOpen(): void {
    if (this.#closed) fail("outbox_closed");
  }
}

function encode(value: unknown): string {
  return restrictedCanonicalJson(value);
}
function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
function recordId(kind: string, identity: string): string {
  return `${kind}_${digest(identity)}`;
}
function interval(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 60_000)
    fail("outbox_invalid_configuration");
  return value;
}
function nonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function validHttpStatus(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 100 &&
    value <= 599
  );
}
function safeCode(value: unknown): value is string {
  return typeof value === "string" && CODES.has(value);
}
function identifier(value: unknown): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    fail("action_identity_invalid");
}
function hex(value: unknown): void {
  if (typeof value !== "string" || !DIGEST.test(value))
    fail("outbox_storage_failed");
}
function object(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    fail("outbox_storage_failed");
  return value as Record<string, unknown>;
}
function fail(code: string): never {
  throw new OpenClawProductActivationError(
    safeCode(code) ? code : "outbox_storage_failed",
  );
}
function isClosed(error: unknown): boolean {
  return errorCode(error) === "outbox_closed";
}
function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || types.isProxy(error))
    return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(error, "code");
  return descriptor && "value" in descriptor && safeCode(descriptor.value)
    ? descriptor.value
    : undefined;
}
function result(
  status: ProductReceiptDeliveryResult["status"],
  auditId: string,
  httpStatus: number | null,
  errorCode: string | null,
): ProductReceiptDeliveryResult {
  return Object.freeze({
    status,
    auditId,
    ...(httpStatus === null ? {} : { httpStatus }),
    ...(errorCode === null ? {} : { errorCode }),
  });
}
function recorded(auditId: string): ProductReceiptDeliveryResult {
  return Object.freeze({ status: "recorded", auditId });
}
function failed(
  errorCode: string,
  auditId?: string,
): ProductReceiptDeliveryResult {
  return Object.freeze({
    status: "failed",
    ...(auditId ? { auditId } : {}),
    errorCode: safeCode(errorCode) ? errorCode : "outbox_storage_failed",
  });
}
function matches(record: JournalRecord, item: ReceiptItem): boolean {
  return record.type === "tombstone"
    ? record.auditId === item.auditId && record.wireDigest === item.wireDigest
    : record.terminal?.auditId === item.auditId &&
        record.terminal.wire === item.wire &&
        record.terminal.wireDigest === item.wireDigest;
}
function pending(
  type: "action" | "receipt",
  anchor: Anchor | null,
  terminal: ReceiptItem | null,
): Pending {
  return {
    version: 1,
    type,
    phase: terminal ? "terminal_pending" : "prepared",
    anchor,
    terminal,
    attempts: 0,
    nextAttemptAt: 0,
    errorCode: null,
    httpStatus: null,
  };
}
function transportFact(
  reply: ProductReceiptTransportResult,
  auditId: string,
): {
  status: ProductReceiptTransportResult["status"];
  httpStatus: number | null;
  errorCode: string | null;
} {
  let snapshot: Record<string, unknown> | undefined;
  if (
    reply &&
    typeof reply === "object" &&
    !types.isProxy(reply) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(reply))
  ) {
    const descriptors = Object.getOwnPropertyDescriptors(reply);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.every(
        (key) =>
          typeof key === "string" &&
          ["status", "auditId", "httpStatus", "errorCode"].includes(key) &&
          "value" in descriptors[key as keyof typeof descriptors],
      )
    ) {
      snapshot = Object.fromEntries(
        keys.map((key) => [
          key,
          descriptors[key as keyof typeof descriptors].value,
        ]),
      );
    }
  }
  if (
    !snapshot ||
    !["recorded", "retryable", "permanent_rejected", "failed"].includes(
      snapshot.status as string,
    )
  ) {
    return {
      status: "failed",
      httpStatus: null,
      errorCode: "receipt_transport_invalid",
    };
  }
  const status = snapshot.status as ProductReceiptTransportResult["status"];
  const httpStatus = validHttpStatus(snapshot.httpStatus)
    ? snapshot.httpStatus
    : null;
  if (status === "recorded") {
    return snapshot.auditId === auditId &&
      (httpStatus === null || (httpStatus >= 200 && httpStatus < 300))
      ? { status: "recorded", httpStatus, errorCode: null }
      : {
          status: "failed",
          httpStatus,
          errorCode: "receipt_acknowledgement_invalid",
        };
  }
  return {
    status,
    httpStatus,
    errorCode: {
      retryable: "receipt_retry_pending",
      permanent_rejected: "receipt_permanently_rejected",
      failed: "receipt_transport_failed",
    }[status],
  };
}

function checkpointRole(value: unknown): value is ProductCheckpointRole {
  return [
    "context_assembled",
    "model_output_produced",
    "tool_result_produced",
  ].includes(value as string);
}

function checkpointStage(stage: string): boolean {
  return [
    "context_assembled",
    "model_output_produced",
    "tool_result_produced",
  ].some((role) => stage === `product_${role}`);
}
