import {
  rfc3339Nanoseconds,
  type OpenClawActivationAckV1,
} from "./activation-ack.js";
import {
  isOpenClawActivationAckHandle,
  type OpenClawActivationAckHandle,
} from "./activation-ack-handle.js";
import { OpenClawProductActivationError } from "./product-manifest.js";
import type {
  GuardEvaluationResponse,
  RuntimeOutcomeReceipt,
} from "../types.js";

type AuthorityContext = {
  readonly evaluation: OpenClawActivationAckHandle;
  consumption?: OpenClawActivationAckHandle;
};

type ReceiptContext = {
  readonly activationAck: OpenClawActivationAckHandle;
  readonly projection: NonNullable<
    RuntimeOutcomeReceipt["metadata"]["activation_ack"]
  >;
  readonly links: Readonly<RuntimeOutcomeReceipt["links"]>;
};

const evaluationContexts = new WeakMap<object, AuthorityContext>();
const receiptContexts = new WeakMap<object, ReceiptContext>();

export type RuntimeOutcomeWire = Omit<RuntimeOutcomeReceipt, "metadata"> & {
  metadata: Omit<RuntimeOutcomeReceipt["metadata"], "activation_ack"> & {
    activation_ack?: OpenClawActivationAckV1;
  };
};

/** One immutable evaluate ACK per action; correlation aliases share its context. */
export function bindEvaluationActivationAck(
  evaluation: GuardEvaluationResponse,
  handle: OpenClawActivationAckHandle,
): void {
  requireHandle(handle);
  const existing = evaluationContexts.get(evaluation);
  if (existing) {
    if (existing.evaluation !== handle) fail("evaluation_ack_conflict");
    return;
  }
  evaluationContexts.set(evaluation, { evaluation: handle });
}

/** The first consume attempt fixes the ACK for all retries of that action. */
export function bindConsumptionActivationAck(
  evaluation: GuardEvaluationResponse,
  handle: OpenClawActivationAckHandle,
): void {
  requireHandle(handle);
  const context = evaluationContexts.get(evaluation);
  if (!context) fail("evaluation_ack_missing");
  for (const field of Object.keys(context.evaluation.identity)) {
    const key = field as keyof typeof context.evaluation.identity;
    if (context.evaluation.identity[key] !== handle.identity[key]) {
      fail("consumption_ack_identity_mismatch");
    }
  }
  if (context.consumption && context.consumption !== handle) {
    fail("consumption_ack_conflict");
  }
  context.consumption = handle;
}

export function evaluationActivationAck(
  evaluation: GuardEvaluationResponse,
): OpenClawActivationAckHandle | undefined {
  return evaluationContexts.get(evaluation)?.evaluation;
}

/** Copies no credential fields into the publicly inspectable correlation state. */
export function copyProductAuthorityContext(
  from: GuardEvaluationResponse,
  to: GuardEvaluationResponse,
): void {
  const context = evaluationContexts.get(from);
  const previous = evaluationContexts.get(to);
  if (previous && previous !== context) fail("evaluation_ack_conflict");
  if (context) evaluationContexts.set(to, context);
}

/** Called only by the receipt builder, never from a session's latest snapshot. */
export function attachRuntimeOutcomeActivationAck(
  receipt: RuntimeOutcomeReceipt,
  evaluation: GuardEvaluationResponse,
): void {
  const context = evaluationContexts.get(evaluation);
  if (!context) {
    if (evaluation.decision_authority?.selection_basis === "profile_all") {
      fail("evaluation_ack_missing");
    }
    return;
  }
  const hasLease =
    receipt.links.lease_id !== undefined ||
    receipt.links.consumption_id !== undefined;
  if (hasLease && (!receipt.links.lease_id || !receipt.links.consumption_id)) {
    fail("receipt_ack_lease_invalid");
  }
  const handle = hasLease ? context.consumption : context.evaluation;
  if (!handle) fail("consumption_ack_missing");
  validateReceiptIdentity(receipt, handle);
  const projection = Object.freeze(handle.toJSON());
  Object.defineProperty(receipt.metadata, "activation_ack", {
    value: projection,
    enumerable: true,
    configurable: false,
    writable: false,
  });
  receiptContexts.set(receipt, {
    activationAck: handle,
    projection,
    links: Object.freeze({ ...receipt.links }),
  });
}

/** Also identifies token-stripped JSON copies, nulls, and raw historical wires. */
export function hasProductReceiptCarrier(receipt: unknown): boolean {
  if (typeof receipt !== "object" || receipt === null) return false;
  if (receiptContexts.has(receipt)) return true;
  const metadata = (receipt as { metadata?: unknown }).metadata;
  return (
    typeof metadata === "object" &&
    metadata !== null &&
    "activation_ack" in metadata
  );
}

/** Explicit transport conversion. Ordinary JSON and inspect never expose ACK tokens. */
export function runtimeOutcomeToWire(
  receipt: RuntimeOutcomeReceipt,
): RuntimeOutcomeWire {
  const context = receiptContexts.get(receipt);
  if (!context) {
    if (hasProductReceiptCarrier(receipt)) fail("receipt_ack_context_missing");
    const { activation_ack: _ack, ...metadata } = receipt.metadata;
    return { ...receipt, metadata };
  }
  if (receipt.metadata.activation_ack !== context.projection) {
    fail("receipt_ack_context_mismatch");
  }
  const keys = Object.keys(receipt.links);
  if (
    keys.length !== Object.keys(context.links).length ||
    keys.some((field) => {
      const key = field as keyof RuntimeOutcomeReceipt["links"];
      return receipt.links[key] !== context.links[key];
    })
  ) {
    fail("receipt_ack_context_mismatch");
  }
  validateReceiptIdentity(receipt, context.activationAck);
  return {
    ...receipt,
    metadata: {
      ...receipt.metadata,
      activation_ack: context.activationAck.toWire(),
    },
  };
}

function validateReceiptIdentity(
  receipt: RuntimeOutcomeReceipt,
  handle: OpenClawActivationAckHandle,
): void {
  if (
    receipt.runtime !== "openclaw" ||
    receipt.metadata.agent_id !== handle.identity.agent_id
  ) {
    fail("receipt_ack_identity_mismatch");
  }
  const issuedAt = rfc3339Nanoseconds(handle.issued_at);
  const timestamp = rfc3339Nanoseconds(receipt.timestamp);
  if (issuedAt === null || timestamp === null || issuedAt > timestamp) {
    fail("receipt_ack_timestamp_invalid");
  }
  // Historical delivery checks the original issuance window on the server.
  // Neither the current clock nor the latest session ACK belongs in this check.
}

function requireHandle(
  value: unknown,
): asserts value is OpenClawActivationAckHandle {
  if (!isOpenClawActivationAckHandle(value))
    fail("activation_ack_handle_invalid");
}

function fail(code: string): never {
  throw new OpenClawProductActivationError(code);
}
