import { types } from "node:util";
import { OpenClawProductEnvelopeStore } from "./product-envelope-store.js";
import { OpenClawProductReceiptOutbox } from "./product-receipt-outbox.js";
import {
  OpenClawProductTransport,
  productTransportBindingDigest,
} from "./product-transport.js";
import { exactDataObject } from "./product-reconciliation.js";

export type OpenClawProductReceiptRecoveryConfig = Readonly<{
  guardApiBaseUrl: string;
  adapterToken: string;
  agentId: string;
  principalId: string;
  runtimeBindingId: string;
  productReceiptDirectory: string;
  productReceiptKeyPath: string;
  requestTimeoutMs?: number;
}>;
export type OpenClawProductReceiptRecovery = Readonly<{
  status: OpenClawProductReceiptOutbox["reconciliationStatus"];
  drain: OpenClawProductReceiptOutbox["drain"];
  reconcileRejectedReceipt: OpenClawProductReceiptOutbox["reconcileRejectedReceipt"];
  close: OpenClawProductReceiptOutbox["close"];
  closeWithin: OpenClawProductReceiptOutbox["closeWithin"];
}>;

/** Opens only an existing producer-bound queue. No manifest, current ACK, Host, or execution authority. */
export async function openOpenClawProductReceiptRecovery(
  input: OpenClawProductReceiptRecoveryConfig,
): Promise<OpenClawProductReceiptRecovery> {
  let outbox: OpenClawProductReceiptOutbox | undefined;
  let store: OpenClawProductEnvelopeStore | undefined;
  try {
    if (!input || typeof input !== "object" || types.isProxy(input))
      throw new Error();
    const required = [
      "guardApiBaseUrl",
      "adapterToken",
      "agentId",
      "principalId",
      "runtimeBindingId",
      "productReceiptDirectory",
      "productReceiptKeyPath",
    ];
    const config = exactDataObject(input, [
      ...required,
      ...(Object.hasOwn(input, "requestTimeoutMs") ? ["requestTimeoutMs"] : []),
    ]);
    if (
      required.some(
        (key) =>
          typeof config[key] !== "string" || !(config[key] as string).length,
      ) ||
      /[\x00-\x1f\x7f]/u.test(config.adapterToken as string)
    )
      throw new Error();
    const timeout = config.requestTimeoutMs ?? 5_000;
    if (
      typeof timeout !== "number" ||
      !Number.isSafeInteger(timeout) ||
      timeout < 1 ||
      timeout > 600_000
    )
      throw new Error();
    const transport = new OpenClawProductTransport({
      guardApiBaseUrl: config.guardApiBaseUrl as string,
      adapterToken: config.adapterToken as string,
      agentId: config.agentId as string,
      runtimeBindingId: config.runtimeBindingId as string,
      requestTimeoutMs: timeout,
    });
    store = await OpenClawProductEnvelopeStore.open({
      directory: config.productReceiptDirectory as string,
      keyPath: config.productReceiptKeyPath as string,
      existingOnly: true,
      namespace: {
        runtime: "openclaw",
        agentId: config.agentId as string,
        principalId: config.principalId as string,
        runtimeBindingId: config.runtimeBindingId as string,
      },
    });
    outbox = new OpenClawProductReceiptOutbox({
      store,
      receiptsOnly: true,
      transportBindingDigest: productTransportBindingDigest(
        config.guardApiBaseUrl as string,
        store.namespace,
      ),
      sendReceipt: (wire) => transport.send(wire),
      transportIdle: () => transport.whenIdle(),
      transportBusy: () => transport.busy,
    });
    const delivery = outbox;
    return Object.freeze({
      status: () => delivery.reconciliationStatus(),
      drain: () => delivery.drain(),
      reconcileRejectedReceipt: (
        selector: Parameters<typeof delivery.reconcileRejectedReceipt>[0],
      ) => delivery.reconcileRejectedReceipt(selector),
      close: () => delivery.close(),
      closeWithin: (timeoutMs: number) => delivery.closeWithin(timeoutMs),
    });
  } catch (error) {
    if (outbox) await outbox.close();
    else await store?.close();
    const failure = new Error("product_receipt_recovery_unavailable");
    const code =
      error && typeof error === "object" && !types.isProxy(error)
        ? Object.getOwnPropertyDescriptor(error, "code")?.value
        : undefined;
    Object.defineProperty(failure, "code", {
      value: [
        "receipt_transport_binding_missing",
        "receipt_transport_binding_mismatch",
      ].includes(code)
        ? code
        : "product_receipt_recovery_unavailable",
      enumerable: true,
    });
    throw failure;
  }
}
