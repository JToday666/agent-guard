import { createHash } from "node:crypto";
import { inspect } from "node:util";
import {
  GuardApiResponseError,
  readBoundedJsonResponse,
  validateGuardApiBaseUrl,
} from "../guard-api-http.js";
import { restrictedCanonicalJson } from "./canonical.js";
import type { OpenClawProductStoreNamespace } from "./product-envelope-store.js";
import type { ProductReceiptTransportResult } from "./product-delivery.js";

export function productTransportBindingDigest(
  baseUrl: string,
  namespace: OpenClawProductStoreNamespace,
): string {
  return createHash("sha256")
    .update(
      restrictedCanonicalJson({
        schema_version: "agentguard-product-receipt-transport/1",
        api_mode: "guard-api-v0.3",
        base_url: validateGuardApiBaseUrl(baseUrl),
        namespace: {
          runtime: namespace.runtime,
          agent_id: namespace.agentId,
          principal_id: namespace.principalId,
          runtime_binding_id: namespace.runtimeBindingId,
        },
      }),
      "utf8",
    )
    .digest("hex");
}

export type ProductTransportConfig = {
  guardApiBaseUrl: string;
  adapterToken: string;
  agentId: string;
  runtimeBindingId: string;
  requestTimeoutMs: number;
};

/** One immutable HTTP attempt. Idle tracks actual local fetch/body settlement, not just its deadline race. */
export class OpenClawProductTransport {
  #config: Readonly<ProductTransportConfig>;
  #fetch: typeof fetch;
  #pending = new Set<Promise<unknown>>();
  #active = false;
  constructor(config: ProductTransportConfig, fetchImpl: typeof fetch = fetch) {
    this.#config = Object.freeze({
      ...config,
      guardApiBaseUrl: validateGuardApiBaseUrl(config.guardApiBaseUrl),
    });
    this.#fetch = fetchImpl;
  }
  get busy(): boolean {
    return this.#active || this.#pending.size > 0;
  }
  async whenIdle(): Promise<void> {
    while (this.#pending.size) await Promise.allSettled([...this.#pending]);
  }
  toJSON(): object {
    return { busy: this.busy };
  }
  [inspect.custom](): object {
    return this.toJSON();
  }
  #track = <T>(work: Promise<T>): Promise<T> => {
    this.#pending.add(work);
    void work.then(
      () => this.#pending.delete(work),
      () => this.#pending.delete(work),
    );
    return work;
  };
  async send(wire: string): Promise<ProductReceiptTransportResult> {
    if (this.busy)
      return { status: "retryable", errorCode: "receipt_transport_busy" };
    this.#active = true;
    try {
      return await this.#send(wire);
    } finally {
      this.#active = false;
    }
  }
  async #send(wire: string): Promise<ProductReceiptTransportResult> {
    const config = this.#config;
    let auditId: string;
    try {
      if (
        !Number.isSafeInteger(config.requestTimeoutMs) ||
        config.requestTimeoutMs < 1 ||
        config.requestTimeoutMs > 600_000 ||
        typeof wire !== "string" ||
        Buffer.byteLength(wire, "utf8") > 512 * 1024
      )
        throw new Error();
      const value: unknown = JSON.parse(wire);
      if (
        !isRecord(value) ||
        value.record_type !== "runtime_outcome" ||
        value.runtime !== "openclaw" ||
        typeof value.audit_id !== "string" ||
        value.audit_id.length < 1 ||
        value.audit_id.length > 256 ||
        !isRecord(value.metadata) ||
        value.metadata.agent_id !== config.agentId ||
        !isRecord(value.metadata.activation_ack) ||
        value.metadata.activation_ack.runtime_binding_id !==
          config.runtimeBindingId
      )
        throw new Error();
      auditId = value.audit_id;
    } catch {
      return { status: "failed", errorCode: "receipt_transport_invalid" };
    }
    const controller = new AbortController();
    const deadline = performance.now() + config.requestTimeoutMs;
    const timeout = setTimeout(
      () => controller.abort(),
      config.requestTimeoutMs,
    );
    let abortListener: () => void;
    const aborted = new Promise<never>((_resolve, reject) => {
      abortListener = () => reject(new GuardApiResponseError("timed_out"));
      controller.signal.addEventListener("abort", abortListener, {
        once: true,
      });
    });
    let httpStatus: number | undefined;
    let response: Response | undefined;
    try {
      const request = this.#track(
        Promise.resolve(
          this.#fetch(`${config.guardApiBaseUrl}/v1/audit/events`, {
            method: "POST",
            body: wire,
            redirect: "manual",
            signal: controller.signal,
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              Authorization: `Bearer ${config.adapterToken}`,
            },
          }),
        ).then((value) => {
          // An injected fetch may ignore abort and resolve after the deadline.
          if (controller.signal.aborted && value.body)
            void this.#track(value.body.cancel()).catch(() => undefined);
          return value;
        }),
      );
      response = await Promise.race([request, aborted]);
      httpStatus = response.status;
      if (controller.signal.aborted || performance.now() >= deadline)
        throw new GuardApiResponseError("timed_out");
      if (httpStatus === 408 || httpStatus === 429 || httpStatus >= 500)
        return {
          status: "retryable",
          auditId,
          httpStatus,
          errorCode: "http_retryable",
        };
      if (httpStatus >= 300)
        return {
          status: "permanent_rejected",
          auditId,
          httpStatus,
          errorCode: "http_permanent_rejection",
        };
      if (httpStatus < 200)
        return {
          status: "failed",
          auditId,
          httpStatus,
          errorCode: "receipt_response_invalid",
        };
      const body = await readBoundedJsonResponse(
        response,
        controller.signal,
        aborted,
        this.#track,
      );
      if (controller.signal.aborted || performance.now() >= deadline)
        throw new GuardApiResponseError("timed_out");
      if (
        !isRecord(body) ||
        body.ok !== true ||
        body.audit_id !== auditId ||
        "skipped" in body
      )
        return {
          status: "failed",
          auditId,
          httpStatus,
          errorCode: "receipt_confirmation_invalid",
        };
      return { status: "recorded", auditId, httpStatus };
    } catch (error) {
      const retryable =
        controller.signal.aborted ||
        error instanceof TypeError ||
        (error instanceof GuardApiResponseError &&
          error.failure === "timed_out");
      return {
        status: retryable ? "retryable" : "failed",
        auditId,
        httpStatus,
        errorCode: retryable
          ? "receipt_transport_unavailable"
          : "receipt_response_invalid",
      };
    } finally {
      clearTimeout(timeout);
      controller.signal.removeEventListener("abort", abortListener!);
      controller.abort();
      if (response?.body && !response.body.locked)
        void this.#track(response.body.cancel()).catch(() => undefined);
    }
  }
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
