import { ActivationAckReadError } from "./activation-ack.js";
import {
  readOpenClawActivationAckHandle,
  type OpenClawActivationAckHandle,
} from "./activation-ack-handle.js";
import {
  OpenClawProductActivationError,
  OpenClawProductManifest,
  type OpenClawProductRuntimeObservation,
} from "./product-manifest.js";
import { restrictedCanonicalJson } from "./canonical.js";

const DRIFT_CODES = new Set([
  "manifest_changed",
  "manifest_not_file_backed",
  "observation_drift",
  "observation_invalid",
  "version_mismatch",
  "runtime_version_unavailable",
  "ack_identity_mismatch",
  "heartbeat_identity_mismatch",
  "configuration_drift",
  "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
  "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
  "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
]);
const SESSION_FAILURE_CODES = new Set([
  ...DRIFT_CODES,
  "session_not_started",
  "session_closed",
  "invalid_max_age",
  "invalid_refresh_interval",
  "invalid_session_callback",
  "heartbeat_unavailable",
  "observation_unavailable",
  "invalid_heartbeat_response",
  "product_configuration_invalid",
  "configuration_identity_mismatch",
]);
const ACK_FAILURE_CODES = new Set([
  "invalid_response",
  "invalid_expected_identity",
  "identity_mismatch",
  "invalid_clock",
  "invalid_max_age",
  "invalid_validity_window",
  "not_yet_valid",
  "expired",
  "too_old",
]);

export type OpenClawActivationSessionOptions = {
  manifest: OpenClawProductManifest;
  observe: (
    signal: AbortSignal,
  ) =>
    | OpenClawProductRuntimeObservation
    | Promise<OpenClawProductRuntimeObservation>;
  sendHeartbeat: (
    body: Record<string, unknown>,
    options: { signal: AbortSignal },
  ) => Promise<unknown>;
  refreshIntervalMs?: number;
  maxAckAgeMs?: number;
};

/** Explicit availability; one cancellable refresh flight and no implicit fallback. */
export class OpenClawActivationSession {
  #manifest: OpenClawProductManifest;
  #observe: OpenClawActivationSessionOptions["observe"];
  #sendHeartbeat: OpenClawActivationSessionOptions["sendHeartbeat"];
  #refreshIntervalMs: number;
  #maxAckAgeMs: number;
  #controller = new AbortController();
  #started = false;
  #closed = false;
  #drift: string | undefined;
  #unavailable = "session_not_started";
  #latest: OpenClawActivationAckHandle | undefined;
  #flight: Promise<OpenClawActivationAckHandle> | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: OpenClawActivationSessionOptions) {
    if (!OpenClawProductManifest.isManifest(options.manifest))
      fail("manifest_not_file_backed");
    const interval = options.refreshIntervalMs ?? 30_000;
    const maxAge = options.maxAckAgeMs ?? 120_000;
    if (!Number.isSafeInteger(maxAge) || maxAge <= 0 || maxAge > 120_000)
      fail("invalid_max_age");
    if (
      !Number.isSafeInteger(interval) ||
      interval <= 0 ||
      interval > maxAge ||
      interval > 30_000
    )
      fail("invalid_refresh_interval");
    if (
      typeof options.observe !== "function" ||
      typeof options.sendHeartbeat !== "function"
    )
      fail("invalid_session_callback");
    this.#manifest = options.manifest;
    this.#observe = options.observe;
    this.#sendHeartbeat = options.sendHeartbeat;
    this.#refreshIntervalMs = interval;
    this.#maxAckAgeMs = maxAge;
  }

  get manifest(): OpenClawProductManifest {
    return this.#manifest;
  }

  async start(): Promise<OpenClawActivationAckHandle> {
    this.#assertOpen();
    if (this.#timer !== undefined) return this.snapshot();
    this.#started = true;
    return this.refresh();
  }

  async refresh(): Promise<OpenClawActivationAckHandle> {
    this.#assertOpen();
    if (!this.#started) fail("session_not_started");
    if (this.#flight !== undefined) return this.#flight;
    const operation = this.#performRefresh()
      .then((ack) => {
        this.#assertOpen();
        ack.assertFresh(Date.now(), this.#maxAckAgeMs);
        this.#latest = ack;
        this.#ensureTimer();
        return ack;
      })
      .catch((error: unknown) => {
        const code = this.#closed
          ? "session_closed"
          : (this.#drift ?? errorCode(error, "heartbeat_unavailable"));
        this.#markUnavailable(code);
        fail(code);
      });
    const flight = operation.finally(() => {
      if (this.#flight === flight) this.#flight = undefined;
    });
    this.#flight = flight;
    return flight;
  }

  async snapshot(): Promise<OpenClawActivationAckHandle> {
    this.#assertOpen();
    if (this.#latest === undefined) fail(this.#unavailable);
    try {
      await abortable(this.#checkLocal(), this.#controller.signal);
      this.#assertOpen();
      // A concurrent refresh can have revoked or replaced the prior snapshot.
      if (this.#latest === undefined) fail(this.#unavailable);
      this.#latest.assertFresh(Date.now(), this.#maxAckAgeMs);
      return this.#latest;
    } catch (error) {
      const code = this.#closed
        ? "session_closed"
        : (this.#drift ?? errorCode(error, "observation_unavailable"));
      this.#markUnavailable(code);
      fail(code);
    }
  }

  close(): void {
    this.#closed = true;
    this.#latest = undefined;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    this.#controller.abort();
  }

  #assertOpen(): void {
    if (this.#closed) fail("session_closed");
    if (this.#drift !== undefined) fail(this.#drift);
  }
  #markUnavailable(code: string): void {
    this.#latest = undefined;
    this.#unavailable = code;
    if (DRIFT_CODES.has(code)) {
      this.#drift = code;
      if (this.#timer !== undefined) clearTimeout(this.#timer);
      this.#timer = undefined;
    }
  }
  #ensureTimer(): void {
    if (this.#closed || this.#drift !== undefined || this.#timer !== undefined)
      return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      void this.refresh()
        .catch(() => undefined)
        .finally(() => this.#ensureTimer());
    }, this.#refreshIntervalMs);
    this.#timer.unref();
  }
  async #checkLocal(): Promise<Record<string, unknown>> {
    this.#assertOpen();
    await this.#manifest.assertUnchanged();
    this.#assertOpen();
    await this.#manifest.assertInstalledVersions();
    this.#assertOpen();
    let observed: OpenClawProductRuntimeObservation;
    try {
      observed = await this.#observe(this.#controller.signal);
    } catch (error) {
      fail(errorCode(error, "observation_unavailable"));
    }
    this.#assertOpen();
    return Object.freeze(this.#manifest.makeHeartbeat(observed));
  }
  async #performRefresh(): Promise<OpenClawActivationAckHandle> {
    const signal = this.#controller.signal;
    const body = await abortable(this.#checkLocal(), signal);
    this.#assertOpen();
    const response = await abortable(
      Promise.resolve().then(() => this.#sendHeartbeat(body, { signal })),
      signal,
    );
    await abortable(this.#checkLocal(), signal);
    this.#assertOpen();
    const responseKeys =
      typeof response === "object" && response !== null
        ? Reflect.ownKeys(response)
        : [];
    if (
      responseKeys.length !== 2 ||
      !responseKeys.includes("runtime_status") ||
      !responseKeys.includes("activation_ack")
    )
      fail("invalid_heartbeat_response");
    const status = ownData(response, "runtime_status");
    if (
      ownData(status, "runtime") !== "openclaw" ||
      ownData(status, "principal_id") !== this.#manifest.data.principal_id ||
      Object.entries(body).some(
        ([key, value]) =>
          restrictedCanonicalJson(ownData(status, key)) !==
          restrictedCanonicalJson(value),
      )
    )
      fail("heartbeat_identity_mismatch");
    return readOpenClawActivationAckHandle(
      ownData(response, "activation_ack"),
      this.#manifest.expectedAckIdentity,
      { nowMs: Date.now(), maxAgeMs: this.#maxAckAgeMs },
    );
  }
}

function errorCode(error: unknown, fallback: string): string {
  try {
    if (error instanceof OpenClawProductActivationError) {
      const code = Object.getOwnPropertyDescriptor(error, "code")?.value;
      if (typeof code === "string" && SESSION_FAILURE_CODES.has(code))
        return code;
    }
    if (error instanceof ActivationAckReadError) {
      const failure = Object.getOwnPropertyDescriptor(error, "failure")?.value;
      if (typeof failure === "string" && ACK_FAILURE_CODES.has(failure)) {
        return failure === "identity_mismatch"
          ? "ack_identity_mismatch"
          : `ack_${failure}`;
      }
    }
  } catch {
    /* Callback error objects and their reflection are untrusted. */
  }
  return fallback;
}
function fail(code: string): never {
  throw new OpenClawProductActivationError(code);
}
function ownData(value: unknown, key: string): unknown {
  if (
    typeof value !== "object" ||
    value === null ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    fail("invalid_heartbeat_response");
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor))
    fail("invalid_heartbeat_response");
  return descriptor.value;
}
function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => {
      cleanup();
      reject(new OpenClawProductActivationError("session_closed"));
    };
    const cleanup = () => signal.removeEventListener("abort", abort);
    signal.addEventListener("abort", abort, { once: true });
    // Always consume late settlement, including a callback that ignores abort.
    operation.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}
