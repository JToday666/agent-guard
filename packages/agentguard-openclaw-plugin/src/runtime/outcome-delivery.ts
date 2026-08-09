import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";

import { logDiagnostic, type GuardApiClient } from "../guard-api-client.js";
import type { AgentGuardPluginConfig, AuditEvent } from "../types.js";
import { unrefTimer } from "./heartbeat.js";

const SPOOL_VERSION = 1;
const SPOOL_FILE_SUFFIX = ".json";
const INVALID_FILE_SUFFIX = ".invalid";
const DEFAULT_RETRY_BASE_MS = 5_000;
const MAX_RETRY_DELAY_MS = 5 * 60_000;
const DEFAULT_DRAIN_INTERVAL_MS = 15_000;
const MAX_PENDING_RECEIPTS = 10_000;
const MAX_RECEIPT_BYTES = 512 * 1024;
const MAX_SPOOL_BYTES = 64 * 1024 * 1024;

type OutcomeEnvelope = {
  version: typeof SPOOL_VERSION;
  receipt: AuditEvent;
  createdAt: number;
  attempts: number;
  nextAttemptAt: number;
};

type DeliveryOptions = {
  spoolDirectory: string;
  config: AgentGuardPluginConfig;
  makeClient: () => GuardApiClient;
  now?: () => number;
  retryBaseMs?: number;
  drainIntervalMs?: number;
};

/**
 * Durable at-least-once delivery for runtime outcome receipts.
 *
 * Each receipt is synchronously persisted before its HTTP submission starts.
 * The Guard API's deterministic audit_id contract makes retries idempotent.
 */
export class RuntimeOutcomeDelivery {
  private readonly spoolDirectory: string;
  private readonly config: AgentGuardPluginConfig;
  private readonly makeClient: () => GuardApiClient;
  private readonly now: () => number;
  private readonly retryBaseMs: number;
  private readonly drainIntervalMs: number;
  private readonly inFlight = new Set<string>();
  private drainPromise: Promise<void> | null = null;
  private drainTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: DeliveryOptions) {
    this.spoolDirectory = options.spoolDirectory;
    this.config = options.config;
    this.makeClient = options.makeClient;
    this.now = options.now ?? Date.now;
    this.retryBaseMs = options.retryBaseMs ?? DEFAULT_RETRY_BASE_MS;
    this.drainIntervalMs = options.drainIntervalMs ?? DEFAULT_DRAIN_INTERVAL_MS;
  }

  start(): void {
    if (this.drainTimer !== null) {
      return;
    }
    this.scheduleDrain();
    this.drainTimer = setInterval(() => {
      this.scheduleDrain();
    }, this.drainIntervalMs);
    unrefTimer(this.drainTimer);
  }

  stop(): void {
    if (this.drainTimer !== null) {
      clearInterval(this.drainTimer);
      this.drainTimer = null;
    }
  }

  submit(
    receipt: AuditEvent,
    client: GuardApiClient,
    logLabel: string,
  ): Promise<void> {
    try {
      validateReceipt(receipt);
    } catch (error) {
      criticalDeliveryError(
        `${logLabel}: invalid runtime outcome receipt was rejected`,
        error,
      );
      return Promise.resolve();
    }
    let key: string;
    try {
      key = this.persistNew(receipt);
    } catch (error) {
      criticalDeliveryError(
        `${logLabel}: runtime outcome receipt could not be persisted`,
        error,
      );
      return client.submitRuntimeOutcome(receipt).then(
        () => undefined,
        (submitError) => {
          criticalDeliveryError(
            `${logLabel}: runtime outcome receipt was neither persisted nor submitted`,
            submitError,
          );
        },
      );
    }
    return this.deliver(key, client, logLabel);
  }

  drain(): Promise<void> {
    if (this.drainPromise !== null) {
      return this.drainPromise;
    }
    this.drainPromise = this.drainPending().finally(() => {
      this.drainPromise = null;
    });
    return this.drainPromise;
  }

  private scheduleDrain(): void {
    void this.drain().catch((error) => {
      criticalDeliveryError("runtime outcome spool drain failed", error);
    });
  }

  private async drainPending(): Promise<void> {
    if (!existsSync(this.spoolDirectory)) {
      return;
    }
    const keys = pendingKeys(this.spoolDirectory);
    for (const key of keys) {
      if (this.inFlight.has(key)) {
        continue;
      }
      let envelope: OutcomeEnvelope;
      try {
        envelope = this.readEnvelope(key);
      } catch (error) {
        this.quarantineInvalid(key);
        criticalDeliveryError(
          "runtime outcome spool contained an invalid receipt",
          error,
        );
        continue;
      }
      if (envelope.nextAttemptAt > this.now()) {
        continue;
      }
      await this.deliver(key, this.makeClient(), "runtime outcome retry");
    }
  }

  private persistNew(receipt: AuditEvent): string {
    ensureSpoolDirectory(this.spoolDirectory);
    const key = receiptKey(receipt.audit_id!);
    const path = join(this.spoolDirectory, key);
    if (existsSync(path)) {
      const persisted = this.readEnvelope(key);
      if (stableJson(persisted.receipt) !== stableJson(receipt)) {
        throw new Error("audit_id is already queued with different content");
      }
      return key;
    }
    if (pendingKeys(this.spoolDirectory).length >= MAX_PENDING_RECEIPTS) {
      throw new Error("runtime outcome spool is full");
    }
    const now = this.now();
    const envelope: OutcomeEnvelope = {
      version: SPOOL_VERSION,
      receipt,
      createdAt: now,
      attempts: 0,
      nextAttemptAt: now,
    };
    const envelopeBytes = Buffer.byteLength(JSON.stringify(envelope), "utf8");
    if (pendingBytes(this.spoolDirectory) + envelopeBytes > MAX_SPOOL_BYTES) {
      throw new Error("runtime outcome spool byte budget is exhausted");
    }
    this.writeEnvelope(key, envelope);
    return key;
  }

  private async deliver(
    key: string,
    client: GuardApiClient,
    logLabel: string,
  ): Promise<void> {
    if (this.inFlight.has(key)) {
      return;
    }
    this.inFlight.add(key);
    try {
      const envelope = this.readEnvelope(key);
      await client.submitRuntimeOutcome(envelope.receipt);
      removeIfPresent(join(this.spoolDirectory, key));
    } catch (error) {
      try {
        const envelope = this.readEnvelope(key);
        const attempts = envelope.attempts + 1;
        this.writeEnvelope(key, {
          ...envelope,
          attempts,
          nextAttemptAt: this.now() + retryDelay(this.retryBaseMs, attempts),
        });
      } catch (persistError) {
        criticalDeliveryError(
          `${logLabel}: runtime outcome retry state could not be persisted`,
          persistError,
        );
      }
      logDiagnostic(
        this.config,
        `${logLabel}: runtime outcome receipt queued for retry`,
        { error: error instanceof Error ? error.message : String(error) },
      );
    } finally {
      this.inFlight.delete(key);
    }
  }

  private readEnvelope(key: string): OutcomeEnvelope {
    const path = join(this.spoolDirectory, key);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("runtime outcome spool entry is not a regular file");
    }
    const raw = readFileSync(path, "utf8");
    if (Buffer.byteLength(raw, "utf8") > MAX_RECEIPT_BYTES) {
      throw new Error("runtime outcome spool entry exceeds the size limit");
    }
    const parsed = JSON.parse(raw) as unknown;
    if (!isOutcomeEnvelope(parsed)) {
      throw new Error("runtime outcome spool entry has an invalid schema");
    }
    validateReceipt(parsed.receipt);
    return parsed;
  }

  private writeEnvelope(key: string, envelope: OutcomeEnvelope): void {
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > MAX_RECEIPT_BYTES) {
      throw new Error("runtime outcome receipt exceeds the spool size limit");
    }
    ensureSpoolDirectory(this.spoolDirectory);
    const target = join(this.spoolDirectory, key);
    const temporary = join(this.spoolDirectory, `.${key}.${randomUUID()}.tmp`);
    let descriptor: number | null = null;
    try {
      descriptor = openSync(temporary, "wx", 0o600);
      writeFileSync(descriptor, serialized, "utf8");
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = null;
      renameSync(temporary, target);
    } finally {
      if (descriptor !== null) {
        closeSync(descriptor);
      }
      removeIfPresent(temporary);
    }
  }

  private quarantineInvalid(key: string): void {
    const source = join(this.spoolDirectory, key);
    const target = join(
      this.spoolDirectory,
      `${key}.${this.now()}${INVALID_FILE_SUFFIX}`,
    );
    try {
      renameSync(source, target);
    } catch (error) {
      criticalDeliveryError(
        "invalid runtime outcome spool entry could not be quarantined",
        error,
      );
    }
  }
}

function validateReceipt(receipt: AuditEvent): void {
  if (
    receipt.schema_version !== "0.4" ||
    receipt.record_type !== "runtime_outcome" ||
    typeof receipt.audit_id !== "string" ||
    receipt.audit_id.length === 0
  ) {
    throw new Error("runtime outcome receipt is missing its strict identity");
  }
}

function isOutcomeEnvelope(value: unknown): value is OutcomeEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    candidate.version === SPOOL_VERSION &&
    typeof candidate.receipt === "object" &&
    candidate.receipt !== null &&
    Number.isFinite(candidate.createdAt) &&
    Number.isInteger(candidate.attempts) &&
    Number(candidate.attempts) >= 0 &&
    Number.isFinite(candidate.nextAttemptAt)
  );
}

function ensureSpoolDirectory(directory: string): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("runtime outcome spool path is not a regular directory");
  }
  chmodSync(directory, 0o700);
}

function pendingKeys(directory: string): string[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(SPOOL_FILE_SUFFIX))
    .sort();
}

function pendingBytes(directory: string): number {
  return pendingKeys(directory).reduce(
    (total, key) => total + statSync(join(directory, key)).size,
    0,
  );
}

function receiptKey(auditId: string): string {
  return `${createHash("sha256").update(auditId).digest("hex")}${SPOOL_FILE_SUFFIX}`;
}

function retryDelay(baseMs: number, attempts: number): number {
  const exponent = Math.min(Math.max(attempts - 1, 0), 10);
  return Math.min(baseMs * 2 ** exponent, MAX_RETRY_DELAY_MS);
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, sortJson(nested)]),
  );
}

function removeIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

function criticalDeliveryError(message: string, error: unknown): void {
  const reason = error instanceof Error ? error.message : String(error);
  console.error(`[AgentGuard OpenClaw] ${message}: ${reason}`);
}
