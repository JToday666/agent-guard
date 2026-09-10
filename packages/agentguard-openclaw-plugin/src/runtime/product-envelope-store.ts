import * as fs from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { createServer, type Server } from "node:net";
import { basename, dirname, isAbsolute, relative, sep } from "node:path";
import { inspect } from "node:util";

export const PRODUCT_MAX_RECORDS = 10_000;
export const PRODUCT_MAX_RECORD_BYTES = 512 * 1024;
export const PRODUCT_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const FORMAT = "agentguard.product-envelope.v1";
const ALGORITHM = "AES-256-GCM";
const ANCHOR = ".owner-namespace.json";
const ANCHOR_FORMAT = "agentguard.product-store-owner.v1";
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const FILENAME = /^[0-9a-f]{64}\.agq$/u;
const KINDS = new Set(["action", "receipt", "tombstone", "breaker"]);
const ERRORS = new Set([
  "invalid_configuration",
  "unsupported_platform",
  "store_closed",
  "store_locked",
  "permission_denied",
  "key_missing",
  "key_invalid",
  "namespace_mismatch",
  "owner_namespace_mismatch",
  "owner_anchor_missing",
  "owner_anchor_invalid",
  "record_invalid",
  "record_conflict",
  "record_missing",
  "decryption_failed",
  "capacity_exceeded",
  "orphan_temporary",
  "read_failed",
  "write_failed",
  "store_failed",
]);

/** Fixed diagnostics never retain payloads, paths, credentials, or raw errors. */
export class OpenClawProductEnvelopeStoreError extends Error {
  readonly code: string;
  constructor(code: string) {
    const safe = ERRORS.has(code) ? code : "store_failed";
    super(`Product envelope store unavailable: ${safe}`);
    this.name = "OpenClawProductEnvelopeStoreError";
    this.code = safe;
  }
}

export type OpenClawProductRecordKind =
  "action" | "receipt" | "tombstone" | "breaker";
export interface OpenClawProductStoreNamespace {
  readonly runtime: "openclaw";
  readonly agentId: string;
  readonly principalId: string;
  readonly runtimeBindingId: string;
}
export interface OpenClawProductStoreUsage {
  readonly recordCount: number;
  readonly storedBytes: number;
}
export interface OpenClawProductEnvelopeStoreOptions {
  directory: string;
  keyPath: string;
  namespace: OpenClawProductStoreNamespace;
  existingOnly?: boolean;
  maxRecords?: number;
  maxRecordBytes?: number;
  maxTotalBytes?: number;
}

/** Payloads require an explicit getter; ordinary JSON and inspection are safe. */
export class OpenClawStoredEnvelope {
  #recordId: string;
  #payload: string;
  #kind: OpenClawProductRecordKind;
  #revision: number;
  #storedBytes: number;
  constructor(
    recordId: string,
    kind: OpenClawProductRecordKind,
    revision: number,
    payload: string,
    storedBytes: number,
  ) {
    this.#recordId = recordId;
    this.#kind = kind;
    this.#revision = revision;
    this.#payload = payload;
    this.#storedBytes = storedBytes;
    Object.freeze(this);
  }
  get recordId(): string {
    return this.#recordId;
  }
  get kind(): OpenClawProductRecordKind {
    return this.#kind;
  }
  get revision(): number {
    return this.#revision;
  }
  get payload(): string {
    return this.#payload;
  }
  get storedBytes(): number {
    return this.#storedBytes;
  }
  toJSON(): object {
    return {
      kind: this.#kind,
      revision: this.#revision,
      storedBytes: this.#storedBytes,
    };
  }
  [inspect.custom](): object {
    return this.toJSON();
  }
}

/**
 * One Linux owner, authenticated opaque UTF-8 records, and atomic CAS replacement.
 * Every kind (including breaker and tombstone) consumes the same capacity. A full
 * record is reserved in the total budget for an atomic replacement temporary.
 * The owner anchor deliberately rejects recovery after a boot/network namespace
 * change or directory copying. Only same-boot/namespace process restart is supported.
 */
export class OpenClawProductEnvelopeStore {
  #existingOnly: boolean;
  #directory: string;
  #keyPath: string;
  #identity: Readonly<OpenClawProductStoreNamespace>;
  #namespaceDigest: string;
  #maxRecords: number;
  #maxRecordBytes: number;
  #maxTotalBytes: number;
  #directoryFd = -1;
  #keyDirectoryFd = -1;
  #directoryMetadata?: fs.BigIntStats;
  #keyDirectoryMetadata?: fs.BigIntStats;
  #anchorMetadata?: fs.BigIntStats;
  #anchorBytes?: Buffer;
  #createdAnchor = false;
  #key?: Buffer;
  #keyDigest?: Buffer;
  #server?: Server;
  #closed = true;
  #lockFailed = false;
  #ownerPid = process.pid;
  #records = new Map<string, OpenClawStoredEnvelope>();
  #closePromise?: Promise<void>;

  private constructor(options: OpenClawProductEnvelopeStoreOptions) {
    if (
      options.existingOnly !== undefined &&
      typeof options.existingOnly !== "boolean"
    )
      fail("invalid_configuration");
    this.#existingOnly = options.existingOnly ?? false;
    this.#directory = absolutePath(options.directory);
    this.#keyPath = absolutePath(options.keyPath);
    const ns = options.namespace;
    if (
      !ns ||
      ns.runtime !== "openclaw" ||
      ![ns.agentId, ns.principalId, ns.runtimeBindingId].every(
        (value) =>
          typeof value === "string" &&
          value.length > 0 &&
          value.length <= 256 &&
          validUtf8(value),
      )
    )
      fail("invalid_configuration");
    this.#identity = Object.freeze({
      runtime: "openclaw",
      agentId: ns.agentId,
      principalId: ns.principalId,
      runtimeBindingId: ns.runtimeBindingId,
    });
    this.#namespaceDigest = digest(
      canonical({
        runtime: ns.runtime,
        agent_id: ns.agentId,
        principal_id: ns.principalId,
        runtime_binding_id: ns.runtimeBindingId,
      }),
    );
    this.#maxRecords = limit(options.maxRecords, PRODUCT_MAX_RECORDS);
    this.#maxRecordBytes = limit(
      options.maxRecordBytes,
      PRODUCT_MAX_RECORD_BYTES,
    );
    this.#maxTotalBytes = limit(options.maxTotalBytes, PRODUCT_MAX_TOTAL_BYTES);
    if (
      this.#maxTotalBytes <= this.#maxRecordBytes ||
      within(this.#directory, this.#keyPath) ||
      within(this.#keyPath, this.#directory)
    )
      fail("invalid_configuration");
  }

  static async open(
    options: OpenClawProductEnvelopeStoreOptions,
  ): Promise<OpenClawProductEnvelopeStore> {
    let store: OpenClawProductEnvelopeStore | undefined;
    try {
      if (
        process.platform !== "linux" ||
        typeof process.geteuid !== "function" ||
        !fs.constants.O_NOFOLLOW ||
        !fs.constants.O_DIRECTORY ||
        !fs.constants.O_NONBLOCK
      )
        fail("unsupported_platform");
      store = new OpenClawProductEnvelopeStore(options);
      store.#directoryFd = openPrivateDirectory(
        store.#directory,
        !store.#existingOnly,
      );
      store.#directoryMetadata = fs.fstatSync(store.#directoryFd, {
        bigint: true,
      });
      store.#initializeAnchor();
      await store.#acquireLock();
      store.#keyDirectoryFd = openPrivateDirectory(
        dirname(store.#keyPath),
        !store.#existingOnly,
      );
      store.#keyDirectoryMetadata = fs.fstatSync(store.#keyDirectoryFd, {
        bigint: true,
      });
      store.#key = store.#loadOrCreateKey();
      store.#keyDigest = createHash("sha256").update(store.#key).digest();
      store.#closed = false;
      store.#scan();
      return store;
    } catch (error) {
      await store?.close();
      throw fixed(error, "read_failed");
    }
  }

  get namespace(): Readonly<OpenClawProductStoreNamespace> {
    return this.#identity;
  }
  /** Only this open initialized a previously absent owner anchor; never inferred from an empty journal. */
  get freshForProducer(): boolean {
    return this.#createdAnchor;
  }
  toJSON(): object {
    return { closed: this.#closed };
  }
  [inspect.custom](): object {
    return this.toJSON();
  }

  close(): Promise<void> {
    this.#closed = true;
    if (this.#closePromise) return this.#closePromise;
    this.#key?.fill(0);
    this.#key = undefined;
    this.#keyDigest = undefined;
    this.#records.clear();
    for (const fd of [this.#keyDirectoryFd, this.#directoryFd]) {
      if (fd >= 0) {
        try {
          fs.closeSync(fd);
        } catch {
          /* No further writes are possible. */
        }
      }
    }
    this.#keyDirectoryFd = -1;
    this.#directoryFd = -1;
    const server = this.#server;
    this.#closePromise = new Promise<void>((resolve) => {
      if (!server) {
        resolve();
        return;
      }
      try {
        server.close(() => resolve());
      } catch {
        resolve();
      }
    });
    return this.#closePromise;
  }

  get(recordId: string): OpenClawStoredEnvelope | undefined {
    checkRecordId(recordId);
    this.#scan();
    return this.#records.get(recordId);
  }
  records(): readonly OpenClawStoredEnvelope[] {
    this.#scan();
    return Object.freeze(
      [...this.#records.values()].sort((a, b) =>
        a.recordId.localeCompare(b.recordId),
      ),
    );
  }
  usage(): OpenClawProductStoreUsage {
    this.#scan();
    return this.#usage();
  }

  create(
    recordId: string,
    payload: string,
    options: { kind?: OpenClawProductRecordKind } = {},
  ): OpenClawStoredEnvelope {
    if (!options || typeof options !== "object") fail("record_invalid");
    const kind = options.kind ?? "action";
    checkInput(recordId, payload, kind);
    this.#scan();
    const previous = this.#records.get(recordId);
    if (previous) {
      if (previous.kind !== kind || previous.payload !== payload)
        fail("record_conflict");
      return previous;
    }
    return this.#persist(recordId, payload, kind, 1);
  }

  replace(
    recordId: string,
    payload: string,
    options: { expectedRevision: number; kind?: OpenClawProductRecordKind },
  ): OpenClawStoredEnvelope {
    checkRecordId(recordId);
    if (
      !options ||
      !Number.isSafeInteger(options.expectedRevision) ||
      options.expectedRevision < 1
    )
      fail("record_conflict");
    this.#scan();
    const previous = this.#records.get(recordId);
    if (!previous) fail("record_missing");
    const kind = options.kind ?? previous.kind;
    checkInput(recordId, payload, kind);
    if (previous.revision !== options.expectedRevision) fail("record_conflict");
    if (previous.kind === kind && previous.payload === payload) return previous;
    return this.#persist(
      recordId,
      payload,
      kind,
      previous.revision + 1,
      previous,
    );
  }

  #initializeAnchor(): void {
    const expected = ownerAnchor(this.#directoryMetadata!);
    const path = at(this.#directoryFd, ANCHOR);
    try {
      readPrivateFile(this.#directoryFd, ANCHOR, 2048);
    } catch (error) {
      if (!hasCode(error, "ENOENT")) throw error;
      if (this.#existingOnly) fail("owner_anchor_missing");
      if (fs.readdirSync(at(this.#directoryFd)).length !== 0)
        fail("owner_anchor_missing");
      let fd = -1;
      try {
        fd = fs.openSync(
          path,
          fs.constants.O_WRONLY |
            fs.constants.O_CREAT |
            fs.constants.O_EXCL |
            fs.constants.O_NOFOLLOW |
            fs.constants.O_NONBLOCK,
          0o600,
        );
        writeAll(fd, expected);
        fs.fsyncSync(fd);
        fs.fsyncSync(this.#directoryFd);
        this.#createdAnchor = true;
      } catch (creationError) {
        if (!hasCode(creationError, "EEXIST"))
          throw fixed(creationError, "write_failed");
      } finally {
        if (fd >= 0) fs.closeSync(fd);
      }
    }
    const anchor = readPrivateFile(this.#directoryFd, ANCHOR, 2048);
    if (!anchor.equals(expected)) fail("owner_namespace_mismatch");
    this.#anchorMetadata = fs.lstatSync(path, { bigint: true });
    checkPrivateFile(this.#anchorMetadata);
    this.#anchorBytes = anchor;
  }

  async #acquireLock(): Promise<void> {
    const meta = this.#directoryMetadata!;
    const address =
      "\0agentguard-product-" +
      digest(Buffer.from(`${FORMAT}:${meta.dev}:${meta.ino}`, "utf8"));
    const server = createServer((socket) => {
      socket.on("error", () => {
        /* No protocol or information is exposed. */
      });
      socket.destroy();
    });
    this.#server = server;
    server.on("error", () => {
      this.#lockFailed = true;
    });
    server.on("close", () => {
      this.#lockFailed = true;
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: NodeJS.ErrnoException): void => {
        reject(
          new OpenClawProductEnvelopeStoreError(
            error.code === "EADDRINUSE"
              ? "store_locked"
              : "unsupported_platform",
          ),
        );
      };
      server.once("error", onError);
      server.listen({ path: address, exclusive: true }, () => {
        server.off("error", onError);
        server.unref();
        resolve();
      });
    });
  }

  #assertOpen(): void {
    if (this.#closed) fail("store_closed");
    if (
      this.#lockFailed ||
      !this.#server?.listening ||
      process.pid !== this.#ownerPid
    )
      fail("store_locked");
  }

  #checkPathsAndAnchor(): void {
    checkDirectoryIdentity(
      this.#directoryFd,
      this.#directory,
      this.#directoryMetadata!,
    );
    checkDirectoryIdentity(
      this.#keyDirectoryFd,
      dirname(this.#keyPath),
      this.#keyDirectoryMetadata!,
    );
    const meta = fs.lstatSync(at(this.#directoryFd, ANCHOR), { bigint: true });
    checkPrivateFile(meta);
    if (!sameInode(meta, this.#anchorMetadata!)) fail("owner_anchor_invalid");
    const bytes = readPrivateFile(this.#directoryFd, ANCHOR, 2048);
    if (
      !bytes.equals(this.#anchorBytes!) ||
      !bytes.equals(ownerAnchor(this.#directoryMetadata!))
    )
      fail("owner_namespace_mismatch");
  }

  #loadOrCreateKey(): Buffer {
    const name = basename(this.#keyPath);
    try {
      return readPrivateFile(this.#keyDirectoryFd, name, 32, true);
    } catch (error) {
      if (!hasCode(error, "ENOENT")) throw error;
      if (this.#existingOnly) fail("key_missing");
      if (fs.readdirSync(at(this.#directoryFd)).some((name) => name !== ANCHOR))
        fail("key_missing");
    }
    let fd = -1;
    try {
      fd = fs.openSync(
        at(this.#keyDirectoryFd, name),
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_EXCL |
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK,
        0o600,
      );
      const key = randomBytes(32);
      writeAll(fd, key);
      fs.fsyncSync(fd);
      fs.fsyncSync(this.#keyDirectoryFd);
      return key;
    } catch (error) {
      if (hasCode(error, "EEXIST"))
        return readPrivateFile(this.#keyDirectoryFd, name, 32, true);
      throw fixed(error, "write_failed");
    } finally {
      if (fd >= 0) fs.closeSync(fd);
    }
  }

  #scan(): void {
    this.#assertOpen();
    try {
      this.#checkPathsAndAnchor();
      const name = basename(this.#keyPath);
      const key = readPrivateFile(this.#keyDirectoryFd, name, 32, true);
      const currentDigest = createHash("sha256").update(key).digest();
      key.fill(0);
      if (!timingSafeEqual(currentDigest, this.#keyDigest!))
        fail("key_invalid");
      const records = new Map<string, OpenClawStoredEnvelope>();
      let total = 0;
      for (const filename of fs.readdirSync(at(this.#directoryFd))) {
        if (filename === ANCHOR) continue;
        if (filename.startsWith(".tmp-")) fail("orphan_temporary");
        if (!FILENAME.test(filename)) fail("record_invalid");
        if (records.size >= this.#maxRecords) fail("capacity_exceeded");
        const bytes = readPrivateFile(
          this.#directoryFd,
          filename,
          this.#maxRecordBytes,
        );
        total += bytes.length;
        if (total > this.#maxTotalBytes - this.#maxRecordBytes)
          fail("capacity_exceeded");
        const record = this.#decode(filename, bytes);
        const prior = this.#records.get(record.recordId);
        if (
          records.has(record.recordId) ||
          (prior &&
            (record.revision < prior.revision ||
              (record.revision === prior.revision &&
                !sameRecord(record, prior))))
        )
          fail("record_conflict");
        records.set(record.recordId, record);
      }
      for (const id of this.#records.keys())
        if (!records.has(id)) fail("record_missing");
      this.#records = records;
    } catch (error) {
      throw fixed(error, "read_failed");
    }
  }

  #decode(filename: string, serialized: Buffer): OpenClawStoredEnvelope {
    let value: Record<string, unknown>;
    let header: Record<string, unknown>;
    let nonce: Buffer;
    let encrypted: Buffer;
    try {
      value = JSON.parse(serialized.toString("utf8")) as Record<
        string,
        unknown
      >;
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        Object.keys(value).sort().join(",") !==
          "algorithm,ciphertext,format,kind,namespace,nonce,record_id,revision" ||
        value.format !== FORMAT ||
        value.algorithm !== ALGORITHM ||
        typeof value.kind !== "string" ||
        !KINDS.has(value.kind) ||
        typeof value.revision !== "number" ||
        !Number.isSafeInteger(value.revision) ||
        value.revision < 1
      )
        fail("record_invalid");
      checkRecordId(value.record_id);
      if (recordFilename(value.record_id as string) !== filename)
        fail("record_invalid");
      if (value.namespace !== this.#namespaceDigest) fail("namespace_mismatch");
      nonce = base64(value.nonce);
      encrypted = base64(value.ciphertext);
      if (
        nonce.length !== 12 ||
        encrypted.length < 16 ||
        !canonical(value).equals(serialized)
      )
        fail("record_invalid");
      header = {
        format: value.format,
        algorithm: value.algorithm,
        namespace: value.namespace,
        record_id: value.record_id,
        kind: value.kind,
        revision: value.revision,
      };
    } catch (error) {
      throw fixed(error, "record_invalid");
    }
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.#key!, nonce, {
        authTagLength: 16,
      });
      decipher.setAAD(canonical(header));
      decipher.setAuthTag(encrypted.subarray(-16));
      const bytes = Buffer.concat([
        decipher.update(encrypted.subarray(0, -16)),
        decipher.final(),
      ]);
      const payload = bytes.toString("utf8");
      if (!Buffer.from(payload, "utf8").equals(bytes)) fail("record_invalid");
      return new OpenClawStoredEnvelope(
        value.record_id as string,
        value.kind as OpenClawProductRecordKind,
        value.revision as number,
        payload,
        serialized.length,
      );
    } catch (error) {
      throw fixed(error, "decryption_failed");
    }
  }

  #usage(): OpenClawProductStoreUsage {
    return Object.freeze({
      recordCount: this.#records.size,
      storedBytes: [...this.#records.values()].reduce(
        (total, record) => total + record.storedBytes,
        0,
      ),
    });
  }

  #persist(
    recordId: string,
    payload: string,
    kind: OpenClawProductRecordKind,
    revision: number,
    previous?: OpenClawStoredEnvelope,
  ): OpenClawStoredEnvelope {
    if (
      Buffer.byteLength(payload, "utf8") > this.#maxRecordBytes ||
      !Number.isSafeInteger(revision)
    )
      fail("capacity_exceeded");
    let serialized: Buffer;
    try {
      const header = {
        format: FORMAT,
        algorithm: ALGORITHM,
        namespace: this.#namespaceDigest,
        record_id: recordId,
        kind,
        revision,
      };
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", this.#key!, nonce, {
        authTagLength: 16,
      });
      cipher.setAAD(canonical(header));
      const ciphertext = Buffer.concat([
        cipher.update(payload, "utf8"),
        cipher.final(),
        cipher.getAuthTag(),
      ]);
      serialized = canonical({
        ...header,
        nonce: nonce.toString("base64"),
        ciphertext: ciphertext.toString("base64"),
      });
    } catch (error) {
      throw fixed(error, "write_failed");
    }
    const usage = this.#usage();
    if (
      serialized.length > this.#maxRecordBytes ||
      usage.recordCount + (previous ? 0 : 1) > this.#maxRecords ||
      usage.storedBytes - (previous?.storedBytes ?? 0) + serialized.length >
        this.#maxTotalBytes - this.#maxRecordBytes ||
      usage.storedBytes + serialized.length > this.#maxTotalBytes
    )
      fail("capacity_exceeded");
    this.#atomicWrite(recordFilename(recordId), serialized);
    const record = new OpenClawStoredEnvelope(
      recordId,
      kind,
      revision,
      payload,
      serialized.length,
    );
    this.#records.set(recordId, record);
    return record;
  }

  #atomicWrite(target: string, serialized: Buffer): void {
    const temporary = `.tmp-${randomBytes(16).toString("hex")}`;
    let fd = -1;
    let created = false;
    try {
      this.#assertOpen();
      fd = fs.openSync(
        at(this.#directoryFd, temporary),
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_EXCL |
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK,
        0o600,
      );
      created = true;
      writeAll(fd, serialized);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = -1;
      this.#assertOpen();
      fs.renameSync(
        at(this.#directoryFd, temporary),
        at(this.#directoryFd, target),
      );
      fs.fsyncSync(this.#directoryFd);
    } catch (error) {
      throw fixed(error, "write_failed");
    } finally {
      if (fd >= 0) {
        try {
          fs.closeSync(fd);
        } catch {
          /* Original error remains fixed. */
        }
      }
      if (created) {
        try {
          fs.unlinkSync(at(this.#directoryFd, temporary));
          fs.fsyncSync(this.#directoryFd);
        } catch {
          /* Never remove a possibly committed record; orphan temps fail closed. */
        }
      }
    }
  }
}

function fail(code: string): never {
  throw new OpenClawProductEnvelopeStoreError(code);
}
function fixed(
  error: unknown,
  fallback: string,
): OpenClawProductEnvelopeStoreError {
  return error instanceof OpenClawProductEnvelopeStoreError
    ? error
    : new OpenClawProductEnvelopeStoreError(fallback);
}
function hasCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === code
  );
}
function digest(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
function canonical(value: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(value, Object.keys(value).sort()), "utf8");
}
function validUtf8(value: string): boolean {
  return Buffer.from(value, "utf8").toString("utf8") === value;
}
function recordFilename(recordId: string): string {
  return `${digest(Buffer.from(recordId, "ascii"))}.agq`;
}
function checkRecordId(value: unknown): void {
  if (typeof value !== "string" || !RECORD_ID.test(value))
    fail("record_invalid");
}
function checkInput(recordId: string, payload: string, kind: string): void {
  checkRecordId(recordId);
  if (typeof payload !== "string" || !validUtf8(payload) || !KINDS.has(kind))
    fail("record_invalid");
}
function sameRecord(
  a: OpenClawStoredEnvelope,
  b: OpenClawStoredEnvelope,
): boolean {
  return (
    a.recordId === b.recordId &&
    a.kind === b.kind &&
    a.revision === b.revision &&
    a.payload === b.payload &&
    a.storedBytes === b.storedBytes
  );
}
function base64(value: unknown): Buffer {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      value,
    )
  )
    fail("record_invalid");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) fail("record_invalid");
  return bytes;
}
function limit(value: number | undefined, maximum: number): number {
  const result = value === undefined ? maximum : value;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum)
    fail("invalid_configuration");
  return result;
}
function absolutePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    value.includes("\0") ||
    value.split(sep).includes("..") ||
    !validUtf8(value)
  )
    fail("invalid_configuration");
  const normalized = value
    .split(sep)
    .filter((part) => part !== "" && part !== ".")
    .join(sep);
  if (!normalized) fail("invalid_configuration");
  return sep + normalized;
}
function within(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return (
    rel === "" ||
    (!rel.startsWith(".." + sep) && rel !== ".." && !isAbsolute(rel))
  );
}
/** Linux procfs supplies a directory-fd-relative pathname; user components never contain slashes. */
function at(fd: number, name?: string): string {
  return `/proc/self/fd/${fd}${name === undefined ? "" : "/" + name}`;
}
function sameInode(a: fs.BigIntStats, b: fs.BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}
function checkPrivateDirectory(meta: fs.BigIntStats): void {
  if (
    !meta.isDirectory() ||
    meta.uid !== BigInt(process.geteuid!()) ||
    (meta.mode & 0o7777n) !== 0o700n
  )
    fail("permission_denied");
}
function checkPrivateFile(meta: fs.BigIntStats): void {
  if (
    !meta.isFile() ||
    meta.uid !== BigInt(process.geteuid!()) ||
    meta.nlink !== 1n ||
    (meta.mode & 0o7777n) !== 0o600n
  )
    fail("permission_denied");
}
function checkDirectoryIdentity(
  fd: number,
  path: string,
  expected: fs.BigIntStats,
): void {
  const held = fs.fstatSync(fd, { bigint: true });
  const named = fs.lstatSync(path, { bigint: true });
  checkPrivateDirectory(held);
  checkPrivateDirectory(named);
  if (!sameInode(held, expected) || !sameInode(held, named))
    fail("permission_denied");
}
function openPrivateDirectory(path: string, create = true): number {
  let fd = fs.openSync("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    for (const part of path.split(sep).filter(Boolean)) {
      let next = -1;
      try {
        next = fs.openSync(
          at(fd, part),
          fs.constants.O_RDONLY |
            fs.constants.O_DIRECTORY |
            fs.constants.O_NOFOLLOW,
        );
      } catch (error) {
        if (!create || !hasCode(error, "ENOENT")) throw error;
        try {
          fs.mkdirSync(at(fd, part), { mode: 0o700 });
          fs.fsyncSync(fd);
        } catch (mkdirError) {
          if (!hasCode(mkdirError, "EEXIST")) throw mkdirError;
        }
        next = fs.openSync(
          at(fd, part),
          fs.constants.O_RDONLY |
            fs.constants.O_DIRECTORY |
            fs.constants.O_NOFOLLOW,
        );
      }
      try {
        fs.closeSync(fd);
      } catch (error) {
        fs.closeSync(next);
        throw error;
      }
      fd = next;
    }
    checkPrivateDirectory(fs.fstatSync(fd, { bigint: true }));
    return fd;
  } catch (error) {
    try {
      fs.closeSync(fd);
    } catch {
      /* Preserve fixed caller diagnostics. */
    }
    throw error;
  }
}
function readPrivateFile(
  directoryFd: number,
  name: string,
  maximum: number,
  key = false,
): Buffer {
  const fd = fs.openSync(
    at(directoryFd, name),
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    checkPrivateFile(before);
    if (before.size > BigInt(maximum) || (key && before.size !== 32n))
      fail(key ? "key_invalid" : "capacity_exceeded");
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(
        fd,
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (count === 0) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    checkPrivateFile(after);
    if (
      before.size !== BigInt(length) ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      !sameInode(before, after)
    )
      fail("read_failed");
    return Buffer.from(buffer.subarray(0, length));
  } finally {
    fs.closeSync(fd);
  }
}
function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.writeSync(fd, bytes, offset, bytes.length - offset, null);
    if (count <= 0) fail("write_failed");
    offset += count;
  }
}
function ownerAnchor(directory: fs.BigIntStats): Buffer {
  const bootId = fs
    .readFileSync("/proc/sys/kernel/random/boot_id", "utf8")
    .trim();
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(bootId))
    fail("unsupported_platform");
  const net = fs.statSync("/proc/self/ns/net", { bigint: true });
  return canonical({
    format: ANCHOR_FORMAT,
    boot_id: bootId,
    netns_dev: net.dev.toString(),
    netns_ino: net.ino.toString(),
    directory_dev: directory.dev.toString(),
    directory_ino: directory.ino.toString(),
  });
}
