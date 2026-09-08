import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  lstat,
  open,
  readFile,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, isAbsolute, normalize, parse, join } from "node:path";
import type { OpenClawActivationAckIdentity } from "./activation-ack.js";
import { restrictedCanonicalJson, restrictedDigest } from "./canonical.js";

const CONSTRUCTION_KEY = Symbol("product-manifest");
const MAX_BYTES = 128 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const RUNTIME_VERSION = "2026.7.1-2";
const PLUGIN_VERSION = "0.1.0-rc.1";
const PROFILE_ID = "agentguard-openclaw-v2-restricted";
const RESIDUALS = Object.freeze([
  "openclaw_has_no_authoritative_invocation_start_hook",
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
  "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
  "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
  "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
]);
const EVENT_PROFILE = [
  ["context_assembled", "pre_execution_c1", []],
  [
    "memory_write_proposed",
    "pre_execution_c1",
    [RESIDUALS[0], RESIDUALS[1], RESIDUALS[3]],
  ],
  [
    "message_send_proposed",
    "pre_execution_c1",
    [RESIDUALS[0], RESIDUALS[1], RESIDUALS[2]],
  ],
  ["model_input_prepared", "pre_execution_c1", []],
  ["model_output_produced", "post_execution_isolation", []],
  ["tool_call_proposed", "pre_execution_c1", [RESIDUALS[0], RESIDUALS[1]]],
  ["tool_result_produced", "post_execution_isolation", [RESIDUALS[4]]],
] as const;
const MANIFEST_FIELDS = [
  "schema_version",
  "runtime",
  "runtime_version",
  "plugin_version",
  "principal_id",
  "agent_id",
  "runtime_binding_id",
  "profile_id",
  "profile_digest",
  "activation_ref_digest",
  "adapter_artifact_digest",
  "capability_report_digest",
  "host_inventory_digest",
  "plugin_inventory_digest",
  "plugin_order_inventory_digest",
  "tool_inventory_digest",
] as const;
const OBSERVATION_FIELDS = [
  "runtime",
  "runtime_version",
  "plugin_version",
  "loaded",
  "enforcement_mode",
  "adapter_artifact_digest",
  "host_inventory_digest",
  "plugin_inventory_digest",
  "plugin_order_inventory_digest",
  "tool_inventory_digest",
  "capability_report",
] as const;
const CAPABILITY_FIELDS = [
  "schema_version",
  "runtime",
  "agent_id",
  "runtime_binding_id",
  "profile_id",
  "supported",
  "active",
  "c0_registration",
  "c1_pre_execution_interception",
  "c2_correlation",
  "c3_atomic_replace_and_seal",
  "c4_outcome_receipts",
  "events",
  "residual_boundaries",
  "report_digest",
] as const;

export class OpenClawProductActivationError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`OpenClaw Product activation unavailable: ${code}`);
    this.name = "OpenClawProductActivationError";
    this.code = code;
  }
}

export type OpenClawProductManifestData = Readonly<{
  schema_version: "1.0";
  runtime: "openclaw";
  runtime_version: "2026.7.1-2";
  plugin_version: "0.1.0-rc.1";
  principal_id: string;
  agent_id: string;
  runtime_binding_id: string;
  profile_id: "agentguard-openclaw-v2-restricted";
  profile_digest: string;
  activation_ref_digest: string;
  adapter_artifact_digest: string;
  capability_report_digest: string;
  host_inventory_digest: string;
  plugin_inventory_digest: string;
  plugin_order_inventory_digest: string;
  tool_inventory_digest: string;
}>;
export type OpenClawProductCapabilityReport = Readonly<{
  schema_version: "2.0";
  runtime: "openclaw";
  agent_id: string;
  runtime_binding_id: string;
  profile_id: "agentguard-openclaw-v2-restricted";
  supported: boolean;
  active: boolean;
  c0_registration: true;
  c1_pre_execution_interception: true;
  c2_correlation: true;
  c3_atomic_replace_and_seal: false;
  c4_outcome_receipts: true;
  events: readonly Readonly<{
    event_type: string;
    supported: boolean;
    active: boolean;
    enforcement: string;
    residual_boundaries: readonly string[];
  }>[];
  residual_boundaries: readonly string[];
  report_digest: string;
}>;
export type OpenClawProductRuntimeObservation = Readonly<{
  runtime: "openclaw";
  runtime_version: string;
  plugin_version: string;
  loaded: boolean;
  enforcement_mode: "enforce" | "observe" | "disabled";
  adapter_artifact_digest: string;
  host_inventory_digest: string;
  plugin_inventory_digest: string;
  plugin_order_inventory_digest: string;
  tool_inventory_digest: string;
  capability_report: OpenClawProductCapabilityReport;
}>;

/** Expected local identity, loaded only from a protected canonical file. */
export class OpenClawProductManifest {
  #data: OpenClawProductManifestData;
  #identity: Readonly<OpenClawActivationAckIdentity>;
  #path: string;
  #fingerprint: string;

  private constructor(
    key: symbol,
    data: OpenClawProductManifestData,
    path: string,
    fingerprint: string,
  ) {
    if (key !== CONSTRUCTION_KEY) fail("manifest_not_file_backed");
    this.#data = data;
    this.#path = path;
    this.#fingerprint = fingerprint;
    const {
      runtime_version,
      plugin_version,
      agent_id,
      runtime_binding_id,
      profile_id,
      activation_ref_digest,
      host_inventory_digest,
      plugin_inventory_digest,
      plugin_order_inventory_digest,
      tool_inventory_digest,
      capability_report_digest,
    } = data;
    this.#identity = Object.freeze({
      runtime_version,
      plugin_version,
      agent_id,
      runtime_binding_id,
      profile_id,
      activation_ref_digest,
      capability_digest: capability_report_digest,
      host_inventory_digest,
      plugin_inventory_digest,
      plugin_order_inventory_digest,
      tool_inventory_digest,
    });
    Object.freeze(this);
  }

  static async fromFile(path: string): Promise<OpenClawProductManifest> {
    if (
      typeof path !== "string" ||
      !isAbsolute(path) ||
      normalize(path) !== path
    )
      fail("manifest_invalid_path");
    const { body, fingerprint } = await readProtected(path);
    let data: OpenClawProductManifestData;
    try {
      const raw: unknown = JSON.parse(body);
      const canonical = restrictedCanonicalJson(raw);
      if (body !== canonical && body !== `${canonical}\n`)
        fail("manifest_not_canonical");
      const value = record(raw, MANIFEST_FIELDS);
      if (
        value.schema_version !== "1.0" ||
        value.runtime !== "openclaw" ||
        value.runtime_version !== RUNTIME_VERSION ||
        value.plugin_version !== PLUGIN_VERSION ||
        value.profile_id !== PROFILE_ID ||
        !identifier(value.principal_id, 256) ||
        !identifier(value.agent_id, 128) ||
        !identifier(value.runtime_binding_id, 256) ||
        MANIFEST_FIELDS.filter((field) => field.endsWith("_digest")).some(
          (field) => !digest(value[field]),
        )
      )
        fail("manifest_invalid");
      data = Object.freeze(value) as OpenClawProductManifestData;
    } catch (error) {
      if (error instanceof OpenClawProductActivationError) throw error;
      fail("manifest_invalid");
    }
    return new OpenClawProductManifest(
      CONSTRUCTION_KEY,
      data,
      path,
      fingerprint,
    );
  }

  static isManifest(value: unknown): value is OpenClawProductManifest {
    return typeof value === "object" && value !== null && #path in value;
  }
  get data(): OpenClawProductManifestData {
    return this.#data;
  }
  get expectedAckIdentity(): Readonly<OpenClawActivationAckIdentity> {
    return this.#identity;
  }

  async assertUnchanged(): Promise<void> {
    try {
      const current = await readProtected(this.#path);
      if (current.fingerprint !== this.#fingerprint) fail("manifest_changed");
    } catch {
      fail("manifest_changed");
    }
  }

  async assertInstalledVersions(): Promise<void> {
    try {
      const own = JSON.parse(
        await readFile(new URL("../../package.json", import.meta.url), "utf8"),
      );
      let cursor = dirname(
        await realpath(
          createRequire(import.meta.url).resolve(
            "openclaw/plugin-sdk/agent-harness",
          ),
        ),
      );
      let host: { name?: unknown; version?: unknown } | undefined;
      while (true) {
        try {
          const candidate = JSON.parse(
            await readFile(join(cursor, "package.json"), "utf8"),
          );
          if (candidate.name === "openclaw") {
            host = candidate;
            break;
          }
        } catch {
          /* Walk the actual resolved SDK's package ancestry. */
        }
        if (cursor === parse(cursor).root) break;
        cursor = dirname(cursor);
      }
      if (
        own.name !== "@agentguard-ai/openclaw-plugin" ||
        own.version !== PLUGIN_VERSION ||
        host?.version !== RUNTIME_VERSION
      )
        fail("version_mismatch");
    } catch (error) {
      if (error instanceof OpenClawProductActivationError) throw error;
      fail("runtime_version_unavailable");
    }
  }

  makeHeartbeat(observed: unknown): Record<string, unknown> {
    const value = readOpenClawProductRuntimeObservation(observed);
    const report = value.capability_report;
    const data = this.#data;
    if (
      !value.loaded ||
      value.enforcement_mode !== "enforce" ||
      !report.active ||
      !report.supported ||
      value.runtime_version !== data.runtime_version ||
      value.plugin_version !== data.plugin_version ||
      report.agent_id !== data.agent_id ||
      report.runtime_binding_id !== data.runtime_binding_id ||
      report.report_digest !== data.capability_report_digest ||
      [
        "adapter_artifact_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
      ].some(
        (field) =>
          value[field as keyof typeof value] !==
          data[field as keyof typeof data],
      )
    )
      fail("observation_drift");
    return {
      schema_version: "2.0",
      status: "loaded",
      loaded: true,
      runtime_id: "openclaw",
      agent_id: data.agent_id,
      runtime_binding_id: data.runtime_binding_id,
      profile_id: data.profile_id,
      runtime_version: value.runtime_version,
      plugin_version: value.plugin_version,
      profile_digest: data.profile_digest,
      adapter_artifact_digest: value.adapter_artifact_digest,
      reported_activation_ref_digest: data.activation_ref_digest,
      host_inventory_digest: value.host_inventory_digest,
      plugin_inventory_digest: value.plugin_inventory_digest,
      plugin_order_inventory_digest: value.plugin_order_inventory_digest,
      tool_inventory_digest: value.tool_inventory_digest,
      capability_report: report,
      source: "agentguard-openclaw-plugin",
      enforcement_mode: value.enforcement_mode,
    };
  }
}

/** Copy own JSON data and validate the complete frozen restricted profile. */
export function readOpenClawProductRuntimeObservation(
  value: unknown,
): OpenClawProductRuntimeObservation {
  try {
    const raw = record(copyJson(value), OBSERVATION_FIELDS);
    if (
      raw.runtime !== "openclaw" ||
      typeof raw.runtime_version !== "string" ||
      typeof raw.plugin_version !== "string" ||
      typeof raw.loaded !== "boolean" ||
      !["enforce", "observe", "disabled"].includes(
        raw.enforcement_mode as string,
      ) ||
      OBSERVATION_FIELDS.filter((key) => key.endsWith("_digest")).some(
        (key) => !digest(raw[key]),
      )
    )
      fail("observation_invalid");
    const report = record(raw.capability_report, CAPABILITY_FIELDS);
    if (
      report.schema_version !== "2.0" ||
      report.runtime !== "openclaw" ||
      report.profile_id !== PROFILE_ID ||
      !identifier(report.agent_id, 128) ||
      !identifier(report.runtime_binding_id, 256) ||
      typeof report.active !== "boolean" ||
      typeof report.supported !== "boolean" ||
      (report.active && !report.supported) ||
      [
        "c0_registration",
        "c1_pre_execution_interception",
        "c2_correlation",
        "c4_outcome_receipts",
      ].some((field) => report[field] !== true) ||
      report.c3_atomic_replace_and_seal !== false ||
      !Array.isArray(report.events) ||
      report.events.length !== EVENT_PROFILE.length ||
      restrictedCanonicalJson(report.residual_boundaries) !==
        restrictedCanonicalJson(RESIDUALS)
    )
      fail("observation_invalid");
    for (let index = 0; index < EVENT_PROFILE.length; index += 1) {
      const event = record(report.events[index], [
        "event_type",
        "supported",
        "active",
        "enforcement",
        "residual_boundaries",
      ]);
      const [name, enforcement, residuals] = EVENT_PROFILE[index];
      if (
        event.event_type !== name ||
        event.supported !== true ||
        event.active !== report.active ||
        event.enforcement !== enforcement ||
        restrictedCanonicalJson(event.residual_boundaries) !==
          restrictedCanonicalJson(residuals)
      )
        fail("observation_invalid");
    }
    const { report_digest, ...projection } = report;
    if (
      !digest(report_digest) ||
      restrictedDigest(projection) !== report_digest
    )
      fail("observation_invalid");
    return deepFreeze(raw) as OpenClawProductRuntimeObservation;
  } catch {
    fail("observation_invalid");
  }
}

function fail(code: string): never {
  throw new OpenClawProductActivationError(code);
}
function digest(value: unknown): boolean {
  return typeof value === "string" && DIGEST.test(value);
}
function identifier(value: unknown, maximum: number): boolean {
  return (
    typeof value === "string" &&
    value.length <= maximum &&
    IDENTIFIER.test(value)
  );
}
function record(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    fail("invalid_data");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  )
    fail("invalid_data");
  const result: Record<string, unknown> = {};
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor))
      fail("invalid_data");
    result[key] = descriptor.value;
  }
  return result;
}
function copyJson(value: unknown, active = new Set<object>()): unknown {
  if (value === null || ["string", "boolean", "number"].includes(typeof value))
    return value;
  if (typeof value !== "object" || active.has(value)) fail("invalid_data");
  active.add(value);
  try {
    const array = Array.isArray(value);
    if (
      !array &&
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    )
      fail("invalid_data");
    const result: unknown[] | Record<string, unknown> = array ? [] : {};
    const keys = Reflect.ownKeys(value);
    if (array && keys.length !== value.length + 1) fail("invalid_data");
    for (const key of keys) {
      if (array && key === "length") continue;
      if (
        typeof key !== "string" ||
        (array && !/^(?:0|[1-9][0-9]*)$/u.test(key))
      )
        fail("invalid_data");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor))
        fail("invalid_data");
      Object.defineProperty(result, key, {
        value: copyJson(descriptor.value, active),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  } finally {
    active.delete(value);
  }
}
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}
function statIdentity(value: BigIntStats): string {
  return [
    value.dev,
    value.ino,
    value.uid,
    value.mode,
    value.nlink,
    value.size,
    value.mtimeNs,
    value.ctimeNs,
  ].join(":");
}
function parentIdentity(value: BigIntStats): string {
  return [value.dev, value.ino, value.uid, value.mode].join(":");
}
async function readProtected(
  path: string,
): Promise<{ body: string; fingerprint: string }> {
  let file: FileHandle | undefined;
  try {
    if (typeof process.getuid !== "function") fail("manifest_insecure");
    const owner = BigInt(process.getuid());
    const parent = await lstat(dirname(path), { bigint: true });
    if (
      !parent.isDirectory() ||
      parent.uid !== owner ||
      (parent.mode & 0o7777n) !== 0o700n ||
      (await realpath(path)) !== path
    )
      fail("manifest_insecure");
    file = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await file.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.uid !== owner ||
      (before.mode & 0o7777n) !== 0o600n ||
      before.nlink !== 1n
    )
      fail("manifest_insecure");
    if (before.size > BigInt(MAX_BYTES)) fail("manifest_too_large");
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let size = 0;
    while (size <= MAX_BYTES) {
      const { bytesRead } = await file.read(
        buffer,
        size,
        buffer.length - size,
        null,
      );
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > MAX_BYTES) fail("manifest_too_large");
    const after = await file.stat({ bigint: true });
    if (
      statIdentity(before) !== statIdentity(after) ||
      statIdentity(await lstat(path, { bigint: true })) !==
        statIdentity(after) ||
      parentIdentity(parent) !==
        parentIdentity(await lstat(dirname(path), { bigint: true })) ||
      (await realpath(path)) !== path
    )
      fail("manifest_changed");
    const bytes = buffer.subarray(0, size);
    const body = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
    return {
      body,
      fingerprint: `${parentIdentity(parent)}:${statIdentity(after)}:${createHash("sha256").update(bytes).digest("hex")}`,
    };
  } catch (error) {
    if (error instanceof OpenClawProductActivationError) throw error;
    return fail("manifest_unavailable");
  } finally {
    try {
      await file?.close();
    } catch {
      fail("manifest_unavailable");
    }
  }
}
