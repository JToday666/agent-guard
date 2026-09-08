/** Transport-only OpenClaw projection of the server's ActivationAckV1. */
export type OpenClawActivationAckIdentity = {
  runtime_version: "2026.7.1-2";
  plugin_version: "0.1.0-rc.1";
  agent_id: string;
  runtime_binding_id: string;
  profile_id: "agentguard-openclaw-v2-restricted";
  activation_ref_digest: string;
  capability_digest: string;
  host_inventory_digest: string;
  plugin_inventory_digest: string;
  plugin_order_inventory_digest: string;
  tool_inventory_digest: string;
};

export type OpenClawActivationAckV1 = OpenClawActivationAckIdentity & {
  schema_version: "1.0";
  runtime: "openclaw";
  issued_at: string;
  expires_at: string;
  /** Opaque server credential: transport-only, never diagnostic data. */
  ack_token: string;
};

export type ActivationAckReadFailure =
  | "invalid_response"
  | "invalid_expected_identity"
  | "identity_mismatch"
  | "invalid_clock"
  | "invalid_max_age"
  | "invalid_validity_window"
  | "not_yet_valid"
  | "expired"
  | "too_old";

/** Fixed, body-free error; never retains the input or its token as a cause. */
export class ActivationAckReadError extends Error {
  readonly failure: ActivationAckReadFailure;

  constructor(failure: ActivationAckReadFailure) {
    super(`Activation ACK read failed: ${failure}`);
    this.name = "ActivationAckReadError";
    this.failure = failure;
  }
}

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TOKEN = /^hmac-sha256:[0-9a-f]{64}$/u;
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u;
const MAX_AGE_MS = 120_000;
const NS_PER_MS = 1_000_000n;
const DIGEST_FIELDS = [
  "activation_ref_digest",
  "capability_digest",
  "host_inventory_digest",
  "plugin_inventory_digest",
  "plugin_order_inventory_digest",
  "tool_inventory_digest",
] as const;
const IDENTITY_FIELDS = [
  "runtime_version",
  "plugin_version",
  "agent_id",
  "runtime_binding_id",
  "profile_id",
  ...DIGEST_FIELDS,
] as const;
const ACK_FIELDS = [
  "schema_version",
  "runtime",
  ...IDENTITY_FIELDS,
  "issued_at",
  "expires_at",
  "ack_token",
] as const;

/**
 * Validate structure, independently supplied identity, and freshness only.
 * This does NOT verify the HMAC: only the server holds its signing key.
 * The returned frozen transport object contains the raw token and must not
 * be logged, JSON-stringified for diagnostics, or persisted as status.
 * Original timestamp strings are preserved for the server's signed projection.
 */
export function readOpenClawActivationAck(
  value: unknown,
  expected: Readonly<OpenClawActivationAckIdentity>,
  options: { nowMs: number; maxAgeMs?: number },
): Readonly<OpenClawActivationAckV1> {
  const identity = readDataObject(
    expected,
    IDENTITY_FIELDS,
    "invalid_expected_identity",
  );
  validateIdentity(identity, "invalid_expected_identity");
  const ack = readDataObject(value, ACK_FIELDS, "invalid_response");
  validateIdentity(ack, "invalid_response");
  if (
    ack.schema_version !== "1.0" ||
    ack.runtime !== "openclaw" ||
    typeof ack.ack_token !== "string" ||
    !TOKEN.test(ack.ack_token)
  ) {
    fail("invalid_response");
  }
  for (const field of IDENTITY_FIELDS) {
    if (ack[field] !== identity[field]) {
      fail("identity_mismatch");
    }
  }
  // Clock/config are local inputs. Validate without invoking property accessors.
  const clock = readClockOptions(options);
  const issuedAt = rfc3339Nanoseconds(ack.issued_at);
  const expiresAt = rfc3339Nanoseconds(ack.expires_at);
  if (issuedAt === null || expiresAt === null) {
    fail("invalid_response");
  }
  if (
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > BigInt(MAX_AGE_MS) * NS_PER_MS
  ) {
    fail("invalid_validity_window");
  }
  const now = BigInt(clock.nowMs) * NS_PER_MS;
  if (now < issuedAt) {
    fail("not_yet_valid");
  }
  if (now >= expiresAt) {
    fail("expired");
  }
  if (now - issuedAt > BigInt(clock.maxAgeMs) * NS_PER_MS) {
    fail("too_old");
  }
  // readDataObject already copied all own data fields into a fresh object.
  return Object.freeze(ack) as Readonly<OpenClawActivationAckV1>;
}

function fail(failure: ActivationAckReadFailure): never {
  throw new ActivationAckReadError(failure);
}

function readDataObject(
  value: unknown,
  fields: readonly string[],
  failure: ActivationAckReadFailure,
): Record<string, unknown> {
  try {
    if (typeof value !== "object" || value === null) {
      fail(failure);
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail(failure);
    }
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== fields.length ||
      keys.some((key) => typeof key !== "string" || !fields.includes(key))
    ) {
      fail(failure);
    }
    const result: Record<string, unknown> = {};
    for (const field of fields) {
      const descriptor = Object.getOwnPropertyDescriptor(value, field);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        fail(failure);
      }
      result[field] = descriptor.value;
    }
    return result;
  } catch {
    // Even hostile reflection/proxy errors must not leak their message/cause.
    return fail(failure);
  }
}

function validateIdentity(
  value: Record<string, unknown>,
  failure: ActivationAckReadFailure,
): void {
  if (
    value.runtime_version !== "2026.7.1-2" ||
    value.plugin_version !== "0.1.0-rc.1" ||
    value.profile_id !== "agentguard-openclaw-v2-restricted" ||
    !boundedScalarString(value.agent_id, 128) ||
    !boundedScalarString(value.runtime_binding_id, 256) ||
    DIGEST_FIELDS.some(
      (field) => typeof value[field] !== "string" || !DIGEST.test(value[field]),
    )
  ) {
    fail(failure);
  }
}

function boundedScalarString(value: unknown, maximum: number): boolean {
  if (typeof value !== "string") {
    return false;
  }
  const scalars = Array.from(value);
  return (
    scalars.length > 0 &&
    scalars.length <= maximum &&
    scalars.every((scalar) => {
      const point = scalar.codePointAt(0)!;
      return point < 0xd800 || point > 0xdfff;
    })
  );
}

function readClockOptions(value: unknown): {
  nowMs: number;
  maxAgeMs: number;
} {
  let options: Record<string, unknown>;
  try {
    const hasMaxAge =
      typeof value === "object" &&
      value !== null &&
      Object.prototype.hasOwnProperty.call(value, "maxAgeMs");
    options = readDataObject(
      value,
      hasMaxAge ? ["nowMs", "maxAgeMs"] : ["nowMs"],
      "invalid_clock",
    );
  } catch {
    return fail("invalid_clock");
  }
  if (
    typeof options.nowMs !== "number" ||
    !Number.isSafeInteger(options.nowMs)
  ) {
    fail("invalid_clock");
  }
  const maxAgeMs =
    options.maxAgeMs === undefined ? MAX_AGE_MS : options.maxAgeMs;
  if (
    typeof maxAgeMs !== "number" ||
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs <= 0 ||
    maxAgeMs > MAX_AGE_MS
  ) {
    fail("invalid_max_age");
  }
  return { nowMs: options.nowMs, maxAgeMs };
}

/** Preserve fractional precision instead of Date.parse's millisecond truncation. */
export function rfc3339Nanoseconds(value: unknown): bigint | null {
  if (typeof value !== "string") {
    return null;
  }
  const match = RFC3339.exec(value);
  if (!match) {
    return null;
  }
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    fraction = "",
    zone,
    sign,
    offsetHourText,
    offsetMinuteText,
  ] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, 0);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    local.getUTCFullYear() !== year ||
    local.getUTCMonth() !== month - 1 ||
    local.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  let offsetMinutes = 0;
  if (zone !== "Z") {
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);
    if (offsetHour > 23 || offsetMinute > 59) {
      return null;
    }
    offsetMinutes = (offsetHour * 60 + offsetMinute) * (sign === "+" ? 1 : -1);
  }
  return (
    BigInt(local.getTime() - offsetMinutes * 60_000) * NS_PER_MS +
    BigInt(fraction.padEnd(9, "0"))
  );
}
