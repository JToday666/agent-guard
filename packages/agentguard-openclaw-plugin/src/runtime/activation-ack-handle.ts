import { inspect } from "node:util";
import {
  readOpenClawActivationAck,
  type OpenClawActivationAckIdentity,
  type OpenClawActivationAckV1,
} from "./activation-ack.js";

const CONSTRUCTION_KEY = Symbol("activation-ack-handle");

/** A branded, secret-safe carrier for one historical server ACK. */
export class OpenClawActivationAckHandle {
  #ack: Readonly<OpenClawActivationAckV1>;
  #identity: Readonly<OpenClawActivationAckIdentity>;

  private constructor(
    key: symbol,
    ack: Readonly<OpenClawActivationAckV1>,
    identity: Readonly<OpenClawActivationAckIdentity>,
  ) {
    if (key !== CONSTRUCTION_KEY)
      throw new TypeError("Invalid activation ACK handle");
    this.#ack = ack;
    this.#identity = identity;
    Object.freeze(this);
  }

  static read(
    value: unknown,
    expected: Readonly<OpenClawActivationAckIdentity>,
    options: { nowMs: number; maxAgeMs?: number },
  ): OpenClawActivationAckHandle {
    const ack = readOpenClawActivationAck(value, expected, options);
    const {
      schema_version: _schema,
      runtime: _runtime,
      issued_at: _issued,
      expires_at: _expires,
      ack_token: _token,
      ...identity
    } = ack;
    return new OpenClawActivationAckHandle(
      CONSTRUCTION_KEY,
      ack,
      Object.freeze(identity),
    );
  }

  static isHandle(value: unknown): value is OpenClawActivationAckHandle {
    return typeof value === "object" && value !== null && #ack in value;
  }

  get identity(): Readonly<OpenClawActivationAckIdentity> {
    return this.#identity;
  }
  get issued_at(): string {
    return this.#ack.issued_at;
  }
  get expires_at(): string {
    return this.#ack.expires_at;
  }

  headerValue(): string {
    return this.#ack.ack_token;
  }

  toWire(): OpenClawActivationAckV1 {
    return { ...this.#ack };
  }

  /** Validate with the strict reader, retaining nanosecond expiry precision. */
  assertFresh(nowMs: number, maxAgeMs = 120_000): number {
    readOpenClawActivationAck(this.#ack, this.#identity, { nowMs, maxAgeMs });
    const now = BigInt(nowMs) * 1_000_000n;
    const expires = timestampNs(this.#ack.expires_at);
    const ageExpires =
      timestampNs(this.#ack.issued_at) + BigInt(maxAgeMs) * 1_000_000n;
    return (
      Number((expires < ageExpires ? expires : ageExpires) - now) / 1_000_000
    );
  }

  toJSON(): Omit<OpenClawActivationAckV1, "ack_token"> {
    const { ack_token: _token, ...safe } = this.#ack;
    return safe;
  }

  [inspect.custom](): unknown {
    return this.toJSON();
  }
}

export function readOpenClawActivationAckHandle(
  value: unknown,
  expected: Readonly<OpenClawActivationAckIdentity>,
  options: { nowMs: number; maxAgeMs?: number },
): OpenClawActivationAckHandle {
  return OpenClawActivationAckHandle.read(value, expected, options);
}

export function isOpenClawActivationAckHandle(
  value: unknown,
): value is OpenClawActivationAckHandle {
  return OpenClawActivationAckHandle.isHandle(value);
}

function timestampNs(value: string): bigint {
  // Structure/calendar were already validated by readOpenClawActivationAck.
  const fraction = /\.(\d{1,9})(?=Z|[+-]\d{2}:\d{2}$)/u.exec(value)?.[1] ?? "";
  const whole = value.replace(/\.\d{1,9}(?=Z|[+-]\d{2}:\d{2}$)/u, "");
  return (
    BigInt(Date.parse(whole)) * 1_000_000n + BigInt(fraction.padEnd(9, "0"))
  );
}
