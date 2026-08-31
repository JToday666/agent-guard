import { createHash } from "node:crypto";

/**
 * AgentGuard's restricted canonical JSON profile for product-activation
 * projections. Arrays retain their order, object keys use Unicode scalar
 * order, and non-safe numeric values are rejected so Python and Node compute
 * the same digest over this contract's integer-free wire models.
 */
export function restrictedCanonicalJson(value: unknown): string {
  const active = new Set<object>();
  return encode(value, active);
}

export function restrictedDigest(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(restrictedCanonicalJson(value), "utf8")
    .digest("hex")}`;
}

function encode(value: unknown, active: Set<object>): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError(
        "restricted canonical JSON accepts only safe, non-negative-zero integers",
      );
    }
    return String(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new TypeError("restricted canonical JSON contains a non-JSON value");
  }
  if (active.has(value)) {
    throw new TypeError("restricted canonical JSON contains a cycle");
  }
  active.add(value);
  try {
    if (Array.isArray(value)) {
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, index)) {
          throw new TypeError("restricted canonical JSON rejects sparse arrays");
        }
        parts.push(encode(value[index], active));
      }
      if (
        Object.keys(value).some(
          (key) =>
            !/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length,
        )
      ) {
        throw new TypeError(
          "restricted canonical JSON rejects named array properties",
        );
      }
      return `[${parts.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(
        "restricted canonical JSON accepts only plain JSON objects",
      );
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError("restricted canonical JSON rejects symbol object keys");
    }
    const entries = Object.entries(value as Record<string, unknown>);
    for (const [key] of entries) {
      assertUnicodeScalarString(key);
    }
    entries.sort(([left], [right]) => compareUnicodeScalars(left, right));
    return `{${entries
      .map(([key, nested]) => `${JSON.stringify(key)}:${encode(nested, active)}`)
      .join(",")}}`;
  } finally {
    active.delete(value);
  }
}

function assertUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(
          "restricted canonical JSON rejects unpaired UTF-16 surrogates",
        );
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(
        "restricted canonical JSON rejects unpaired UTF-16 surrogates",
      );
    }
  }
}

function compareUnicodeScalars(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0)!);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0)!);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) {
      return difference;
    }
  }
  return leftPoints.length - rightPoints.length;
}
