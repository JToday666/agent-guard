import { types } from "node:util";
import { FixtureError } from "./memory.mjs";

export function ownObject(value, allowed, required = allowed) {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new FixtureError("invalid_product_profile");
  const result = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !allowed.includes(key) ||
      !descriptor?.enumerable ||
      !("value" in descriptor)
    )
      throw new FixtureError("invalid_product_profile");
    result[key] = descriptor.value;
  }
  if (required.some((key) => !Object.hasOwn(result, key)))
    throw new FixtureError("invalid_product_profile");
  return result;
}

export function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value))
    return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object" && !types.isProxy(value)) {
    const own = ownObject(value, Object.keys(value));
    return `{${Object.keys(own)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(own[key])}`)
      .join(",")}}`;
  }
  throw new FixtureError("invalid_product_profile");
}

export function freeze(value) {
  if (value && typeof value === "object") {
    for (const field of Object.values(value)) freeze(field);
    Object.freeze(value);
  }
  return value;
}
