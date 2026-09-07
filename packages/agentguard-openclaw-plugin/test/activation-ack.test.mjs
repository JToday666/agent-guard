import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ActivationAckReadError,
  readOpenClawActivationAck,
} from "../dist/runtime/activation-ack.js";

const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../../tests/fixtures/product_activation_v2_golden.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const NOW = Date.parse("2026-09-01T00:00:00Z");
const DIGEST_FIELDS = [
  "activation_ref_digest",
  "capability_digest",
  "host_inventory_digest",
  "plugin_inventory_digest",
  "plugin_order_inventory_digest",
  "tool_inventory_digest",
];
// Independently authored local frozen identity, not copied from the ACK input.
const EXPECTED = Object.freeze({
  runtime_version: "2026.7.1-2",
  plugin_version: "0.1.0-rc.1",
  agent_id: "main",
  runtime_binding_id: "binding:openclaw:main",
  profile_id: "agentguard-openclaw-v2-restricted",
  activation_ref_digest:
    "sha256:84137653945295959e6ee2a0d64019347e8e0baeaca10a22c350064afbb25e3b",
  capability_digest:
    "sha256:d106043e3d9022ecc3484113c06d08a5ede6734bd6e426212e6d7ec7479f9964",
  host_inventory_digest: `sha256:${"2".repeat(64)}`,
  plugin_inventory_digest: `sha256:${"3".repeat(64)}`,
  plugin_order_inventory_digest: `sha256:${"8".repeat(64)}`,
  tool_inventory_digest: `sha256:${"4".repeat(64)}`,
});

function wire(changes = {}) {
  return {
    ...fixture.activation_ack_signature_payload.ack,
    ack_token: fixture.activation_ack_token,
    ...changes,
  };
}

function read(value, expected = EXPECTED, options = { nowMs: NOW }) {
  return readOpenClawActivationAck(value, expected, options);
}

function rejects(
  value,
  failure,
  expected = EXPECTED,
  options = { nowMs: NOW },
) {
  assert.throws(
    () => read(value, expected, options),
    (error) => {
      assert.ok(error instanceof ActivationAckReadError);
      assert.equal(error.failure, failure);
      assert.equal(error.message, `Activation ACK read failed: ${failure}`);
      assert.equal(Object.hasOwn(error, "cause"), false);
      assert.equal(String(error).includes(fixture.activation_ack_token), false);
      assert.equal(
        JSON.stringify(error).includes(fixture.activation_ack_token),
        false,
      );
      return true;
    },
  );
}

test("ACK reader accepts Python golden transport and freezes a fresh snapshot", () => {
  const input = wire();
  const before = structuredClone(input);
  const actual = read(input);
  assert.deepEqual(actual, input);
  assert.notEqual(actual, input);
  assert.equal(Object.isFrozen(actual), true);
  assert.deepEqual(input, before);
  assert.equal(Object.isFrozen(input), false);
  input.agent_id = "changed-after-read";
  assert.equal(actual.agent_id, "main");
  assert.throws(() => {
    actual.agent_id = "mutated";
  }, TypeError);
  assert.equal(actual.issued_at, "2026-09-01T00:00:00+00:00");
});

test("ACK reader checks shape and freshness, not server HMAC authenticity", () => {
  const opaque = `hmac-sha256:${"0".repeat(64)}`;
  assert.equal(read(wire({ ack_token: opaque })).ack_token, opaque);
});

test("ACK reader rejects every missing field, extra fields, and wrong field types", () => {
  assert.equal(Object.keys(wire()).length, 16);
  for (const field of Object.keys(wire())) {
    const missing = wire();
    delete missing[field];
    rejects(missing, "invalid_response");
    for (const value of [undefined, null, false, 1, [], {}]) {
      rejects(wire({ [field]: value }), "invalid_response");
    }
  }
  rejects(wire({ unknown: fixture.activation_ack_token }), "invalid_response");
  for (const value of [undefined, null, false, 1, "ack", [], new Date()]) {
    rejects(value, "invalid_response");
  }
});

test("ACK reader refuses inherited fields, symbols, accessors, and hostile reflection", () => {
  rejects(Object.create(wire()), "invalid_response");
  rejects(
    Object.assign(wire(), { [Symbol("extra")]: true }),
    "invalid_response",
  );
  let getterCalls = 0;
  const accessor = wire();
  Object.defineProperty(accessor, "ack_token", {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error(fixture.activation_ack_token);
    },
  });
  rejects(accessor, "invalid_response");
  assert.equal(getterCalls, 0);
  const hidden = wire();
  Object.defineProperty(hidden, "agent_id", {
    value: "main",
    enumerable: false,
  });
  rejects(hidden, "invalid_response");
  rejects(
    new Proxy(wire(), {
      ownKeys() {
        throw new Error(fixture.activation_ack_token);
      },
    }),
    "invalid_response",
  );
  assert.equal(
    read(Object.assign(Object.create(null), wire())).agent_id,
    "main",
  );
});

test("ACK reader enforces frozen runtime, plugin and profile pins", () => {
  for (const [field, value] of Object.entries({
    schema_version: "2.0",
    runtime: "langgraph",
    runtime_version: "2026.7.1",
    plugin_version: "0.1.0-beta.1",
    profile_id: "agentguard-langgraph-v2",
  })) {
    rejects(wire({ [field]: value }), "invalid_response");
  }
});

test("ACK reader compares every independent identity and digest field", () => {
  assert.equal(Object.keys(EXPECTED).length, 11);
  for (const field of ["agent_id", "runtime_binding_id"]) {
    rejects(wire({ [field]: "different" }), "identity_mismatch");
    rejects(wire(), "identity_mismatch", { ...EXPECTED, [field]: "different" });
  }
  for (const field of DIGEST_FIELDS) {
    const other = `sha256:${"a".repeat(64)}`;
    rejects(wire({ [field]: other }), "identity_mismatch");
    rejects(wire(), "identity_mismatch", { ...EXPECTED, [field]: other });
    for (const malformed of [
      "",
      `sha256:${"A".repeat(64)}`,
      `sha256:${"a".repeat(63)}`,
      `${other}\n`,
    ]) {
      rejects(wire({ [field]: malformed }), "invalid_response");
      rejects(wire(), "invalid_expected_identity", {
        ...EXPECTED,
        [field]: malformed,
      });
    }
  }
  for (const malformed of [
    "",
    "secret",
    `hmac-sha256:${"A".repeat(64)}`,
    `${fixture.activation_ack_token}\n`,
  ]) {
    rejects(wire({ ack_token: malformed }), "invalid_response");
  }
});

test("ACK reader independently rejects incomplete, unpinned or accessor expected identity", () => {
  for (const field of Object.keys(EXPECTED)) {
    const missing = { ...EXPECTED };
    delete missing[field];
    rejects(wire(), "invalid_expected_identity", missing);
    rejects(wire(), "invalid_expected_identity", {
      ...EXPECTED,
      [field]: null,
    });
  }
  rejects(wire(), "invalid_expected_identity", {
    ...EXPECTED,
    runtime: "openclaw",
  });
  for (const [field, value] of Object.entries({
    runtime_version: "future",
    plugin_version: "0.1.0-beta.1",
    profile_id: "other",
  })) {
    rejects(wire(), "invalid_expected_identity", {
      ...EXPECTED,
      [field]: value,
    });
  }
  const expected = { ...EXPECTED };
  Object.defineProperty(expected, "agent_id", {
    enumerable: true,
    get() {
      throw new Error(fixture.activation_ack_token);
    },
  });
  rejects(wire(), "invalid_expected_identity", expected);
});

test("ACK reader enforces Core scalar-string bounds without UTF-16 truncation", () => {
  for (const [field, maximum] of [
    ["agent_id", 128],
    ["runtime_binding_id", 256],
  ]) {
    for (const value of ["", "a".repeat(maximum + 1), "\ud800", "\udfff"]) {
      rejects(wire({ [field]: value }), "invalid_response");
      rejects(wire(), "invalid_expected_identity", {
        ...EXPECTED,
        [field]: value,
      });
    }
    const valid = "😀".repeat(maximum);
    assert.equal(
      read(wire({ [field]: valid }), { ...EXPECTED, [field]: valid })[field],
      valid,
    );
  }
});

test("ACK window is half-open and never longer than 120 seconds", () => {
  assert.equal(read(wire(), EXPECTED, { nowMs: NOW }).runtime, "openclaw");
  assert.equal(
    read(wire(), EXPECTED, { nowMs: NOW + 119_999 }).runtime,
    "openclaw",
  );
  rejects(wire(), "not_yet_valid", EXPECTED, { nowMs: NOW - 1 });
  rejects(wire(), "expired", EXPECTED, { nowMs: NOW + 120_000 });
  rejects(wire(), "expired", EXPECTED, { nowMs: NOW + 120_001 });
  for (const expires_at of [
    "2026-09-01T00:00:00Z",
    "2026-08-31T23:59:59Z",
    "2026-09-01T00:02:01Z",
  ]) {
    rejects(wire({ expires_at }), "invalid_validity_window");
  }
});

test("ACK reader preserves sub-millisecond window, future and age boundaries", () => {
  rejects(
    wire({ expires_at: "2026-09-01T00:02:00.000001Z" }),
    "invalid_validity_window",
  );
  rejects(
    wire({ expires_at: "2026-09-01T00:02:00.000000001Z" }),
    "invalid_validity_window",
  );
  rejects(wire({ issued_at: "2026-09-01T00:00:00.000001Z" }), "not_yet_valid");
  rejects(
    wire({ issued_at: "2026-09-01T00:00:00.000000001Z" }),
    "not_yet_valid",
  );
  rejects(
    wire({ expires_at: "2026-09-01T00:00:00.999999Z" }),
    "expired",
    EXPECTED,
    { nowMs: NOW + 1_000 },
  );
  const value = wire({
    issued_at: "2026-08-31T23:59:59.999999Z",
    expires_at: "2026-09-01T00:01:00Z",
  });
  rejects(value, "too_old", EXPECTED, { nowMs: NOW + 1_000, maxAgeMs: 1_000 });
  const exact = wire({
    issued_at: "2026-09-01T00:00:00.000001Z",
    expires_at: "2026-09-01T00:02:00.000001Z",
  });
  assert.equal(
    read(exact, EXPECTED, { nowMs: NOW + 120_000 }).expires_at,
    exact.expires_at,
  );
});

test("ACK reader validates local age limit and deterministic integer clock", () => {
  assert.equal(
    read(wire(), EXPECTED, { nowMs: NOW + 1_000, maxAgeMs: 1_000 }).runtime,
    "openclaw",
  );
  rejects(wire(), "too_old", EXPECTED, { nowMs: NOW + 1_001, maxAgeMs: 1_000 });
  for (const maxAgeMs of [
    null,
    "120000",
    false,
    0,
    -1,
    120_001,
    1.5,
    NaN,
    Infinity,
  ]) {
    rejects(wire(), "invalid_max_age", EXPECTED, { nowMs: NOW, maxAgeMs });
  }
  for (const nowMs of [
    null,
    undefined,
    "0",
    false,
    NaN,
    Infinity,
    NOW + 0.5,
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    rejects(wire(), "invalid_clock", EXPECTED, { nowMs });
  }
  rejects(wire(), "invalid_clock", EXPECTED, {});
  rejects(wire(), "invalid_clock", EXPECTED, { nowMs: NOW, extra: true });
  rejects(wire(), "invalid_clock", EXPECTED, {
    get nowMs() {
      throw new Error(fixture.activation_ack_token);
    },
  });
});

test("ACK reader validates actual calendar dates and explicit RFC3339 timezone", () => {
  const invalid = [
    "2026-09-01T00:00:00",
    "2026-09-01 00:00:00Z",
    "2026-02-29T00:00:00Z",
    "2026-04-31T00:00:00Z",
    "0000-09-01T00:00:00Z",
    "2026-00-01T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-09-00T00:00:00Z",
    "2026-09-01T24:00:00Z",
    "2026-09-01T00:60:00Z",
    "2026-09-01T00:00:60Z",
    "2026-09-01T00:00:00+24:00",
    "2026-09-01T00:00:00+08:60",
    "2026-09-01T00:00:00.1234567890Z",
    "2026-09-01T00:00:00Z\n",
  ];
  for (const timestamp of invalid) {
    rejects(wire({ issued_at: timestamp }), "invalid_response");
    rejects(wire({ expires_at: timestamp }), "invalid_response");
  }
  for (const [issued_at, expires_at] of [
    ["2026-09-01T08:00:00+08:00", "2026-09-01T08:02:00+08:00"],
    ["2026-08-31T19:00:00-05:00", "2026-08-31T19:02:00-05:00"],
  ]) {
    assert.equal(read(wire({ issued_at, expires_at })).issued_at, issued_at);
  }
  const leap = wire({
    issued_at: "2024-02-29T00:00:00Z",
    expires_at: "2024-02-29T00:02:00Z",
  });
  assert.equal(
    read(leap, EXPECTED, { nowMs: Date.parse(leap.issued_at) }).issued_at,
    leap.issued_at,
  );
});
