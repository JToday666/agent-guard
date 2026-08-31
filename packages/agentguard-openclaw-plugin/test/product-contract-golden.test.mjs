import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  restrictedCanonicalJson,
  restrictedDigest,
} from "../dist/runtime/canonical.js";

const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../../tests/fixtures/product_activation_v2_golden.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function restrictedHmac(key, value) {
  return `hmac-sha256:${createHmac("sha256", key)
    .update(restrictedCanonicalJson(value), "utf8")
    .digest("hex")}`;
}

test("P0 activation projections have frozen Python-Node canonical vectors", () => {
  const key = Buffer.from(fixture.test_hmac_key_utf8, "utf8");

  assert.equal(
    restrictedCanonicalJson(fixture.canonical_value),
    fixture.canonical_value_json,
  );
  assert.equal(
    restrictedDigest(fixture.canonical_value),
    fixture.canonical_value_digest,
  );
  assert.equal(
    restrictedHmac(key, fixture.canonical_value),
    fixture.canonical_value_hmac,
  );
  assert.equal(
    restrictedDigest(fixture.openclaw_capability_projection),
    fixture.openclaw_capability_digest,
  );
  assert.equal(
    restrictedHmac(key, fixture.residual_risk_signature_payload),
    fixture.residual_risk_signature,
  );
  assert.equal(
    restrictedHmac(key, fixture.activation_ack_signature_payload),
    fixture.activation_ack_token,
  );
});

test("P0 activation HMAC vectors are domain and payload bound", () => {
  const key = Buffer.from(fixture.test_hmac_key_utf8, "utf8");
  const changedDomain = {
    ...fixture.activation_ack_signature_payload,
    domain: "agentguard/activation-ack/tampered",
  };
  const changedAck = {
    ...fixture.activation_ack_signature_payload,
    ack: {
      ...fixture.activation_ack_signature_payload.ack,
      runtime_binding_id: "binding:openclaw:other",
    },
  };
  const changedProfile = {
    ...fixture.activation_ack_signature_payload,
    ack: {
      ...fixture.activation_ack_signature_payload.ack,
      profile_id: "wrong-profile",
    },
  };

  assert.notEqual(
    restrictedHmac(key, changedDomain),
    fixture.activation_ack_token,
  );
  assert.notEqual(restrictedHmac(key, changedAck), fixture.activation_ack_token);
  assert.notEqual(
    restrictedHmac(key, changedProfile),
    fixture.activation_ack_token,
  );
});

test("restricted canonical encoder rejects values outside P0 projection domain", () => {
  assert.throws(() => restrictedCanonicalJson(1.5), TypeError);
  assert.throws(
    () => restrictedCanonicalJson(Number.MAX_SAFE_INTEGER + 1),
    TypeError,
  );
  assert.throws(() => restrictedCanonicalJson(-0), TypeError);
  assert.throws(() => restrictedCanonicalJson("\ud800"), TypeError);

  const sparse = [];
  sparse.length = 1;
  assert.throws(() => restrictedCanonicalJson(sparse), TypeError);

  assert.equal(
    createHash("sha256")
      .update(fixture.canonical_value_json, "utf8")
      .digest("hex"),
    fixture.canonical_value_digest.replace("sha256:", ""),
  );
});
