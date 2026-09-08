import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspect } from "node:util";

import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { readHistoricalOpenClawActivationAck } from "../dist/runtime/activation-ack.js";
import {
  readOpenClawActivationAckHandle,
  isOpenClawActivationAckHandle,
} from "../dist/runtime/activation-ack-handle.js";
import {
  attachRuntimeOutcomeActivationAck,
  bindEvaluationActivationAck,
  bindConsumptionActivationAck,
} from "../dist/runtime/product-authority-context.js";
import {
  captureProductReceiptWire,
  prepareProductReceipt,
  readHistoricalProductReceiptWire,
} from "../dist/runtime/product-receipt-wire.js";

const NS = Object.freeze({
  runtime: "openclaw",
  agentId: "agent_rte_fixture",
  principalId: "principal:product-wire-test",
  runtimeBindingId: "binding:wire:test",
});
const IDENTITY = {
  runtime_version: "2026.7.1-2",
  plugin_version: "0.1.0-rc.1",
  agent_id: NS.agentId,
  runtime_binding_id: NS.runtimeBindingId,
  profile_id: "agentguard-openclaw-v2-restricted",
  ...Object.fromEntries(
    [
      "activation_ref_digest",
      "capability_digest",
      "host_inventory_digest",
      "plugin_inventory_digest",
      "plugin_order_inventory_digest",
      "tool_inventory_digest",
    ].map((key, i) => [key, `sha256:${String(i + 1).repeat(64)}`]),
  ),
};
const TOKEN = `hmac-sha256:${"a".repeat(64)}`;
const ACK = {
  schema_version: "1.0",
  runtime: "openclaw",
  ...IDENTITY,
  issued_at: "2026-08-15T07:59:00.000000001Z",
  expires_at: "2026-08-15T08:01:00.000000001Z",
  ack_token: TOKEN,
};
const kinds = [
  "pre_execution_deny",
  "approval_release",
  "tool_result_modified",
  "tool_result_quarantined",
  "execution_completed",
  "execution_failed",
];
function fixture(kind = "execution_completed") {
  const receipt = JSON.parse(
    readFileSync(
      new URL(
        `../../../tests/fixtures/runtime_enforcement/${kind}.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  );
  receipt.runtime = "openclaw";
  receipt.metadata.activation_ack = { ...ACK };
  return receipt;
}
function read(value, namespace = NS) {
  return readHistoricalProductReceiptWire(
    restrictedCanonicalJson(value),
    namespace,
  );
}
function invalid(callback) {
  assert.throws(callback, (error) => {
    assert.equal(error.name, "OpenClawProductActivationError");
    assert.equal(error.code, "product_receipt_invalid");
    assert.equal(Object.hasOwn(error, "cause"), false);
    for (const rendered of [
      String(error),
      JSON.stringify(error),
      inspect(error),
    ])
      assert.equal(rendered.includes(TOKEN), false);
    return true;
  });
}
for (const kind of kinds)
  test(`historical receipt accepts shared Core ${kind} fixture`, () => {
    const value = fixture(kind);
    assert.deepEqual(read(value), value);
  });

test("historical reader retains original bytes and does not create an execution handle", () => {
  const value = fixture();
  value.timestamp = "2036-08-15T08:10:03+00:00";
  value.evidence.execution.completed_at = value.timestamp;
  value.metadata.activation_ack.activation_ref_digest = `sha256:${"f".repeat(64)}`;
  const wire = restrictedCanonicalJson(value);
  const restored = readHistoricalProductReceiptWire(wire, NS);
  assert.deepEqual(restored, value);
  assert.equal(restrictedCanonicalJson(restored), wire);
  assert.equal(
    isOpenClawActivationAckHandle(restored.metadata.activation_ack),
    false,
  );
});

test("historical ACK accepts a sub-millisecond window without inventing a fake current clock", () => {
  const value = { ...ACK, expires_at: "2026-08-15T07:59:00.000000002Z" };
  assert.deepEqual(readHistoricalOpenClawActivationAck(value), value);
  assert.equal(
    Object.isFrozen(readHistoricalOpenClawActivationAck(value)),
    true,
  );
  const receipt = fixture();
  receipt.metadata.activation_ack = value;
  assert.deepEqual(read(receipt), receipt);
});

test("first persistence requires a genuine carrier; ordinary JSON and raw wire cannot recreate it", () => {
  const receipt = fixture();
  const handle = readOpenClawActivationAckHandle(ACK, IDENTITY, {
    nowMs: Date.parse("2026-08-15T07:59:00.001Z"),
  });
  const evaluation = {};
  bindEvaluationActivationAck(evaluation, handle);
  delete receipt.metadata.activation_ack;
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  assert.equal(JSON.stringify(receipt).includes(TOKEN), false);
  const wire = prepareProductReceipt(receipt, NS);
  assert.deepEqual(
    readHistoricalProductReceiptWire(wire, NS).metadata.activation_ack,
    ACK,
  );
  invalid(() => prepareProductReceipt(JSON.parse(JSON.stringify(receipt)), NS));
  invalid(() => prepareProductReceipt(JSON.parse(wire), NS));
  const noAck = fixture();
  delete noAck.metadata.activation_ack;
  invalid(() => captureProductReceiptWire(noAck));
  invalid(() => prepareProductReceipt(noAck, NS));
});

const deniedShapes = [
  ["binding_failed", "failed", ["binding_mismatch", "lease_consumed"]],
  ["timed_out", "passed", ["binding_exact", "lease_consume_timed_out"]],
  ["binding_failed", "passed", ["binding_exact", "lease_expired"]],
  ["binding_failed", "passed", ["binding_exact", "lease_response_invalid"]],
  ["binding_failed", "failed", ["multiple_binding_conflict"]],
];
function consumedFixture(shape = deniedShapes[0]) {
  const receipt = fixture("pre_execution_deny");
  receipt.links = {
    ...receipt.links,
    action_id: "act_consumed",
    approval_id: "apr_consumed",
    lease_id: "lease_consumed",
    consumption_id: "consume_consumed",
  };
  receipt.evidence.approval = {
    approval_id: "apr_consumed",
    status: "allowed",
    decision: "allow_once",
    resolved_at: "2026-08-15T07:59:30Z",
  };
  receipt.evidence.enforcement = {
    gate_state: shape[0],
    binding_check_status: shape[1],
    lease_consume_outcome: "consumed",
    reason_codes: shape[2].map((v) => `rte-05:${v}`),
  };
  return receipt;
}
for (const shape of deniedShapes)
  test(`consumed then denied permits exact frozen shape ${shape[2].join("+")}`, () => {
    const receipt = consumedFixture(shape);
    assert.deepEqual(read(receipt), receipt);
    receipt.evidence.enforcement.reason_codes.push("rte-05:identity_denied");
    invalid(() => read(receipt));
  });

test("consumed receipt preserves original consumption ACK after a later refresh", () => {
  const receipt = consumedFixture();
  const evaluation = {};
  const first = readOpenClawActivationAckHandle(ACK, IDENTITY, {
    nowMs: Date.parse("2026-08-15T07:59:01Z"),
  });
  const consumeAck = {
    ...ACK,
    issued_at: "2026-08-15T07:59:30Z",
    expires_at: "2026-08-15T08:01:30Z",
    ack_token: `hmac-sha256:${"b".repeat(64)}`,
  };
  const consumed = readOpenClawActivationAckHandle(consumeAck, IDENTITY, {
    nowMs: Date.parse(consumeAck.issued_at),
  });
  bindEvaluationActivationAck(evaluation, first);
  bindConsumptionActivationAck(evaluation, consumed);
  delete receipt.metadata.activation_ack;
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  const wire = prepareProductReceipt(receipt, NS);
  assert.deepEqual(
    readHistoricalProductReceiptWire(wire, NS).metadata.activation_ack,
    consumeAck,
  );
});

const mutations = {
  "missing ACK": (r) => {
    delete r.metadata.activation_ack;
  },
  "null ACK": (r) => {
    r.metadata.activation_ack = null;
  },
  "unexpected ACK field": (r) => {
    r.metadata.activation_ack.extra = true;
  },
  "wrong runtime": (r) => {
    r.runtime = "langgraph";
  },
  "wrong agent": (r) => {
    r.metadata.agent_id = "other";
  },
  "wrong binding": (r) => {
    r.metadata.activation_ack.runtime_binding_id = "other";
  },
  "wrong pinned version": (r) => {
    r.metadata.activation_ack.plugin_version = "0.1.0-beta.1";
  },
  "wrong digest format": (r) => {
    r.metadata.activation_ack.host_inventory_digest = "digest";
  },
  "wrong token format": (r) => {
    r.metadata.activation_ack.ack_token = "token";
  },
  "invalid timestamp": (r) => {
    r.timestamp = "2026-02-30T00:00:00Z";
  },
  "ACK issued after terminal": (r) => {
    r.metadata.activation_ack.issued_at = "2036-08-15T08:10:03Z";
    r.metadata.activation_ack.expires_at = "2036-08-15T08:11:03Z";
  },
  "ACK window too long": (r) => {
    r.metadata.activation_ack.expires_at = "2026-08-15T08:12:00Z";
  },
  "completed timestamp mismatch": (r) => {
    r.evidence.execution.completed_at = "2026-08-15T08:10:04Z";
  },
  "invoked after completed": (r) => {
    r.evidence.execution.invoked_at = "2026-08-15T08:10:04Z";
  },
  "wrong audit identity": (r) => {
    r.audit_id = "other";
  },
  "extra top field": (r) => {
    r.extra = true;
  },
  "extra nested field": (r) => {
    r.evidence.execution.extra = true;
  },
  "missing nested field": (r) => {
    delete r.evidence.execution.receipt_recorded;
  },
  "bad enum": (r) => {
    r.evidence.result.disposition = "safe";
  },
  "risk out of range": (r) => {
    r.risk_score = 101;
  },
  "wrong bounded field": (r) => {
    r.trace_id = "x".repeat(161);
  },
  "executed error": (r) => {
    r.evidence.execution.error = "bad";
  },
  "measured without count": (r) => {
    r.evidence.side_effects.measurement_status = "measured";
  },
  "unmeasured with count": (r) => {
    r.evidence.side_effects.count = 1;
  },
  "approval link mismatch": (r) => {
    r.links.approval_id = "other";
  },
  "allowed without allow_once": (r) => {
    r.evidence.approval.status = "allowed";
  },
  "kind status mismatch": (r) => {
    r.evidence.execution.status = "unknown";
  },
  "unpaired lease": (r) => {
    r.links.lease_id = "lease";
  },
  "lease without enforcement": (r) => {
    r.links.lease_id = "lease";
    r.links.consumption_id = "consumption";
  },
  "secret in summary": (r) => {
    r.summary = TOKEN;
  },
  "secret in link": (r) => {
    r.links.action_id = TOKEN;
  },
  "lease token in ACK identity": (r) => {
    r.metadata.activation_ack.runtime_binding_id = `lease-v1:${"a".repeat(64)}`;
  },
};
for (const [name, mutate] of Object.entries(mutations))
  test(`historical receipt rejects ${name} with a fixed error`, () => {
    const receipt = fixture();
    mutate(receipt);
    invalid(() => read(receipt));
  });
for (const mutate of [
  (r) => {
    delete r.links.action_id;
  },
  (r) => {
    r.evidence.enforcement.lease_consume_outcome = "not_attempted";
  },
  (r) => {
    r.evidence.approval.status = "pending";
    r.evidence.approval.decision = null;
  },
  (r) => {
    r.evidence.enforcement.reason_codes.push(
      r.evidence.enforcement.reason_codes[0],
    );
  },
])
  test("consumed receipt rejects missing authority linkage or invalid enforcement", () => {
    const receipt = consumedFixture();
    mutate(receipt);
    invalid(() => read(receipt));
  });

test("historical wire rejects duplicate keys, extra whitespace, malformed JSON and oversize", () => {
  const wire = restrictedCanonicalJson(fixture());
  for (const bad of [
    wire + "\n",
    `{\"audit_id\":\"shadow\",${wire.slice(1)}`,
    "{",
    ` ${wire}`,
    "x".repeat(512 * 1024 + 1),
  ])
    invalid(() => readHistoricalProductReceiptWire(bad, NS));
});
test("first persistence refuses accessors without running them, and hides hostile errors", () => {
  let touched = false;
  const receipt = fixture();
  Object.defineProperty(receipt, "summary", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error(TOKEN);
    },
  });
  invalid(() => prepareProductReceipt(receipt, NS));
  assert.equal(touched, false);
  invalid(() =>
    readHistoricalProductReceiptWire(
      restrictedCanonicalJson(fixture()),
      new Proxy(NS, {
        ownKeys() {
          throw new Error(TOKEN);
        },
      }),
    ),
  );
});
test("synchronous carrier capture refuses getters before any value is observed", () => {
  let reads = 0;
  const receipt = fixture();
  Object.defineProperty(receipt.evidence.execution, "status", {
    enumerable: true,
    get() {
      reads += 1;
      return "executed";
    },
  });
  invalid(() => captureProductReceiptWire(receipt));
  assert.equal(reads, 0);
});
test("namespace requires only stable identity and cannot accept current activation digest", () => {
  invalid(() =>
    read(fixture(), {
      ...NS,
      activationRefDigest: IDENTITY.activation_ref_digest,
    }),
  );
  invalid(() => read(fixture(), { ...NS, principalId: "" }));
  assert.deepEqual(
    read(fixture(), { ...NS, principalId: "principal:server-checks-issuance" }),
    fixture(),
  );
});
