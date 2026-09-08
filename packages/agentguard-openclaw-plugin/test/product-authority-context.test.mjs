import assert from "node:assert/strict";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import test from "node:test";

import { readOpenClawActivationAckHandle } from "../dist/runtime/activation-ack-handle.js";
import {
  bindConsumptionActivationAck,
  bindEvaluationActivationAck,
  copyProductAuthorityContext,
  evaluationActivationAck,
  hasProductReceiptCarrier,
  runtimeOutcomeToWire,
} from "../dist/runtime/product-authority-context.js";
import { receiptEvaluation } from "../dist/runtime/state.js";
import { RuntimeOutcomeDelivery } from "../dist/runtime/outcome-delivery.js";
import { buildRuntimeOutcomeAuditEvent } from "../dist/mapping/audit-outcomes.js";

const NOW = Date.parse("2026-09-01T00:00:00Z");
const TOKEN_A = `hmac-sha256:${"a".repeat(64)}`;
const TOKEN_B = `hmac-sha256:${"b".repeat(64)}`;
const IDENTITY = Object.freeze({
  runtime_version: "2026.7.1-2",
  plugin_version: "0.1.0-rc.1",
  agent_id: "main",
  runtime_binding_id: "binding:openclaw:main",
  profile_id: "agentguard-openclaw-v2-restricted",
  activation_ref_digest: `sha256:${"1".repeat(64)}`,
  capability_digest: `sha256:${"2".repeat(64)}`,
  host_inventory_digest: `sha256:${"3".repeat(64)}`,
  plugin_inventory_digest: `sha256:${"4".repeat(64)}`,
  plugin_order_inventory_digest: `sha256:${"5".repeat(64)}`,
  tool_inventory_digest: `sha256:${"6".repeat(64)}`,
});
const EVENT = {
  event_id: "event_product_carrier",
  schema_version: "0.4",
  record_type: "guard_event",
  event_type: "tool_call_proposed",
  runtime: "openclaw",
  trace_id: "trace_product_carrier",
  timestamp: new Date(NOW).toISOString(),
  pre_execution: true,
  security_context: {
    agent_id: "main",
    user_task: "fixture",
    source_type: "tool",
    source_trust: "untrusted",
    run_id: "run_product_carrier",
    current_step: "tool_call",
    context_sources: [],
    derived_paths: [],
    metadata: {},
  },
  payload: {
    tool: { name: "read", call_id: "call_product_carrier" },
    arguments: {},
    derived_resources: [],
  },
  metadata: {},
};
const CONFIG = {
  guardApiBaseUrl: "https://guard.test",
  adapterToken: "test-adapter-token",
  officialProfileId: "",
  enforcementMode: "enforce",
  requestTimeoutMs: 1_000,
  approvalPollIntervalMs: 10,
  approvalTimeoutMs: 10,
  diagnosticLogging: false,
  agentId: "main",
};

function ack(offset = 0, identity = IDENTITY, token = TOKEN_A) {
  return readOpenClawActivationAckHandle(
    {
      schema_version: "1.0",
      runtime: "openclaw",
      ...identity,
      issued_at: new Date(NOW + offset).toISOString(),
      expires_at: new Date(NOW + offset + 120_000).toISOString(),
      ack_token: token,
    },
    identity,
    { nowMs: NOW + offset },
  );
}

function evaluation(product = true) {
  return {
    decision: {
      decision_id: "decision_product_carrier",
      decision: "deny",
      risk_score: 90,
      severity: "high",
      reason: "denied by fixture",
      rule_hits: [],
    },
    approval: null,
    policy_audit_id: "policy_product_carrier",
    ...(product
      ? {
          decision_authority: {
            source: "v21",
            mode: "active",
            selection_basis: "profile_all",
            matched_path_ids: [],
            legacy_floor_applied: false,
            activation_ref_digest: IDENTITY.activation_ref_digest,
            approval_release: "not_applicable",
          },
          approval_release_directive: {
            schema_version: "2.0",
            mode: "not_applicable",
            required_runtime_profile: null,
            human_only: true,
            single_use: true,
            action_binding: "none",
            receipt_requirement: "not_applicable",
            activation_ref_digest: IDENTITY.activation_ref_digest,
            scope_digest: `sha256:${"7".repeat(64)}`,
            capability_digest: IDENTITY.capability_digest,
            residual_boundaries: [],
          },
        }
      : {}),
  };
}

function receipt(source, options = {}, event = EVENT) {
  return buildRuntimeOutcomeAuditEvent(event, source, "pre_execution_deny", {
    timestamp: new Date(NOW + 60_000).toISOString(),
    ...options,
  });
}

function deniedAfterConsumption() {
  return {
    lease: {
      leaseId: "lease_product_carrier",
      consumptionId: "consumption_product_carrier",
    },
    enforcement: {
      gate_state: "binding_failed",
      binding_check_status: "failed",
      lease_consume_outcome: "consumed",
      reason_codes: ["rte-05:binding_mismatch", "rte-05:lease_consumed"],
    },
  };
}

function code(expected) {
  return (error) => {
    assert.equal(error.code, expected);
    for (const secret of [TOKEN_A, TOKEN_B]) {
      assert.equal(String(error).includes(secret), false);
      assert.equal(
        inspect(error, { showHidden: true }).includes(secret),
        false,
      );
    }
    return true;
  };
}

test("evaluation and receipt default JSON/inspection exclude credentials; explicit wire retains original ACK", () => {
  const source = evaluation();
  const original = ack();
  bindEvaluationActivationAck(source, original);
  const result = receipt(source);
  assert.equal(evaluationActivationAck(source), original);
  assert.equal(hasProductReceiptCarrier(result), true);
  assert.equal(
    Object.hasOwn(result.metadata.activation_ack, "ack_token"),
    false,
  );
  assert.equal(Object.isFrozen(result.metadata.activation_ack), true);
  for (const value of [source, result, receiptEvaluation(source)]) {
    assert.equal(JSON.stringify(value).includes(TOKEN_A), false);
    assert.equal(
      inspect(value, { showHidden: true, depth: null }).includes(TOKEN_A),
      false,
    );
  }
  assert.deepEqual(
    runtimeOutcomeToWire(result).metadata.activation_ack,
    original.toWire(),
  );
  assert.equal(result.evidence.execution.status, "not_invoked");
});

test("receiptEvaluation preserves authority/directive and privately shares the later consume snapshot", () => {
  const source = evaluation();
  source.enforcement_binding = { authorization_fingerprint: TOKEN_A };
  bindEvaluationActivationAck(source, ack());
  const alias = receiptEvaluation(source);
  assert.deepEqual(alias.decision_authority, source.decision_authority);
  assert.deepEqual(
    alias.approval_release_directive,
    source.approval_release_directive,
  );
  assert.equal(Object.hasOwn(alias, "enforcement_binding"), false);
  bindConsumptionActivationAck(source, ack(30_000, IDENTITY, TOKEN_B));
  assert.equal(
    runtimeOutcomeToWire(receipt(alias, deniedAfterConsumption())).metadata
      .activation_ack.ack_token,
    TOKEN_B,
  );
  assert.equal(
    runtimeOutcomeToWire(receipt(alias)).metadata.activation_ack.ack_token,
    TOKEN_A,
  );
});

test("an already built receipt retains its evaluate ACK after consumption and unrelated refresh", () => {
  const source = evaluation();
  bindEvaluationActivationAck(source, ack());
  const result = receipt(source);
  bindConsumptionActivationAck(source, ack(30_000, IDENTITY, TOKEN_B));
  const other = evaluation();
  bindEvaluationActivationAck(other, ack(60_000, IDENTITY, TOKEN_B));
  assert.equal(
    runtimeOutcomeToWire(result).metadata.activation_ack.ack_token,
    TOKEN_A,
  );
});

test("historical receipt accepts expired original ACK without any current-session dependency", () => {
  const source = evaluation();
  const original = ack();
  bindEvaluationActivationAck(source, original);
  assert.throws(() => original.assertFresh(NOW + 600_000));
  const result = receipt(source, {
    timestamp: new Date(NOW + 600_000).toISOString(),
  });
  assert.equal(
    runtimeOutcomeToWire(result).metadata.activation_ack.ack_token,
    TOKEN_A,
  );
});

test("Product evaluation or lease correlation cannot silently lose its required ACK", () => {
  assert.throws(() => receipt(evaluation()), code("evaluation_ack_missing"));
  const source = evaluation();
  bindEvaluationActivationAck(source, ack());
  assert.throws(
    () => receipt(source, deniedAfterConsumption()),
    code("consumption_ack_missing"),
  );
  assert.throws(
    () => bindConsumptionActivationAck(evaluation(), ack()),
    code("evaluation_ack_missing"),
  );
});

test("untrusted structural lookalikes are not ACK handles", () => {
  for (const candidate of [
    null,
    {},
    ack().toWire(),
    { toWire: () => ack().toWire() },
    Object.create(Object.getPrototypeOf(ack())),
  ]) {
    assert.throws(
      () => bindEvaluationActivationAck(evaluation(), candidate),
      code("activation_ack_handle_invalid"),
    );
  }
});

test("evaluate and consume context cannot be rebound to a fresh ACK during an uncertain action", () => {
  const source = evaluation();
  const first = ack();
  bindEvaluationActivationAck(source, first);
  bindEvaluationActivationAck(source, first);
  assert.throws(
    () => bindEvaluationActivationAck(source, ack()),
    code("evaluation_ack_conflict"),
  );
  const consume = ack(30_000, IDENTITY, TOKEN_B);
  bindConsumptionActivationAck(source, consume);
  bindConsumptionActivationAck(source, consume);
  assert.throws(
    () => bindConsumptionActivationAck(source, ack(60_000, IDENTITY, TOKEN_B)),
    code("consumption_ack_conflict"),
  );
  const other = evaluation();
  bindEvaluationActivationAck(other, ack());
  assert.throws(
    () => copyProductAuthorityContext(source, other),
    code("evaluation_ack_conflict"),
  );
});

test("consume ACK preserves every independently trusted identity field", () => {
  for (const field of [
    "agent_id",
    "runtime_binding_id",
    "activation_ref_digest",
    "capability_digest",
    "host_inventory_digest",
    "plugin_inventory_digest",
    "plugin_order_inventory_digest",
    "tool_inventory_digest",
  ]) {
    const source = evaluation();
    bindEvaluationActivationAck(source, ack());
    const changed = {
      ...IDENTITY,
      [field]: field.endsWith("_digest")
        ? `sha256:${"f".repeat(64)}`
        : "changed",
    };
    assert.throws(
      () => bindConsumptionActivationAck(source, ack(30_000, changed, TOKEN_B)),
      code("consumption_ack_identity_mismatch"),
    );
  }
});

test("receipt ACK agent and issuance time match Core semantics including sub-millisecond precision", () => {
  const source = evaluation();
  bindEvaluationActivationAck(source, ack());
  assert.throws(
    () =>
      receipt(
        source,
        {},
        {
          ...EVENT,
          security_context: { ...EVENT.security_context, agent_id: "other" },
        },
      ),
    code("receipt_ack_identity_mismatch"),
  );
  for (const timestamp of [
    "2026-08-31T23:59:59.999999999Z",
    "2026-09-01",
    "2026-09-31T00:00:00Z",
    "bad-time",
  ]) {
    assert.throws(
      () => receipt(source, { timestamp }),
      code("receipt_ack_timestamp_invalid"),
    );
  }
  const tiny = readOpenClawActivationAckHandle(
    { ...ack().toWire(), issued_at: "2026-09-01T00:00:00.000000001Z" },
    IDENTITY,
    { nowMs: NOW + 1 },
  );
  const precise = evaluation();
  bindEvaluationActivationAck(precise, tiny);
  assert.throws(
    () => receipt(precise, { timestamp: "2026-09-01T00:00:00.000000000Z" }),
    code("receipt_ack_timestamp_invalid"),
  );
  assert.ok(receipt(precise, { timestamp: "2026-09-01T00:00:00.000000001Z" }));
});

test("JSON copies and externally supplied metadata cannot impersonate a private receipt carrier", () => {
  const source = evaluation();
  bindEvaluationActivationAck(source, ack());
  const result = receipt(source);
  for (const copy of [
    { ...result },
    JSON.parse(JSON.stringify(result)),
    runtimeOutcomeToWire(result),
  ]) {
    assert.equal(hasProductReceiptCarrier(copy), true);
    assert.throws(
      () => runtimeOutcomeToWire(copy),
      code("receipt_ack_context_missing"),
    );
  }
  for (const activation_ack of [null, undefined, {}, ack().toWire()]) {
    const candidate = receipt(evaluation(false));
    candidate.metadata.activation_ack = activation_ack;
    assert.equal(hasProductReceiptCarrier(candidate), true);
    assert.throws(
      () => runtimeOutcomeToWire(candidate),
      code("receipt_ack_context_missing"),
    );
  }
});

test("a receipt cannot reuse its evaluate carrier after acquiring different lease or policy links", () => {
  for (const changes of [
    { lease_id: "lease_other", consumption_id: "consume_other" },
    { policy_audit_id: "policy_other" },
  ]) {
    const source = evaluation();
    bindEvaluationActivationAck(source, ack());
    const result = receipt(source);
    Object.assign(result.links, changes);
    assert.throws(
      () => runtimeOutcomeToWire(result),
      code("receipt_ack_context_mismatch"),
    );
  }
  const source = evaluation();
  bindEvaluationActivationAck(source, ack());
  const result = receipt(source);
  result.metadata = { agent_id: "main", outcome_kind: "pre_execution_deny" };
  assert.equal(hasProductReceiptCarrier(result), true);
  assert.throws(
    () => runtimeOutcomeToWire(result),
    code("receipt_ack_context_mismatch"),
  );
});

test("legacy receipts remain compatible and do not gain an ACK", () => {
  const source = evaluation(false);
  const result = receipt(receiptEvaluation(source));
  assert.equal(evaluationActivationAck(source), undefined);
  assert.equal(hasProductReceiptCarrier(result), false);
  assert.deepEqual(runtimeOutcomeToWire(result), result);
  assert.equal(
    Object.hasOwn(runtimeOutcomeToWire(result).metadata, "activation_ack"),
    false,
  );
});

test("plaintext spool rejects private, stripped, and raw ACK carriers before disk writes or direct fallback", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "agentguard-product-carrier-"),
  );
  const spoolDirectory = join(directory, "never-created");
  const client = {
    async submitRuntimeOutcome() {
      assert.fail("Product receipt cannot use legacy direct send");
    },
  };
  const delivery = new RuntimeOutcomeDelivery({
    spoolDirectory,
    config: CONFIG,
    makeClient: () => client,
  });
  try {
    const source = evaluation();
    bindEvaluationActivationAck(source, ack());
    const result = receipt(source);
    for (const candidate of [
      result,
      JSON.parse(JSON.stringify(result)),
      runtimeOutcomeToWire(result),
    ]) {
      assert.throws(
        () => delivery.submit(candidate, client, "fixture"),
        code("product_delivery_unavailable"),
      );
    }
    assert.deepEqual(await readdir(directory), []);
    await writeFile(spoolDirectory, "unwritable spool target");
    assert.throws(
      () => delivery.submit(result, client, "fixture"),
      code("product_delivery_unavailable"),
    );
    assert.deepEqual(await readdir(directory), ["never-created"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("plaintext spool recovery quarantines a raw historical ACK without sending or logging it", async (t) => {
  const spoolDirectory = await mkdtemp(
    join(tmpdir(), "agentguard-product-carrier-recovery-"),
  );
  const messages = [];
  t.mock.method(console, "error", (...args) => messages.push(args));
  const client = {
    async submitRuntimeOutcome() {
      assert.fail("raw Product receipt cannot use legacy recovery");
    },
  };
  try {
    const source = evaluation();
    bindEvaluationActivationAck(source, ack());
    await mkdir(spoolDirectory, { recursive: true });
    await writeFile(
      join(spoolDirectory, "historical.json"),
      JSON.stringify({
        version: 1,
        receipt: runtimeOutcomeToWire(receipt(source)),
        createdAt: NOW,
        attempts: 0,
        nextAttemptAt: NOW,
      }),
      { mode: 0o600 },
    );
    const delivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config: CONFIG,
      makeClient: () => client,
      now: () => NOW + 600_000,
    });
    await delivery.drain();
    assert.deepEqual(await readdir(spoolDirectory), [
      `historical.json.${NOW + 600_000}.invalid`,
    ]);
    assert.equal(JSON.stringify(messages).includes(TOKEN_A), false);
    assert.ok(messages.length > 0);
  } finally {
    await rm(spoolDirectory, { recursive: true, force: true });
  }
});

test("legacy delivery freezes initial Product intent and refuses later configuration enablement", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "agentguard-product-carrier-config-"),
  );
  const client = {
    async submitRuntimeOutcome() {
      assert.fail("Product mode cannot use legacy delivery");
    },
  };
  try {
    for (const flag of [
      "officialProfileId",
      "officialProfileDigest",
      "productManifestPath",
      "restrictedAskReleaseEnabled",
    ]) {
      const config = {
        ...CONFIG,
        [flag]: flag === "restrictedAskReleaseEnabled" ? true : "configured",
      };
      const delivery = new RuntimeOutcomeDelivery({
        spoolDirectory: join(directory, flag),
        config,
        makeClient: () => client,
      });
      delete config[flag];
      assert.throws(
        () => delivery.submit(receipt(evaluation(false)), client, "fixture"),
        code("product_delivery_unavailable"),
      );
      await assert.rejects(
        delivery.drain(),
        code("product_delivery_unavailable"),
      );
    }
    const config = { ...CONFIG };
    const delivery = new RuntimeOutcomeDelivery({
      spoolDirectory: join(directory, "late"),
      config,
      makeClient: () => client,
    });
    config.officialProfileId = "configured-later";
    assert.throws(
      () => delivery.submit(receipt(evaluation(false)), client, "fixture"),
      code("product_delivery_unavailable"),
    );
    await assert.rejects(
      delivery.drain(),
      code("product_delivery_unavailable"),
    );
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
