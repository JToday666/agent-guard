import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { inspect } from "node:util";
import {
  OpenClawProductEnvelopeStore,
  OpenClawProductEnvelopeStoreError,
} from "../dist/runtime/product-envelope-store.js";
import { OpenClawProductReceiptOutbox } from "../dist/runtime/product-receipt-outbox.js";
import {
  productTransportBindingDigest,
  OpenClawProductTransport,
} from "../dist/runtime/product-transport.js";
import { prepareProductReceipt } from "../dist/runtime/product-receipt-wire.js";
import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { openOpenClawProductReceiptRecovery } from "../product-runtime/receipt-recovery.mjs";
import {
  buildProductContentCheckpoint,
  ProductContentCheckpoint,
} from "../dist/mapping/product-content-receipts.js";
import { bindEvaluationActivationAck } from "../dist/runtime/product-authority-context.js";
import {
  NS,
  TOKEN,
  fixture,
  preparation,
  ok,
  deferred,
  handle,
} from "./support/product-reconciliation-fixture.mjs";

const URL = "http://127.0.0.1:48111";
const BINDING = productTransportBindingDigest(URL, NS);
const reject = async () => ({ status: "permanent_rejected", httpStatus: 409 });
const rawDigest = (wire) => createHash("sha256").update(wire).digest("hex");
const selected = (receipt) => ({
  auditId: receipt.audit_id,
  expectedWireDigest: rawDigest(prepareProductReceipt(receipt, NS)),
});

async function rig(t) {
  const root = await mkdtemp(join(tmpdir(), "ag-reconcile-"));
  const opened = [];
  const config = {
    guardApiBaseUrl: URL,
    adapterToken: "private-test-adapter",
    ...NS,
    productReceiptDirectory: join(root, "queue"),
    productReceiptKeyPath: join(root, "keys", "receipt.key"),
  };
  delete config.runtime;
  const make = async (
    sendReceipt = reject,
    options = {},
    storeOptions = {},
  ) => {
    const store = await OpenClawProductEnvelopeStore.open({
      directory: config.productReceiptDirectory,
      keyPath: config.productReceiptKeyPath,
      namespace: NS,
      ...storeOptions,
    });
    opened.push(store);
    const outbox = new OpenClawProductReceiptOutbox({
      store,
      sendReceipt,
      transportBindingDigest: BINDING,
      retryBaseMs: 1,
      ...options,
    });
    opened.push(outbox);
    return { outbox, store };
  };
  t.after(async () => {
    for (const item of opened.reverse()) await item.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, config, make };
}
function entries(store) {
  return store
    .records()
    .map((entry) => ({ entry, data: JSON.parse(entry.payload) }));
}
function replace(store, found, data) {
  return store.replace(found.entry.recordId, restrictedCanonicalJson(data), {
    kind: found.entry.kind,
    expectedRevision: found.entry.revision,
  });
}

test("existing owner anchor with no control cannot be silently adopted as a new bound queue", async (t) => {
  const f = await rig(t);
  const store = await OpenClawProductEnvelopeStore.open({
    directory: f.config.productReceiptDirectory,
    keyPath: f.config.productReceiptKeyPath,
    namespace: NS,
  });
  assert.equal(store.freshForProducer, true);
  await store.close();
  await assert.rejects(
    f.make(),
    (error) => error.code === "receipt_transport_binding_missing",
  );
});

test("binding hashes the complete common canonical projection with raw lowercase SHA256", () => {
  const object = {
    schema_version: "agentguard-product-receipt-transport/1",
    api_mode: "guard-api-v0.3",
    base_url: URL,
    namespace: {
      runtime: NS.runtime,
      agent_id: NS.agentId,
      principal_id: NS.principalId,
      runtime_binding_id: NS.runtimeBindingId,
    },
  };
  assert.equal(BINDING, rawDigest(restrictedCanonicalJson(object)));
  assert.equal(
    BINDING,
    "d30dffcc5481cd5c44c66fb592d89fe6ed685abf838e65bacaee7c937bb6a9fa",
  );
  assert.match(BINDING, /^[a-f0-9]{64}$/u);
  assert.equal(productTransportBindingDigest(`${URL}///`, NS), BINDING);
  for (const key of ["agentId", "principalId", "runtimeBindingId"])
    assert.notEqual(
      productTransportBindingDigest(URL, { ...NS, [key]: `${NS[key]}-other` }),
      BINDING,
    );
  assert.notEqual(productTransportBindingDigest(`${URL}/other`, NS), BINDING);
});

for (const role of [
  "context_assembled",
  "model_output_produced",
  "tool_result_produced",
])
  test(`bound ${role} checkpoint preserves role and cannot become action authority`, async (t) => {
    const f = await rig(t);
    const ack = handle();
    const event = {
      event_id: `unit_${role}`,
      event_type: role,
      trace_id: "trace_checkpoint",
      security_context: { agent_id: NS.agentId },
      payload: { tool: { call_id: "call_prior" } },
    };
    const policy = {
      decision: {
        decision: "allow",
        decision_id: `decision_${role}`,
        risk_score: 0,
        severity: "low",
      },
      approval: null,
      policy_audit_id: `policy_${role}`,
      decision_authority: {
        source: "v21",
        mode: "active",
        selection_basis: "profile_all",
        activation_ref_digest: ack.identity.activation_ref_digest,
        legacy_floor_applied: false,
      },
      approval_release_directive: { mode: "not_applicable" },
    };
    bindEvaluationActivationAck(policy, ack);
    const checkpoint = buildProductContentCheckpoint(event, policy, true);
    const { wire } = ProductContentCheckpoint.read(checkpoint, NS);
    const first = await f.make();
    assert.equal(
      (await first.outbox.submitCheckpoint(checkpoint)).status,
      "permanent_rejected",
    );
    await first.outbox.close();
    const second = await f.make(ok, { receiptsOnly: true });
    const selection = {
      auditId: JSON.parse(wire).audit_id,
      expectedWireDigest: rawDigest(wire),
    };
    assert.equal(
      (await second.outbox.reconcileRejectedReceipt(selection)).status,
      "recorded",
    );
    const tombstone = entries(second.store).find(
      ({ data }) => data.type === "tombstone",
    ).data;
    assert.equal(tombstone.checkpointRole, role);
    assert.equal(tombstone.actionTerminal, false);
    assert.equal(tombstone.transportBindingDigest, BINDING);
    await second.outbox.close();
    const third = await f.make();
    assert.equal(third.outbox.status().breakerOpen, true);
  });

test("unknown released action remains unknown and cannot be completed by recovery", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  const first = await f.make();
  const ticket = first.outbox.prepareAction(preparation(receipt));
  first.outbox.releaseAction(ticket);
  await first.outbox.close();
  let sends = 0;
  const second = await f.make(
    async (wire) => {
      sends++;
      return ok(wire);
    },
    { receiptsOnly: true },
  );
  assert.equal(second.outbox.status().unknownActionCount, 1);
  assert.equal(
    (await second.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "failed",
  );
  assert.equal(
    (await second.outbox.finishAction(ticket, receipt)).status,
    "failed",
  );
  assert.deepEqual(await second.outbox.drain(), []);
  assert.equal(sends, 0);
  assert.equal(
    entries(second.store).find(({ data }) => data.type === "action").data
      .terminal,
    null,
  );
});

test("ambiguous audit ID across action and receipt records sends nothing on reconciliation", async (t) => {
  const f = await rig(t);
  let sends = 0;
  const first = await f.make(async () => {
    sends++;
    return reject();
  });
  const receipt = fixture();
  const ticket = first.outbox.prepareAction(preparation(receipt));
  first.outbox.releaseAction(ticket);
  await first.outbox.finishAction(ticket, receipt);
  const other = fixture("execution_completed", "one", handle(), (value) => {
    value.links.action_id = "different_action";
  });
  await first.outbox.submit(other);
  assert.equal(sends, 2);
  await first.outbox.close();
  const recovered = await f.make(
    async () => {
      sends++;
      return reject();
    },
    { receiptsOnly: true },
  );
  assert.equal(
    (await recovered.outbox.reconcileRejectedReceipt(selected(receipt)))
      .errorCode,
    "receipt_reconciliation_invalid",
  );
  assert.equal(sends, 2);
});

test("reconciliation metadata exceeding the original envelope capacity is never sent", async (t) => {
  const f = await rig(t);
  const first = await f.make();
  const receipt = fixture();
  await first.outbox.submit(receipt);
  const size = entries(first.store).find(({ data }) => data.type === "receipt")
    .entry.storedBytes;
  await first.outbox.close();
  let sends = 0;
  const second = await f.make(
    async (wire) => {
      sends++;
      return ok(wire);
    },
    { receiptsOnly: true },
    { maxRecordBytes: size + 8 },
  );
  assert.equal(
    (await second.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "failed",
  );
  assert.equal(sends, 0);
  assert.equal(second.outbox.status().pendingCount, 1);
});

for (const kind of ["action", "receipt"])
  for (const httpStatus of [409, 422])
    test(`${kind} rejection ${httpStatus} survives restart, exact explicit replay and sticky completed restart`, async (t) => {
      const f = await rig(t);
      const receipt = fixture();
      const wire = prepareProductReceipt(receipt, NS);
      const first = await f.make(async () => ({
        status: "permanent_rejected",
        httpStatus,
      }));
      if (kind === "action") {
        const ticket = first.outbox.prepareAction(preparation(receipt));
        first.outbox.releaseAction(ticket);
        assert.equal(
          (await first.outbox.finishAction(ticket, receipt)).status,
          "permanent_rejected",
        );
      } else
        assert.equal(
          (await first.outbox.submit(receipt)).status,
          "permanent_rejected",
        );
      for (const { data } of entries(first.store))
        assert.equal(data.transportBindingDigest, BINDING);
      await first.outbox.close();
      const sent = [];
      const recovered = await f.make(
        async (body) => {
          sent.push(body);
          return ok(body);
        },
        { receiptsOnly: true },
      );
      assert.deepEqual(await recovered.outbox.drain(), []);
      assert.equal(
        (await recovered.outbox.reconcileRejectedReceipt(selected(receipt)))
          .status,
        "recorded",
      );
      assert.deepEqual(sent, [wire]);
      const snapshot = recovered.outbox.reconciliationStatus();
      assert.equal(snapshot.reconciliations[0].originalHttpStatus, httpStatus);
      assert.equal(snapshot.reconciliations[0].attempts[0].status, "recorded");
      assert.equal(snapshot.pendingCount, 0);
      assert.equal(snapshot.breakerOpen, true);
      assert.equal(
        (await recovered.outbox.reconcileRejectedReceipt(selected(receipt)))
          .status,
        "recorded",
      );
      assert.equal(sent.length, 1);
      assert.equal(inspect(snapshot).includes(TOKEN), false);
      await recovered.outbox.close();
      const again = await f.make();
      assert.equal(again.outbox.status().breakerOpen, true);
      assert.throws(() =>
        again.outbox.prepareAction(
          preparation(fixture("execution_completed", "next")),
        ),
      );
    });

for (const empty of [true, false])
  test(`legacy ${empty ? "empty control" : "pending"} is never retrospectively bound`, async (t) => {
    const f = await rig(t);
    const first = await f.make(async () => ({ status: "retryable" }), {
      transportBindingDigest: undefined,
    });
    if (!empty) await first.outbox.submit(fixture());
    await first.outbox.close();
    const legacy = await f.make(async (body) => ok(body));
    assert.equal(legacy.outbox.reconciliationStatus().transportBound, false);
    if (!empty) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      assert.equal((await legacy.outbox.drain())[0].status, "recorded");
    }
    assert.equal(
      (await legacy.outbox.reconcileRejectedReceipt(selected(fixture())))
        .errorCode,
      "receipt_reconciliation_worker_required",
    );
    await legacy.outbox.close();
    await assert.rejects(
      openOpenClawProductReceiptRecovery(f.config),
      /recovery_unavailable/u,
    );
  });

test("recovery requires existing original endpoint and exposes no producer functions", async (t) => {
  const f = await rig(t);
  await assert.rejects(openOpenClawProductReceiptRecovery(f.config));
  const first = await f.make();
  await first.outbox.submit(fixture());
  assert.equal(
    (await first.outbox.reconcileRejectedReceipt(selected(fixture())))
      .errorCode,
    "receipt_reconciliation_worker_required",
  );
  assert.equal(first.outbox.reconciliationStatus().reconciliations.length, 0);
  await first.outbox.close();
  await assert.rejects(
    openOpenClawProductReceiptRecovery({
      ...f.config,
      guardApiBaseUrl: `${URL}/different`,
    }),
  );
  const recovery = await openOpenClawProductReceiptRecovery(f.config);
  try {
    assert.deepEqual(Object.keys(recovery).sort(), [
      "close",
      "closeWithin",
      "drain",
      "reconcileRejectedReceipt",
      "status",
    ]);
    assert.equal(recovery.status().receiptsOnly, true);
    assert.equal(recovery.status().transportBound, true);
  } finally {
    await recovery.close();
  }
  const direct = await f.make(ok, { receiptsOnly: true });
  for (const invoke of [
    () => direct.outbox.start(),
    () => direct.outbox.assertReady(),
    () => direct.outbox.prepareAction(preparation(fixture())),
    () => direct.outbox.releaseAction({}),
    () => direct.outbox.markActionUnknown({}),
    () => direct.outbox.tripActionBarrier(),
  ])
    assert.throws(invoke);
  for (const result of [
    await direct.outbox.submit(fixture()),
    await direct.outbox.submitHistoricalWire(
      prepareProductReceipt(fixture(), NS),
    ),
    await direct.outbox.finishAction({}, fixture()),
  ])
    assert.equal(result.status, "failed");
});

for (const httpStatus of [null, 200, 408, 429, 503]) {
  test(`bound producer rejects invalid permanent HTTP ${httpStatus} without creating reconciliation authority`, async (t) => {
    const f = await rig(t);
    const receipt = fixture();
    const producer = await f.make(async () => ({
      status: "permanent_rejected",
      httpStatus,
    }));
    assert.deepEqual(await producer.outbox.submit(receipt), {
      status: "failed",
      auditId: receipt.audit_id,
      ...(httpStatus === null ? {} : { httpStatus }),
      errorCode: "receipt_transport_invalid",
    });
    await producer.outbox.close();
    const recovered = await f.make(
      async () => assert.fail("invalid original rejection was resent"),
      { receiptsOnly: true },
    );
    assert.equal(
      (await recovered.outbox.reconcileRejectedReceipt(selected(receipt)))
        .errorCode,
      "receipt_reconciliation_not_eligible",
    );
    assert.deepEqual(await recovered.outbox.drain(), []);
    const row = entries(recovered.store).find(
      ({ data }) => data.type === "receipt",
    ).data;
    assert.equal(row.phase, "failed");
    assert.equal(row.reconciliation, null);
  });

  test(`manual invalid permanent HTTP ${httpStatus} is durably failed and ineligible after reopen`, async (t) => {
    const f = await rig(t);
    const receipt = fixture();
    const producer = await f.make();
    await producer.outbox.submit(receipt);
    await producer.outbox.close();
    let sends = 0;
    const recovery = await f.make(
      async () => {
        sends++;
        return { status: "permanent_rejected", httpStatus };
      },
      { receiptsOnly: true },
    );
    const failed = await recovery.outbox.reconcileRejectedReceipt(
      selected(receipt),
    );
    assert.equal(failed.status, "failed");
    assert.equal(failed.errorCode, "receipt_transport_invalid");
    const attempt = entries(recovery.store)
      .find(({ data }) => data.type === "receipt")
      .data.reconciliation.attempts.at(-1);
    assert.equal(attempt.status, "failed");
    assert.equal(attempt.httpStatus, httpStatus);
    assert.equal(attempt.errorCode, "receipt_transport_invalid");
    await recovery.outbox.close();
    const reopened = await f.make(
      async () => assert.fail("invalid manual transport was resent"),
      { receiptsOnly: true },
    );
    assert.equal(
      (await reopened.outbox.reconcileRejectedReceipt(selected(receipt)))
        .errorCode,
      "receipt_reconciliation_not_eligible",
    );
    assert.deepEqual(await reopened.outbox.drain(), []);
    assert.equal(sends, 1);
  });
}

for (const receiptsOnly of [false, true])
  test(`${receiptsOnly ? "manual recovery" : "bound producer"} cannot confirm a receipt without actual HTTP status`, async (t) => {
    const f = await rig(t);
    const receipt = fixture();
    if (receiptsOnly) {
      const producer = await f.make();
      await producer.outbox.submit(receipt);
      await producer.outbox.close();
    }
    const delivery = await f.make(
      async () => ({ status: "recorded", auditId: receipt.audit_id }),
      { receiptsOnly },
    );
    const result = receiptsOnly
      ? await delivery.outbox.reconcileRejectedReceipt(selected(receipt))
      : await delivery.outbox.submit(receipt);
    assert.equal(result.status, "failed");
    assert.equal(result.errorCode, "receipt_acknowledgement_invalid");
    assert.equal(delivery.outbox.status().completedCount, 0);
    await delivery.outbox.close();
    const reopened = await f.make(
      async () => assert.fail("unproven HTTP confirmation was resent"),
      { receiptsOnly: true },
    );
    assert.equal(
      (await reopened.outbox.reconcileRejectedReceipt(selected(receipt)))
        .errorCode,
      "receipt_reconciliation_not_eligible",
    );
  });

test("failed acknowledgement during reconciliation becomes permanently ineligible across reopen", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  const producer = await f.make();
  await producer.outbox.submit(receipt);
  await producer.outbox.close();
  let sends = 0;
  const recovery = await f.make(
    async () => {
      sends++;
      return { status: "recorded", auditId: "wrong", httpStatus: 200 };
    },
    { receiptsOnly: true },
  );
  assert.equal(
    (await recovery.outbox.reconcileRejectedReceipt(selected(receipt)))
      .errorCode,
    "receipt_acknowledgement_invalid",
  );
  assert.equal(
    (await recovery.outbox.reconcileRejectedReceipt(selected(receipt)))
      .errorCode,
    "receipt_reconciliation_not_eligible",
  );
  assert.equal(sends, 1);
  await recovery.outbox.close();
  const reopened = await f.make(
    async (wire) => {
      sends++;
      return ok(wire);
    },
    { receiptsOnly: true },
  );
  assert.equal(
    (await reopened.outbox.reconcileRejectedReceipt(selected(receipt)))
      .errorCode,
    "receipt_reconciliation_not_eligible",
  );
  assert.equal(sends, 1);
  assert.deepEqual(await reopened.outbox.drain(), []);
});

for (const changed of ["control", "peer receipt"])
  test(`inflight ${changed} binding drift cannot produce a confirmed tombstone`, async (t) => {
    const f = await rig(t);
    const receipt = fixture();
    const producer = await f.make();
    await producer.outbox.submit(receipt);
    await producer.outbox.submit(fixture("execution_completed", "peer"));
    await producer.outbox.close();
    let recovery;
    recovery = await f.make(
      async (wire) => {
        const found = entries(recovery.store).find(({ data }) =>
          changed === "control"
            ? data.type === "breaker"
            : data.type === "receipt" && data.terminal.auditId.includes("peer"),
        );
        replace(recovery.store, found, {
          ...found.data,
          transportBindingDigest: "9".repeat(64),
        });
        return ok(wire);
      },
      { receiptsOnly: true },
    );
    assert.equal(
      (await recovery.outbox.reconcileRejectedReceipt(selected(receipt)))
        .status,
      "failed",
    );
    assert.equal(
      entries(recovery.store).some(({ data }) => data.type === "tombstone"),
      false,
    );
    assert.equal(recovery.outbox.status().breakerOpen, true);
  });

for (const change of [
  "control",
  "record",
  "strip-record-binding",
  "legacy-record",
])
  test(`bound journal rejects ${change} mismatch before HTTP`, async (t) => {
    const f = await rig(t);
    let calls = 0;
    const first = await f.make();
    await first.outbox.submit(fixture());
    const found = entries(first.store).find(({ data }) =>
      change === "control" ? data.type === "breaker" : data.type === "receipt",
    );
    const data = { ...found.data };
    if (change === "strip-record-binding") delete data.transportBindingDigest;
    else if (change === "legacy-record") {
      data.version = 1;
      delete data.transportBindingDigest;
      delete data.checkpointRole;
      delete data.reconciliation;
    } else data.transportBindingDigest = "e".repeat(64);
    replace(first.store, found, data);
    await first.outbox.close();
    await assert.rejects(
      f.make(async (wire) => {
        calls++;
        return ok(wire);
      }),
    );
    assert.equal(calls, 0);
  });

test("failed, unknown and wrong selectors cannot create or replace a terminal", async (t) => {
  const f = await rig(t);
  let calls = 0;
  let first = await f.make(async () => {
    calls++;
    return { status: "failed" };
  });
  const receipt = fixture();
  await first.outbox.submit(receipt);
  await first.outbox.close();
  first = await f.make(
    async () => {
      calls++;
      return { status: "failed" };
    },
    { receiptsOnly: true },
  );
  calls = 0;
  const selection = selected(receipt);
  for (const value of [
    {
      ...selection,
      expectedWireDigest: `sha256:${selection.expectedWireDigest}`,
    },
    { ...selection, expectedWireDigest: "A".repeat(64) },
    { ...selection, auditId: "missing" },
    { ...selection, expectedWireDigest: "0".repeat(64) },
    { ...selection, extra: true },
    {
      get auditId() {
        throw new Error("must not run");
      },
      expectedWireDigest: selection.expectedWireDigest,
    },
    new Proxy(selection, {
      ownKeys() {
        throw new Error("must not run");
      },
    }),
    selection,
  ])
    assert.equal(
      (await first.outbox.reconcileRejectedReceipt(value)).status,
      "failed",
    );
  assert.equal(calls, 0);
  await first.outbox.close();
});

test("manual retryable outcomes remain blocked, capped at 32 persisted attempts", async (t) => {
  const f = await rig(t);
  let calls = 0;
  const send = async () => {
    calls++;
    return calls === 1
      ? { status: "permanent_rejected", httpStatus: 422 }
      : { status: "retryable" };
  };
  let first = await f.make(send);
  const receipt = fixture();
  await first.outbox.submit(receipt);
  await first.outbox.close();
  first = await f.make(send, { receiptsOnly: true });
  for (let n = 0; n < 32; n++) {
    const delivery = await first.outbox.reconcileRejectedReceipt(
      selected(receipt),
    );
    assert.equal(delivery.status, "queued_durable");
    assert.equal(delivery.manualRetryRequired, true);
  }
  assert.equal(
    (await first.outbox.reconcileRejectedReceipt(selected(receipt))).errorCode,
    "receipt_reconciliation_limit",
  );
  assert.deepEqual(await first.outbox.drain(), []);
  assert.equal(calls, 33);
  const record = entries(first.store).find(
    ({ data }) => data.type === "receipt",
  ).data;
  assert.equal(record.phase, "permanent_rejected");
  assert.equal(record.httpStatus, 422);
  assert.equal(record.reconciliation.attempts.length, 32);
});

test("attempt write failure sends nothing; confirmation failure preserves same wire with unknown attempt", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  let sends = 0;
  let first = await f.make();
  await first.outbox.submit(receipt);
  await first.outbox.close();
  first = await f.make(
    async (wire) => {
      sends++;
      return ok(wire);
    },
    { receiptsOnly: true },
  );
  const originalReplace = first.store.replace.bind(first.store);
  first.store.replace = (id, payload, options) => {
    if (options.kind === "receipt")
      throw new OpenClawProductEnvelopeStoreError("write_failed");
    return originalReplace(id, payload, options);
  };
  assert.equal(
    (await first.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "failed",
  );
  assert.equal(first.outbox.reconciliationStatus().reconciliations.length, 0);
  first.store.replace = originalReplace;
  await first.outbox.close();
  const second = await f.make(
    async (wire) => {
      sends++;
      return ok(wire);
    },
    { receiptsOnly: true },
  );
  const replaceSecond = second.store.replace.bind(second.store);
  second.store.replace = (id, payload, options) => {
    if (options.kind === "tombstone")
      throw new OpenClawProductEnvelopeStoreError("write_failed");
    return replaceSecond(id, payload, options);
  };
  assert.equal(
    (await second.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "failed",
  );
  assert.equal(sends, 1);
  assert.equal(
    second.outbox.reconciliationStatus().reconciliations[0].attempts[0].status,
    "inflight",
  );
  await second.outbox.close();
  const third = await f.make(
    async (wire) => {
      sends++;
      assert.equal(wire, prepareProductReceipt(receipt, NS));
      return ok(wire);
    },
    { receiptsOnly: true },
  );
  assert.equal(
    (await third.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "recorded",
  );
  assert.deepEqual(
    third.outbox
      .reconciliationStatus()
      .reconciliations[0].attempts.map((a) => a.status),
    ["unknown", "recorded"],
  );
  assert.equal(sends, 2);
});

test("completed tombstone is sticky even when every breaker-control CAS failed", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  let allow = false;
  const originalReplace = OpenClawProductEnvelopeStore.prototype.replace;
  OpenClawProductEnvelopeStore.prototype.replace = function (
    id,
    payload,
    options,
  ) {
    if (options.kind === "breaker")
      throw new OpenClawProductEnvelopeStoreError("write_failed");
    return originalReplace.call(this, id, payload, options);
  };
  t.after(() => {
    OpenClawProductEnvelopeStore.prototype.replace = originalReplace;
  });
  let first = await f.make();
  await first.outbox.submit(receipt);
  await first.outbox.close();
  first = await f.make(ok, { receiptsOnly: true });
  assert.equal(
    (await first.outbox.reconcileRejectedReceipt(selected(receipt))).status,
    "recorded",
  );
  assert.equal(
    entries(first.store).find(({ data }) => data.type === "breaker").data
      .tripped,
    false,
  );
  await first.outbox.close();
  OpenClawProductEnvelopeStore.prototype.replace = originalReplace;
  const second = await f.make();
  assert.equal(second.outbox.status().breakerOpen, true);
  assert.throws(() => second.outbox.assertReady());
  await second.outbox.close();
  const third = await f.make();
  assert.equal(third.outbox.status().breakerOpen, true);
});

test("same selection is single-flight and close keeps owner through pending HTTP and local confirmation", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  const entered = deferred();
  const finish = deferred();
  let release = false;
  let sends = 0;
  const send = async (wire) => {
    if (!release) return reject();
    sends++;
    entered.resolve();
    await finish.promise;
    return ok(wire);
  };
  let first = await f.make(send);
  await first.outbox.submit(receipt);
  await first.outbox.close();
  release = true;
  first = await f.make(send, { receiptsOnly: true });
  const a = first.outbox.reconcileRejectedReceipt(selected(receipt));
  const b = first.outbox.reconcileRejectedReceipt(selected(receipt));
  assert.equal(a, b);
  await entered.promise;
  assert.equal(
    (
      await first.outbox.reconcileRejectedReceipt({
        ...selected(receipt),
        auditId: "other",
      })
    ).errorCode,
    "receipt_reconciliation_busy",
  );
  assert.deepEqual(await first.outbox.drain(), []);
  assert.deepEqual(await first.outbox.closeWithin(5), {
    status: "pending",
    ownerHeld: true,
  });
  await assert.rejects(f.make(), (error) => error.code === "store_locked");
  finish.resolve();
  assert.equal((await a).status, "recorded");
  await first.outbox.close();
  assert.equal(sends, 1);
  const second = await f.make();
  assert.equal(second.outbox.status().completedCount, 1);
});

test("deadline does not release owner while actual fetch ignores abort", async (t) => {
  const f = await rig(t);
  const receipt = fixture();
  const entered = deferred();
  const finish = deferred();
  const transport = new OpenClawProductTransport(
    {
      guardApiBaseUrl: URL,
      adapterToken: "test",
      agentId: NS.agentId,
      runtimeBindingId: NS.runtimeBindingId,
      requestTimeoutMs: 5,
    },
    async () => {
      entered.resolve();
      await finish.promise;
      return new Response("{}", { status: 200 });
    },
  );
  const first = await f.make((wire) => transport.send(wire), {
    transportIdle: () => transport.whenIdle(),
    transportBusy: () => transport.busy,
  });
  const sending = first.outbox.submit(receipt);
  await entered.promise;
  assert.equal((await sending).status, "queued_durable");
  assert.deepEqual(await first.outbox.closeWithin(5), {
    status: "pending",
    ownerHeld: true,
  });
  await assert.rejects(f.make(), (error) => error.code === "store_locked");
  finish.resolve();
  await first.outbox.close();
  const second = await f.make(ok);
  assert.equal(second.outbox.status().pendingCount, 1);
});
