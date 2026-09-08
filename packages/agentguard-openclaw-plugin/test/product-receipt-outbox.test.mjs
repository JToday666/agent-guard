import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import test from "node:test";

import { readOpenClawActivationAckHandle } from "../dist/runtime/activation-ack-handle.js";
import {
  attachRuntimeOutcomeActivationAck,
  bindEvaluationActivationAck,
  runtimeOutcomeToWire,
} from "../dist/runtime/product-authority-context.js";
import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { productReceiptCompatibilityResponse } from "../dist/runtime/product-delivery.js";
import {
  OpenClawProductEnvelopeStore,
  OpenClawProductEnvelopeStoreError,
} from "../dist/runtime/product-envelope-store.js";
import {
  OpenClawProductActionTicket,
  OpenClawProductReceiptOutbox,
} from "../dist/runtime/product-receipt-outbox.js";

const TOKEN = `hmac-sha256:${"a".repeat(64)}`;
const NS = Object.freeze({
  runtime: "openclaw",
  agentId: "agent_rte_fixture",
  principalId: "principal:outbox:test",
  runtimeBindingId: "binding:outbox:test",
});
const IDENTITY = Object.freeze({
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
});
function handle(token = TOKEN) {
  return readOpenClawActivationAckHandle(
    {
      schema_version: "1.0",
      runtime: "openclaw",
      ...IDENTITY,
      issued_at: "2026-08-15T07:59:00.000000001Z",
      expires_at: "2026-08-15T08:01:00.000000001Z",
      ack_token: token,
    },
    IDENTITY,
    { nowMs: Date.parse("2026-08-15T08:00:00Z") },
  );
}
function fixture(kind = "execution_completed", name = "one", ack = handle()) {
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
  receipt.links.event_id = `event_${name}`;
  receipt.links.action_id = `action_${name}`;
  receipt.links.decision_id = `decision_${name}`;
  receipt.links.policy_audit_id = `policy_${name}`;
  receipt.audit_id = `audit_outcome_event_${name}_${kind}`;
  const evaluation = {};
  bindEvaluationActivationAck(evaluation, ack);
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  return receipt;
}
function preparation(receipt, ack = handle()) {
  return {
    actionId: receipt.links.action_id,
    eventId: receipt.links.event_id,
    policyAuditId: receipt.links.policy_audit_id,
    decisionId: receipt.links.decision_id,
    ...(receipt.links.approval_id
      ? { approvalId: receipt.links.approval_id }
      : {}),
    activationAck: ack,
  };
}
function ok(wire) {
  return {
    status: "recorded",
    auditId: JSON.parse(wire).audit_id,
    httpStatus: 200,
  };
}
function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
function rejects(code) {
  return (error) => error.code === code && !inspect(error).includes(TOKEN);
}
async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), "ag-product-outbox-"));
  const opened = [];
  const clock = { value: 1_000_000 };
  t.after(async () => {
    for (const outbox of opened) await outbox.close();
    await rm(directory, { recursive: true, force: true });
  });
  const make = async (sendReceipt = async (wire) => ok(wire), options = {}) => {
    const store = await OpenClawProductEnvelopeStore.open({
      directory: join(directory, "queue"),
      keyPath: join(directory, "keys", "key"),
      namespace: NS,
      ...options,
    });
    const outbox = new OpenClawProductReceiptOutbox({
      store,
      sendReceipt,
      retryBaseMs: 10,
      retryMaxMs: 40,
      drainIntervalMs: 10,
      now: () => clock.value,
    });
    opened.push(outbox);
    return { outbox, store };
  };
  return { directory, make, clock };
}
function records(store, kind) {
  return store
    .records()
    .filter((entry) => entry.kind === kind)
    .map((entry) => JSON.parse(entry.payload));
}

test("receipt is encrypted and durable before HTTP; exact ACK creates a small counted tombstone", async (t) => {
  const { directory, make } = await setup(t);
  const sent = [];
  const { outbox, store } = await make(async (wire) => {
    sent.push(wire);
    assert.equal(records(store, "receipt")[0].terminal.wire, wire);
    return ok(wire);
  });
  const receipt = fixture();
  const result = await outbox.submit(receipt);
  assert.equal(result.status, "recorded");
  assert.equal(productReceiptCompatibilityResponse(result).ok, true);
  assert.equal(JSON.parse(sent[0]).metadata.activation_ack.ack_token, TOKEN);
  assert.equal(records(store, "receipt").length, 0);
  assert.equal(records(store, "tombstone").length, 1);
  assert.equal(
    JSON.stringify(records(store, "tombstone")).includes(TOKEN),
    false,
  );
  assert.deepEqual(outbox.status(), {
    pendingCount: 0,
    completedCount: 1,
    unknownActionCount: 0,
    breakerOpen: false,
    ...store.usage(),
  });
  assert.equal(outbox.status().recordCount, 2);
  assert.equal((await outbox.submit(receipt)).status, "recorded");
  assert.equal(sent.length, 1);
  for (const name of readdirSync(join(directory, "queue"))) {
    if (name.endsWith(".agq"))
      assert.equal(
        readFileSync(join(directory, "queue", name), "utf8").includes(TOKEN),
        false,
      );
  }
  assert.equal(inspect(outbox, { showHidden: true }).includes(TOKEN), false);
  assert.equal(JSON.stringify(outbox).includes(TOKEN), false);
});

test("retry is bounded and preserves immutable bytes; queued durable never means recorded", async (t) => {
  const { make, clock } = await setup(t);
  const sent = [];
  let unavailable = true;
  const { outbox, store } = await make(async (wire) => {
    sent.push(wire);
    return unavailable
      ? { status: "retryable", httpStatus: 503, errorCode: TOKEN }
      : ok(wire);
  });
  const receipt = fixture();
  const result = await outbox.submit(receipt);
  assert.equal(result.status, "queued_durable");
  assert.equal(productReceiptCompatibilityResponse(result).ok, false);
  assert.equal(inspect(result).includes(TOKEN), false);
  assert.deepEqual(await outbox.drain(), []);
  assert.equal((await outbox.submit(receipt)).status, "queued_durable");
  assert.equal(sent.length, 1);
  for (const delay of [10, 20, 40, 40]) {
    assert.equal(
      records(store, "receipt")[0].nextAttemptAt,
      clock.value + delay,
    );
    clock.value += delay;
    assert.equal((await outbox.drain())[0].status, "queued_durable");
  }
  unavailable = false;
  clock.value += 40;
  assert.equal((await outbox.drain())[0].status, "recorded");
  assert.equal(new Set(sent).size, 1);
});

test("restart drains original historical wire without current session or fresh ACK", async (t) => {
  const { make, clock } = await setup(t);
  const { outbox } = await make(async () => ({ status: "retryable" }));
  const receipt = fixture();
  const wire = restrictedCanonicalJson(runtimeOutcomeToWire(receipt));
  assert.equal((await outbox.submit(receipt)).status, "queued_durable");
  await outbox.close();
  const sent = [];
  const { outbox: recovered } = await make(async (value) => {
    sent.push(value);
    return ok(value);
  });
  clock.value += 100;
  assert.equal((await recovered.drain())[0].status, "recorded");
  assert.deepEqual(sent, [wire]);
  assert.equal((await recovered.submitHistoricalWire(wire)).status, "recorded");
  recovered.assertReady();
});

for (const httpStatus of [401, 409, 422])
  test(`permanent ${httpStatus} retains evidence and breaker across restart without hot retry`, async (t) => {
    const { make, clock } = await setup(t);
    let sends = 0;
    const { outbox, store } = await make(async () => {
      sends += 1;
      return { status: "permanent_rejected", httpStatus, errorCode: TOKEN };
    });
    const receipt = fixture();
    const result = await outbox.submit(receipt);
    assert.equal(result.status, "permanent_rejected");
    assert.equal(result.httpStatus, httpStatus);
    assert.equal(inspect(result).includes(TOKEN), false);
    assert.equal(records(store, "receipt").length, 1);
    assert.equal(outbox.status().breakerOpen, true);
    clock.value += 100_000;
    assert.deepEqual(await outbox.drain(), []);
    assert.equal((await outbox.submit(receipt)).status, "permanent_rejected");
    assert.equal(sends, 1);
    await outbox.close();
    const { outbox: recovered } = await make();
    assert.throws(
      () => recovered.assertReady(),
      rejects("receipt_permanently_rejected"),
    );
  });

for (const reply of [
  { status: "recorded", auditId: "wrong", httpStatus: 200 },
  { status: "recorded", httpStatus: 200 },
  {
    status: "recorded",
    auditId: "audit_outcome_event_one_execution_completed",
    httpStatus: 503,
  },
  { status: "other", errorCode: TOKEN },
])
  test(`malformed success ${JSON.stringify(reply.status)} never deletes evidence or retries`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make(async () => reply);
    const result = await outbox.submit(fixture());
    assert.equal(result.status, "failed");
    assert.equal(outbox.status().breakerOpen, true);
    assert.equal(records(store, "receipt").length, 1);
    assert.deepEqual(await outbox.drain(), []);
  });

test("conflicting same audit ID retains original and permanently blocks", async (t) => {
  const { make } = await setup(t);
  const { outbox, store } = await make(async () => ({ status: "retryable" }));
  const receipt = fixture();
  await outbox.submit(receipt);
  const original = records(store, "receipt")[0].terminal.wire;
  receipt.reason = "different terminal content";
  assert.equal(
    (await outbox.submit(receipt)).errorCode,
    "outbox_receipt_conflict",
  );
  assert.equal(records(store, "receipt")[0].terminal.wire, original);
  assert.equal(outbox.status().breakerOpen, true);
});

for (const corruption of ["clone", "missing", "namespace", "wire"])
  test(`invalid ${corruption} receipt sends zero HTTP and never creates a permit`, async (t) => {
    const { make } = await setup(t);
    let sends = 0;
    const { outbox } = await make(async (wire) => {
      sends += 1;
      return ok(wire);
    });
    let receipt = fixture();
    if (corruption === "clone") receipt = JSON.parse(JSON.stringify(receipt));
    if (corruption === "missing")
      receipt = {
        ...receipt,
        metadata: { agent_id: NS.agentId, outcome_kind: "execution_completed" },
      };
    if (corruption === "namespace") receipt.metadata.agent_id = "another";
    const result =
      corruption === "wire"
        ? await outbox.submitHistoricalWire("{" + TOKEN)
        : await outbox.submit(receipt);
    assert.equal(result.status, "failed");
    assert.equal(sends, 0);
    assert.equal(outbox.status().breakerOpen, true);
    assert.equal(inspect(result).includes(TOKEN), false);
  });

test("disk persistence failure causes zero HTTP and breaker", async (t) => {
  const { make } = await setup(t);
  let sends = 0;
  const { outbox, store } = await make(async (wire) => {
    sends += 1;
    return ok(wire);
  });
  const create = store.create;
  store.create = () => {
    throw new OpenClawProductEnvelopeStoreError("write_failed");
  };
  assert.equal((await outbox.submit(fixture())).status, "failed");
  assert.equal(sends, 0);
  store.create = create;
  assert.equal(outbox.status().breakerOpen, true);
});

test("tombstones and fixed breaker control consume the count quota", async (t) => {
  const { make } = await setup(t);
  let sends = 0;
  const { outbox, store } = await make(
    async (wire) => {
      sends += 1;
      return ok(wire);
    },
    { maxRecords: 2 },
  );
  assert.equal((await outbox.submit(fixture())).status, "recorded");
  assert.equal(
    (await outbox.submit(fixture("execution_completed", "two"))).status,
    "failed",
  );
  assert.equal(sends, 1);
  assert.equal(store.usage().recordCount, 2);
  assert.equal(outbox.status().breakerOpen, true);
});

test("prepare and release persist one action record without claiming invocation or issuing HTTP", async (t) => {
  const { make } = await setup(t);
  const phases = [];
  const { outbox, store } = await make(async (wire) => {
    phases.push(records(store, "action")[0]);
    return ok(wire);
  });
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  assert.equal(records(store, "action")[0].phase, "prepared");
  assert.equal(records(store, "action")[0].terminal, null);
  assert.equal(phases.length, 0);
  outbox.releaseAction(ticket);
  assert.equal(records(store, "action")[0].phase, "released");
  assert.equal(
    JSON.stringify(records(store, "action")).includes("invoked_at"),
    false,
  );
  assert.throws(
    () =>
      outbox.prepareAction(preparation(fixture("execution_completed", "two"))),
    rejects("action_already_active"),
  );
  assert.equal(
    (await outbox.submit(receipt)).errorCode,
    "action_journal_required",
  );
  assert.equal((await outbox.finishAction(ticket, receipt)).status, "recorded");
  assert.equal(phases[0].phase, "terminal_pending");
  assert.equal(
    phases[0].terminal.wire,
    restrictedCanonicalJson(runtimeOutcomeToWire(receipt)),
  );
  assert.equal(records(store, "action").length, 0);
  assert.equal(store.usage().recordCount, 2);
  assert.equal((await outbox.finishAction(ticket, receipt)).status, "recorded");
  assert.equal(phases.length, 1);
  assert.throws(
    () => outbox.prepareAction(preparation(receipt)),
    rejects("action_already_known"),
  );
  outbox.assertReady();
  assert.equal(inspect(ticket, { showHidden: true }).includes(TOKEN), false);
  assert.equal(inspect(ticket).includes(receipt.links.action_id), false);
});

test("known pre-release not-invoked can finish but cannot claim executed", async (t) => {
  const { make } = await setup(t);
  const { outbox } = await make();
  const denied = fixture("pre_execution_deny");
  const ticket = outbox.prepareAction(preparation(denied));
  assert.equal((await outbox.finishAction(ticket, denied)).status, "recorded");
  outbox.assertReady();
  const executed = fixture("execution_completed", "two");
  const invalid = outbox.prepareAction(preparation(executed));
  assert.equal(
    (await outbox.finishAction(invalid, executed)).errorCode,
    "action_terminal_invalid",
  );
  assert.equal(outbox.status().breakerOpen, true);
});

for (const phase of ["prepared", "released"])
  test(`restart of ${phase} preserves unknown intent and never recreates a ticket`, async (t) => {
    const { make } = await setup(t);
    const { outbox } = await make();
    const receipt = fixture();
    const ticket = outbox.prepareAction(preparation(receipt));
    if (phase === "released") outbox.releaseAction(ticket);
    await outbox.close();
    assert.equal(outbox.status().unknownActionCount, 1);
    let sends = 0;
    const { outbox: recovered, store } = await make(async (wire) => {
      sends += 1;
      return ok(wire);
    });
    assert.equal(recovered.status().unknownActionCount, 1);
    assert.equal(recovered.status().breakerOpen, true);
    assert.throws(
      () =>
        recovered.prepareAction(
          preparation(fixture("execution_completed", "two")),
        ),
      rejects("action_outcome_unknown"),
    );
    assert.equal(
      (await recovered.finishAction(ticket, receipt)).errorCode,
      "action_ticket_invalid",
    );
    assert.deepEqual(await recovered.drain(), []);
    assert.equal(records(store, "action")[0].terminal, null);
    assert.equal(sends, 0);
  });

test("explicit missing Host after outcome keeps intent and locks breaker without fabricated receipt", async (t) => {
  const { make } = await setup(t);
  const { outbox, store } = await make();
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  outbox.releaseAction(ticket);
  outbox.markActionUnknown(ticket);
  assert.equal(outbox.status().unknownActionCount, 1);
  assert.equal(outbox.status().breakerOpen, true);
  assert.equal(records(store, "action")[0].terminal, null);
  assert.deepEqual(await outbox.drain(), []);
});

test("terminal restart replays only exact terminal bytes and unblocks after confirmation", async (t) => {
  const { make, clock } = await setup(t);
  const { outbox } = await make(async () => ({ status: "retryable" }));
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  outbox.releaseAction(ticket);
  assert.equal(
    (await outbox.finishAction(ticket, receipt)).status,
    "queued_durable",
  );
  await outbox.close();
  const sent = [];
  const { outbox: recovered } = await make(async (wire) => {
    sent.push(wire);
    return ok(wire);
  });
  assert.equal(recovered.status().unknownActionCount, 0);
  clock.value += 100;
  assert.equal((await recovered.drain())[0].status, "recorded");
  assert.deepEqual(sent, [
    restrictedCanonicalJson(runtimeOutcomeToWire(receipt)),
  ]);
  recovered.assertReady();
});

for (const interrupted of ["close", "breaker", "pending"])
  test(`release rechecks ${interrupted} before returning permission`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make(async () => ({ status: "retryable" }));
    const ticket = outbox.prepareAction(preparation(fixture()));
    if (interrupted === "close") await outbox.close();
    else if (interrupted === "breaker") await outbox.submit({});
    else await outbox.submit(fixture("execution_completed", "other"));
    assert.throws(() => outbox.releaseAction(ticket));
    if (interrupted !== "close")
      assert.equal(records(store, "action")[0].phase, "prepared");
  });

for (const changed of ["ack", "policy", "action", "decision", "approval"])
  test(`terminal cannot rebind prepared ${changed}`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make();
    const original = fixture();
    const ticket = outbox.prepareAction(preparation(original));
    outbox.releaseAction(ticket);
    const receipt = fixture(
      "execution_completed",
      "one",
      changed === "ack" ? handle(`hmac-sha256:${"b".repeat(64)}`) : handle(),
    );
    if (changed !== "ack") {
      const field = {
        policy: "policy_audit_id",
        action: "action_id",
        decision: "decision_id",
        approval: "approval_id",
      }[changed];
      // Re-bind a new legitimate private carrier after changing the independent event fixture.
      const clone = JSON.parse(JSON.stringify(receipt));
      delete clone.metadata.activation_ack;
      clone.links[field] = "different";
      const evaluation = {};
      bindEvaluationActivationAck(evaluation, handle());
      attachRuntimeOutcomeActivationAck(clone, evaluation);
      assert.equal((await outbox.finishAction(ticket, clone)).status, "failed");
    } else
      assert.equal(
        (await outbox.finishAction(ticket, receipt)).status,
        "failed",
      );
    assert.equal(outbox.status().breakerOpen, true);
    assert.equal(records(store, "action")[0].terminal, null);
  });

test("forged and foreign tickets cannot release or finish", async (t) => {
  const { make } = await setup(t);
  const { outbox } = await make();
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  assert.throws(
    () => new OpenClawProductActionTicket(Symbol("fake")),
    rejects("action_ticket_invalid"),
  );
  const clone = structuredClone(ticket);
  assert.throws(
    () => outbox.releaseAction(clone),
    rejects("action_ticket_invalid"),
  );
  assert.equal(
    (await outbox.finishAction(clone, receipt)).errorCode,
    "action_ticket_invalid",
  );
});

test("close during network wait cannot mutate journal on late success", async (t) => {
  const { make } = await setup(t);
  const entered = deferred();
  const finish = deferred();
  const { outbox } = await make(async (wire) => {
    entered.resolve();
    await finish.promise;
    return ok(wire);
  });
  const pending = outbox.submit(fixture());
  await entered.promise;
  await outbox.close();
  assert.equal(outbox.status().pendingCount, 1);
  finish.resolve();
  assert.equal((await pending).errorCode, "outbox_closed");
  const { outbox: recovered } = await make();
  assert.equal(recovered.status().pendingCount, 1);
  assert.equal((await recovered.drain())[0].status, "recorded");
});

test("parallel drain and repeated submissions never send one record concurrently", async (t) => {
  const { make, clock } = await setup(t);
  const entered = deferred();
  const finish = deferred();
  let sends = 0;
  const { outbox } = await make(async (wire) => {
    sends += 1;
    entered.resolve();
    await finish.promise;
    return ok(wire);
  });
  const receipt = fixture();
  const first = outbox.submit(receipt);
  await entered.promise;
  const a = outbox.drain();
  const b = outbox.drain();
  assert.equal(a, b);
  assert.equal((await outbox.submit(receipt)).status, "queued_durable");
  assert.equal((await a)[0].status, "queued_durable");
  clock.value += 100;
  assert.equal(sends, 1);
  finish.resolve();
  assert.equal((await first).status, "recorded");
});

test("terminal persistence failure sends no HTTP and leaves unknown journal on restart", async (t) => {
  const { make } = await setup(t);
  let sends = 0;
  const { outbox, store } = await make(async (wire) => {
    sends += 1;
    return ok(wire);
  });
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  outbox.releaseAction(ticket);
  const replace = store.replace;
  store.replace = () => {
    throw new OpenClawProductEnvelopeStoreError("write_failed");
  };
  assert.equal((await outbox.finishAction(ticket, receipt)).status, "failed");
  assert.equal(sends, 0);
  store.replace = replace;
  await outbox.close();
  const { outbox: recovered } = await make();
  assert.equal(recovered.status().unknownActionCount, 1);
  assert.equal(recovered.status().breakerOpen, true);
});

test("background worker retries durable receipt and close releases ownership", async (t) => {
  const { make, clock } = await setup(t);
  const retried = deferred();
  let sends = 0;
  const { outbox } = await make(async (wire) => {
    sends += 1;
    if (sends === 1) return { status: "retryable" };
    retried.resolve();
    return ok(wire);
  });
  await outbox.submit(fixture());
  clock.value += 100;
  outbox.start();
  const timeout = setTimeout(() => retried.resolve("timeout"), 2000);
  assert.notEqual(await retried.promise, "timeout");
  clearTimeout(timeout);
  await outbox.close();
  const { outbox: recovered } = await make();
  const pending = recovered.status().pendingCount;
  assert.equal((await recovered.drain()).length, pending);
});

for (const kind of [
  "approval_release",
  "tool_result_modified",
  "tool_result_quarantined",
]) {
  test(`auxiliary ${kind} cannot serve as action terminal or remove its journal`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make();
    const auxiliary = fixture(kind);
    const ticket = outbox.prepareAction(preparation(auxiliary));
    outbox.releaseAction(ticket);
    const result = await outbox.finishAction(ticket, auxiliary);
    assert.equal(result.status, "failed");
    assert.equal(records(store, "action")[0].terminal, null);
    assert.equal(outbox.status().breakerOpen, true);
  });

  test(`auxiliary ${kind} is separately durable and pending evidence blocks release`, async (t) => {
    const { make, clock } = await setup(t);
    let retry = true;
    const { outbox, store } = await make(async (wire) =>
      retry ? { status: "retryable" } : ok(wire),
    );
    const auxiliary = fixture(kind);
    const ticket = outbox.prepareAction(preparation(auxiliary));
    assert.equal((await outbox.submit(auxiliary)).status, "queued_durable");
    assert.equal(records(store, "action")[0].terminal, null);
    assert.equal(records(store, "receipt").length, 1);
    assert.equal(outbox.status().recordCount, 3);
    assert.throws(
      () => outbox.releaseAction(ticket),
      rejects("outbox_pending_receipts"),
    );
    retry = false;
    clock.value += 100;
    assert.equal((await outbox.drain())[0].status, "recorded");
    assert.equal(records(store, "action")[0].phase, "prepared");
    outbox.releaseAction(ticket);
    assert.equal(records(store, "action")[0].phase, "released");
    assert.throws(() => outbox.assertReady(), rejects("action_already_active"));
  });
}

test("late real after on the same process records terminal while unknown breaker stays sticky", async (t) => {
  const { make } = await setup(t);
  const { outbox, store } = await make();
  const receipt = fixture();
  const ticket = outbox.prepareAction(preparation(receipt));
  outbox.releaseAction(ticket);
  outbox.markActionUnknown(ticket);
  assert.equal(outbox.status().unknownActionCount, 1);
  assert.equal((await outbox.finishAction(ticket, receipt)).status, "recorded");
  assert.equal(records(store, "action").length, 0);
  assert.equal(outbox.status().unknownActionCount, 0);
  assert.equal(outbox.status().breakerOpen, true);
  assert.throws(() => outbox.assertReady(), rejects("action_outcome_unknown"));
});

for (const status of ["failed", "permanent_rejected"])
  test(`durable ${status} phase restores breaker even when control write failed`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make(async () => ({
      status,
      httpStatus: 422,
    }));
    const replace = store.replace;
    store.replace = function (id, ...args) {
      if (id === "barrier_control")
        throw new OpenClawProductEnvelopeStoreError("write_failed");
      return replace.call(this, id, ...args);
    };
    assert.equal((await outbox.submit(fixture())).status, status);
    assert.equal(records(store, "breaker")[0].tripped, false);
    store.replace = replace;
    await outbox.close();
    const { outbox: recovered, store: restored } = await make();
    assert.equal(recovered.status().breakerOpen, true);
    assert.equal(recovered.status().pendingCount, 1);
    assert.equal(records(restored, "receipt")[0].phase, status);
    assert.deepEqual(await recovered.drain(), []);
  });

for (const field of ["status", "httpStatus", "auditId", "errorCode"])
  test(`transport ${field} accessor never executes or reaches status`, async (t) => {
    const { make } = await setup(t);
    let reads = 0;
    const reply = {
      status: "recorded",
      auditId: "audit_outcome_event_one_execution_completed",
      httpStatus: 200,
    };
    Object.defineProperty(reply, field, {
      enumerable: true,
      get() {
        reads += 1;
        return reads === 1 ? "failed" : TOKEN;
      },
    });
    const { outbox, store } = await make(async () => reply);
    const result = await outbox.submit(fixture());
    assert.equal(result.status, "failed");
    assert.equal(result.errorCode, "receipt_transport_invalid");
    assert.equal(reads, 0);
    assert.equal(outbox.status().breakerOpen, true);
    assert.equal(records(store, "receipt")[0].phase, "failed");
    assert.equal(inspect(result).includes(TOKEN), false);
  });

for (const operation of ["releaseAction", "markActionUnknown"])
  test(`${operation} never rethrows contaminated same-type error`, async (t) => {
    const { OpenClawProductActivationError } =
      await import("../dist/runtime/product-manifest.js");
    const { make } = await setup(t);
    const { outbox, store } = await make();
    const ticket = outbox.prepareAction(preparation(fixture()));
    const original = store.records;
    const error = new OpenClawProductActivationError("outbox_storage_failed");
    error.message = TOKEN;
    error.cause = new Error(TOKEN);
    store.records = () => {
      throw error;
    };
    assert.throws(
      () => outbox[operation](ticket),
      (failure) => {
        assert.notEqual(failure, error);
        assert.equal(failure.code, "outbox_storage_failed");
        assert.equal(
          inspect(failure, { showHidden: true }).includes(TOKEN),
          false,
        );
        return true;
      },
    );
    store.records = original;
  });

test("transport proxy traps are rejected without inspecting untrusted properties", async (t) => {
  const { make } = await setup(t);
  let traps = 0;
  const proxy = new Proxy(
    {},
    {
      get(_target, key) {
        if (key === "then") return undefined;
        traps += 1;
        return TOKEN;
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      ownKeys() {
        traps += 1;
        return ["status"];
      },
    },
  );
  const { outbox } = await make(async () => proxy);
  const result = await outbox.submit(fixture());
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "receipt_transport_invalid");
  assert.equal(traps, 0);
});

for (const kind of [
  "execution_completed",
  "execution_failed",
  "pre_execution_deny",
])
  test(`standalone ${kind} tombstone rejects another preparation of the same action`, async (t) => {
    const { make } = await setup(t);
    const { outbox, store } = await make();
    const receipt = fixture(kind);
    assert.equal((await outbox.submit(receipt)).status, "recorded");
    assert.equal(
      records(store, "tombstone")[0].actionId,
      receipt.links.action_id,
    );
    assert.equal(records(store, "tombstone")[0].actionTerminal, true);
    assert.throws(
      () => outbox.prepareAction(preparation(receipt)),
      rejects("action_already_known"),
    );
    outbox.assertReady();
    await outbox.close();
    const { outbox: recovered } = await make();
    assert.throws(
      () => recovered.prepareAction(preparation(receipt)),
      rejects("action_already_known"),
    );
  });

test("auxiliary tombstone cannot be confused with a completed action", async (t) => {
  const { make } = await setup(t);
  const { outbox, store } = await make();
  const receipt = fixture("tool_result_quarantined");
  assert.equal((await outbox.submit(receipt)).status, "recorded");
  assert.equal(records(store, "tombstone")[0].actionTerminal, false);
  const ticket = outbox.prepareAction(preparation(receipt));
  outbox.releaseAction(ticket);
  assert.equal(records(store, "action")[0].phase, "released");
});
