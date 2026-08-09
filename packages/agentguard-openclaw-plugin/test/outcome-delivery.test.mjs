import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { RuntimeOutcomeDelivery } from "../dist/runtime/outcome-delivery.js";

const config = {
  guardApiBaseUrl: "http://guard.test",
  adapterToken: "secret-token",
  enforcementMode: "enforce",
  requestTimeoutMs: 1_000,
  approvalPollIntervalMs: 10,
  approvalTimeoutMs: 10,
  diagnosticLogging: false,
  agentId: "main",
};

function receipt(auditId = "audit_outcome_001") {
  return {
    audit_id: auditId,
    schema_version: "0.4",
    record_type: "runtime_outcome",
    trace_id: "trace_001",
    runtime: "openclaw",
    timestamp: "2026-08-09T00:00:00.000Z",
    stage: "before_tool_call",
    event_type: "runtime_outcome",
    summary: "Tool execution blocked",
    decision: "deny",
    risk_score: 0.9,
    severity: "high",
    blocked: true,
    reason: "Blocked by policy",
    links: {
      event_id: "event_001",
      policy_audit_id: "audit_policy_001",
    },
  };
}

async function withSpool(run) {
  const root = await mkdtemp(join(tmpdir(), "agentguard-outcome-spool-"));
  const spoolDirectory = join(root, "runtime-outcomes");
  try {
    await run(spoolDirectory);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function pendingFiles(spoolDirectory) {
  return (await readdir(spoolDirectory)).filter((name) =>
    name.endsWith(".json"),
  );
}

test("runtime outcome delivery persists before submitting and removes on success", async () => {
  await withSpool(async (spoolDirectory) => {
    let pendingDuringSubmit = 0;
    const client = {
      async submitRuntimeOutcome() {
        pendingDuringSubmit = (await pendingFiles(spoolDirectory)).length;
        return { ok: true, audit_id: "audit_outcome_001", created: true };
      },
    };
    const delivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config,
      makeClient: () => client,
    });

    await delivery.submit(receipt(), client, "test");

    assert.equal(pendingDuringSubmit, 1);
    assert.deepEqual(await pendingFiles(spoolDirectory), []);
  });
});

test("runtime outcome delivery retries a persisted receipt after restart", async () => {
  await withSpool(async (spoolDirectory) => {
    let now = 1_000;
    const failingClient = {
      async submitRuntimeOutcome() {
        throw new Error("network unavailable");
      },
    };
    const firstDelivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config,
      makeClient: () => failingClient,
      now: () => now,
      retryBaseMs: 100,
    });

    await firstDelivery.submit(receipt(), failingClient, "test");
    const queued = await pendingFiles(spoolDirectory);
    assert.equal(queued.length, 1);
    const envelope = JSON.parse(
      await readFile(join(spoolDirectory, queued[0]), "utf8"),
    );
    assert.equal(envelope.attempts, 1);
    assert.equal(envelope.nextAttemptAt, 1_100);

    let deliveredAuditId = null;
    const recoveredClient = {
      async submitRuntimeOutcome(event) {
        deliveredAuditId = event.audit_id;
        return { ok: true, audit_id: event.audit_id, created: true };
      },
    };
    now = 1_100;
    const recoveredDelivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config,
      makeClient: () => recoveredClient,
      now: () => now,
      retryBaseMs: 100,
    });

    await recoveredDelivery.drain();

    assert.equal(deliveredAuditId, "audit_outcome_001");
    assert.deepEqual(await pendingFiles(spoolDirectory), []);
  });
});

test("runtime outcome delivery quarantines malformed spool entries", async () => {
  await withSpool(async (spoolDirectory) => {
    await mkdir(spoolDirectory, { recursive: true });
    await writeFile(join(spoolDirectory, "broken.json"), "{not-json", "utf8");
    const client = {
      async submitRuntimeOutcome() {
        assert.fail("malformed receipts must not be submitted");
      },
    };
    const delivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config,
      makeClient: () => client,
      now: () => 2_000,
    });

    await delivery.drain();

    const files = await readdir(spoolDirectory);
    assert.deepEqual(files, ["broken.json.2000.invalid"]);
  });
});

test("runtime outcome delivery rejects non-outcome records before HTTP", async () => {
  await withSpool(async (spoolDirectory) => {
    let submitCalls = 0;
    const client = {
      async submitRuntimeOutcome() {
        submitCalls += 1;
        return { ok: true, audit_id: "wrong" };
      },
    };
    const delivery = new RuntimeOutcomeDelivery({
      spoolDirectory,
      config,
      makeClient: () => client,
    });

    await delivery.submit(
      { ...receipt(), record_type: "runtime_observation" },
      client,
      "test",
    );

    assert.equal(submitCalls, 0);
    await assert.rejects(() => readdir(spoolDirectory), { code: "ENOENT" });
  });
});
