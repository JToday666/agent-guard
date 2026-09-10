import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  stat,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import test from "node:test";
import { OpenClawProductEnvelopeStore } from "../packages/agentguard-openclaw-plugin/dist/runtime/product-envelope-store.js";
import { OpenClawProductReceiptOutbox } from "../packages/agentguard-openclaw-plugin/dist/runtime/product-receipt-outbox.js";
import {
  OpenClawProductTransport,
  productTransportBindingDigest,
} from "../packages/agentguard-openclaw-plugin/dist/runtime/product-transport.js";
import { prepareProductReceipt } from "../packages/agentguard-openclaw-plugin/dist/runtime/product-receipt-wire.js";
import {
  NS,
  TOKEN,
  fixture,
} from "../packages/agentguard-openclaw-plugin/test/support/product-reconciliation-fixture.mjs";

const source = fileURLToPath(
  new URL("../packages/agentguard-openclaw-plugin", import.meta.url),
);
const cli = fileURLToPath(
  new URL("product-runtime-reconcile-openclaw.mjs", import.meta.url),
);
const AUTH = "private-recovery-cli-test";
function run(args, env = {}) {
  return new Promise((resolve) =>
    execFile(
      process.execPath,
      [cli, ...args],
      { env: { ...process.env, ...env }, timeout: 10000 },
      (error, stdout, stderr) =>
        resolve({ code: error?.code ?? 0, stdout, stderr }),
    ),
  );
}
async function setup(t) {
  const root = await mkdtemp(path.join(tmpdir(), "ag-cli-reconcile-"));
  const requests = [];
  let injected = 409;
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const wire = Buffer.concat(chunks).toString("utf8");
    requests.push({
      url: request.url,
      wire,
      authorization: request.headers.authorization,
    });
    response.writeHead(injected, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify(
        injected === 200
          ? { ok: true, audit_id: JSON.parse(wire).audit_id }
          : { ok: false },
      ),
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const config = {
    guardApiBaseUrl: base,
    agentId: NS.agentId,
    principalId: NS.principalId,
    runtimeBindingId: NS.runtimeBindingId,
    productReceiptDirectory: path.join(root, "queue"),
    productReceiptKeyPath: path.join(root, "keys/receipt.key"),
    adapterTokenEnv: "AGENTGUARD_RECEIPT_CLI_TEST_TOKEN",
  };
  const configPath = path.join(root, "recovery.json");
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const store = await OpenClawProductEnvelopeStore.open({
    directory: config.productReceiptDirectory,
    keyPath: config.productReceiptKeyPath,
    namespace: NS,
  });
  const transport = new OpenClawProductTransport({
    ...config,
    adapterToken: AUTH,
    requestTimeoutMs: 1000,
  });
  const outbox = new OpenClawProductReceiptOutbox({
    store,
    transportBindingDigest: productTransportBindingDigest(base, NS),
    sendReceipt: (wire) => transport.send(wire),
    transportIdle: () => transport.whenIdle(),
    transportBusy: () => transport.busy,
  });
  const receipt = fixture();
  const wire = prepareProductReceipt(receipt, NS);
  assert.equal((await outbox.submit(receipt)).status, "permanent_rejected");
  await outbox.close();
  const digest = createHash("sha256").update(wire).digest("hex");
  const args = (report = path.join(root, "report.json")) => [
    "--package-root",
    source,
    "--config",
    configPath,
    "--audit-id",
    receipt.audit_id,
    "--expected-wire-digest",
    digest,
    "--report",
    report,
  ];
  return {
    root,
    config,
    configPath,
    requests,
    wire,
    args,
    inject: (status) => {
      injected = status;
    },
  };
}

test("CLI retries one original receipt across PID using only audit HTTP and atomic private report", async (t) => {
  const f = await setup(t);
  f.inject(200);
  const result = await run(f.args(), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(result.code, 0, result.stderr + result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.selected_confirmed, true);
  assert.equal(report.scope, "single_receipt");
  assert.equal(report.complete, undefined);
  assert.equal(report.snapshot.breakerOpen, true);
  assert.equal(report.snapshot.pendingCount, 0);
  assert.equal(report.close.ownerHeld, false);
  assert.deepEqual(
    f.requests.map((r) => r.url),
    ["/v1/audit/events", "/v1/audit/events"],
  );
  assert.deepEqual(
    f.requests.map((r) => r.wire),
    [f.wire, f.wire],
  );
  assert.equal(f.requests[1].authorization, `Bearer ${AUTH}`);
  assert.equal(
    (await stat(path.join(f.root, "report.json"))).mode & 0o777,
    0o600,
  );
  assert.deepEqual(
    JSON.parse(await readFile(path.join(f.root, "report.json"), "utf8")),
    report,
  );
  for (const secret of [TOKEN, AUTH])
    assert.equal((result.stdout + result.stderr).includes(secret), false);
  const repeat = await run(f.args(path.join(f.root, "repeat.json")), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(repeat.code, 0);
  assert.equal(f.requests.length, 2);
});

test("CLI reports permanent retry failure and rejects a substituted endpoint before any HTTP", async (t) => {
  const f = await setup(t);
  f.inject(422);
  const rejected = await run(f.args(), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(rejected.code, 1);
  assert.equal(
    JSON.parse(rejected.stdout).delivery.status,
    "permanent_rejected",
  );
  await writeFile(
    f.configPath,
    JSON.stringify({
      ...f.config,
      guardApiBaseUrl: `${f.config.guardApiBaseUrl}/different`,
    }),
    { mode: 0o600 },
  );
  const drift = await run(f.args(path.join(f.root, "drift.json")), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(drift.code, 1);
  assert.equal(f.requests.length, 2);
});

test("CLI refuses symlinked credential configuration and missing credentials without revealing configuration", async (t) => {
  const f = await setup(t);
  const absent = await run(f.args());
  assert.equal(absent.code, 2);
  const real = path.join(f.root, "real.json");
  await writeFile(real, JSON.stringify(f.config), { mode: 0o600 });
  await rm(f.configPath);
  await symlink(real, f.configPath);
  const bad = await run(f.args(path.join(f.root, "symlink.json")), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(bad.code, 2);
  assert.equal(f.requests.length, 1);
  assert.equal(bad.stdout.includes(AUTH), false);
});

test("CLI rejects duplicate decoded configuration keys and classifies retryable HTTP as incomplete", async (t) => {
  const f = await setup(t);
  await writeFile(
    f.configPath,
    JSON.stringify(f.config).replace(
      "{",
      '{"guardApiBaseUrl":"http://127.0.0.1:1",',
    ),
    { mode: 0o600 },
  );
  const duplicate = await run(f.args(), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(duplicate.code, 2);
  assert.equal(f.requests.length, 1);
  await writeFile(f.configPath, JSON.stringify(f.config), { mode: 0o600 });
  f.inject(503);
  const retry = await run(f.args(path.join(f.root, "retry.json")), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(retry.code, 2);
  assert.equal(JSON.parse(retry.stdout).selected_confirmed, false);
  assert.equal(f.requests.length, 2);
});

test("CLI preserves an existing report byte-for-byte instead of replacing evidence", async (t) => {
  const f = await setup(t);
  f.inject(200);
  const report = path.join(f.root, "report.json");
  const original = Buffer.from("prior independent evidence\n");
  await writeFile(report, original, { mode: 0o600 });
  const result = await run(f.args(), {
    AGENTGUARD_RECEIPT_CLI_TEST_TOKEN: AUTH,
  });
  assert.equal(result.code, 2);
  assert.equal(
    JSON.parse(result.stdout).error_code,
    "receipt_reconciliation_report_failed",
  );
  assert.deepEqual(await readFile(report), original);
});
