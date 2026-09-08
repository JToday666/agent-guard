import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import test from "node:test";

import {
  OpenClawProductEnvelopeStore as Store,
  OpenClawProductEnvelopeStoreError as StoreError,
  PRODUCT_MAX_RECORDS,
  PRODUCT_MAX_RECORD_BYTES,
  PRODUCT_MAX_TOTAL_BYTES,
} from "../dist/runtime/product-envelope-store.js";

const namespace = Object.freeze({
  runtime: "openclaw",
  agentId: "agent-private",
  principalId: "principal-private",
  runtimeBindingId: "binding-private",
});
const SECRET = "historical-ack-token-do-not-log";
const wire = JSON.stringify({
  audit_id: "audit-1",
  metadata: {
    activation_ack: { ack_token: SECRET, issued_at: "2000-01-01T00:00:00Z" },
  },
});
const moduleUrl = new URL(
  "../dist/runtime/product-envelope-store.js",
  import.meta.url,
).href;
const anchorName = ".owner-namespace.json";
const canonical = (value) => JSON.stringify(value, Object.keys(value).sort());
const filename = (id) =>
  createHash("sha256").update(id, "ascii").digest("hex") + ".agq";
const code = (expected) => (error) =>
  error instanceof StoreError &&
  error.code === expected &&
  !String(error.stack).includes(SECRET);

async function fixture(t, changes = {}) {
  const root = fs.mkdtempSync(join(tmpdir(), "agentguard-product-store-"));
  fs.chmodSync(root, 0o700);
  const options = {
    directory: join(root, "queue"),
    keyPath: join(root, "secret", "key"),
    namespace,
    ...changes,
  };
  const stores = [];
  t.after(async () => {
    for (const store of stores) await store.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  const open = async (extra = {}) => {
    const store = await Store.open({ ...options, ...extra });
    stores.push(store);
    return store;
  };
  return {
    root,
    options,
    open,
    recordPath: (id) => join(options.directory, filename(id)),
  };
}

function rewrite(path, mutate) {
  const value = JSON.parse(fs.readFileSync(path, "utf8"));
  mutate(value);
  fs.writeFileSync(path, canonical(value), { mode: 0o600 });
}

function patchFs(name, implementation, run) {
  const original = fs[name];
  fs[name] = implementation;
  syncBuiltinESMExports();
  try {
    return run(original);
  } finally {
    fs[name] = original;
    syncBuiltinESMExports();
  }
}

test("AES-256-GCM encrypts exact UTF-8 payload and keeps projections private", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const payload = wire + "\n中文💾";
  const entry = store.create("receipt_private-id", payload, {
    kind: "receipt",
  });
  assert.equal(entry.payload, payload);
  assert.equal(entry.revision, 1);
  assert.deepEqual(store.namespace, namespace);
  assert.throws(() => {
    store.namespace.agentId = "changed";
  }, TypeError);
  assert.throws(() => {
    entry.payload = "changed";
  }, TypeError);
  for (const rendered of [
    JSON.stringify(entry),
    inspect(entry),
    JSON.stringify(store),
    inspect(store),
    JSON.stringify(store.records()),
  ]) {
    assert.equal(rendered.includes(SECRET), false);
    assert.equal(rendered.includes("receipt_private-id"), false);
  }
  const bytes = fs.readFileSync(f.recordPath("receipt_private-id"));
  assert.equal(bytes.includes(SECRET), false);
  assert.equal(bytes.includes("中文"), false);
  const envelope = JSON.parse(bytes);
  assert.equal(envelope.algorithm, "AES-256-GCM");
  assert.equal(Buffer.from(envelope.nonce, "base64").length, 12);
  assert.equal(fs.readFileSync(f.options.keyPath).length, 32);
  assert.equal(entry.storedBytes, bytes.length);
  assert.deepEqual(store.usage(), {
    recordCount: 1,
    storedBytes: bytes.length,
  });
  assert.equal(store.get("missing"), undefined);
  for (const directory of [f.options.directory, join(f.root, "secret")])
    assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  for (const path of [
    f.recordPath("receipt_private-id"),
    f.options.keyPath,
    join(f.options.directory, anchorName),
  ])
    assert.equal(fs.statSync(path).mode & 0o777, 0o600);
});

test("same namespace process restart restores old ACK and immutable payload", async (t) => {
  const f = await fixture(t);
  const first = await f.open();
  first.create("receipt_old", wire, { kind: "receipt" });
  const originalBytes = fs.readFileSync(f.recordPath("receipt_old"));
  await first.close();
  const second = await f.open();
  assert.equal(second.get("receipt_old").payload, wire);
  assert.equal(second.get("receipt_old").revision, 1);
  assert.deepEqual(fs.readFileSync(f.recordPath("receipt_old")), originalBytes);
});

test("create is idempotent and replacement uses strict CAS with fresh nonce", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("action_1", wire);
  const before = fs.readFileSync(f.recordPath("action_1"));
  assert.equal(store.create("action_1", wire).revision, 1);
  assert.deepEqual(fs.readFileSync(f.recordPath("action_1")), before);
  assert.throws(
    () => store.create("action_1", "other"),
    code("record_conflict"),
  );
  assert.throws(
    () => store.create("action_1", wire, { kind: "receipt" }),
    code("record_conflict"),
  );
  assert.throws(
    () => store.replace("missing", "x", { expectedRevision: 1 }),
    code("record_missing"),
  );
  assert.throws(
    () => store.replace("action_1", "x", { expectedRevision: 2 }),
    code("record_conflict"),
  );
  assert.equal(
    store.replace("action_1", wire, { expectedRevision: 1 }).revision,
    1,
  );
  const complete = store.replace("action_1", "completed-hash", {
    expectedRevision: 1,
    kind: "tombstone",
  });
  assert.equal(complete.kind, "tombstone");
  assert.equal(complete.revision, 2);
  assert.notEqual(
    JSON.parse(before).nonce,
    JSON.parse(fs.readFileSync(f.recordPath("action_1"))).nonce,
  );
  assert.throws(
    () => store.replace("action_1", wire, { expectedRevision: 1 }),
    code("record_conflict"),
  );
});

test("all record kinds including tombstones and breaker count toward quota", async (t) => {
  const f = await fixture(t, { maxRecords: 4 });
  const store = await f.open();
  for (const kind of ["action", "receipt", "tombstone", "breaker"])
    store.create(kind, "x", { kind });
  assert.equal(store.usage().recordCount, 4);
  assert.throws(() => store.create("fifth", "x"), code("capacity_exceeded"));
  store.replace("breaker", "tripped", { expectedRevision: 1 });
  assert.equal(store.get("breaker").payload, "tripped");
});

test("single-record cap applies to encoded envelope, not only plaintext", async (t) => {
  const f = await fixture(t, { maxRecordBytes: 512, maxTotalBytes: 2048 });
  const store = await f.open();
  store.create("small", "ok");
  assert.throws(
    () => store.create("large", "x".repeat(256)),
    code("capacity_exceeded"),
  );
  assert.equal(store.usage().recordCount, 1);
});

test("large authenticated records round-trip within the actual 512 KiB cap", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const payload = "x".repeat(300 * 1024);
  const record = store.create("large", payload);
  assert.ok(record.storedBytes < PRODUCT_MAX_RECORD_BYTES);
  assert.equal(store.get("large").payload, payload);
  assert.throws(
    () => store.create("over", "x".repeat(PRODUCT_MAX_RECORD_BYTES)),
    code("capacity_exceeded"),
  );
});

test("total cap reserves a full encrypted record for atomic replacement", async (t) => {
  const f = await fixture(t, { maxRecordBytes: 512, maxTotalBytes: 1200 });
  const store = await f.open();
  store.create("one", "ok");
  store.create("two", "ok");
  assert.throws(() => store.create("three", "ok"), code("capacity_exceeded"));
  const total = store.usage().storedBytes;
  const original = fs.renameSync;
  patchFs(
    "renameSync",
    (source, target) => {
      const actualBytes = fs
        .readdirSync(f.options.directory)
        .filter((n) => n.endsWith(".agq") || n.startsWith(".tmp-"))
        .reduce(
          (sum, n) => sum + fs.statSync(join(f.options.directory, n)).size,
          0,
        );
      assert.ok(actualBytes <= 1200);
      assert.ok(actualBytes > total);
      original(source, target);
    },
    () => store.replace("one", "next", { expectedRevision: 1 }),
  );
});

test("capacity constants retain the frozen upper limits", () => {
  assert.equal(PRODUCT_MAX_RECORDS, 10_000);
  assert.equal(PRODUCT_MAX_RECORD_BYTES, 512 * 1024);
  assert.equal(PRODUCT_MAX_TOTAL_BYTES, 64 * 1024 * 1024);
});

test("same-process lock contention rejects second owner without disturbing first", async (t) => {
  const f = await fixture(t);
  const owner = await f.open();
  await assert.rejects(f.open(), code("store_locked"));
  owner.create("still_owned", wire);
  await owner.close();
  const next = await f.open();
  assert.equal(next.get("still_owned").payload, wire);
});

test("unexpected owner socket close immediately disables all further store operations", async (t) => {
  const f = await fixture(t);
  const original = net.createServer;
  let server;
  net.createServer = (...args) => {
    server = original(...args);
    return server;
  };
  syncBuiltinESMExports();
  let store;
  try {
    store = await f.open();
  } finally {
    net.createServer = original;
    syncBuiltinESMExports();
  }
  store.create("receipt", wire);
  const closing = new Promise((resolve) => server.close(resolve));
  assert.throws(() => store.create("late", wire), code("store_locked"));
  assert.throws(() => store.records(), code("store_locked"));
  await closing;
  assert.equal(fs.existsSync(f.recordPath("late")), false);
});

test("a local socket connection receives no data and cannot hold the store open", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const meta = fs.statSync(f.options.directory, { bigint: true });
  const address =
    "\0agentguard-product-" +
    createHash("sha256")
      .update(`agentguard.product-envelope.v1:${meta.dev}:${meta.ino}`)
      .digest("hex");
  const socket = net.createConnection({ path: address });
  const data = [];
  socket.on("data", (chunk) => data.push(chunk));
  await once(socket, "close");
  assert.equal(Buffer.concat(data).length, 0);
  await store.close();
  await f.open();
});

test("cross-process lock is exclusive and SIGKILL releases it for receipt-only recovery", async (t) => {
  const f = await fixture(t);
  const source = `import { OpenClawProductEnvelopeStore as Store } from ${JSON.stringify(moduleUrl)};
    const s = await Store.open(JSON.parse(process.argv[1]));
    s.create("receipt_crash", ${JSON.stringify(wire)}, {kind:"receipt"});
    process.stdout.write("ready\\n"); setInterval(()=>{},1000);`;
  const child = spawn(
    process.execPath,
    ["--input-type=module", "-e", source, JSON.stringify(f.options)],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  t.after(() => {
    if (child.exitCode === null) child.kill("SIGKILL");
  });
  let errors = "";
  child.stderr.on("data", (value) => {
    errors += value;
  });
  await Promise.race([
    once(child.stdout, "data"),
    once(child, "exit").then(() => {
      throw new Error("child failed: " + errors);
    }),
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("child timeout")), 8000);
      timer.unref();
    }),
  ]);
  await assert.rejects(f.open(), code("store_locked"));
  const exited = once(child, "exit");
  child.kill("SIGKILL");
  await exited;
  const recovered = await f.open();
  assert.equal(recovered.get("receipt_crash").payload, wire);
  assert.equal(recovered.get("receipt_crash").revision, 1);
});

for (const field of ["boot_id", "netns_ino", "directory_ino"]) {
  test(`owner anchor ${field} drift blocks reopening without rewriting it`, async (t) => {
    const f = await fixture(t);
    const store = await f.open();
    store.create("receipt", wire);
    await store.close();
    const path = join(f.options.directory, anchorName);
    rewrite(path, (value) => {
      value[field] =
        field === "boot_id" ? "00000000-0000-0000-0000-000000000000" : "0";
    });
    const changed = fs.readFileSync(path);
    await assert.rejects(f.open(), code("owner_namespace_mismatch"));
    assert.deepEqual(fs.readFileSync(path), changed);
  });
}

test("existing receipts never recreate a missing owner anchor", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("receipt", wire);
  await store.close();
  fs.unlinkSync(join(f.options.directory, anchorName));
  await assert.rejects(f.open(), code("owner_anchor_missing"));
  assert.equal(fs.existsSync(join(f.options.directory, anchorName)), false);
});

test("partially initialized anchor is retained and never repaired", async (t) => {
  const f = await fixture(t);
  fs.mkdirSync(f.options.directory, { mode: 0o700 });
  fs.writeFileSync(join(f.options.directory, anchorName), "", { mode: 0o600 });
  await assert.rejects(f.open(), code("owner_namespace_mismatch"));
  assert.equal(
    fs.readFileSync(join(f.options.directory, anchorName), "utf8"),
    "",
  );
});

test("live anchor replacement and namespace edits fail before record writes", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const path = join(f.options.directory, anchorName);
  const original = fs.readFileSync(path);
  fs.renameSync(path, join(f.root, "old-anchor"));
  fs.writeFileSync(path, original, { mode: 0o600 });
  assert.throws(
    () => store.create("blocked", wire),
    code("owner_anchor_invalid"),
  );
  assert.equal(fs.existsSync(f.recordPath("blocked")), false);
});

for (const field of ["agentId", "principalId", "runtimeBindingId"]) {
  test(`AAD namespace ${field} mismatch rejects historical ciphertext`, async (t) => {
    const f = await fixture(t);
    const store = await f.open();
    store.create("receipt", wire);
    await store.close();
    await assert.rejects(
      f.open({ namespace: { ...namespace, [field]: "different" } }),
      code("namespace_mismatch"),
    );
  });
}

for (const field of ["kind", "revision", "nonce", "ciphertext"]) {
  test(`authenticated ${field} tampering fails without exposing ACK`, async (t) => {
    const f = await fixture(t);
    const store = await f.open();
    store.create("receipt", wire, { kind: "receipt" });
    rewrite(f.recordPath("receipt"), (value) => {
      if (field === "kind") value.kind = "action";
      else if (field === "revision") value.revision = 2;
      else {
        const bytes = Buffer.from(value[field], "base64");
        bytes[0] ^= 1;
        value[field] = bytes.toString("base64");
      }
    });
    assert.throws(() => store.get("receipt"), code("decryption_failed"));
  });
}

test("record-id substitution with a matching filename still fails AAD authentication", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("original", wire);
  const value = JSON.parse(fs.readFileSync(f.recordPath("original"), "utf8"));
  value.record_id = "replacement";
  fs.unlinkSync(f.recordPath("original"));
  fs.writeFileSync(f.recordPath("replacement"), canonical(value), {
    mode: 0o600,
  });
  assert.throws(() => store.records(), code("decryption_failed"));
});

test("missing or changed key is never replaced when receipts exist", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("receipt", wire);
  const original = fs.readFileSync(f.options.keyPath);
  fs.writeFileSync(f.options.keyPath, Buffer.alloc(32), { mode: 0o600 });
  assert.throws(() => store.records(), code("key_invalid"));
  fs.writeFileSync(f.options.keyPath, original);
  await store.close();
  fs.unlinkSync(f.options.keyPath);
  await assert.rejects(f.open(), code("key_missing"));
  assert.equal(fs.existsSync(f.options.keyPath), false);
});

test("same-owner process detects disappeared records and rollback", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("receipt", wire);
  const first = fs.readFileSync(f.recordPath("receipt"));
  store.replace("receipt", "terminal", { expectedRevision: 1 });
  fs.writeFileSync(f.recordPath("receipt"), first);
  assert.throws(() => store.records(), code("record_conflict"));
  fs.unlinkSync(f.recordPath("receipt"));
  assert.throws(() => store.records(), code("record_missing"));
});

for (const malformed of [
  "not-json",
  "[".repeat(10_000) + "0" + "]".repeat(10_000),
  "{}",
  '{"format":1,"format":2}',
]) {
  test(`damaged envelope returns fixed record_invalid (${malformed.slice(0, 12)})`, async (t) => {
    const f = await fixture(t);
    const store = await f.open();
    store.create("receipt", wire);
    fs.writeFileSync(f.recordPath("receipt"), malformed);
    assert.throws(() => store.records(), code("record_invalid"));
  });
}

test("unknown files and orphan temporary records are retained and block reopening", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  await store.close();
  const temporary = join(f.options.directory, ".tmp-crashed");
  fs.writeFileSync(temporary, "partial", { mode: 0o600 });
  await assert.rejects(f.open(), code("orphan_temporary"));
  assert.equal(fs.readFileSync(temporary, "utf8"), "partial");
  fs.renameSync(temporary, join(f.options.directory, "unknown"));
  await assert.rejects(f.open(), code("record_invalid"));
});

for (const target of ["directory", "key", "record", "anchor"]) {
  test(`unsafe ${target} permissions fail closed`, async (t) => {
    const f = await fixture(t);
    const store = await f.open();
    store.create("receipt", wire);
    const path =
      target === "directory"
        ? f.options.directory
        : target === "key"
          ? f.options.keyPath
          : target === "anchor"
            ? join(f.options.directory, anchorName)
            : f.recordPath("receipt");
    fs.chmodSync(path, target === "directory" ? 0o755 : 0o644);
    assert.throws(() => store.records(), code("permission_denied"));
  });
}

test("hardlinks and symbolic record links are rejected before reading", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("receipt", wire);
  fs.linkSync(f.recordPath("receipt"), join(f.root, "outside"));
  assert.throws(() => store.records(), code("permission_denied"));
  fs.unlinkSync(f.recordPath("receipt"));
  fs.symlinkSync(join(f.root, "outside"), f.recordPath("receipt"));
  assert.throws(() => store.records(), code("read_failed"));
});

test("directory symlinks and in-queue keys cannot be used", async (t) => {
  const f = await fixture(t);
  fs.mkdirSync(join(f.root, "real"), { mode: 0o700 });
  fs.symlinkSync(join(f.root, "real"), f.options.directory);
  await assert.rejects(f.open(), code("read_failed"));
  await assert.rejects(
    f.open({ keyPath: join(f.options.directory, "key") }),
    code("invalid_configuration"),
  );
});

test("FIFO records do not block because reads use O_NONBLOCK", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const result = spawnSync("mkfifo", ["-m", "600", f.recordPath("fifo")], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.throws(() => store.records(), code("permission_denied"));
});

test("file write failure keeps prior record and exposes only fixed error", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("action", "old");
  const before = fs.readFileSync(f.recordPath("action"));
  patchFs(
    "writeSync",
    () => {
      throw new Error(SECRET);
    },
    () => {
      assert.throws(
        () => store.replace("action", wire, { expectedRevision: 1 }),
        code("write_failed"),
      );
    },
  );
  assert.deepEqual(fs.readFileSync(f.recordPath("action")), before);
  assert.equal(store.get("action").payload, "old");
  assert.equal(
    fs.readdirSync(f.options.directory).some((n) => n.startsWith(".tmp-")),
    false,
  );
});

test("short writes are completed before atomic replacement", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const original = fs.writeSync;
  let calls = 0;
  patchFs(
    "writeSync",
    (fd, bytes, offset, length, position) => {
      calls++;
      return original(fd, bytes, offset, Math.min(length, 13), position);
    },
    () => store.create("receipt", wire),
  );
  assert.ok(calls > 1);
  assert.equal(store.get("receipt").payload, wire);
});

test("rename failure preserves committed bytes and cleans only its temporary", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("action", "old");
  const before = fs.readFileSync(f.recordPath("action"));
  patchFs(
    "renameSync",
    () => {
      throw new Error(SECRET);
    },
    () => {
      assert.throws(
        () => store.replace("action", wire, { expectedRevision: 1 }),
        code("write_failed"),
      );
    },
  );
  assert.deepEqual(fs.readFileSync(f.recordPath("action")), before);
  assert.equal(store.get("action").revision, 1);
});

test("directory fsync failure reports failure and retains possibly committed new version", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("action", "old");
  const original = fs.fsyncSync;
  patchFs(
    "fsyncSync",
    (fd) => {
      if (fs.fstatSync(fd).isDirectory()) throw new Error(SECRET);
      return original(fd);
    },
    () => {
      assert.throws(
        () => store.replace("action", wire, { expectedRevision: 1 }),
        code("write_failed"),
      );
    },
  );
  assert.equal(store.get("action").revision, 2);
  assert.equal(store.get("action").payload, wire);
  await store.close();
  assert.equal((await f.open()).get("action").payload, wire);
});

test("read failure neither returns stale cached data nor leaks underlying error", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  store.create("receipt", wire);
  patchFs(
    "readSync",
    () => {
      throw new Error(SECRET);
    },
    () => {
      assert.throws(() => store.get("receipt"), code("read_failed"));
    },
  );
});

test("close immediately prohibits operations and remains idempotent", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  const closing = store.close();
  assert.throws(() => store.create("late", wire), code("store_closed"));
  assert.throws(() => store.get("late"), code("store_closed"));
  assert.throws(() => store.usage(), code("store_closed"));
  await closing;
  await store.close();
  await f.open();
});

for (const changes of [
  { maxRecords: 0 },
  { maxRecords: null },
  { maxRecords: 10_001 },
  { maxRecordBytes: 512 * 1024 + 1 },
  { maxTotalBytes: 64 * 1024 * 1024 + 1 },
  { maxRecords: 1.5 },
  { maxRecordBytes: 1000, maxTotalBytes: 1000 },
  { directory: "relative" },
  { namespace: { ...namespace, runtime: "langgraph" } },
  { namespace: { ...namespace, agentId: "" } },
]) {
  test(`invalid store configuration fails closed (${JSON.stringify(changes)})`, async (t) => {
    const f = await fixture(t);
    await assert.rejects(f.open(changes), code("invalid_configuration"));
  });
}

test("record inputs reject traversal, invalid Unicode and non-string payloads", async (t) => {
  const f = await fixture(t);
  const store = await f.open();
  for (const id of ["../secret", "", "/absolute", "x\n", "a".repeat(257)])
    assert.throws(() => store.create(id, wire), code("record_invalid"));
  for (const payload of [null, Buffer.from(wire), "\ud800"])
    assert.throws(
      () => store.create("receipt", payload),
      code("record_invalid"),
    );
  assert.throws(
    () => store.create("receipt", wire, { kind: "unknown" }),
    code("record_invalid"),
  );
  assert.throws(
    () => store.create("receipt", wire, null),
    code("record_invalid"),
  );
});
