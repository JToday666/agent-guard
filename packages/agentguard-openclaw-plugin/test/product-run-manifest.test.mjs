import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { chmod, mkdtemp, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { readProductRunManifest } from "../dist/runtime/product-run-manifest.js";
import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { readProductFile } from "../dist/runtime/product-protected-file.js";
const data = {
  schemaVersion: 1,
  activationManifestPath: "/tmp/activation.json",
  candidateTgzPath: "/tmp/candidate.tgz",
  profileConfigPath: "/tmp/profile.json",
  guardApiBaseUrl: "http://127.0.0.1:8000",
  adapterTokenRef: {
    source: "env",
    provider: "default",
    id: "PRODUCT_TEST_TOKEN",
  },
  taskId: "task-product",
  scopeDigest: `hmac-sha256:${"a".repeat(64)}`,
  taskText: "Read the actual fixture.",
  traceId: "trace-product",
  productReceiptDirectory: "/tmp/receipts",
  productReceiptKeyPath: "/tmp/keys/receipt.key",
};
async function fixture(fn) {
  const root = await mkdtemp(path.join(tmpdir(), "agentguard-run-file-")),
    file = path.join(root, "run.json");
  try {
    await writeFile(file, restrictedCanonicalJson(data) + "\n", {
      mode: 0o600,
    });
    await fn(file, root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
test("protected run config is immutable and changing task invalidates it", () =>
  fixture(async (file) => {
    const run = readProductRunManifest(file);
    assert.equal(run.data.taskId, data.taskId);
    assert(Object.isFrozen(run.data.adapterTokenRef));
    run.assertCurrent();
    await writeFile(
      file,
      restrictedCanonicalJson({ ...data, taskText: "Another task" }) + "\n",
    );
    assert.throws(() => run.assertCurrent(), /product_run_manifest_changed/u);
  }));
for (const [name, mutation] of [
  ["unknown option", (d) => ({ ...d, observe: true })],
  ["raw credential", (d) => ({ ...d, adapterTokenRef: "secret-test-only" })],
  [
    "execution secret provider",
    (d) => ({
      ...d,
      adapterTokenRef: { source: "exec", provider: "default", id: "TOKEN" },
    }),
  ],
  ["relative candidate", (d) => ({ ...d, candidateTgzPath: "candidate.tgz" })],
  ["secret URL", (d) => ({ ...d, guardApiBaseUrl: "http://secret@127.0.0.1" })],
  ["invalid task identity", (d) => ({ ...d, taskId: "unsafe task" })],
])
  test(`run config rejects ${name}`, () =>
    fixture(async (file) => {
      await writeFile(file, restrictedCanonicalJson(mutation(data)) + "\n");
      assert.throws(
        () => readProductRunManifest(file),
        /product_run_manifest_invalid/u,
      );
    }));
test("duplicate keys cannot silently choose another task", () =>
  fixture(async (file) => {
    await writeFile(
      file,
      restrictedCanonicalJson(data).replace(
        '"taskId":',
        '"taskId":"unchecked","taskId":',
      ),
    );
    assert.throws(
      () => readProductRunManifest(file),
      /product_run_manifest_invalid/u,
    );
  }));
test("world-readable run file and symlink are rejected", () =>
  fixture(async (file, root) => {
    await chmod(file, 0o644);
    assert.throws(
      () => readProductRunManifest(file),
      /product_run_manifest_invalid/u,
    );
    await chmod(file, 0o600);
    const alias = path.join(root, "link.json");
    await symlink(file, alias);
    assert.throws(
      () => readProductRunManifest(alias),
      /product_run_manifest_invalid/u,
    );
  }));
test("protected reader bounds bytes even when the file grows after fstat", () =>
  fixture(async (file) => {
    const admittedSize = fs.statSync(file).size;
    const originalRead = fs.readSync;
    let requestedBytes = 0;
    let grew = false;
    try {
      fs.readSync = (fd, buffer, offset, length, position) => {
        if (!grew) {
          grew = true;
          fs.appendFileSync(file, Buffer.alloc(4096, 0x61));
        }
        requestedBytes += length;
        return originalRead(fd, buffer, offset, length, position);
      };
      syncBuiltinESMExports();
      assert.throws(
        () => readProductFile(file, admittedSize),
        /^Error: product_protected_file_invalid$/u,
      );
      assert.equal(grew, true);
      assert.equal(requestedBytes, admittedSize + 1);
    } finally {
      fs.readSync = originalRead;
      syncBuiltinESMExports();
    }
  }));
