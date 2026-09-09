/** Pinned Host loader bytes/identity only; no activation, agent loop, or Provider. */
import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

const actualRoot = path.dirname(
  path.dirname(
    path.dirname(
      realpathSync(
        createRequire(import.meta.url).resolve(
          "openclaw/plugin-sdk/agent-harness",
        ),
      ),
    ),
  ),
);
const dist = fileURLToPath(new URL("../dist/runtime/", import.meta.url));
const entry = "runtime-plugins-ICju_gEw.js";
const standalone = "standalone-runtime-registry-loader-DHlUPKIt.js";
const directories = [];
const safeInput = {
  config: { plugins: { enabled: false } },
  workspaceDir: "/unused-loader-test-workspace",
};
after(async () => {
  await Promise.all(
    directories.map((p) => rm(p, { recursive: true, force: true })),
  );
});

// Install the exact three admitted Host files in an isolated module-resolution
// root. Direct dependencies link to the real pinned SDK; they are not executed
// as an agent loop. No production path/version/byte override exists.
async function installation(change = async () => {}) {
  const root = await mkdtemp(path.join(tmpdir(), "agentguard-host-loader-"));
  directories.push(root);
  const adapter = path.join(root, "adapter");
  const host = path.join(adapter, "node_modules/openclaw");
  await mkdir(path.join(adapter, "dist/runtime"), { recursive: true });
  await mkdir(path.join(host, "dist/plugin-sdk"), { recursive: true });
  await writeFile(
    path.join(adapter, "package.json"),
    JSON.stringify({ type: "module" }),
  );
  for (const file of [
    "product-host-loader.js",
    "product-protected-file.js",
    "canonical.js",
  ])
    await copyFile(
      path.join(dist, file),
      path.join(adapter, "dist/runtime", file),
    );
  await copyFile(
    path.join(actualRoot, "package.json"),
    path.join(host, "package.json"),
  );
  await writeFile(
    path.join(host, "dist/plugin-sdk/agent-harness.js"),
    "export {};\n",
  );
  const dependencies = new Set();
  for (const file of [entry, standalone]) {
    const original = path.join(actualRoot, "dist", file);
    await copyFile(original, path.join(host, "dist", file));
    const source = await readFile(original, "utf8");
    for (const match of source.matchAll(/from "\.\/([^"\n]+)"/gu))
      if (![entry, standalone].includes(match[1])) dependencies.add(match[1]);
  }
  for (const file of dependencies)
    await symlink(
      path.join(actualRoot, "dist", file),
      path.join(host, "dist", file),
    );
  await change(host);
  const api = await import(
    pathToFileURL(path.join(adapter, "dist/runtime/product-host-loader.js"))
  );
  return { host, api };
}

test("exact pinned Host metadata and startup entries admit a local loader binding", async () => {
  const { api } = await installation();
  await api.loadPinnedOpenClawHostRegistry(safeInput);
  assert.doesNotThrow(() => api.assertPinnedOpenClawHostLoader());
});
test("another Host version cannot select a compatible-looking internal export", async () => {
  const { api } = await installation(async (host) => {
    const p = path.join(host, "package.json");
    const metadata = JSON.parse(await readFile(p, "utf8"));
    metadata.version = "2026.7.1-3";
    await writeFile(p, JSON.stringify(metadata));
  });
  await assert.rejects(
    api.loadPinnedOpenClawHostRegistry(safeInput),
    /^Error: product_host_loader_invalid$/u,
  );
});
test("same version with altered raw package metadata is rejected", async () => {
  const { api } = await installation(async (host) => {
    const p = path.join(host, "package.json");
    await writeFile(p, `${await readFile(p, "utf8")}\n`);
  });
  await assert.rejects(
    api.loadPinnedOpenClawHostRegistry(safeInput),
    /product_host_loader_invalid/u,
  );
});
for (const file of [entry, standalone]) {
  test(`changed ${file} bytes are rejected before module evaluation`, async () => {
    const marker = `loader-marker-${file}`;
    const { api } = await installation(async (host) => {
      await writeFile(
        path.join(host, "dist", file),
        `globalThis[${JSON.stringify(marker)}] = true; export const t = () => {};\n`,
      );
    });
    await assert.rejects(
      api.loadPinnedOpenClawHostRegistry(safeInput),
      /product_host_loader_invalid/u,
    );
    assert.equal(globalThis[marker], undefined);
  });
  test(`symlink substitution of ${file} is rejected even with original bytes`, async () => {
    const { api } = await installation(async (host) => {
      const p = path.join(host, "dist", file);
      await rm(p);
      await symlink(path.join(actualRoot, "dist", file), p);
    });
    await assert.rejects(
      api.loadPinnedOpenClawHostRegistry(safeInput),
      /product_host_loader_invalid/u,
    );
  });
}
test("a loaded module cache cannot hide later startup file replacement", async () => {
  const { host, api } = await installation();
  await api.loadPinnedOpenClawHostRegistry(safeInput);
  const p = path.join(host, "dist", entry);
  const sameBytes = await readFile(p);
  await rm(p);
  await writeFile(p, sameBytes);
  assert.throws(
    () => api.assertPinnedOpenClawHostLoader(),
    /product_host_loader_invalid/u,
  );
  await assert.rejects(
    api.loadPinnedOpenClawHostRegistry(safeInput),
    /product_host_loader_invalid/u,
  );
});
test("a loaded binding rejects later raw metadata changes", async () => {
  const { host, api } = await installation();
  await api.loadPinnedOpenClawHostRegistry(safeInput);
  const p = path.join(host, "package.json");
  await writeFile(p, `${await readFile(p, "utf8")}\n`);
  assert.throws(
    () => api.assertPinnedOpenClawHostLoader(),
    /product_host_loader_invalid/u,
  );
});
