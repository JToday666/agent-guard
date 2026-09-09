/** Actual pinned Host full loading and public SDK tools; no fake API, activation, or Provider. */
import assert from "node:assert/strict";
import { before, after, test } from "node:test";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import {
  createSyntheticProductPackage,
  packSyntheticProductPackage,
} from "../../../tests/support/openclaw-product-transport-package.mjs";
let root, profile, packed, inspect, create, getRegistry, createdRuntime;
let requests = 0;
const originalFetch = globalThis.fetch;
const savedEnvironment = { ...process.env };
before(async () => {
  root = await mkdtemp(path.join(tmpdir(), "agentguard-registration-test-"));
  const pkg = await createSyntheticProductPackage({
    directory: path.join(root, "installed"),
  });
  packed = await packSyntheticProductPackage({
    packageRoot: pkg.packageRoot,
    directory: path.join(root, "candidate"),
  });
  await chmod(packed.candidateTgzPath, 0o600);
  const profileRoot = path.join(root, "runtime");
  await mkdir(profileRoot, { mode: 0o700 });
  const { createProductRuntimeProfile } = await import(
    pathToFileURL(path.join(pkg.packageRoot, "product-runtime/profile.mjs"))
  );
  profile = await createProductRuntimeProfile({
    root: profileRoot,
    runManifestPath: path.join(root, "future-run.json"),
    inboxUrl: "http://127.0.0.1:9/inbox",
    provider: {
      id: "agentguard-acceptance",
      modelId: "registration-only",
      baseUrl: "http://127.0.0.1:9/v1",
      apiKey: {
        source: "env",
        provider: "default",
        id: "UNUSED_TEST_MODEL_TOKEN",
      },
    },
  });
  ({
    inspectOpenClawProductRuntime: inspect,
    createOpenClawProductRuntime: create,
  } = await import(
    pathToFileURL(
      path.join(pkg.packageRoot, "dist/runtime/product-composition.js"),
    )
  ));
  const { restrictedCanonicalJson } = await import(
    pathToFileURL(path.join(pkg.packageRoot, "dist/runtime/canonical.js"))
  );
  await writeFile(
    profile.runManifestPath,
    restrictedCanonicalJson({
      schemaVersion: 1,
      activationManifestPath: path.join(root, "not-issued-activation.json"),
      candidateTgzPath: packed.candidateTgzPath,
      profileConfigPath: profile.configPath,
      guardApiBaseUrl: "http://127.0.0.1:9",
      adapterTokenRef: {
        source: "env",
        provider: "default",
        id: "UNUSED_TEST_ADAPTER_TOKEN",
      },
      taskId: "registration-only-task",
      scopeDigest: `sha256:${"a".repeat(64)}`,
      taskText: "Inspect the registered tools without starting an agent.",
      traceId: "registration-only-trace",
      productReceiptDirectory: path.join(root, "not-opened-receipts"),
      productReceiptKeyPath: path.join(root, "not-opened-key"),
    }),
    { mode: 0o600 },
  );
  const require = createRequire(path.join(pkg.packageRoot, "package.json"));
  ({ getGlobalPluginRegistry: getRegistry } = await import(
    pathToFileURL(require.resolve("openclaw/plugin-sdk/plugin-runtime"))
  ));
  globalThis.fetch = async () => {
    requests++;
    throw new Error("network_must_not_run");
  };
});
after(async () => {
  await createdRuntime?.close();
  globalThis.fetch = originalFetch;
  for (const k of Object.keys(process.env))
    if (!(k in savedEnvironment)) delete process.env[k];
  Object.assign(process.env, savedEnvironment);
  await rm(root, { recursive: true, force: true });
});
const inspectCurrent = () =>
  inspect({
    profileConfigPath: profile.configPath,
    candidateTgzPath: packed.candidateTgzPath,
  });
test("pinned Host startup loads complete real registry before activation", async () => {
  const actual = await inspectCurrent();
  assert.equal(actual.active, false);
  assert.equal(actual.inventory.tools.length, 8);
  assert.equal(actual.modelVisibleTools.length, 8);
  assert.equal(actual.capabilityConsumers.length, 7);
  assert.equal(
    getRegistry().plugins.find(
      (p) => p.id === "agentguard-product-runtime-fixture",
    ).status,
    "loaded",
  );
  assert.ok(getRegistry().plugins.some((p) => p.status === "disabled"));
  assert.ok(
    getRegistry()
      .plugins.filter((p) => p.id !== "agentguard-product-runtime-fixture")
      .every(
        (p) =>
          p.status === "disabled" &&
          p.enabled === false &&
          p.activated === false,
      ),
  );
  assert.equal(getRegistry().runtimeLifecycles.length, 1);
  assert.equal(requests, 0);
});
async function changed(target, key, value) {
  const original = target[key];
  try {
    target[key] = value;
    await assert.rejects(inspectCurrent(), /product_registration_incomplete/u);
    assert.equal(requests, 0);
  } finally {
    target[key] = original;
  }
}
test("missing Provider wrapper blocks before any transport", async () => {
  await changed(getRegistry().providers[0].provider, "wrapStreamFn", undefined);
});
test("missing replay policy blocks before any transport", async () => {
  await changed(
    getRegistry().providers[0].provider,
    "buildReplayPolicy",
    undefined,
  );
});
test("missing native middleware blocks before any transport", async () => {
  await changed(getRegistry(), "agentToolResultMiddlewares", []);
});
test("missing entire provider registration blocks before any transport", async () => {
  await changed(getRegistry(), "providers", []);
});
test("missing the entire Product descriptor blocks despite disabled discovery records", async () => {
  await changed(
    getRegistry(),
    "plugins",
    getRegistry().plugins.filter(
      (p) => p.id !== "agentguard-product-runtime-fixture",
    ),
  );
});
for (const [key, value] of [
  ["status", "error"],
  ["status", "loaded"],
  ["status", "loading"],
  ["enabled", true],
  ["activated", true],
  ["imported", true],
]) {
  test(`another descriptor ${key}=${value} cannot hide behind discovery metadata`, async () => {
    await changed(
      getRegistry().plugins.find(
        (p) => p.id !== "agentguard-product-runtime-fixture",
      ),
      key,
      value,
    );
  });
}
for (const name of ["services", "httpRoutes", "commands", "gatewayHandlers"]) {
  test(`an unexpected ${name} runtime registration is refused`, async () => {
    await changed(
      getRegistry(),
      name,
      name === "gatewayHandlers"
        ? { unexpected: () => {} }
        : [{ pluginId: "disabled-foreign-plugin" }],
    );
  });
}
test("duplicate hook cannot replace a missing required hook", async () => {
  const r = getRegistry();
  await changed(
    r,
    "typedHooks",
    r.typedHooks.map((h, i) => (i === 1 ? r.typedHooks[0] : h)),
  );
});
test("duplicate factory cannot replace another required memory tool", async () => {
  const r = getRegistry();
  await changed(r.tools[1], "factory", r.tools[0].factory);
});
test("replaced persistence callback cannot retain a registration witness", async () => {
  await changed(
    getRegistry().typedHooks.find((h) => h.hookName === "tool_result_persist"),
    "handler",
    () => ({}),
  );
});
test("replaced channel send path cannot retain a registration witness", async () => {
  const channel = getRegistry().channels[0].plugin;
  await changed(channel, "outbound", {
    ...channel.outbound,
    sendPayload: async () => ({ messageId: "fake" }),
  });
});
test("missing automatic channel setup registration is refused", async () => {
  await changed(getRegistry(), "channelSetups", []);
});
test("setup channel must be the exact same registered runtime channel", async () => {
  await changed(getRegistry().channelSetups[0], "plugin", {
    ...getRegistry().channels[0].plugin,
  });
});
test("automatic channel setup must have the verified Product owner", async () => {
  await changed(
    getRegistry().channelSetups[0],
    "pluginId",
    "disabled-foreign-plugin",
  );
});
test("missing cleanup cannot retain a registration witness", async () => {
  await changed(getRegistry(), "runtimeLifecycles", []);
});
for (const key of ["PI_CODING_AGENT_DIR", "OPENCLAW_UNSELECTED_STATE"]) {
  test(`unselected Host environment ${key} cannot reuse registration`, async () => {
    const previous = process.env[key];
    try {
      process.env[key] = "/unselected/personal-state";
      await assert.rejects(inspectCurrent(), /product_environment_invalid/u);
      assert.equal(requests, 0);
    } finally {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    }
  });
}
test("restoring the same actual registry retains inspect-only status", async () => {
  assert.equal((await inspectCurrent()).active, false);
  assert.equal(requests, 0);
});
test("concurrent public preparations cannot reload another inspection's registry", async () => {
  const first = inspectCurrent();
  await assert.rejects(inspectCurrent(), /product_runtime_already_selected/u);
  await assert.rejects(
    create({ runManifestPath: profile.runManifestPath }),
    /product_runtime_already_selected/u,
  );
  assert.equal((await first).active, false);
  assert.equal(requests, 0);
});
test("start cannot claim ownership during public inspection and the created runtime remains usable", async () => {
  createdRuntime = await create({ runManifestPath: profile.runManifestPath });
  const pending = inspectCurrent();
  await assert.rejects(
    createdRuntime.start(),
    /product_composition_preparing/u,
  );
  assert.equal((await pending).active, false);
  assert.equal(createdRuntime.snapshot().state, "created");
  assert.equal(requests, 0);
});
test("start cannot claim ownership during another public factory preparation", async () => {
  const pending = create({ runManifestPath: profile.runManifestPath });
  await assert.rejects(
    createdRuntime.start(),
    /product_composition_preparing/u,
  );
  const other = await pending;
  assert.equal(other.snapshot().state, "created");
  assert.equal(createdRuntime.snapshot().state, "created");
  assert.equal(requests, 0);
});
test("failed public preparation releases the reservation without credentials or an ACK", async () => {
  await assert.rejects(
    inspect({
      profileConfigPath: profile.configPath,
      candidateTgzPath: path.join(root, "absent.tgz"),
    }),
    /product_candidate_invalid/u,
  );
  assert.equal((await inspectCurrent()).active, false);
  assert.equal(createdRuntime.snapshot().state, "created");
  assert.equal(requests, 0);
});
test("a Host agent_end cannot retire an unstarted Product run", () => {
  const handler = getRegistry().typedHooks.find(
    (hook) => hook.hookName === "agent_end",
  ).handler;
  assert.throws(
    () =>
      handler(
        { runId: "unstarted-run", messages: [], success: true },
        { runId: "unstarted-run", agentId: profile.agentId },
      ),
    /^Error: product_composition_unavailable$/u,
  );
  assert.equal(createdRuntime.snapshot().state, "created");
  assert.equal(requests, 0);
});
test("agent_end rechecks the actual registry before consuming a Host lifecycle event", () => {
  const registry = getRegistry();
  const handler = registry.typedHooks.find(
    (hook) => hook.hookName === "agent_end",
  ).handler;
  const original = registry.providers[0].provider.wrapStreamFn;
  try {
    registry.providers[0].provider.wrapStreamFn = undefined;
    assert.throws(
      () =>
        handler(
          { runId: "drifted-run", messages: [], success: true },
          { runId: "drifted-run", agentId: profile.agentId },
        ),
      /^Error: product_registration_incomplete$/u,
    );
    assert.equal(requests, 0);
  } finally {
    registry.providers[0].provider.wrapStreamFn = original;
  }
  assert.equal(createdRuntime.snapshot().state, "created");
});
