/** Real public Host snapshot and env SecretRef APIs; no gateway or model calls. */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import net from "node:net";
import {
  clearRuntimeConfigSnapshot,
  getRuntimeConfigSnapshot,
  getRuntimeConfigSourceSnapshot,
  setRuntimeConfigSnapshot,
} from "openclaw/plugin-sdk/runtime-config-snapshot";
import { createProductRuntimeProfile } from "../product-runtime/profile.mjs";
import { prepareProductRuntimeConfig } from "../dist/runtime/product-runtime-config.js";

let root, profile;
let networkAttempts = 0;
const previousConnect = net.Socket.prototype.connect;
const previousFetch = globalThis.fetch;
const previousModel = process.env.PRODUCT_LOCAL_MODEL_TOKEN;
const previousGateway = process.env.AGENTGUARD_PRODUCT_GATEWAY_TOKEN;
before(async () => {
  root = await mkdtemp(path.join(tmpdir(), "product-local-config-"));
  profile = await createProductRuntimeProfile({
    root,
    runManifestPath: path.join(root, "future-run.json"),
    inboxUrl: "http://127.0.0.1:9/inbox",
    provider: {
      id: "agentguard-acceptance",
      modelId: "local-config-test",
      baseUrl: "http://127.0.0.1:9/v1",
      apiKey: {
        source: "env",
        provider: "default",
        id: "PRODUCT_LOCAL_MODEL_TOKEN",
      },
    },
  });
  process.env.PRODUCT_LOCAL_MODEL_TOKEN = "synthetic-local-model";
  process.env.AGENTGUARD_PRODUCT_GATEWAY_TOKEN = "synthetic-local-gateway";
  net.Socket.prototype.connect = function () {
    networkAttempts++;
    throw new Error("network_must_not_run");
  };
  globalThis.fetch = async () => {
    networkAttempts++;
    throw new Error("network_must_not_run");
  };
});
after(async () => {
  net.Socket.prototype.connect = previousConnect;
  globalThis.fetch = previousFetch;
  for (const [key, previous] of [
    ["PRODUCT_LOCAL_MODEL_TOKEN", previousModel],
    ["AGENTGUARD_PRODUCT_GATEWAY_TOKEN", previousGateway],
  ]) {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
  clearRuntimeConfigSnapshot();
  await rm(root, { recursive: true, force: true });
});
test("both env credentials materialize only in the public in-memory snapshot", async () => {
  const original = await readFile(profile.configPath, "utf8");
  const handle = await prepareProductRuntimeConfig(
    profile,
    new AbortController().signal,
  );
  try {
    const runtime = getRuntimeConfigSnapshot();
    const source = getRuntimeConfigSourceSnapshot();
    assert.equal(
      runtime.models.providers[profile.providerId].apiKey,
      "synthetic-local-model",
    );
    assert.equal(runtime.gateway.auth.token, "synthetic-local-gateway");
    assert.deepEqual(source, profile.config);
    assert.equal(
      typeof source.models.providers[profile.providerId].apiKey,
      "object",
    );
    assert.equal(await readFile(profile.configPath, "utf8"), original);
    assert.equal(networkAttempts, 0);
    handle.assertCurrent();
  } finally {
    handle.close();
  }
  assert.equal(getRuntimeConfigSnapshot(), null);
});
test("missing env credentials reject before installing any runtime snapshot", async () => {
  delete process.env.PRODUCT_LOCAL_MODEL_TOKEN;
  try {
    await assert.rejects(
      prepareProductRuntimeConfig(profile, new AbortController().signal),
      /^Error: product_local_credentials_unavailable$/u,
    );
    assert.equal(getRuntimeConfigSnapshot(), null);
    assert.equal(networkAttempts, 0);
  } finally {
    process.env.PRODUCT_LOCAL_MODEL_TOKEN = "synthetic-local-model";
  }
});
test("mutation of the selected native runtime config is rejected", async () => {
  const handle = await prepareProductRuntimeConfig(
    profile,
    new AbortController().signal,
  );
  try {
    getRuntimeConfigSnapshot().models.providers[profile.providerId].baseUrl =
      "http://127.0.0.1:8/v1";
    assert.throws(
      () => handle.assertCurrent(),
      /^Error: product_runtime_configuration_changed$/u,
    );
    assert.equal(networkAttempts, 0);
  } finally {
    handle.close();
  }
});
test("replacement snapshot is rejected and close leaves its ownership intact", async () => {
  const handle = await prepareProductRuntimeConfig(
    profile,
    new AbortController().signal,
  );
  const replacement = structuredClone(getRuntimeConfigSnapshot());
  setRuntimeConfigSnapshot(replacement, structuredClone(profile.config));
  assert.throws(
    () => handle.assertCurrent(),
    /^Error: product_runtime_configuration_changed$/u,
  );
  handle.close();
  assert.equal(getRuntimeConfigSnapshot(), replacement);
  assert.equal(networkAttempts, 0);
  clearRuntimeConfigSnapshot();
});
test("cancelled secret preparation cannot overwrite the next owner snapshot", async () => {
  const controller = new AbortController();
  const preparing = prepareProductRuntimeConfig(profile, controller.signal);
  controller.abort();
  const replacement = structuredClone(profile.config);
  setRuntimeConfigSnapshot(replacement, structuredClone(profile.config));
  try {
    await assert.rejects(
      preparing,
      /^Error: product_local_credentials_unavailable$/u,
    );
    assert.equal(getRuntimeConfigSnapshot(), replacement);
    assert.equal(networkAttempts, 0);
  } finally {
    clearRuntimeConfigSnapshot();
  }
});
for (const [name, change] of [
  [
    "literal provider token",
    (source) => {
      source.models.providers[profile.providerId].apiKey =
        "synthetic-local-model";
    },
  ],
  ["missing source", () => null],
  [
    "another provider env identity",
    (source) => {
      source.models.providers[profile.providerId].apiKey.id =
        "ANOTHER_MODEL_TOKEN";
    },
  ],
  [
    "another gateway env identity",
    (source) => {
      source.gateway.auth.token.id = "ANOTHER_GATEWAY_TOKEN";
    },
  ],
]) {
  test(`runtime source ${name} is rejected before Host credential persistence`, async () => {
    const handle = await prepareProductRuntimeConfig(
      profile,
      new AbortController().signal,
    );
    try {
      const source = structuredClone(profile.config);
      const changed = change(source);
      setRuntimeConfigSnapshot(
        getRuntimeConfigSnapshot(),
        changed === null ? undefined : source,
      );
      assert.throws(
        () => handle.assertCurrent(),
        /^Error: product_runtime_configuration_changed$/u,
      );
      assert.equal(networkAttempts, 0);
    } finally {
      handle.close();
    }
  });
}
