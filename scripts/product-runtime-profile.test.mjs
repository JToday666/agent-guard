import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createProductRuntimeProfile,
  PRODUCT_TOOL_IDS,
} from "../tests/support/openclaw-product-runtime/profile.mjs";

async function withRoot(fn) {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "agentguard-product-profile-"),
  );
  try {
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
const endpoints = {
  inboxUrl: "http://127.0.0.1:43123/inbox",
  modelBaseUrl: "http://127.0.0.1:43124/v1",
};

test("fresh profile limits tools and native persistence without touching personal state", async () => {
  await withRoot(async (root) => {
    const profile = await createProductRuntimeProfile({ root, ...endpoints });
    const config = JSON.parse(await readFile(profile.configPath, "utf8"));
    assert.deepEqual(config.tools.allow, [...PRODUCT_TOOL_IDS]);
    assert.equal(config.tools.exec.security, "deny");
    assert.equal(config.tools.fs.workspaceOnly, true);
    assert.equal(config.agents.defaults.memorySearch.enabled, false);
    assert.equal(config.agents.defaults.compaction.memoryFlush.enabled, false);
    assert.equal(config.plugins.slots.memory, "none");
    assert.deepEqual(config.agents.list[0].skills, []);
    assert.deepEqual(config.plugins.allow, [
      "agentguard-product-runtime-fixture",
    ]);
    assert.deepEqual(Object.keys(config.channels), ["agentguard-fixture"]);
    assert.ok(profile.env.OPENCLAW_STATE_DIR.startsWith(root + path.sep));
    assert.equal(profile.env.HOME, undefined);
    assert.equal((await stat(profile.configPath)).mode & 0o777, 0o600);
    assert.equal((await stat(profile.stateDir)).mode & 0o777, 0o700);
    await assert.rejects(createProductRuntimeProfile({ root, ...endpoints }), {
      code: "EEXIST",
    });
  });
});

test("profile refuses remote, credential-bearing, and ambiguous local endpoints", async () => {
  for (const url of [
    "https://example.com",
    "http://localhost:9000",
    "http://127.0.0.1.evil.invalid",
    "http://u:p@127.0.0.1",
    "http://127.0.0.1/#fragment",
  ]) {
    await withRoot(async (root) => {
      await assert.rejects(
        createProductRuntimeProfile({ root, ...endpoints, inboxUrl: url }),
      );
    });
  }
});

test("profile refuses symlink roots and relative paths", async () => {
  await withRoot(async (root) => {
    const link = root + "-link";
    try {
      await symlink(root, link);
      await assert.rejects(
        createProductRuntimeProfile({ root: link, ...endpoints }),
      );
      await assert.rejects(
        createProductRuntimeProfile({ root: ".", ...endpoints }),
      );
    } finally {
      await rm(link, { force: true });
    }
  });
});
