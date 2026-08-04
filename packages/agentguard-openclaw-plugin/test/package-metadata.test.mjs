import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const packageRoot = new URL("../", import.meta.url);

test("package, manifest, and heartbeat versions stay aligned", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("package.json", packageRoot), "utf8"),
  );
  const manifest = JSON.parse(
    await readFile(new URL("openclaw.plugin.json", packageRoot), "utf8"),
  );
  const source = await readFile(new URL("src/index.ts", packageRoot), "utf8");
  const heartbeatVersion = source.match(
    /const PLUGIN_VERSION = "([^"]+)";/,
  )?.[1];

  assert.equal(packageJson.name, "@agentguard-ai/openclaw-plugin");
  assert.equal(manifest.version, packageJson.version);
  assert.equal(heartbeatVersion, packageJson.version);
});
