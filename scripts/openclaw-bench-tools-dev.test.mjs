import assert from "node:assert/strict";
import test from "node:test";

import {
  BENCH_PLUGIN_ID,
  buildPatchedOpenClawConfig,
} from "./openclaw-bench-tools-dev.mjs";

test("buildPatchedOpenClawConfig preserves existing plugin paths and appends bench plugin config", () => {
  const patched = buildPatchedOpenClawConfig(
    {
      plugins: {
        load: { paths: ["/existing/agentguard-security"] },
        entries: {
          "agentguard-security": { enabled: true },
        },
      },
      agents: {
        defaults: { model: { primary: "deepseek/deepseek-v4-pro" } },
        list: [{ id: "main", default: true, identity: { name: "Main" } }],
      },
      meta: {
        lastTouchedVersion: "2026.6.6",
        lastTouchedAt: "2026-07-01T00:00:00.000Z",
      },
    },
    {
      stagingDir: "/repo/.openclaw-dev/agentguard-bench-tools",
      runtimeConfigPath: "/repo/.openclaw-dev/bench-tools-runtime.json",
    },
  );

  assert.deepEqual(patched.plugins.load.paths, [
    "/existing/agentguard-security",
    "/repo/.openclaw-dev/agentguard-bench-tools",
  ]);
  assert.equal(patched.plugins.entries["agentguard-security"].enabled, true);
  assert.equal(patched.plugins.entries[BENCH_PLUGIN_ID].enabled, true);
  assert.equal(
    patched.plugins.entries[BENCH_PLUGIN_ID].config.runtimeConfigPath,
    "/repo/.openclaw-dev/bench-tools-runtime.json",
  );
  assert.equal(patched.agents.defaults.model.primary, "deepseek/deepseek-v4-pro");
  const benchAgent = patched.agents.list.find((agent) => agent.id === "agentguard-bench");
  assert(benchAgent);
  assert.equal(benchAgent.sandbox.mode, "off");
  assert.equal(benchAgent.tools.profile, "full");
  assert.equal(Object.hasOwn(benchAgent.tools, "alsoAllow"), false);
  assert(benchAgent.tools.allow.includes("read_file"));
  assert.equal(Object.hasOwn(patched, "meta"), false);
});
