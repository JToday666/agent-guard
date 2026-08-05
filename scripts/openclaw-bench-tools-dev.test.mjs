import assert from "node:assert/strict";
import test from "node:test";

import {
  BENCH_AGENT_ID,
  BENCH_PLUGIN_ID,
  buildPatchedOpenClawConfig,
  openClawConfigPatchArgs,
} from "./openclaw-bench-tools-dev.mjs";

const FORBIDDEN_AGENT_VISIBLE_TERMS = [
  "AgentGuard",
  "AttackBench",
  "benchmark",
  "verification",
  "case_id",
  "trace_id",
];

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
        list: [
          { id: "main", default: true, identity: { name: "Main" } },
          {
            id: "agentguard-bench",
            identity: { name: "AgentGuard AttackBench" },
          },
        ],
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
  assert.equal(
    patched.agents.defaults.model.primary,
    "deepseek/deepseek-v4-pro",
  );
  const benchAgent = patched.agents.list.find(
    (agent) => agent.id === BENCH_AGENT_ID,
  );
  assert(benchAgent);
  assert.equal(BENCH_AGENT_ID, "local-task-runner");
  assert.equal(benchAgent.identity.name, "Local Task Runner");
  assert.equal(benchAgent.identity.theme, "Local task automation");
  assert.equal(benchAgent.contextInjection, "never");
  assert.equal(benchAgent.sandbox.mode, "off");
  assert.equal(benchAgent.tools.profile, "full");
  assert.equal(Object.hasOwn(benchAgent.tools, "alsoAllow"), false);
  assert(benchAgent.tools.allow.includes("read_file"));
  assert(benchAgent.tools.allow.includes("local_tool_call"));
  assert(!benchAgent.tools.allow.includes("agentguard_bench_tool"));
  assert(!patched.agents.list.some((agent) => agent.id === "agentguard-bench"));
  const visibleAgentConfig = JSON.stringify({
    id: benchAgent.id,
    identity: benchAgent.identity,
    allow: benchAgent.tools.allow,
    contextInjection: benchAgent.contextInjection,
  });
  for (const term of FORBIDDEN_AGENT_VISIBLE_TERMS) {
    assert.doesNotMatch(visibleAgentConfig, new RegExp(term, "i"), term);
  }
  assert.equal(Object.hasOwn(patched, "meta"), false);
});

test("openClawConfigPatchArgs intentionally replaces agents list", () => {
  assert.deepEqual(openClawConfigPatchArgs("/tmp/patch.json"), [
    "config",
    "patch",
    "--file",
    "/tmp/patch.json",
    "--replace-path",
    "agents.list",
  ]);
});
