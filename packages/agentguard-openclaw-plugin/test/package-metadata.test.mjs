import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  OPENCLAW_ENFORCEMENT_HOOKS,
  OPENCLAW_FAIL_CLOSED_HOOKS,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";

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

test("manifest exposes one strict config surface and a SecretRef token", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("openclaw.plugin.json", packageRoot), "utf8"),
  );
  const properties = manifest.configSchema.properties;

  assert.deepEqual(Object.keys(properties).sort(), [
    "adapterToken",
    "agentId",
    "approvalPollIntervalMs",
    "approvalTimeoutMs",
    "diagnosticLogging",
    "enforcementMode",
    "guardApiBaseUrl",
    "requestTimeoutMs",
    "runtimeBindingId",
    "strongApprovalBindingEnabled",
  ]);
  assert.deepEqual(manifest.configSchema.required, ["adapterToken"]);
  const adapterToken = properties.adapterToken;
  assert.equal(adapterToken.type, undefined);
  assert.ok(Array.isArray(adapterToken.oneOf));
  assert.equal(adapterToken.oneOf.length, 2);
  const [secretRefBranch, materializedBranch] = adapterToken.oneOf;
  assert.equal(secretRefBranch.type, "object");
  assert.equal(secretRefBranch.additionalProperties, false);
  assert.deepEqual(secretRefBranch.required, ["source", "provider", "id"]);
  assert.deepEqual(secretRefBranch.properties.source, {
    type: "string",
    enum: ["env", "file", "exec"],
  });
  assert.deepEqual(secretRefBranch.properties.provider, {
    type: "string",
    pattern: "^[a-z][a-z0-9_-]{0,63}$",
  });
  assert.deepEqual(secretRefBranch.properties.id, {
    type: "string",
    minLength: 1,
    maxLength: 256,
  });
  assert.deepEqual(materializedBranch, { type: "string", minLength: 1 });
  assert.deepEqual(manifest.configContracts.secretInputs.paths, [
    { path: "adapterToken", expected: "string" },
  ]);
  assert.equal("approvalWaitBudgetMs" in properties, false);
  assert.deepEqual(properties.strongApprovalBindingEnabled, {
    type: "boolean",
    default: false,
    description:
      "Enable canary strong-binding processing. Server-declared execution leases are always enforced, but current OpenClaw cannot atomically replace and seal the final action, so heartbeat C3 remains false.",
  });
  assert.equal(
    manifest.uiHints.strongApprovalBindingEnabled.help,
    "Enables canary processing; current OpenClaw lacks atomic replace-and-seal, so C3 is not advertised. Server-declared execution leases still fail closed.",
  );
  assert.deepEqual(properties.runtimeBindingId, {
    type: "string",
    pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    description:
      "Trusted runtime binding identifier provisioned with this OpenClaw adapter. It must exactly match a server-declared strong binding.",
  });
});

test("hook contract uses supported OpenClaw enforcement surfaces", () => {
  // RTE-03：after_tool_call 观察组新增 → 24 个 REQUIRED hook。
  assert.equal(OPENCLAW_REQUIRED_HOOKS.length, 24);
  assert.ok(OPENCLAW_REQUIRED_HOOKS.includes("before_agent_run"));
  assert.ok(OPENCLAW_REQUIRED_HOOKS.includes("after_tool_call"));
  // terminal closure 是观察型能力：不进阻断/fail-closed 清单。
  assert.equal(OPENCLAW_ENFORCEMENT_HOOKS.includes("after_tool_call"), false);
  assert.equal(
    OPENCLAW_ENFORCEMENT_HOOKS.includes("before_prompt_build"),
    false,
  );
  assert.equal(OPENCLAW_ENFORCEMENT_HOOKS.includes("llm_input"), false);
  assert.deepEqual(OPENCLAW_FAIL_CLOSED_HOOKS, OPENCLAW_ENFORCEMENT_HOOKS);
});
