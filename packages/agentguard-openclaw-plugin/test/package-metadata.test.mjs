import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { validateJsonSchemaValue } from "openclaw/plugin-sdk/json-schema-runtime";
import { buildPluginConfig } from "../dist/guard-api-client.js";
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
    "activationAckMaxAgeMs",
    "adapterToken",
    "agentId",
    "approvalPollIntervalMs",
    "approvalTimeoutMs",
    "diagnosticLogging",
    "enforcementMode",
    "guardApiBaseUrl",
    "officialProfileDigest",
    "officialProfileId",
    "requestTimeoutMs",
    "restrictedAskReleaseEnabled",
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
  assert.equal(properties.strongApprovalBindingEnabled.type, "boolean");
  assert.equal(properties.strongApprovalBindingEnabled.deprecated, true);
  assert.match(
    properties.strongApprovalBindingEnabled.description,
    /deprecated/i,
  );
  assert.match(
    properties.strongApprovalBindingEnabled.description,
    /C3.*false/i,
  );
  assert.match(
    manifest.uiHints.strongApprovalBindingEnabled.help,
    /deprecated/i,
  );
  assert.match(
    manifest.uiHints.strongApprovalBindingEnabled.help,
    /C3.*false/i,
  );
  assert.equal(properties.officialProfileId.type, "string");
  assert.deepEqual(properties.officialProfileId.enum, [
    "agentguard-openclaw-v2-restricted",
  ]);
  assert.equal(properties.officialProfileDigest.type, "string");
  assert.equal(
    properties.officialProfileDigest.pattern,
    "^sha256:[0-9a-f]{64}$",
  );
  assert.equal(properties.restrictedAskReleaseEnabled.type, "boolean");
  assert.equal(properties.activationAckMaxAgeMs.type, "integer");
  assert.equal(properties.activationAckMaxAgeMs.minimum, 1);
  assert.equal(properties.activationAckMaxAgeMs.maximum, 120000);
  for (const field of [
    "strongApprovalBindingEnabled",
    "officialProfileId",
    "officialProfileDigest",
    "restrictedAskReleaseEnabled",
    "activationAckMaxAgeMs",
  ]) {
    assert.equal(
      Object.hasOwn(properties[field], "default"),
      false,
      `${field} must not be injected by Host default hydration`,
    );
    assert.ok(
      properties[field].description.length > 0,
      `${field} needs a description`,
    );
    assert.ok(
      manifest.uiHints[field].label.length > 0,
      `${field} needs a label`,
    );
    assert.ok(
      manifest.uiHints[field].help.length > 0,
      `${field} needs migration help`,
    );
  }
  assert.match(
    manifest.uiHints.restrictedAskReleaseEnabled.help,
    /not available/i,
  );
  assert.match(manifest.uiHints.activationAckMaxAgeMs.help, /120000/);
  assert.deepEqual(properties.runtimeBindingId, {
    type: "string",
    pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    description:
      "Trusted runtime binding identifier provisioned with this OpenClaw adapter. It must exactly match a server-declared strong binding.",
  });
});

test("pinned Host schema hydration does not manufacture migration conflicts", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("openclaw.plugin.json", packageRoot), "utf8"),
  );
  const migrationFields = [
    "strongApprovalBindingEnabled",
    "officialProfileId",
    "officialProfileDigest",
    "restrictedAskReleaseEnabled",
    "activationAckMaxAgeMs",
  ];
  const cases = [
    {},
    { strongApprovalBindingEnabled: false },
    { strongApprovalBindingEnabled: true },
    { restrictedAskReleaseEnabled: false },
    { activationAckMaxAgeMs: 120000 },
    {
      officialProfileId: "agentguard-openclaw-v2-restricted",
      officialProfileDigest: `sha256:${"a".repeat(64)}`,
      runtimeBindingId: "binding:openclaw:main",
      restrictedAskReleaseEnabled: false,
    },
  ];
  for (const value of cases) {
    const input = { adapterToken: "resolved-token", ...value };
    const result = validateJsonSchemaValue({
      schema: manifest.configSchema,
      cacheKey: "agentguard-p0-config-hydration",
      value: input,
      applyDefaults: true,
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    for (const field of migrationFields) {
      assert.equal(
        Object.hasOwn(result.value, field),
        Object.hasOwn(input, field),
        `Host must preserve the presence of ${field}`,
      );
    }
    if (Object.hasOwn(value, "officialProfileId")) {
      assert.throws(
        () => buildPluginConfig(result.value),
        /officialProfileId activation is not available/,
      );
      continue;
    }
    const config = buildPluginConfig(result.value);
    assert.equal(
      config.strongApprovalBindingEnabled,
      value.strongApprovalBindingEnabled ?? false,
    );
    assert.equal(config.restrictedAskReleaseEnabled, false);
    assert.equal(config.activationAckMaxAgeMs, 120000);
  }
});

test("pinned Host schema rejects malformed new configuration fields", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("openclaw.plugin.json", packageRoot), "utf8"),
  );
  for (const invalid of [
    { officialProfileId: "" },
    { officialProfileId: "another-profile" },
    { officialProfileId: false },
    { officialProfileDigest: "" },
    { officialProfileDigest: `sha256:${"A".repeat(64)}` },
    { officialProfileDigest: 1 },
    { restrictedAskReleaseEnabled: "false" },
    { restrictedAskReleaseEnabled: 0 },
    { activationAckMaxAgeMs: 0 },
    { activationAckMaxAgeMs: 120001 },
    { activationAckMaxAgeMs: 1.5 },
    { activationAckMaxAgeMs: "120000" },
  ]) {
    const result = validateJsonSchemaValue({
      schema: manifest.configSchema,
      cacheKey: "agentguard-p0-config-hydration",
      value: { adapterToken: "resolved-token", ...invalid },
      applyDefaults: true,
    });
    assert.equal(result.ok, false, `Host accepted ${JSON.stringify(invalid)}`);
  }
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
