import assert from "node:assert/strict";
import test from "node:test";

import {
  OPENCLAW_PRODUCT_CORE_SOURCE_ID,
  OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID,
  OPENCLAW_PRODUCT_RUNTIME_VERSION,
  OPENCLAW_PRODUCT_TOOL_IDS,
  ProductInventoryError,
  buildOpenClawProductInventory,
  collectOpenClawProductInventory,
} from "../dist/runtime/product-inventory.js";

const SCHEMA = {
  type: "object",
  properties: { value: { type: "string" } },
  required: ["value"],
  additionalProperties: false,
};
const ORDER = [
  OPENCLAW_PRODUCT_CORE_SOURCE_ID,
  OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID,
];

function descriptors() {
  return OPENCLAW_PRODUCT_TOOL_IDS.map((name) => ({
    name,
    parameters: structuredClone(SCHEMA),
    sourcePluginId: name.startsWith("agentguard_memory_")
      ? OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID
      : OPENCLAW_PRODUCT_CORE_SOURCE_ID,
  }));
}

function build(tools = descriptors(), options = {}) {
  return buildOpenClawProductInventory({
    tools,
    pluginOrder: ORDER,
    ...options,
  });
}

function rejected(failure) {
  return (error) => {
    assert.ok(error instanceof ProductInventoryError);
    assert.equal(error.failure, failure);
    assert.equal(error.message, `Product inventory rejected: ${failure}`);
    assert.equal(Object.hasOwn(error, "cause"), false);
    assert.equal(
      JSON.stringify(error).includes("private-schema-secret"),
      false,
    );
    return true;
  };
}

test("inventory matches independently generated Python frozen-contract digests", () => {
  // Generated with OpenClawFrozenToolV1 + build_openclaw_inventory_digests,
  // not with the JavaScript implementation under test.
  const inventory = build();
  assert.deepEqual(inventory.digests, {
    schema_version: "1.0",
    host_inventory_digest:
      "sha256:6fa621a89b1bab2f7f764aa1e3fd9c032a1fcd39a449f962c0aa77292c93ebea",
    plugin_inventory_digest:
      "sha256:a8c756ec9043c01e7f2f251d070d0f42a2f8a53af73c5674797ce5950c414199",
    plugin_order_inventory_digest:
      "sha256:7a3b6bd031ddab5a605bb65880442ccee0da89c2adb062b5c8dc79525ef0461f",
    tool_inventory_digest:
      "sha256:489229d091d8b98dd7c18d6b51f6bf447f34a5b8474dbc56d64ef49d47bc0484",
  });
  assert.equal(inventory.tools.length, 8);
  for (const tool of inventory.tools) {
    assert.equal(
      tool.input_schema_digest,
      "sha256:12ed9447fbbb261381b19f521a226cefef9dd3f6250b42a14873a051886c18e7",
    );
    assert.equal(tool.fixture_id, `openclaw:${tool.tool_id}:restricted-v1`);
    assert.equal(
      tool.event_type,
      tool.tool_id === "agentguard_memory_write"
        ? "memory_write_proposed"
        : "tool_call_proposed",
    );
  }
});

test("tool enumeration is canonical but source-plugin order remains semantic", () => {
  const baseline = build();
  assert.deepEqual(build(descriptors().reverse()).digests, baseline.digests);
  const reordered = build(descriptors(), { pluginOrder: [...ORDER].reverse() });
  for (const field of [
    "host_inventory_digest",
    "plugin_inventory_digest",
    "tool_inventory_digest",
  ]) {
    assert.equal(reordered.digests[field], baseline.digests[field]);
  }
  assert.notEqual(
    reordered.digests.plugin_order_inventory_digest,
    baseline.digests.plugin_order_inventory_digest,
  );
});

test("actual parameter changes alter the schema and tool digests only", () => {
  const baseline = build();
  const tools = descriptors();
  tools.find(
    (tool) => tool.name === "exec",
  ).parameters.properties.value.maxLength = 16;
  const changed = build(tools);
  assert.notEqual(
    changed.tools.find((tool) => tool.tool_id === "exec").input_schema_digest,
    baseline.tools.find((tool) => tool.tool_id === "exec").input_schema_digest,
  );
  assert.notEqual(
    changed.digests.tool_inventory_digest,
    baseline.digests.tool_inventory_digest,
  );
  assert.equal(
    changed.digests.host_inventory_digest,
    baseline.digests.host_inventory_digest,
  );
});

test("inventory retains an immutable schema snapshot without freezing Host objects", () => {
  const input = descriptors();
  const inventory = build(input);
  input[0].parameters.properties.value.type = "integer";
  assert.equal(
    inventory.inputSchemas.agentguard_memory_read.properties.value.type,
    "string",
  );
  assert.equal(Object.isFrozen(input[1].parameters), false);
  for (const value of [
    inventory,
    inventory.tools,
    inventory.tools[0],
    inventory.pluginOrder,
    inventory.digests,
    inventory.inputSchemas,
    inventory.inputSchemas.read.properties,
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
});

test("missing, duplicate, and unexpected runtime tools are rejected without filtering", () => {
  assert.throws(() => build(descriptors().slice(1)), rejected("missing_tool"));
  assert.throws(
    () => build([...descriptors(), descriptors()[0]]),
    rejected("duplicate_tool"),
  );
  assert.throws(
    () =>
      build([
        ...descriptors(),
        { ...descriptors()[0], name: "memory_write_hidden" },
      ]),
    rejected("unexpected_tool"),
  );
  assert.throws(() => build(null), rejected("invalid_descriptor"));
});

test("memory and core tool ownership must match the independently fixed profile", () => {
  for (const name of ["agentguard_memory_write", "exec"]) {
    const tools = descriptors();
    tools.find((tool) => tool.name === name).sourcePluginId = "impostor";
    assert.throws(() => build(tools), rejected("owner_mismatch"));
  }
  assert.throws(
    () => build(descriptors(), { memoryToolPluginId: "impostor" }),
    rejected("owner_mismatch"),
  );
});

test("plugin order must contain each source exactly once", () => {
  for (const pluginOrder of [
    [],
    [ORDER[0]],
    [...ORDER, "unknown"],
    [ORDER[0], ORDER[0]],
    null,
  ]) {
    assert.throws(
      () => build(descriptors(), { pluginOrder }),
      rejected("invalid_plugin_order"),
    );
  }
});

test("missing or noncanonical schemas fail closed without schema error disclosure", () => {
  const cyclic = {};
  cyclic.self = cyclic;
  const sparse = [];
  sparse.length = 2;
  const invalid = [
    undefined,
    null,
    [],
    "private-schema-secret",
    { multipleOf: 0.5 },
    { x: NaN },
    { x: -0 },
    { x: "\ud800" },
    { x: cyclic },
    { x: sparse },
    { x: new Date() },
    { [Symbol("unknown")]: true },
    { x: undefined },
  ];
  for (const parameters of invalid) {
    const tools = descriptors();
    tools[0].parameters = parameters;
    assert.throws(() => build(tools), rejected("invalid_schema"));
  }
});

test("schema and descriptor accessors are never invoked", () => {
  let called = 0;
  const parameters = {
    type: "object",
    get properties() {
      called += 1;
      throw Error("private-schema-secret");
    },
  };
  const tools = descriptors();
  tools[0].parameters = parameters;
  assert.throws(() => build(tools), rejected("invalid_schema"));
  Object.defineProperty(tools[0], "name", {
    get() {
      called += 1;
      return "read";
    },
  });
  assert.throws(() => build(tools), rejected("invalid_descriptor"));
  assert.equal(called, 0);
});

function sdkFixture(overrides = {}) {
  let executions = 0;
  const tools = descriptors().map(({ name, parameters, sourcePluginId }) => ({
    name,
    parameters,
    sourcePluginId,
    execute() {
      executions += 1;
      throw Error("tool execution is forbidden in inventory");
    },
  }));
  const sdk = {
    createOpenClawCodingTools: () => tools,
    inspectRuntimeToolInputSchemas: () => [],
    normalizeAgentRuntimeTools: ({ tools }) => tools,
    getPluginToolMeta: (tool) =>
      tool.sourcePluginId === OPENCLAW_PRODUCT_CORE_SOURCE_ID
        ? undefined
        : { pluginId: tool.sourcePluginId },
    projectRuntimeToolInputSchema: (parameters) => ({
      schema: parameters,
      violations: [],
    }),
    ...overrides,
  };
  return { sdk, tools, executions: () => executions };
}

function collect(sdk, changes = {}) {
  return collectOpenClawProductInventory({
    runtimeVersion: OPENCLAW_PRODUCT_RUNTIME_VERSION,
    sdk,
    toolOptions: {
      agentId: "acceptance",
      workspaceDir: "/isolated-workspace",
      modelProvider: "offline",
    },
    pluginOrder: ORDER,
    ...changes,
  });
}

test("SDK collection constructs real descriptors but never calls their execute methods", async () => {
  const fixture = sdkFixture();
  assert.deepEqual((await collect(fixture.sdk)).digests, build().digests);
  assert.equal(fixture.executions(), 0);
});

test("unsupported Host versions are rejected before invoking the SDK", async () => {
  let called = 0;
  const { sdk } = sdkFixture({
    createOpenClawCodingTools: () => {
      called += 1;
      return [];
    },
  });
  await assert.rejects(
    collect(sdk, { runtimeVersion: "2026.6.6" }),
    rejected("unsupported_runtime"),
  );
  assert.equal(called, 0);
});

test("SDK exceptions and diagnostics are redacted, not converted to empty success", async () => {
  const throwing = sdkFixture({
    createOpenClawCodingTools: () => {
      throw Error("private-schema-secret");
    },
  });
  await assert.rejects(
    collect(throwing.sdk),
    rejected("sdk_collection_failed"),
  );
  const incompatible = sdkFixture({
    inspectRuntimeToolInputSchemas: () => [
      { message: "private-schema-secret" },
    ],
  });
  await assert.rejects(collect(incompatible.sdk), rejected("invalid_schema"));
});

test("provider normalization cannot silently drop, replace, or reassign tools", async () => {
  const missing = sdkFixture({
    normalizeAgentRuntimeTools: ({ tools }) => tools.slice(1),
  });
  await assert.rejects(collect(missing.sdk), rejected("missing_tool"));
  const owner = sdkFixture({
    normalizeAgentRuntimeTools: ({ tools }) =>
      tools.map((tool) => ({ ...tool, sourcePluginId: "impostor" })),
  });
  await assert.rejects(collect(owner.sdk), rejected("owner_mismatch"));
  const unknown = sdkFixture({
    normalizeAgentRuntimeTools: ({ tools }) => [
      ...tools,
      { ...tools[0], name: "unknown" },
    ],
  });
  await assert.rejects(collect(unknown.sdk), rejected("unexpected_tool"));
});

test("collection hashes the actual provider-normalized descriptor schema", async () => {
  const fixture = sdkFixture({
    normalizeAgentRuntimeTools: ({ tools }) =>
      tools.map((tool) => ({
        ...tool,
        parameters: { ...tool.parameters, additionalProperties: true },
      })),
  });
  const result = await collect(fixture.sdk);
  assert.equal(result.inputSchemas.read.additionalProperties, true);
  assert.notEqual(
    result.digests.tool_inventory_digest,
    build().digests.tool_inventory_digest,
  );
});

test("pinned public schema projection handles actual TypeBox metadata without retaining symbols", async () => {
  const host = await import("openclaw/plugin-sdk/agent-harness");
  const { sdk, tools } = sdkFixture({
    projectRuntimeToolInputSchema: host.projectRuntimeToolInputSchema,
    inspectRuntimeToolInputSchemas: host.inspectRuntimeToolInputSchemas,
  });
  for (const tool of tools)
    tool.parameters[Symbol.for("TypeBox.Kind")] = "Object";
  const result = await collect(sdk);
  assert.deepEqual(result.digests, build().digests);
  assert.equal(
    Object.getOwnPropertySymbols(result.inputSchemas.read).length,
    0,
  );
});
