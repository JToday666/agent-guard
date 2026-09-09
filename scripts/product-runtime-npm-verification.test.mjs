import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  NPM_CANDIDATE_VERSION,
  SDK_VERSIONS,
  assertInstallationLocation,
  rawDigest,
  readBoundedRegular,
  validateInstalledMetadata,
  validateProductInspection,
} from "./verify-npm-tarball-worker.mjs";
import {
  installationEnvironment,
  verifyTarball,
  spawnWithProtectedUmask,
} from "./verify-npm-tarball.mjs";
const VERSION = NPM_CANDIDATE_VERSION;
const PLUGIN = "agentguard-product-runtime-fixture";
const TOOLS = [
  "agentguard_memory_read",
  "agentguard_memory_write",
  "edit",
  "exec",
  "message",
  "process",
  "read",
  "write",
];
const RESIDUALS = [
  "openclaw_has_no_authoritative_invocation_start_hook",
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
  "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
  "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
  "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
];
function metadata(version = SDK_VERSIONS[1]) {
  return {
    package: { name: "@agentguard-ai/openclaw-plugin", version: VERSION },
    manifest: { id: "agentguard-security", version: VERSION },
    productPackage: {
      name: "@agentguard-ai/openclaw-product-runtime",
      version: VERSION,
    },
    productManifest: { id: PLUGIN, version: VERSION },
    compiledEntry: `const PLUGIN_VERSION = "${VERSION}";`,
    factory: `version: "${VERSION}"`,
    host: { name: "openclaw", version },
  };
}
function inspection() {
  const parameters = { type: "object" };
  const consumerResiduals = {
    context_assembled: [],
    memory_write_proposed: [0, 1, 3],
    message_send_proposed: [0, 1, 2],
    model_input_prepared: [],
    model_output_produced: [],
    tool_call_proposed: [0, 1],
    tool_result_produced: [4],
  };
  const execution = {
    root: "/isolated/workspace",
    memory_namespace: "/isolated/workspace/memory.sqlite",
    inbox_url: "http://127.0.0.1:9/inbox",
    script_digest: rawDigest("script"),
  };
  return {
    active: false,
    packageVersion: VERSION,
    runtimeVersion: SDK_VERSIONS[1],
    artifactDigest: rawDigest("actual archive"),
    execution,
    inventory: {
      tools: TOOLS.map((tool_id) => ({
        tool_id,
        input_schema_digest: rawDigest(JSON.stringify(parameters)),
        source_plugin_id: tool_id.startsWith("agentguard_memory_")
          ? PLUGIN
          : "openclaw-core",
      })),
      input_schemas: Object.fromEntries(
        TOOLS.map((name) => [name, parameters]),
      ),
    },
    modelVisibleTools: TOOLS.map((name) => ({ name, parameters })),
    capabilityConsumers: Object.entries(consumerResiduals).map(
      ([event_type, indexes]) => ({
        event_type,
        enforcement: ["model_output_produced", "tool_result_produced"].includes(
          event_type,
        )
          ? "post_execution_isolation"
          : "pre_execution_c1",
        residual_boundaries: indexes.map((index) => RESIDUALS[index]),
      }),
    ),
    residualBoundaries: [...RESIDUALS],
  };
}
for (const version of SDK_VERSIONS)
  test(`installed metadata validates actual ${version} with all rc1 identities`, () =>
    validateInstalledMetadata(metadata(version), version));
for (const key of ["package", "manifest", "productPackage", "productManifest"])
  test(`stale ${key} is rejected even if the archive filename says rc1`, () => {
    const value = metadata();
    value[key].version = "0.1.0-beta.1";
    assert.throws(
      () => validateInstalledMetadata(value, SDK_VERSIONS[1]),
      /npm_candidate_metadata_mismatch/,
    );
  });
for (const key of ["package", "productPackage", "manifest", "productManifest"])
  test(`wrong installed ${key} identity is rejected`, () => {
    const value = metadata();
    value[key][key.includes("Package") || key === "package" ? "name" : "id"] =
      "impostor";
    assert.throws(
      () => validateInstalledMetadata(value, SDK_VERSIONS[1]),
      /npm_candidate_identity_mismatch/,
    );
  });
for (const variant of [
  "host",
  "compiled",
  "duplicate_compiled",
  "factory",
  "duplicate_factory",
])
  test(`installed ${variant} drift is rejected`, () => {
    const value = metadata();
    if (variant === "host") value.host.version = SDK_VERSIONS[0];
    if (variant === "compiled")
      value.compiledEntry = 'const PLUGIN_VERSION = "0.1.0-beta.1";';
    if (variant === "duplicate_compiled")
      value.compiledEntry += value.compiledEntry;
    if (variant === "factory") value.factory = 'version: "0.1.0"';
    if (variant === "duplicate_factory") value.factory += value.factory;
    assert.throws(
      () => validateInstalledMetadata(value, SDK_VERSIONS[1]),
      /npm_.*_mismatch/,
    );
  });
test("inactive Product inspection checks exact tool/model schemas, consumers and residuals", () => {
  const value = inspection();
  validateProductInspection(value, {
    artifactDigest: value.artifactDigest,
    execution: value.execution,
  });
});
const inspectionMutations = {
  active: (value) => {
    value.active = true;
  },
  digest: (value) => {
    value.artifactDigest = rawDigest("different");
  },
  missing_tool: (value) => {
    value.inventory.tools.pop();
  },
  duplicate_tool: (value) => {
    value.inventory.tools[1] = value.inventory.tools[0];
  },
  schema: (value) => {
    value.inventory.input_schemas.read = { type: "string" };
  },
  visible_schema: (value) => {
    value.modelVisibleTools[0].parameters = { type: "string" };
  },
  source: (value) => {
    value.inventory.tools[0].source_plugin_id = "other";
  },
  missing_consumer: (value) => {
    value.capabilityConsumers.pop();
  },
  missing_residual: (value) => {
    value.residualBoundaries.pop();
  },
  consumer_residual: (value) => {
    value.capabilityConsumers[1].residual_boundaries = [];
  },
  strong_binding: (value) => {
    value.capabilityConsumers[0].c3_atomic_replace_and_seal = true;
  },
  enforcement: (value) => {
    value.capabilityConsumers[0].enforcement = "strong";
  },
  execution_root: (value) => {
    value.execution.root = "/other";
  },
};
for (const [variant, mutate] of Object.entries(inspectionMutations))
  test(`Product inspection rejects ${variant} instead of admitting incomplete installation`, () => {
    const value = inspection(),
      expected = {
        artifactDigest: value.artifactDigest,
        execution: structuredClone(value.execution),
      };
    mutate(value);
    assert.throws(
      () => validateProductInspection(value, expected),
      /npm_product_/,
    );
  });
test("repository and sibling package roots cannot pass as isolated installed dependencies", () => {
  assertInstallationLocation(
    "/evidence/lane/node_modules/.pnpm/pkg/package",
    "/evidence/lane",
  );
  for (const value of [
    "/repository/package",
    "/evidence/lane",
    "/evidence/lane-other/package",
    "/evidence/other/package",
  ])
    assert.throws(
      () => assertInstallationLocation(value, "/evidence/lane"),
      /npm_install_outside_lane/,
    );
});
test("subprocess environment contains no inherited Host, Provider or runtime injection configuration", () => {
  const env = installationEnvironment(
    {
      PATH: "/bin",
      HOME: "/user",
      OPENCLAW_STATE_DIR: "/user/openclaw",
      NODE_OPTIONS: "private",
      NODE_PATH: "private",
      AGENTGUARD_LLM_API_KEY: "private",
      OPENAI_API_KEY: "private",
      AGENTGUARD_CONTROL_TOKEN: "private",
    },
    "/isolated/home",
  );
  assert.equal(env.HOME, "/isolated/home");
  assert.equal(env.PATH, "/bin");
  assert.equal(JSON.stringify(env).includes("private"), false);
  assert.equal(
    Object.keys(env).some((key) => key.startsWith("OPENCLAW")),
    false,
  );
});
test("bounded installed-file read rejects symlink, empty and oversized evidence", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "npm-evidence-unit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const regular = path.join(root, "regular"),
    link = path.join(root, "link"),
    empty = path.join(root, "empty");
  await writeFile(regular, "actual");
  await writeFile(empty, "");
  await symlink(regular, link);
  assert.equal((await readBoundedRegular(regular, 6)).toString(), "actual");
  for (const [filename, maximum] of [
    [link, 6],
    [empty, 6],
    [regular, 5],
  ])
    await assert.rejects(readBoundedRegular(filename, maximum));
});
test("persistent installation evidence requires both retained environment and full source SHA before installing", async () => {
  for (const options of [
    { reportPath: "/tmp/report" },
    { environmentRoot: "/tmp/env" },
    {
      reportPath: "/tmp/report",
      environmentRoot: "/tmp/env",
      sourceRevision: "short",
    },
  ])
    await assert.rejects(
      verifyTarball({ tarball: "/not-read.tgz", ...options }),
      /npm_persistent_evidence_options_invalid/,
    );
});

test("clean install subprocess receives protective umask without rewriting installed files or changing its caller", () => {
  const original = process.umask(0o002);
  try {
    const child = spawnWithProtectedUmask(
      process.execPath,
      ["-e", "process.stdout.write(process.umask().toString(8))"],
      { encoding: "utf8" },
    );
    assert.equal(child.status, 0);
    assert.equal(child.stdout, "22");
    assert.equal(process.umask(), 0o002);
  } finally {
    process.umask(original);
  }
});
