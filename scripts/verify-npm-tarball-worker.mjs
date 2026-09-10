/** A separate process per installed Host; never resolve dependencies from this repository. */
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const NPM_CANDIDATE_VERSION = "0.1.0-rc.1";
export const SDK_VERSIONS = Object.freeze(["2026.6.6", "2026.7.1-2"]);
const PACKAGE = "@agentguard-ai/openclaw-plugin";
const PRODUCT_ID = "agentguard-product-runtime-fixture";
const TARGET = "fixture-inbox@agentguard.invalid";
const TOOL_IDS = Object.freeze([
  "agentguard_memory_read",
  "agentguard_memory_write",
  "edit",
  "exec",
  "message",
  "process",
  "read",
  "write",
]);
const EVENTS = Object.freeze([
  "context_assembled",
  "memory_write_proposed",
  "message_send_proposed",
  "model_input_prepared",
  "model_output_produced",
  "tool_call_proposed",
  "tool_result_produced",
]);
const RESIDUALS = Object.freeze([
  "openclaw_has_no_authoritative_invocation_start_hook",
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
  "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
  "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
  "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
]);
export const REQUIRED_PACKAGE_FILES = Object.freeze([
  "package.json",
  "openclaw.plugin.json",
  "LICENSE",
  "dist/index.js",
  "dist/runtime/product-composition.js",
  "dist/runtime/product-candidate.js",
  "dist/runtime/product-host-loader.js",
  "product-runtime/product/package.json",
  "product-runtime/product/openclaw.plugin.json",
  "product-runtime/product/index.mjs",
  "product-runtime/profile.mjs",
  "product-runtime/profile.d.mts",
  "product-runtime/factory.mjs",
  "product-runtime/factory.d.mts",
  "product-runtime/inbox.mjs",
  "product-runtime/inbox.d.mts",
  "product-runtime/message-permits.mjs",
  "product-runtime/message-permits.d.mts",
  "product-runtime/memory.mjs",
  "product-runtime/marker.mjs",
]);
const MAX_FILE = 8 * 1024 * 1024;
export const rawDigest = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const canonical = (value) =>
  JSON.stringify(
    value && typeof value === "object"
      ? Array.isArray(value)
        ? value.map((entry) => JSON.parse(canonical(entry)))
        : Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((key) => [key, JSON.parse(canonical(value[key]))]),
          )
      : value,
  );
function fail(code) {
  throw new Error(code);
}
function assert(condition, code) {
  if (!condition) fail(code);
}
function same(value, expected, code) {
  assert(canonical(value) === canonical(expected), code);
}
export function assertInstallationLocation(filename, installRoot) {
  const relative = path.relative(installRoot, filename);
  assert(
    relative !== "" &&
      !relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative),
    "npm_install_outside_lane",
  );
}
export async function readBoundedRegular(filename, maximum = MAX_FILE) {
  const handle = await open(
    filename,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    assert(
      before.isFile() &&
        before.nlink === 1n &&
        before.size > 0n &&
        before.size <= BigInt(maximum),
      "npm_installed_file_invalid",
    );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < bytes.length) {
      const result = await handle.read(bytes, used, bytes.length - used, null);
      if (result.bytesRead === 0) break;
      used += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true }),
      named = await lstat(filename, { bigint: true });
    for (const key of [
      "dev",
      "ino",
      "nlink",
      "uid",
      "size",
      "mtimeNs",
      "ctimeNs",
      "mode",
    ])
      assert(
        before[key] === after[key] && after[key] === named[key],
        "npm_installed_file_changed",
      );
    assert(
      !named.isSymbolicLink() && BigInt(used) === before.size,
      "npm_installed_file_changed",
    );
    return bytes.subarray(0, used);
  } finally {
    await handle.close();
  }
}
const file = readBoundedRegular;
export function validateInstalledMetadata(material, hostVersion) {
  assert(SDK_VERSIONS.includes(hostVersion), "npm_host_version_invalid");
  for (const key of [
    "package",
    "manifest",
    "productPackage",
    "productManifest",
  ])
    assert(
      material[key]?.version === NPM_CANDIDATE_VERSION,
      "npm_candidate_metadata_mismatch",
    );
  assert(
    material.package.name === PACKAGE &&
      material.manifest.id === "agentguard-security" &&
      material.productPackage.name ===
        "@agentguard-ai/openclaw-product-runtime" &&
      material.productManifest.id === PRODUCT_ID,
    "npm_candidate_identity_mismatch",
  );
  assert(
    material.host?.name === "openclaw" && material.host.version === hostVersion,
    "npm_host_version_mismatch",
  );
  const version = [
    ...material.compiledEntry.matchAll(/const PLUGIN_VERSION = "([^"]+)";/gu),
  ];
  assert(
    version.length === 1 && version[0][1] === NPM_CANDIDATE_VERSION,
    "npm_compiled_version_mismatch",
  );
  const factory = [...material.factory.matchAll(/version: "([^"]+)"/gu)];
  assert(
    factory.length === 1 && factory[0][1] === NPM_CANDIDATE_VERSION,
    "npm_product_factory_version_mismatch",
  );
}
export function validateProductInspection(observed, expected) {
  assert(
    observed.active === false &&
      observed.packageVersion === NPM_CANDIDATE_VERSION &&
      observed.runtimeVersion === SDK_VERSIONS[1] &&
      observed.artifactDigest === expected.artifactDigest,
    "npm_product_inspection_identity_mismatch",
  );
  const tools = observed.inventory?.tools;
  same(
    tools?.map((tool) => tool.tool_id),
    TOOL_IDS,
    "npm_product_tool_set_mismatch",
  );
  same(
    Object.keys(observed.inventory.input_schemas).sort(),
    TOOL_IDS,
    "npm_product_schema_set_mismatch",
  );
  same(
    observed.modelVisibleTools?.map((tool) => tool.name),
    TOOL_IDS,
    "npm_product_model_tools_mismatch",
  );
  for (const tool of tools) {
    const schema = observed.inventory.input_schemas[tool.tool_id];
    assert(
      tool.input_schema_digest === rawDigest(canonical(schema)),
      "npm_product_schema_digest_mismatch",
    );
    same(
      observed.modelVisibleTools.find((entry) => entry.name === tool.tool_id)
        .parameters,
      schema,
      "npm_product_model_schema_mismatch",
    );
    assert(
      tool.source_plugin_id ===
        (tool.tool_id.startsWith("agentguard_memory_")
          ? PRODUCT_ID
          : "openclaw-core"),
      "npm_product_tool_source_mismatch",
    );
  }
  same(
    observed.capabilityConsumers?.map((entry) => entry.event_type),
    EVENTS,
    "npm_product_consumers_mismatch",
  );
  same(
    observed.residualBoundaries,
    RESIDUALS,
    "npm_product_residuals_mismatch",
  );
  for (const consumer of observed.capabilityConsumers) {
    const post = ["model_output_produced", "tool_result_produced"].includes(
      consumer.event_type,
    );
    assert(
      consumer.enforcement ===
        (post ? "post_execution_isolation" : "pre_execution_c1"),
      "npm_product_binding_mismatch",
    );
    assert(
      consumer.c3_atomic_replace_and_seal !== true,
      "npm_product_binding_mismatch",
    );
    const residualIndexes = {
      context_assembled: [],
      memory_write_proposed: [0, 1, 3],
      message_send_proposed: [0, 1, 2],
      model_input_prepared: [],
      model_output_produced: [],
      tool_call_proposed: [0, 1],
      tool_result_produced: [4],
    };
    same(
      consumer.residual_boundaries,
      residualIndexes[consumer.event_type].map((index) => RESIDUALS[index]),
      "npm_product_consumer_residuals_mismatch",
    );
  }
  same(
    observed.execution,
    expected.execution,
    "npm_product_execution_mismatch",
  );
}
async function publishedFiles(root) {
  const files = [];
  async function visit(directory, depth = 0) {
    assert(depth <= 32 && files.length <= 8192, "npm_installed_tree_invalid");
    const stat = await lstat(directory);
    assert(
      stat.isDirectory() && !stat.isSymbolicLink(),
      "npm_installed_tree_invalid",
    );
    for (const entry of (
      await readdir(directory, { withFileTypes: true })
    ).sort((a, b) => a.name.localeCompare(b.name))) {
      if (directory === root && entry.name === "node_modules") continue;
      const filename = path.join(directory, entry.name);
      assert(!entry.isSymbolicLink(), "npm_installed_tree_invalid");
      if (entry.isDirectory()) await visit(filename, depth + 1);
      else {
        const bytes = await file(filename);
        files.push({
          path: filename,
          size: bytes.length,
          raw_sha256: rawDigest(bytes),
        });
      }
    }
  }
  await visit(root);
  assert(files.length <= 8192, "npm_installed_tree_invalid");
  return files;
}
let verificationStage = "input";
async function verifyLane(input) {
  verificationStage = "installed_metadata";
  const installRoot = await realpath(input.installRoot);
  assert(installRoot === input.installRoot, "npm_install_root_invalid");
  const requireInstalled = createRequire(
    path.join(installRoot, "package.json"),
  );
  const packageRoot = await realpath(
    path.dirname(requireInstalled.resolve(`${PACKAGE}/package.json`)),
  );
  assertInstallationLocation(packageRoot, installRoot);
  const hostSdk = await realpath(
    requireInstalled.resolve("openclaw/plugin-sdk/agent-harness"),
  );
  assertInstallationLocation(hostSdk, installRoot);
  const hostRoot = path.dirname(path.dirname(path.dirname(hostSdk)));
  const bytesByPath = new Map();
  for (const name of REQUIRED_PACKAGE_FILES)
    bytesByPath.set(name, await file(path.join(packageRoot, name)));
  const json = (name) => JSON.parse(bytesByPath.get(name).toString("utf8"));
  validateInstalledMetadata(
    {
      package: json("package.json"),
      manifest: json("openclaw.plugin.json"),
      productPackage: json("product-runtime/product/package.json"),
      productManifest: json("product-runtime/product/openclaw.plugin.json"),
      host: JSON.parse(
        (await file(path.join(hostRoot, "package.json"))).toString("utf8"),
      ),
      compiledEntry: bytesByPath.get("dist/index.js").toString("utf8"),
      factory: bytesByPath.get("product-runtime/factory.mjs").toString("utf8"),
    },
    input.hostVersion,
  );
  verificationStage = "compatibility_import";
  const entry = await import(
    pathToFileURL(path.join(packageRoot, "dist/index.js")).href
  );
  assert(
    entry.default?.id === "agentguard-security" &&
      typeof entry.default.register === "function",
    "npm_compatibility_entry_missing",
  );
  const report = {
    runtime_version: input.hostVersion,
    package_version: NPM_CANDIDATE_VERSION,
    installation_root: installRoot,
    plugin_root: packageRoot,
    runtime_root: hostRoot,
    artifact_digest: input.artifactDigest,
    files: await publishedFiles(packageRoot),
    compatibility_import: true,
    product_inspection: null,
    product_active_enabled: false,
  };
  if (input.hostVersion === SDK_VERSIONS[1]) {
    const importPackage = (name) =>
      import(pathToFileURL(path.join(packageRoot, name)).href);
    const production = await importPackage("product-runtime/profile.mjs");
    const composition = await importPackage(
      "dist/runtime/product-composition.js",
    );
    const productEntry = await importPackage(
      "product-runtime/product/index.mjs",
    );
    assert(
      typeof production.createProductRuntimeProfile === "function" &&
        typeof composition.inspectOpenClawProductRuntime === "function" &&
        typeof composition.createOpenClawProductRuntime === "function" &&
        productEntry.default?.id === PRODUCT_ID &&
        typeof productEntry.default.register === "function",
      "npm_product_entry_missing",
    );
    const profileRoot = path.join(installRoot, "product-inspection");
    await mkdir(profileRoot, { mode: 0o700 });
    verificationStage = "product_profile";
    const profile = await production.createProductRuntimeProfile({
      root: profileRoot,
      inboxUrl: "http://127.0.0.1:9/inbox",
      runManifestPath: path.join(profileRoot, "not-issued-run.json"),
      provider: {
        id: "agentguard-acceptance",
        modelId: "package-inspection",
        baseUrl: "http://127.0.0.1:9/v1",
        apiKey: {
          source: "env",
          provider: "default",
          id: "UNUSED_PACKAGE_INSPECTION_TOKEN",
        },
      },
    });
    assert(
      profile.inboxTarget === TARGET &&
        profile.toolOptions.messageTo === TARGET,
      "npm_product_target_mismatch",
    );
    verificationStage = "product_inspection";
    const observed = await composition.inspectOpenClawProductRuntime({
      profileConfigPath: profile.configPath,
      candidateTgzPath: input.candidateTgzPath,
    });
    validateProductInspection(observed, {
      artifactDigest: input.artifactDigest,
      execution: {
        root: profile.workspaceDir,
        memory_namespace: path.join(profile.workspaceDir, "memory.sqlite"),
        inbox_url: profile.inboxUrl,
        script_digest: rawDigest(bytesByPath.get("product-runtime/marker.mjs")),
      },
    });
    const { buildOpenClawProductInventory } = await importPackage(
      "dist/runtime/product-inventory.js",
    );
    const rebuilt = buildOpenClawProductInventory({
      tools: observed.inventory.tools.map((tool) => ({
        name: tool.tool_id,
        sourcePluginId: tool.source_plugin_id,
        parameters: observed.inventory.input_schemas[tool.tool_id],
      })),
      pluginOrder: observed.inventory.plugin_order,
    });
    same(
      rebuilt.tools,
      observed.inventory.tools,
      "npm_product_inventory_tools_mismatch",
    );
    same(
      rebuilt.digests,
      observed.digests,
      "npm_product_inventory_digest_mismatch",
    );
    report.product_inspection = observed;
  }
  await writeFile(input.outputPath, JSON.stringify(report) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      assert(size <= 16 * 1024, "npm_worker_input_invalid");
      chunks.push(chunk);
    }
    const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    await verifyLane(input);
  } catch (error) {
    const code = /^npm_[a-z_]+$/u.test(error?.message ?? "")
      ? error.message
      : /^product_[a-z_]+$/u.test(error?.message ?? "")
        ? `npm_${error.message}`
        : `npm_${verificationStage}_failed`;
    process.stderr.write(code + "\n");
    process.exitCode = 1;
  }
}
