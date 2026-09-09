/** Real pinned CLI test driver; synthetic package metadata is explicitly test-only. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { appendFileSync } from "node:fs";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createSyntheticProductPackage } from "./openclaw-product-transport-package.mjs";
import {
  createProductRuntimeProfile,
  PRODUCT_FIXTURE_PLUGIN_ID,
} from "./openclaw-product-runtime/profile.mjs";

import { PRODUCT_INBOX_TARGET } from "./openclaw-product-runtime/inbox.mjs";

const helperPath = fileURLToPath(
  new URL("./openclaw-product-native-plugin.mjs", import.meta.url),
);
const fixturePath = fileURLToPath(
  new URL("./openclaw-product-runtime/", import.meta.url),
);
const script =
  "import fs from 'node:fs';\nconst p = 'command-marker.txt';\nconst fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);\ntry { fs.writeSync(fd, 'isolated command executed\\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }\nprocess.stdout.write(JSON.stringify({ok: true, marker: p}) + '\\n');\n";
const privateJson = (file, data) =>
  writeFile(file, JSON.stringify(data), { mode: 0o600, flag: "wx" });
let stage = "input";

function isolatedEnv(profile) {
  const env = {};
  for (const key of [
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "NODE_EXTRA_CA_CERTS",
  ])
    if (process.env[key]) env[key] = process.env[key];
  return {
    ...env,
    ...profile.env,
    OPENCLAW_AGENT_DIR: profile.agentDir,
    NO_COLOR: "1",
    FORCE_COLOR: "0",
  };
}
async function prepare(input) {
  stage = "prepare-package";
  const root = await realpath(input.root);
  if (root !== input.root) throw new Error("native_test_root_invalid");
  const packageFixture = await createSyntheticProductPackage({
    directory: path.join(root, "synthetic-sdk"),
  });
  const requirePackage = createRequire(
    path.join(packageFixture.packageRoot, "package.json"),
  );
  const sdkPath = requirePackage.resolve("openclaw/plugin-sdk/agent-harness");
  const hostRoot = await realpath(
    path.join(packageFixture.packageRoot, "node_modules", "openclaw"),
  );
  const pluginRoot = path.join(root, "native-plugin");
  await mkdir(pluginRoot, { mode: 0o700 });
  const preparedPath = path.join(root, "prepared.json"),
    runtimePath = path.join(root, "runtime.json");
  const manifest = JSON.parse(
    await readFile(path.join(fixturePath, "openclaw.plugin.json"), "utf8"),
  );
  manifest.configSchema.properties.inboxTarget = {
    type: "string",
    const: PRODUCT_INBOX_TARGET,
    default: PRODUCT_INBOX_TARGET,
  };
  manifest.providers = ["agentguard-acceptance"];
  manifest.contracts.agentToolResultMiddleware = ["openclaw"];
  await privateJson(path.join(pluginRoot, "openclaw.plugin.json"), manifest);
  await privateJson(path.join(pluginRoot, "package.json"), {
    name: "agentguard-native-loop-test",
    version: "0.0.0",
    type: "module",
    openclaw: { extensions: ["./index.mjs"] },
  });
  // Same real plugin entry, with a private file selecting the test assembly phase.
  await writeFile(
    path.join(pluginRoot, "index.mjs"),
    `import { existsSync } from 'node:fs';\nimport { createNativeLoopPlugin } from ${JSON.stringify(pathToFileURL(helperPath).href)};\nexport default createNativeLoopPlugin(${JSON.stringify(preparedPath)}, existsSync(${JSON.stringify(runtimePath)}) ? ${JSON.stringify(runtimePath)} : undefined);\n`,
    { mode: 0o600, flag: "wx" },
  );
  const modelId = input.modelId ?? "inventory-probe";
  const profile = await createProductRuntimeProfile({
    root,
    fixturePluginPath: pluginRoot,
    modelBaseUrl: input.modelBaseUrl,
    inboxUrl: input.inboxUrl,
    modelId,
  });
  // This test assembly uses Product mode; the shared B01 factory stays legacy.
  profile.config.plugins.entries[PRODUCT_FIXTURE_PLUGIN_ID].config.inboxTarget =
    PRODUCT_INBOX_TARGET;
  profile.toolOptions.messageTo = PRODUCT_INBOX_TARGET;
  profile.config.agents.defaults.model.fallbacks = [];
  profile.config.agents.defaults.envelopeTimestamp = "off";
  await writeFile(profile.configPath, JSON.stringify(profile.config), {
    mode: 0o600,
  });
  await writeFile(
    path.join(profile.workspaceDir, "fixture.txt"),
    "native-loop-safe\n",
    { mode: 0o600, flag: "wx" },
  );
  await writeFile(path.join(profile.workspaceDir, "marker.mjs"), script, {
    mode: 0o600,
    flag: "wx",
  });
  const staged = {
    root,
    profile,
    packageRoot: packageFixture.packageRoot,
    hostRoot,
    modelId,
    modelBaseUrl: input.modelBaseUrl,
    inboxUrl: input.inboxUrl,
  };
  // Initial assembly is inventory-only; no SDK client or stream is entered.
  await privateJson(preparedPath, staged);
  Object.assign(process.env, isolatedEnv(profile));
  stage = "prepare-register";
  const sdk = await import(pathToFileURL(sdkPath).href);
  const loader = await import(
    pathToFileURL(path.join(hostRoot, "dist/plugins/loader.js")).href
  );
  const quiet = { info() {}, warn() {}, error() {}, debug() {} };
  const registry = loader.loadOpenClawPlugins({
    config: profile.config,
    workspaceDir: profile.workspaceDir,
    env: isolatedEnv(profile),
    cache: false,
    activate: true,
    forceFullRuntimeForChannelPlugins: true,
    onlyPluginIds: [PRODUCT_FIXTURE_PLUGIN_ID],
    throwOnLoadError: true,
    logger: quiet,
  });
  if (
    registry.plugins.filter((p) => p.status === "loaded").length !== 1 ||
    registry.providers.filter((p) => p.provider.id === "agentguard-acceptance")
      .length !== 1 ||
    registry.agentToolResultMiddlewares.length !== 1
  )
    throw new Error("native_test_registration_missing");
  stage = "prepare-inventory";
  const tools = sdk.createOpenClawCodingTools(profile.toolOptions);
  const pluginOrder = [
    ...new Set(
      tools.map((t) => sdk.getPluginToolMeta(t)?.pluginId ?? "openclaw-core"),
    ),
  ];
  const inventoryModule = await import(
    pathToFileURL(
      path.join(
        packageFixture.packageRoot,
        "dist/runtime/product-inventory.js",
      ),
    ).href
  );
  const collected = await inventoryModule.collectOpenClawProductInventory({
    runtimeVersion: "2026.7.1-2",
    sdk,
    toolOptions: profile.toolOptions,
    pluginOrder,
    normalizationOptions: { allowProviderRuntimePluginLoad: false },
  });
  // The pinned native model context orders descriptors by tool name. Inventory
  // plugin group order remains the independent first-seen catalog evidence.
  const modelVisible = tools
    .map((tool) => ({
      name: tool.name,
      description: tool.description,
      parameters: collected.inputSchemas[tool.name],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const inventory = {
    tools: collected.tools,
    input_schemas: collected.inputSchemas,
    plugin_order: collected.pluginOrder,
  };
  const execution = {
    root: profile.workspaceDir,
    memory_namespace: path.join(profile.workspaceDir, "memory.sqlite"),
    inbox_url: input.inboxUrl,
    script_digest: `sha256:${createHash("sha256").update(script).digest("hex")}`,
  };
  const completed = {
    ...staged,
    inventory,
    execution,
    model_visible_tools: modelVisible,
    digests: collected.digests,
  };
  await writeFile(preparedPath, JSON.stringify(completed), { mode: 0o600 });
  return {
    phase: "prepare",
    profile: {
      agentId: profile.agentId,
      sessionId: profile.sessionId,
      sessionKey: profile.sessionKey,
      agentDir: profile.agentDir,
      workspaceDir: profile.workspaceDir,
      configPath: profile.configPath,
    },
    execution,
    inventory,
    digests: collected.digests,
    model_visible_tools: modelVisible,
    synthetic_metadata: true,
    external_provider_requests: 0,
  };
}
async function run(input) {
  stage = "run-load";
  const prepared = JSON.parse(
    await readFile(path.join(input.root, "prepared.json"), "utf8"),
  );
  const { profile } = prepared;
  await privateJson(path.join(input.root, "runtime.json"), input);
  const host = JSON.parse(
    await readFile(path.join(prepared.hostRoot, "package.json"), "utf8"),
  );
  if (host.version !== "2026.7.1-2") throw new Error("native_test_host_drift");
  const bin = typeof host.bin === "string" ? host.bin : host.bin.openclaw;
  const args = [
    path.join(prepared.hostRoot, bin),
    "agent",
    "--local",
    "--agent",
    profile.agentId,
    "--session-key",
    profile.sessionKey,
    "--session-id",
    profile.sessionId,
    "--channel",
    "agentguard-fixture",
    "--to",
    profile.toolOptions.messageTo,
    "--message",
    input.taskText,
    "--thinking",
    "off",
    "--timeout",
    "60",
    "--json",
  ];
  const output = await new Promise((resolve) => {
    stage = "run-native-cli";
    const child = spawn(process.execPath, args, {
      cwd: profile.workspaceDir,
      env: isolatedEnv(profile),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks = [];
    let size = 0,
      timedOut = false,
      outputLimitExceeded = false,
      killTimer;
    const stop = () => {
      child.kill("SIGTERM");
      killTimer ??= setTimeout(() => child.kill("SIGKILL"), 1000);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, input.timeoutMs ?? 80000);
    for (const stream of [child.stdout, child.stderr])
      stream.on("data", (chunk) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) {
          outputLimitExceeded = true;
          stop();
        } else chunks.push(chunk);
      });
    child.once("error", () => {
      clearTimeout(timer);
      resolve({
        code: -1,
        timedOut,
        outputLimitExceeded,
        bytes: Buffer.concat(chunks),
      });
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      resolve({
        code,
        timedOut,
        outputLimitExceeded,
        bytes: Buffer.concat(chunks),
      });
    });
  });
  const logPath = path.join(input.root, "native-agent.log");
  await writeFile(logPath, output.bytes, { mode: 0o600, flag: "wx" });
  let stages = [];
  try {
    stages = (
      await readFile(path.join(input.root, "native-events.jsonl"), "utf8")
    )
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    /* absence is reported */
  }
  return {
    phase: "run",
    exit_code: output.code,
    timed_out: output.timedOut,
    output_limit_exceeded: output.outputLimitExceeded,
    stages,
    log_path: logPath,
    synthetic_metadata: true,
    external_provider_requests: 0,
  };
}

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 512 * 1024) throw new Error("input_too_large");
  }
  input = JSON.parse(raw);
  const stdoutWrite = process.stdout.write.bind(process.stdout);
  if (!path.isAbsolute(input.root)) throw new Error("root_invalid");
  let capturedBytes = 0;
  // Retain this capture through process exit: late SDK logs must never become
  // protocol output. Only the saved writer below can publish the response.
  process.stdout.write = (chunk, encoding, callback) => {
    const bytes =
      typeof chunk === "string"
        ? Buffer.from(chunk, typeof encoding === "string" ? encoding : "utf8")
        : Buffer.from(chunk);
    const captured = bytes.subarray(
      0,
      Math.max(0, 1024 * 1024 - capturedBytes),
    );
    if (captured.length) {
      appendFileSync(path.join(input.root, "probe-host-stdout.log"), captured, {
        mode: 0o600,
      });
      capturedBytes += captured.length;
    }
    const done = typeof encoding === "function" ? encoding : callback;
    if (typeof done === "function") queueMicrotask(done);
    return true;
  };
  const result =
    input.phase === "prepare"
      ? await prepare(input)
      : input.phase === "run"
        ? await run(input)
        : undefined;
  if (!result) throw new Error("phase_invalid");
  stdoutWrite(JSON.stringify(result));
} catch (error) {
  if (input?.root && path.isAbsolute(input.root)) {
    try {
      await writeFile(
        path.join(input.root, "probe-private-error.log"),
        String(error?.stack ?? "probe failed"),
        { mode: 0o600 },
      );
    } catch {}
  }
  process.stderr.write(`native_product_loop_probe_failed:${stage}\n`);
  process.exitCode = 1;
}
