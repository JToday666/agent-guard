#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const BENCH_PLUGIN_ID = "agentguard-bench-tools";
export const BENCH_AGENT_ID = "local-task-runner";
const LEGACY_BENCH_AGENT_IDS = new Set(["agentguard-bench", BENCH_AGENT_ID]);
export const BENCH_TOOL_NAMES = [
  "read_file",
  "write_file",
  "send_email",
  "call_api",
  "code_exec",
  "memory_write",
  "memory_read",
  "memory_search",
  "browser_start",
  "browser_navigate",
  "browser_input",
  "browser_click",
  "browser_extract_text",
  "browser_inspect",
  "mcp_call",
  "rag_retrieve",
  "rag_answer",
  "local_tool_call",
];

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = "@agentguard/openclaw-bench-tools";
const PLUGIN_ROOT = path.join(
  ROOT,
  "packages",
  "agentguard-openclaw-bench-tools",
);
const DEV_ROOT = path.join(ROOT, ".openclaw-dev");
const STAGING_DIR = path.join(DEV_ROOT, BENCH_PLUGIN_ID);
const RUNTIME_CONFIG_PATH = path.join(DEV_ROOT, "bench-tools-runtime.json");
const BACKUP_DIR = path.join(DEV_ROOT, "backups");

const command = process.argv[2];

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}

async function main() {
  if (command === "install") {
    install();
    return;
  }
  if (command === "uninstall") {
    uninstall();
    return;
  }
  if (command === "verify") {
    verify();
    return;
  }
  usage();
  process.exit(command ? 1 : 0);
}

function install() {
  run("pnpm", ["--filter", PACKAGE, "plugin:build"]);
  rebuildStaging();
  backupOpenClawConfig("install-bench-tools");
  uninstallExistingPlugin();
  run("openclaw", ["plugins", "install", "-l", STAGING_DIR]);
  patchOpenClawConfig(
    buildPatchedOpenClawConfig(readOpenClawConfig(), {
      stagingDir: STAGING_DIR,
      runtimeConfigPath: RUNTIME_CONFIG_PATH,
    }),
  );
  refreshPluginRegistry();
  restartGateway();
  waitForGateway();
  console.log(
    `Installed ${BENCH_PLUGIN_ID} from ${relativePath(STAGING_DIR)}.`,
  );
}

function uninstall() {
  backupOpenClawConfig("uninstall-bench-tools");
  const current = readOpenClawConfig();
  const next = structuredCloneSafe(current);
  const currentPaths = Array.isArray(next.plugins?.load?.paths)
    ? next.plugins.load.paths
    : [];
  next.plugins = next.plugins || {};
  next.plugins.load = next.plugins.load || {};
  next.plugins.entries = next.plugins.entries || {};
  next.plugins.load.paths = currentPaths.filter(
    (item) => typeof item === "string" && !isBenchLoadPath(item),
  );
  delete next.plugins.entries[BENCH_PLUGIN_ID];
  if (next.agents && Array.isArray(next.agents.list)) {
    next.agents.list = next.agents.list.filter(
      (agent) => !LEGACY_BENCH_AGENT_IDS.has(String(agent?.id || "")),
    );
  }
  patchOpenClawConfig(next);
  const removed = run(
    "openclaw",
    ["plugins", "uninstall", BENCH_PLUGIN_ID, "--force"],
    { allowFailure: true, capture: true },
  );
  if (
    removed.status !== 0 &&
    !/not found|no plugin|unknown plugin|does not exist|missing/i.test(
      combinedOutput(removed),
    )
  ) {
    throw new Error(
      `Failed to uninstall ${BENCH_PLUGIN_ID}:\n${combinedOutput(removed)}`,
    );
  }
  refreshPluginRegistry();
  restartGateway();
  waitForGateway();
  console.log(`Uninstalled ${BENCH_PLUGIN_ID}.`);
}

function verify() {
  const inspect = run(
    "openclaw",
    ["plugins", "inspect", BENCH_PLUGIN_ID, "--runtime", "--json"],
    { capture: true },
  );
  const parsed = parseJsonObject(inspect.stdout);
  const plugin = parsed.plugin ?? {};
  if (plugin.status !== "loaded") {
    throw new Error(
      `Expected ${BENCH_PLUGIN_ID} status=loaded, got ${String(plugin.status)}`,
    );
  }
  console.log(`Verified ${BENCH_PLUGIN_ID}: status=loaded.`);
}

export function buildPatchedOpenClawConfig(config, options) {
  const next = structuredCloneSafe(config || {});
  delete next.meta;
  next.plugins = next.plugins || {};
  next.plugins.load = next.plugins.load || {};
  next.plugins.entries = next.plugins.entries || {};
  const currentPaths = Array.isArray(next.plugins.load.paths)
    ? next.plugins.load.paths
    : [];
  next.plugins.load.paths = [
    ...currentPaths.filter(
      (item) => typeof item === "string" && !isBenchLoadPath(item),
    ),
    options.stagingDir,
  ];
  next.plugins.entries[BENCH_PLUGIN_ID] = {
    enabled: true,
    config: {
      runtimeConfigPath: options.runtimeConfigPath,
    },
  };
  next.agents = next.agents || {};
  next.agents.list = Array.isArray(next.agents.list) ? next.agents.list : [];
  const benchAgent = {
    id: BENCH_AGENT_ID,
    skills: [],
    contextInjection: "never",
    identity: {
      name: "Local Task Runner",
      theme: "Local task automation",
    },
    sandbox: {
      mode: "off",
    },
    tools: {
      profile: "full",
      allow: BENCH_TOOL_NAMES,
    },
  };
  next.agents.list = [
    ...next.agents.list.filter(
      (agent) => !LEGACY_BENCH_AGENT_IDS.has(String(agent?.id || "")),
    ),
    benchAgent,
  ];
  return next;
}

function rebuildStaging() {
  fs.rmSync(STAGING_DIR, { recursive: true, force: true });
  fs.mkdirSync(STAGING_DIR, { recursive: true });
  copyRecursive(path.join(PLUGIN_ROOT, "dist"), path.join(STAGING_DIR, "dist"));
  for (const fileName of [
    "openclaw.plugin.json",
    "package.json",
    "README.md",
  ]) {
    fs.copyFileSync(
      path.join(PLUGIN_ROOT, fileName),
      path.join(STAGING_DIR, fileName),
    );
  }
}

function backupOpenClawConfig(reason) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const configPath = resolveOpenClawConfigPath();
  if (!fs.existsSync(configPath)) {
    return null;
  }
  const backupPath = path.join(
    BACKUP_DIR,
    `${timestamp()}-${reason}-openclaw.json`,
  );
  fs.copyFileSync(configPath, backupPath);
  fs.chmodSync(backupPath, 0o600);
  console.log(`Backed up OpenClaw config to ${relativePath(backupPath)}.`);
  return backupPath;
}

function patchOpenClawConfig(patch) {
  fs.mkdirSync(DEV_ROOT, { recursive: true });
  const patchFile = path.join(
    DEV_ROOT,
    `.openclaw-bench-tools-config-patch-${process.pid}.json`,
  );
  fs.writeFileSync(patchFile, `${JSON.stringify(patch, null, 2)}\n`, {
    mode: 0o600,
  });
  try {
    run("openclaw", openClawConfigPatchArgs(patchFile));
  } finally {
    fs.rmSync(patchFile, { force: true });
  }
}

export function openClawConfigPatchArgs(patchFile) {
  return [
    "config",
    "patch",
    "--file",
    patchFile,
    "--replace-path",
    "agents.list",
  ];
}

function readOpenClawConfig() {
  const configPath = resolveOpenClawConfigPath();
  if (!fs.existsSync(configPath)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(configPath, "utf8"));
}

function resolveOpenClawConfigPath() {
  const result = run("openclaw", ["config", "file"], {
    allowFailure: true,
    capture: true,
  });
  if (result.status === 0) {
    const line = result.stdout
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean)
      .at(-1);
    if (line) {
      return expandHome(line);
    }
  }
  return path.join(os.homedir(), ".openclaw", "openclaw.json");
}

function uninstallExistingPlugin() {
  run("openclaw", ["plugins", "uninstall", BENCH_PLUGIN_ID, "--force"], {
    allowFailure: true,
    capture: true,
  });
}

function refreshPluginRegistry() {
  const result = run("openclaw", ["plugins", "registry", "--refresh"], {
    allowFailure: true,
    capture: true,
  });
  if (result.status !== 0) {
    throw new Error(
      `Failed to refresh OpenClaw plugin registry:\n${combinedOutput(result)}`,
    );
  }
}

function restartGateway() {
  run("openclaw", ["gateway", "restart", "--safe"], {
    allowFailure: true,
    capture: true,
  });
}

function waitForGateway() {
  let lastOutput = "";
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const result = run("openclaw", ["gateway", "status"], {
      allowFailure: true,
      capture: true,
    });
    lastOutput = combinedOutput(result);
    if (
      result.status === 0 &&
      /Runtime:\s+running/.test(result.stdout) &&
      /Connectivity probe:\s+ok/.test(result.stdout)
    ) {
      return;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  throw new Error(`OpenClaw gateway did not become healthy:\n${lastOutput}`);
}

function isBenchLoadPath(value) {
  const resolved = path.resolve(expandHome(value));
  return (
    resolved === path.resolve(STAGING_DIR) ||
    /agentguard-bench-tools/.test(value)
  );
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (!options.allowFailure && result.status !== 0) {
    throw new Error(
      `Command failed: ${cmd} ${args.join(" ")}\n${combinedOutput(result)}`,
    );
  }
  return result;
}

function combinedOutput(result) {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function parseJsonObject(output) {
  const start = output.indexOf("{");
  const end = output.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    throw new Error(`Expected JSON object in command output:\n${output}`);
  }
  return JSON.parse(output.slice(start, end + 1));
}

function copyRecursive(source, destination) {
  const stat = fs.statSync(source);
  if (stat.isDirectory()) {
    fs.mkdirSync(destination, { recursive: true });
    for (const entry of fs.readdirSync(source)) {
      copyRecursive(path.join(source, entry), path.join(destination, entry));
    }
    return;
  }
  fs.copyFileSync(source, destination);
}

function structuredCloneSafe(value) {
  return JSON.parse(JSON.stringify(value || {}));
}

function expandHome(value) {
  return value.startsWith("~/")
    ? path.join(os.homedir(), value.slice(2))
    : value;
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function relativePath(value) {
  return path.relative(ROOT, value) || ".";
}

function usage() {
  console.log(`Usage:
  node scripts/openclaw-bench-tools-dev.mjs install
  node scripts/openclaw-bench-tools-dev.mjs verify
  node scripts/openclaw-bench-tools-dev.mjs uninstall`);
}
