#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ROOT = process.cwd();
const PLUGIN_ID = "agentguard-security";
const PLUGIN_PACKAGE = "@agentguard/openclaw-plugin";
const PLUGIN_ROOT = path.join(ROOT, "packages", "agentguard-openclaw-plugin");
const DEV_ROOT = path.join(ROOT, ".openclaw-dev");
const STAGING_DIR = path.join(DEV_ROOT, PLUGIN_ID);
const BACKUP_DIR = path.join(DEV_ROOT, "backups");
const CODE_ROOT = path.resolve(ROOT, "..");
const LOCAL_OPENCLAW_HOME = path.join(CODE_ROOT, ".openclaw-home");
const LOCAL_OPENCLAW_STATE_DIR = path.join(CODE_ROOT, ".openclaw");
const LOCAL_OPENCLAW_CONFIG_PATH = path.join(
  LOCAL_OPENCLAW_STATE_DIR,
  "openclaw.json",
);
const LOCAL_TOOLS_BIN = path.join(CODE_ROOT, ".tools", "bin");
const LOCAL_NODE_BIN = path.join(
  CODE_ROOT,
  ".tools",
  "node-v24.15.0-linux-x64",
  "bin",
);
const REQUIRED_HOOKS = [
  "after_compaction",
  "before_agent_finalize",
  "before_compaction",
  "before_install",
  "before_message_write",
  "before_prompt_build",
  "before_tool_call",
  "cron_changed",
  "gateway_start",
  "gateway_stop",
  "llm_input",
  "llm_output",
  "message_received",
  "message_sending",
  "model_call_ended",
  "model_call_started",
  "resolve_exec_env",
  "session_end",
  "session_start",
  "subagent_ended",
  "subagent_spawned",
  "tool_result_persist",
];

const command = process.argv[2];
const flags = new Set(process.argv.slice(3));

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

async function main() {
  if (command === "install") {
    install();
    return;
  }
  if (command === "verify") {
    await verify({ record: flags.has("--record") });
    return;
  }
  if (command === "uninstall") {
    uninstall({ cleanStaging: flags.has("--clean-staging") });
    return;
  }
  usage();
  process.exit(command ? 1 : 0);
}

function install() {
  const env = readDotEnv();
  const adapterToken = requireEnv(env, "AGENTGUARD_ADAPTER_TOKEN");
  const host = env.AGENTGUARD_HOST || "127.0.0.1";
  const port = env.AGENTGUARD_PORT || "8088";
  const guardApiBaseUrl = `http://${host}:${port}`;

  run("pnpm", ["--filter", PLUGIN_PACKAGE, "build"]);
  rebuildStaging();
  backupOpenClawConfig("install");
  uninstallExistingPlugin();
  run("openclaw", ["plugins", "install", "-l", STAGING_DIR]);
  patchOpenClawConfig({
    plugins: {
      load: {
        paths: agentGuardLoadPaths({ includeStaging: true }),
      },
      entries: {
        [PLUGIN_ID]: {
          enabled: true,
          hooks: { timeoutMs: 10000, allowConversationAccess: true },
          config: {
            guardApiBaseUrl,
            adapterToken,
            requestTimeoutMs: 3000,
            approvalPollIntervalMs: 100,
            approvalTimeoutMs: 3000,
          },
        },
      },
    },
  });
  refreshPluginRegistry();
  restartGateway();
  waitForGateway();
  console.log(`Installed ${PLUGIN_ID} from ${relativePath(STAGING_DIR)}.`);
}

async function verify({ record }) {
  try {
    const inspect = run(
      "openclaw",
      ["plugins", "inspect", PLUGIN_ID, "--runtime", "--json"],
      {
        capture: true,
      },
    );
    const parsed = parseJsonObject(inspect.stdout);
    const plugin = parsed.plugin ?? {};
    const typedHooks = Array.isArray(parsed.typedHooks)
      ? parsed.typedHooks
      : [];
    const diagnostics = Array.isArray(parsed.diagnostics)
      ? parsed.diagnostics
      : [];
    const hookNames = new Set(
      typedHooks.map((hook) => hook?.name).filter(Boolean),
    );
    const missingHooks = REQUIRED_HOOKS.filter(
      (hookName) => !hookNames.has(hookName),
    );
    const conversationAccessDiagnostics = diagnostics
      .map((item) => String(item?.message ?? ""))
      .filter((message) => /allowConversationAccess=true/.test(message));

    const failures = [];
    if (plugin.status !== "loaded") {
      failures.push(
        `expected plugin status=loaded, got ${String(plugin.status)}`,
      );
    }
    if (plugin.hookCount !== REQUIRED_HOOKS.length) {
      failures.push(
        `expected hookCount=${REQUIRED_HOOKS.length}, got ${String(plugin.hookCount)}`,
      );
    }
    if (!pluginUsesStaging(plugin)) {
      failures.push(
        `expected plugin source/rootDir to use ${relativePath(STAGING_DIR)}, got ${plugin.source ?? plugin.rootDir}`,
      );
    }
    if (missingHooks.length > 0) {
      failures.push(`missing hooks: ${missingHooks.join(", ")}`);
    }
    if (conversationAccessDiagnostics.length > 0) {
      failures.push(conversationAccessDiagnostics.join("; "));
    }
    if (failures.length > 0) {
      throw new Error(
        `OpenClaw plugin verification failed:\n- ${failures.join("\n- ")}`,
      );
    }

    waitForGateway();
    const status = {
      status: "loaded",
      loaded: true,
      hook_count: plugin.hookCount,
      expected_hook_count: REQUIRED_HOOKS.length,
      last_verified_at: new Date().toISOString(),
      error: null,
      source: "openclaw-plugin-dev",
    };
    if (record) {
      await recordOpenClawStatus(status);
    }
    console.log(
      `Verified ${PLUGIN_ID}: status=loaded, hookCount=${REQUIRED_HOOKS.length}.`,
    );
  } catch (error) {
    if (record) {
      try {
        await recordOpenClawStatus({
          status: "error",
          loaded: false,
          hook_count: null,
          expected_hook_count: REQUIRED_HOOKS.length,
          last_verified_at: new Date().toISOString(),
          error: error instanceof Error ? error.message : String(error),
          source: "openclaw-plugin-dev",
        });
      } catch (recordError) {
        console.warn(
          `Failed to record OpenClaw verification status: ${recordError instanceof Error ? recordError.message : String(recordError)}`,
        );
      }
    }
    throw error;
  }
}

function uninstall({ cleanStaging }) {
  backupOpenClawConfig("uninstall");
  patchOpenClawConfig({
    plugins: {
      load: {
        paths: agentGuardLoadPaths({ includeStaging: false }),
      },
      entries: {
        [PLUGIN_ID]: null,
      },
    },
  });
  const removed = run(
    "openclaw",
    ["plugins", "uninstall", PLUGIN_ID, "--force"],
    {
      allowFailure: true,
      capture: true,
    },
  );
  if (removed.status !== 0 && !looksLikeMissingPlugin(removed)) {
    throw new Error(
      `Failed to uninstall ${PLUGIN_ID}:\n${combinedOutput(removed)}`,
    );
  }
  refreshPluginRegistry();
  restartGateway();
  waitForGateway();
  if (cleanStaging) {
    fs.rmSync(STAGING_DIR, { recursive: true, force: true });
    console.log(`Removed ${relativePath(STAGING_DIR)}.`);
  }
  console.log(`Uninstalled ${PLUGIN_ID}.`);
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
  if (fs.existsSync(path.join(STAGING_DIR, "node_modules"))) {
    throw new Error("staging unexpectedly contains node_modules");
  }
}

function backupOpenClawConfig(reason) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const configPath = resolveOpenClawConfigPath();
  if (!fs.existsSync(configPath)) {
    console.warn(
      `OpenClaw config not found at ${configPath}; skipping backup.`,
    );
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

function resolveOpenClawConfigPath() {
  const explicit =
    process.env.OPENCLAW_CONFIG_PATH?.trim() || LOCAL_OPENCLAW_CONFIG_PATH;
  if (explicit) {
    return expandHome(explicit);
  }
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

function patchOpenClawConfig(patch) {
  fs.mkdirSync(DEV_ROOT, { recursive: true });
  const patchFile = path.join(
    DEV_ROOT,
    `.openclaw-config-patch-${process.pid}.json`,
  );
  fs.writeFileSync(patchFile, `${JSON.stringify(patch, null, 2)}\n`, {
    mode: 0o600,
  });
  try {
    run("openclaw", ["config", "patch", "--file", patchFile]);
  } finally {
    fs.rmSync(patchFile, { force: true });
  }
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
  console.log("Refreshed OpenClaw plugin registry.");
}

function agentGuardLoadPaths({ includeStaging }) {
  const config = readOpenClawConfig();
  const currentPaths = Array.isArray(config.plugins?.load?.paths)
    ? config.plugins.load.paths
    : [];
  const filtered = currentPaths.filter(
    (item) => typeof item === "string" && !isAgentGuardLoadPath(item),
  );
  return includeStaging ? [...filtered, STAGING_DIR] : filtered;
}

function readOpenClawConfig() {
  const configPath = resolveOpenClawConfigPath();
  if (!fs.existsSync(configPath)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(configPath, "utf8"));
}

function isAgentGuardLoadPath(value) {
  const expanded = expandHome(value);
  const resolved = path.resolve(expanded);
  if (resolved === path.resolve(STAGING_DIR)) {
    return true;
  }
  return /agentguard-openclaw-plugin-install-p2|agentguard-security/.test(
    value,
  );
}

function pluginUsesStaging(plugin) {
  const staging = path.resolve(STAGING_DIR);
  const source =
    typeof plugin.source === "string" ? path.resolve(plugin.source) : "";
  const rootDir =
    typeof plugin.rootDir === "string" ? path.resolve(plugin.rootDir) : "";
  return rootDir === staging || source.startsWith(`${staging}${path.sep}`);
}

function restartGateway() {
  const result = run("openclaw", ["gateway", "restart", "--safe"], {
    allowFailure: true,
    capture: true,
  });
  if (result.status !== 0) {
    console.warn(
      "Gateway restart returned a non-zero status; checking gateway status before failing.",
    );
    const output = combinedOutput(result).trim();
    if (output) {
      console.warn(output);
    }
  }
}

function waitForGateway() {
  const attempts = 12;
  let lastOutput = "";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
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

function uninstallExistingPlugin() {
  const result = run(
    "openclaw",
    ["plugins", "uninstall", PLUGIN_ID, "--force"],
    {
      allowFailure: true,
      capture: true,
    },
  );
  if (
    result.status !== 0 &&
    !looksLikeMissingPlugin(result) &&
    combinedOutput(result).trim()
  ) {
    throw new Error(
      `Failed to remove existing ${PLUGIN_ID} install:\n${combinedOutput(result)}`,
    );
  }
}

function looksLikeMissingPlugin(result) {
  return /not found|no plugin|unknown plugin|does not exist|missing/i.test(
    combinedOutput(result),
  );
}

function readDotEnv() {
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath)) {
    throw new Error(
      "Missing .env. Copy .env.example to .env and set AGENTGUARD_ADAPTER_TOKEN.",
    );
  }
  const parsed = { ...process.env };
  const content = fs.readFileSync(envPath, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) {
      continue;
    }
    parsed[match[1]] = stripEnvValue(match[2]);
  }
  return parsed;
}

async function recordOpenClawStatus(status) {
  const env = readDotEnv();
  const controlToken = requireEnv(env, "AGENTGUARD_CONTROL_TOKEN");
  const host = env.AGENTGUARD_HOST || "127.0.0.1";
  const port = env.AGENTGUARD_PORT || "8088";
  const apiBaseUrl = (
    env.AGENTGUARD_API_URL || `http://${host}:${port}`
  ).replace(/\/+$/, "");
  const response = await fetch(`${apiBaseUrl}/v1/adapters/openclaw/status`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${controlToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(status),
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Guard API status record failed: HTTP ${response.status} ${body}`,
    );
  }
}

function requireEnv(env, key) {
  const value = env[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(
      `.env is missing ${key}; refusing to write an empty OpenClaw adapter token.`,
    );
  }
  return value.trim();
}

function stripEnvValue(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  const hashIndex = trimmed.indexOf(" #");
  return hashIndex === -1 ? trimmed : trimmed.slice(0, hashIndex).trim();
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: ROOT,
    env: localCommandEnv(),
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

function localCommandEnv() {
  const pathEntries = [
    LOCAL_TOOLS_BIN,
    LOCAL_NODE_BIN,
    path.join(ROOT, "node_modules", ".pnpm", "node_modules", ".bin"),
    path.join(PLUGIN_ROOT, "node_modules", ".bin"),
    process.env.PATH ?? "",
  ].filter(Boolean);
  return {
    ...process.env,
    PATH: pathEntries.join(path.delimiter),
    OPENCLAW_HOME: process.env.OPENCLAW_HOME || LOCAL_OPENCLAW_HOME,
    OPENCLAW_STATE_DIR:
      process.env.OPENCLAW_STATE_DIR || LOCAL_OPENCLAW_STATE_DIR,
    OPENCLAW_CONFIG_PATH:
      process.env.OPENCLAW_CONFIG_PATH || LOCAL_OPENCLAW_CONFIG_PATH,
    COREPACK_HOME:
      process.env.COREPACK_HOME || path.join(CODE_ROOT, ".cache", "corepack"),
    npm_config_cache:
      process.env.npm_config_cache || path.join(CODE_ROOT, ".cache", "npm"),
    PNPM_HOME: process.env.PNPM_HOME || LOCAL_TOOLS_BIN,
  };
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
  node scripts/openclaw-plugin-dev.mjs install
  node scripts/openclaw-plugin-dev.mjs verify [--record]
  node scripts/openclaw-plugin-dev.mjs uninstall [--clean-staging]`);
}
