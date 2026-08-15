#!/usr/bin/env node
// OpenClaw 真实运行时兼容门禁 smoke driver。
// 供 CI openclaw-runtime-smoke job 调用，也可本机隔离干跑。
// 流程：隔离 profile → 工作区外 openclaw CLI → 事务化安装 → 真实 Guard API（_test 库）
//       → 随机端口真实前台 Gateway → 新鲜 heartbeat（23 hooks / loaded）
//       → 安装器 verify 口径 → uninstall 清理与残留检查 → 脱敏 JSON 报告。
// 安全边界：严禁触碰用户真实 profile（~/.openclaw）与用户真实 Gateway。

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { OPENCLAW_REQUIRED_HOOKS } from "../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import { resolveGuardApiBaseUrl } from "./guard-api-endpoint.mjs";
import { resolveToolCommand, runTool } from "./openclaw-command-resolve.mjs";
import {
  buildCommandEnv,
  createRuntimeDeps,
  executeInstall,
  executeUninstall,
  executeVerify,
  extractAgentGuardFragment,
  parseOpenClawVersion,
  PLUGIN_ID,
  redactSecrets,
  resolveProfile,
  STATE_ENV_TOKEN_KEY,
  waitForFreshHeartbeat,
} from "./openclaw-plugin-dev.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, "..");
const REPO_ENV_PATH = path.join(ROOT, ".env");
const EXPECTED_HOOK_COUNT = OPENCLAW_REQUIRED_HOOKS.length;

// ---------- 纯函数层 ----------

export function parseSmokeArgs(args, env = {}) {
  const options = {
    openclawRoot: env.AGENTGUARD_OPENCLAW_ROOT ?? null,
    expectVersion: env.AGENTGUARD_OPENCLAW_EXPECT_VERSION ?? null,
    skipGuardApi: false,
    provisionEnv: false,
    reportPath: null,
    heartbeatTimeoutMs: 90_000,
  };
  const list = Array.isArray(args) ? args : [];
  for (let index = 0; index < list.length; index += 1) {
    const arg = list[index];
    const take = () => {
      const value = list[index + 1];
      if (typeof value !== "string" || value === "") {
        throw new Error(`缺少 ${arg} 的取值`);
      }
      index += 1;
      return value;
    };
    if (arg === "--openclaw-root") {
      options.openclawRoot = take();
    } else if (arg.startsWith("--openclaw-root=")) {
      options.openclawRoot = arg.slice("--openclaw-root=".length);
    } else if (arg === "--expect-version") {
      options.expectVersion = take();
    } else if (arg.startsWith("--expect-version=")) {
      options.expectVersion = arg.slice("--expect-version=".length);
    } else if (arg === "--report") {
      options.reportPath = take();
    } else if (arg.startsWith("--report=")) {
      options.reportPath = arg.slice("--report=".length);
    } else if (arg === "--heartbeat-timeout-ms") {
      options.heartbeatTimeoutMs = Number(take());
    } else if (arg.startsWith("--heartbeat-timeout-ms=")) {
      options.heartbeatTimeoutMs = Number(
        arg.slice("--heartbeat-timeout-ms=".length),
      );
    } else if (arg === "--skip-guard-api") {
      options.skipGuardApi = true;
    } else if (arg === "--provision-env") {
      options.provisionEnv = true;
    } else {
      throw new Error(`未知 smoke 参数：${arg}`);
    }
  }
  if (!options.openclawRoot) {
    throw new Error(
      "必须通过 --openclaw-root 或 AGENTGUARD_OPENCLAW_ROOT 指定工作区外的 openclaw 安装根目录",
    );
  }
  if (
    !Number.isInteger(options.heartbeatTimeoutMs) ||
    options.heartbeatTimeoutMs <= 0
  ) {
    throw new Error("--heartbeat-timeout-ms 必须是正整数");
  }
  return options;
}

/**
 * 在工作区外 openclaw 根目录中定位 CLI bin 目录。
 * 兼容 npm --prefix 安装（<root>/node_modules/.bin）与全局 prefix
 * （shim 直接位于 <root>，如 Windows npm 全局安装）。
 */
export function resolveOpenclawBinDir(
  rootDir,
  { platform = process.platform, fileExists = fs.existsSync } = {},
) {
  const resolvedRoot = path.resolve(rootDir);
  const candidates = [path.join(resolvedRoot, "node_modules", ".bin"), resolvedRoot];
  const names = platform === "win32" ? ["openclaw.cmd", "openclaw"] : ["openclaw"];
  for (const dir of candidates) {
    for (const name of names) {
      if (fileExists(path.join(dir, name))) {
        return dir;
      }
    }
  }
  throw new Error(
    `无法在 openclaw 根目录 ${resolvedRoot} 下定位 CLI bin（已探测：${candidates
      .map((dir) => path.join(dir, names[0]))
      .join(", ")}）`,
  );
}

/**
 * 把 bin 目录前置到 env 的 PATH（Windows 尊重已有的 Path 键），返回新 env。
 */
export function withOpenclawBinOnPath(env, binDir, platform = process.platform) {
  const key =
    platform === "win32" && env.Path !== undefined && env.PATH === undefined
      ? "Path"
      : "PATH";
  const separator = platform === "win32" ? ";" : path.delimiter;
  const current = env[key] ?? "";
  return { ...env, [key]: current ? `${binDir}${separator}${current}` : binDir };
}

/**
 * 隔离 profile 目录安全护栏：禁止落在用户真实 profile（~/.openclaw）
 * 或仓库工作区内，避免触碰真实 Gateway 状态与污染仓库。
 */
export function assertIsolatedProfileDir(
  profileDir,
  { homedir, workspaceRoot },
) {
  const resolved = path.resolve(profileDir);
  const forbidden = [
    path.join(path.resolve(homedir), ".openclaw"),
    path.resolve(workspaceRoot),
  ];
  for (const base of forbidden) {
    if (resolved === base || resolved.startsWith(base + path.sep)) {
      throw new Error(
        `拒绝使用 ${resolved} 作为隔离 profile：落在受保护目录 ${base} 内`,
      );
    }
  }
  return resolved;
}

/** 合并隔离 profile 的 gateway 配置：固定本地模式与随机端口。 */
export function mergeGatewayConfig(config, port) {
  const base = config && typeof config === "object" ? config : {};
  const gateway =
    base.gateway && typeof base.gateway === "object" ? base.gateway : {};
  return {
    ...base,
    gateway: {
      ...gateway,
      mode: gateway.mode ?? "local",
      port,
    },
  };
}

/**
 * 为隔离 profile 开启插件诊断日志（仅隔离环境；安装器卸载时 entry 整体移除，
 * 不会泄漏到真实 profile）。开启后插件 heartbeat 提交结果会写入网关日志，
 * 作为无 Guard API 时的真实加载证据（inspect 的 hookCount 只在 hooks 被
 * agent runtime 实际触发后才上报，隔离 Gateway 中不可靠）。
 */
export function withDiagnosticLogging(config, pluginId) {
  const base = config && typeof config === "object" ? { ...config } : {};
  const plugins =
    base.plugins && typeof base.plugins === "object" ? { ...base.plugins } : {};
  const entries =
    plugins.entries && typeof plugins.entries === "object"
      ? { ...plugins.entries }
      : {};
  const entry =
    entries[pluginId] && typeof entries[pluginId] === "object"
      ? { ...entries[pluginId] }
      : {};
  entry.config = {
    ...(entry.config && typeof entry.config === "object" ? entry.config : {}),
    diagnosticLogging: true,
  };
  entries[pluginId] = entry;
  plugins.entries = entries;
  base.plugins = plugins;
  return base;
}

/**
 * 为隔离 Gateway 持久化随机 auth token：否则每次启动生成临时 token，
 * CLI（gateway status / plugins inspect）无法与运行中的 gateway 建立 RPC。
 */
export function withGatewayAuthToken(config, token) {
  const base = config && typeof config === "object" ? { ...config } : {};
  const gateway =
    base.gateway && typeof base.gateway === "object" ? { ...base.gateway } : {};
  gateway.auth = { mode: "token", token };
  base.gateway = gateway;
  return base;
}

/** 解析 dotenv 文本为键值对（去引号）。 */
export function parseDotEnvContent(content) {
  const parsed = {};
  for (const rawLine of String(content ?? "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) {
      continue;
    }
    let value = match[2].trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    parsed[match[1]] = value;
  }
  return parsed;
}

/** 取一个可用端口（监听 0 端口后释放）。 */
export async function pickFreePort(host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, host, () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// ---------- 编排层 ----------

function log(message) {
  console.log(`[smoke] ${message}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function combinedOutput(result) {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function requireProcessEnv(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`环境变量 ${name} 未设置或为空`);
  }
  return value.trim();
}

function applyRepoEnvDefaults() {
  if (!fs.existsSync(REPO_ENV_PATH)) {
    return false;
  }
  const parsed = parseDotEnvContent(fs.readFileSync(REPO_ENV_PATH, "utf8"));
  for (const [key, value] of Object.entries(parsed)) {
    if (process.env[key] === undefined || process.env[key] === "") {
      process.env[key] = value;
    }
  }
  return true;
}

function writeProvisionedEnv({ controlToken, adapterToken, testDatabaseUrl, port }) {
  const lines = [
    "AGENTGUARD_ENV=ci-smoke",
    "AGENTGUARD_STORAGE_BACKEND=postgres",
    `AGENTGUARD_DATABASE_URL=${testDatabaseUrl}`,
    `AGENTGUARD_TEST_DATABASE_URL=${testDatabaseUrl}`,
    `AGENTGUARD_ADAPTER_TOKEN=${adapterToken}`,
    `AGENTGUARD_CONTROL_TOKEN=${controlToken}`,
    "AGENTGUARD_HOST=127.0.0.1",
    `AGENTGUARD_PORT=${port}`,
  ];
  fs.writeFileSync(REPO_ENV_PATH, `${lines.join("\n")}\n`, { mode: 0o600 });
  log("已生成 CI 用根目录 .env（仅含 smoke 所需最小配置）。");
}

async function issueAdapterCredential(baseUrl, controlToken) {
  const response = await fetch(`${baseUrl}/v1/credentials`, {
    method: "POST",
    redirect: "error",
    headers: {
      Authorization: `Bearer ${controlToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      principal_id: "openclaw-runtime-smoke",
      runtime: "openclaw",
      agent_id: "main",
    }),
  });
  if (!response.ok) {
    throw new Error(
      `签发 OpenClaw adapter 凭证失败：HTTP ${response.status} ${await response.text()}`,
    );
  }
  const body = await response.json();
  if (typeof body?.token !== "string" || body.token === "") {
    throw new Error("签发 OpenClaw adapter 凭证失败：响应缺少 token");
  }
  return body.token;
}

async function fetchAdapterStatus(baseUrl, controlToken) {
  const response = await fetch(`${baseUrl}/v1/adapters/openclaw/status`, {
    redirect: "error",
    headers: { Authorization: `Bearer ${controlToken}` },
  });
  if (!response.ok) {
    throw new Error(`查询 adapter 状态失败：HTTP ${response.status}`);
  }
  return response.json();
}

function spawnGateway({ binDir, gatewayPort, profileDir, logPath, secrets }) {
  const resolved = resolveToolCommand("openclaw");
  const profile = resolveProfile(process.env);
  const child = spawn(
    resolved.command,
    [...resolved.prependArgs, "gateway", "--port", String(gatewayPort)],
    {
      cwd: profileDir,
      env: buildCommandEnv(process.env, { profile }),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const chunks = [];
  const append = (chunk) => {
    const text = String(chunk);
    chunks.push(text);
    try {
      fs.appendFileSync(logPath, redactSecrets(text, { secrets }));
    } catch {
      // 日志写入失败不影响主流程
    }
  };
  child.stdout.on("data", append);
  child.stderr.on("data", append);
  return {
    child,
    tail: () =>
      redactSecrets(chunks.join("").slice(-8000), { secrets }).trimEnd(),
  };
}

function killGateway(gateway) {
  if (!gateway || gateway.child.exitCode !== null) {
    return;
  }
  try {
    gateway.child.kill("SIGKILL");
  } catch {
    // 子进程可能已退出
  }
}

/** 探测端口是否可连接（1s 超时）。 */
function tryConnectPort(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const socket = net.createConnection(port, host);
    const done = (ok) => {
      socket.destroy();
      resolve(ok);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    setTimeout(() => done(false), 1000);
  });
}

/**
 * 等待 Gateway 子进程真正退出（SIGKILL 后 exitCode 落地有延迟）。
 * 旧实例未退出就重启会让新实例与旧实例争抢同一端口。
 */
export async function waitForGatewayExit(
  gateway,
  timeoutMs,
  { sleep: sleepFn = sleep, pollMs = 100 } = {},
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!gateway || gateway.child.exitCode !== null) {
      return true;
    }
    await sleepFn(pollMs);
  }
  return !gateway || gateway.child.exitCode !== null;
}

/**
 * 等待端口完全释放（连接被拒绝）：确保重启后的新实例独占端口，
 * 避免旧实例残留监听导致 verify 探测到已停止的旧实例。
 */
export async function waitForPortFree(
  port,
  timeoutMs,
  { connect = tryConnectPort, sleep: sleepFn = sleep, pollMs = 250 } = {},
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!(await connect(port))) {
      return true;
    }
    await sleepFn(pollMs);
  }
  return !(await connect(port));
}

/** 等待前台 Gateway 就绪：TCP 端口可连后再留缓冲时间供插件加载。 */
async function waitForGatewayReady(gateway, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (gateway.child.exitCode !== null) {
      throw new Error(`Gateway 在就绪前退出：\n${gateway.tail()}`);
    }
    if (await tryConnectPort(port)) {
      await sleep(3000);
      return;
    }
    await sleep(500);
  }
  throw new Error(`等待 Gateway 就绪超时：\n${gateway.tail()}`);
}

/**
 * 无 Guard API 时的兼容证据：以网关日志中的插件加载列表与插件自身诊断
 * 日志（heartbeat 提交尝试/结果）作为真实加载证据；inspect hookCount 只在
 * hooks 被 agent runtime 实际触发后才上报，隔离 Gateway 中不可靠。
 */
async function pollGatewayPluginEvidence({ timeoutMs, gateway }) {
  const deadline = Date.now() + timeoutMs;
  const loadedLine = new RegExp(`plugins: [^\\n]*${PLUGIN_ID}`);
  const diagnosticLine = /\[AgentGuard OpenClaw\]/;
  while (Date.now() < deadline) {
    const text = gateway.tail();
    const pluginListed = loadedLine.test(text);
    const diagnosticObserved = diagnosticLine.test(text);
    if (pluginListed && diagnosticObserved) {
      const observed = [...new Set(
        text
          .split("\n")
          .filter((line) => diagnosticLine.test(line))
          .map((line) => line.replace(/^\S+\s+/, "").slice(0, 160)),
      )].slice(0, 10);
      return {
        ok: true,
        detail: {
          plugin_listed: pluginListed,
          plugin_diagnostics_observed: observed,
          note: "inspect hookCount 需 hooks 实际触发后才上报，隔离 Gateway 中以插件加载列表与诊断日志作为加载证据",
        },
      };
    }
    await sleep(1500);
  }
  return { ok: false, detail: gateway.tail() };
}

async function runSmoke(options) {
  const startedAtMs = Date.now();
  const stages = [];
  const failures = [];
  const secrets = [];
  let guardApi = null;
  let gateway = null;
  let runner = null;
  const reportBase = process.env.RUNNER_TEMP || os.tmpdir();
  const reportPath =
    options.reportPath ??
    path.join(reportBase, "agentguard-openclaw-runtime-smoke-report.json");
  const gatewayLogPath = path.join(
    reportBase,
    "agentguard-openclaw-smoke-gateway.log",
  );

  const record = (name, ok, detail = undefined) => {
    stages.push(
      detail === undefined ? { name, ok } : { name, ok, detail },
    );
    log(`${ok ? "PASS" : "FAIL"} ${name}`);
    if (!ok) {
      failures.push(
        detail === undefined
          ? { message: name }
          : { message: name, details: detail },
      );
    }
  };

  const writeReport = (ok) => {
    const report = redactSecrets(
      JSON.stringify(
        {
          ok,
          generated_at: new Date().toISOString(),
          duration_ms: Date.now() - startedAtMs,
          scope: {
            openclaw_root: options.openclawRoot,
            openclaw_version: scopeVersion,
            expect_version: options.expectVersion,
            guard_api: options.skipGuardApi ? "skipped" : scopeBaseUrl,
            guard_database: scopeDatabase,
            platform: process.platform,
          },
          stages,
          adapter_status: scopeAdapterStatus,
          failures,
        },
        null,
        2,
      ),
      { secrets },
    );
    fs.writeFileSync(reportPath, `${report}\n`, { mode: 0o600 });
    log(`报告已写入 ${reportPath}`);
  };

  let scopeVersion = null;
  let scopeBaseUrl = null;
  let scopeDatabase = null;
  let scopeAdapterStatus = null;

  try {
    // Step 1 隔离 profile
    const openclawRoot = path.resolve(options.openclawRoot);
    if (!fs.existsSync(openclawRoot)) {
      throw new Error(`openclaw 根目录不存在：${openclawRoot}`);
    }
    const workBase = process.env.RUNNER_TEMP || os.tmpdir();
    const workDir = fs.mkdtempSync(
      path.join(workBase, "agentguard-openclaw-smoke-"),
    );
    const profileDir = assertIsolatedProfileDir(
      path.join(workDir, "profile"),
      { homedir: os.homedir(), workspaceRoot: ROOT },
    );
    fs.mkdirSync(profileDir, { recursive: true });
    process.env.OPENCLAW_HOME = profileDir;
    process.env.OPENCLAW_STATE_DIR = profileDir;
    process.env.OPENCLAW_CONFIG_PATH = path.join(profileDir, "openclaw.json");
    record("isolate-profile", true, { profile_dir: profileDir });

    // Step 2 仓库 .env：存在则补齐缺失变量，缺失时仅 CI 允许生成
    const envFileExists = applyRepoEnvDefaults();
    if (!envFileExists) {
      if (!options.provisionEnv) {
        throw new Error(
          "仓库根目录缺少 .env，且未指定 --provision-env；本机运行请先准备 .env",
        );
      }
      log("仓库缺少 .env，将在 Guard API 凭证就绪后生成最小配置。");
    }

    // Step 3 工作区外 openclaw CLI 解析与版本核对
    const binDir = resolveOpenclawBinDir(openclawRoot);
    Object.assign(process.env, withOpenclawBinOnPath(process.env, binDir));
    const versionResult = runTool("openclaw", ["--version"], {
      capture: true,
      allowFailure: true,
    });
    if (versionResult.status !== 0) {
      throw new Error(
        `openclaw --version 执行失败：${combinedOutput(versionResult)}`,
      );
    }
    scopeVersion = parseOpenClawVersion(combinedOutput(versionResult));
    if (!scopeVersion) {
      throw new Error(
        `无法解析 OpenClaw 版本：${combinedOutput(versionResult)}`,
      );
    }
    if (options.expectVersion && scopeVersion !== options.expectVersion) {
      throw new Error(
        `OpenClaw 版本不符：期望 ${options.expectVersion}，实际 ${scopeVersion}`,
      );
    }
    record("resolve-openclaw-cli", true, {
      bin_dir: binDir,
      version: scopeVersion,
    });

    // Step 3.5 CF-08/09 语义复验（RTE-04 Tier 3 硬化）：在安装版本上
    // 复跑 spike 探针，探测版本间语义漂移（跨 hook 单一 toolCallId、
    // blocked 零调用 + block 结果返回、失败传播）。live observer emission
    // 仍需模型 turn，继续由归档取证工件锁定（见 conformance 矩阵 note）。
    const spikeScript = path.join(
      ROOT,
      "scripts",
      "openclaw-after-tool-call-spike.mjs",
    );
    const spikeReportPath = path.join(workDir, "rte-spike-probe-report.json");
    const spikeResult = runTool(
      "node",
      [spikeScript, spikeReportPath],
      {
        capture: true,
        allowFailure: true,
        env: {
          ...process.env,
          AGENTGUARD_OPENCLAW_SPIKE_ROOT: path.join(
            openclawRoot,
            "package.json",
          ),
        },
      },
    );
    if (spikeResult.status !== 0) {
      record("cf08-cf09-spike-probe", false, {
        error: combinedOutput(spikeResult).slice(0, 2000),
      });
      throw new Error("spike 探针在安装的 openclaw 版本上执行失败");
    }
    const spikeReport = JSON.parse(
      fs.readFileSync(spikeReportPath, "utf8"),
    );
    const probeAllow = spikeReport.scenarios.allow_success;
    const probeDeny = spikeReport.scenarios.deny_block;
    const probeFailure = spikeReport.scenarios.tool_failure;
    const probeAllowIds = new Set(
      probeAllow.evidence.map(
        (entry) => entry.toolCallId ?? entry.ctxToolCallId,
      ),
    );
    const probeOk =
      spikeReport.resolved_version === scopeVersion &&
      probeAllow.invocation_count === 1 &&
      probeAllowIds.size === 1 &&
      probeDeny.invocation_count === 0 &&
      probeDeny.blocked_result_returned === true &&
      probeFailure.invocation_count === 1 &&
      probeFailure.host_propagated_error === true;
    record("cf08-cf09-spike-probe", probeOk, {
      resolved_version: spikeReport.resolved_version,
      allow_invocations: probeAllow.invocation_count,
      allow_identity_size: probeAllowIds.size,
      deny_invocations: probeDeny.invocation_count,
      deny_blocked_result: probeDeny.blocked_result_returned,
      failure_propagated: probeFailure.host_propagated_error,
    });
    if (!probeOk) {
      throw new Error(
        "CF-08/09 spike 探针语义在安装的 openclaw 版本上发生漂移",
      );
    }

    // Step 4 真实 Guard API（_test 库）：随机端口、重置测试库、前台启动
    let adapterToken = process.env.AGENTGUARD_ADAPTER_TOKEN ?? null;
    let guardApiBaseUrl = null;
    let gatewayPort = null;
    const devRoot = path.join(workDir, ".openclaw-dev");
    const depsOverrides = {
      devRoot,
      stagingDir: path.join(devRoot, PLUGIN_ID),
      backupDir: path.join(devRoot, "backups"),
      secretPath: path.join(devRoot, "secrets", "openclaw-adapter-token"),
      noRestart: true,
    };

    if (!options.skipGuardApi) {
      const controlToken = requireProcessEnv("AGENTGUARD_CONTROL_TOKEN");
      secrets.push(controlToken);
      if (!adapterToken) {
        adapterToken = "agentguard-smoke-placeholder";
        process.env.AGENTGUARD_ADAPTER_TOKEN = adapterToken;
      }
      const guardApiPort = await pickFreePort();
      process.env.AGENTGUARD_HOST = "127.0.0.1";
      process.env.AGENTGUARD_PORT = String(guardApiPort);
      guardApiBaseUrl = resolveGuardApiBaseUrl(process.env);
      scopeBaseUrl = guardApiBaseUrl;

      runner = await import("./openclaw-e2e-runner.mjs");
      const testDatabaseUrl = runner.assertSafeTestDatabaseUrl(
        requireProcessEnv("AGENTGUARD_TEST_DATABASE_URL"),
      );
      scopeDatabase = new URL(
        testDatabaseUrl.replace(/^postgresql\+psycopg:\/\//, "postgresql://"),
      ).pathname.replace(/^\//, "");

      runner.resetAndInitializeTestDatabase(testDatabaseUrl);
      await runner.assertGuardApiPortIsFree();
      guardApi = runner.startGuardApi({ databaseUrl: testDatabaseUrl });
      await runner.waitForGuardApiHealth(guardApi);
      record("guard-api", true, { base_url: guardApiBaseUrl });

      adapterToken = await issueAdapterCredential(
        guardApiBaseUrl,
        controlToken,
      );
      secrets.push(adapterToken);
      process.env.AGENTGUARD_ADAPTER_TOKEN = adapterToken;
      if (!envFileExists && options.provisionEnv) {
        writeProvisionedEnv({
          controlToken,
          adapterToken,
          testDatabaseUrl,
          port: guardApiPort,
        });
      } else if (envFileExists) {
        // 不改动用户既有 .env：通过 readRepoEnv 覆盖注入本次签发的 token 与端口
        log("检测到既有 .env，保持文件不变，通过运行时覆盖注入本次凭证。");
      }
      gatewayPort = await runner.pickRandomPort();
    } else {
      if (!adapterToken) {
        throw new Error(
          "--skip-guard-api 模式需要仓库 .env 提供 AGENTGUARD_ADAPTER_TOKEN",
        );
      }
      secrets.push(adapterToken);
      guardApiBaseUrl = resolveGuardApiBaseUrl(process.env);
      scopeBaseUrl = guardApiBaseUrl;
      gatewayPort = await pickFreePort();
    }

    // Step 5 事务化安装（安装器纯编排复用，隔离 staging/devRoot）
    // 不改动用户 .env：通过 readRepoEnv 覆盖注入本次所需凭证与端点；
    // 仓库根 .env 保持只读，不写入任何值。
    const baseDeps = createRuntimeDeps({});
    const customRepoEnv = () => {
      const repoEnv = baseDeps.readRepoEnv();
      const merged = { ...repoEnv };
      if (adapterToken) {
        merged.AGENTGUARD_ADAPTER_TOKEN = adapterToken;
      }
      if (!options.skipGuardApi) {
        merged.AGENTGUARD_API_URL = guardApiBaseUrl;
      }
      return merged;
    };
    const makeDeps = (extra = {}) =>
      createRuntimeDeps({
        ...depsOverrides,
        readRepoEnv: customRepoEnv,
        ...extra,
      });
    const installResult = await executeInstall(makeDeps());
    record("install", true, {
      strategy: installResult.strategy,
      restart: installResult.restart,
    });

    // Step 6 隔离 profile gateway 配置 + 随机端口真实前台 Gateway
    const configPath = path.join(profileDir, "openclaw.json");
    const currentConfig = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, "utf8"))
      : {};
    let profileConfig = mergeGatewayConfig(currentConfig, gatewayPort);
    // 持久化随机 auth token，使 CLI（gateway status / plugins inspect --runtime）
    // 能与隔离 Gateway 建立 RPC；token 仅存于临时目录隔离 profile。
    const gatewayAuthToken = `smoke-gateway-${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 10)}`;
    secrets.push(gatewayAuthToken);
    profileConfig = withGatewayAuthToken(profileConfig, gatewayAuthToken);
    if (options.skipGuardApi) {
      // 无 Guard API 时开启插件诊断日志，作为真实加载证据来源
      profileConfig = withDiagnosticLogging(profileConfig, PLUGIN_ID);
    }
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(profileConfig, null, 2)}\n`,
      { mode: 0o600 },
    );

    let since = new Date();
    gateway = spawnGateway({
      binDir,
      gatewayPort,
      profileDir,
      logPath: gatewayLogPath,
      secrets,
    });
    log(`前台 Gateway 已启动（端口 ${gatewayPort}），等待插件注册与 heartbeat。`);

    if (!options.skipGuardApi) {
      const controlToken = requireProcessEnv("AGENTGUARD_CONTROL_TOKEN");
      // Step 7 新鲜 heartbeat（23 hooks、loaded）
      const heartbeat = await waitForFreshHeartbeat({
        fetchImpl: (...args) => fetch(...args),
        baseUrl: guardApiBaseUrl,
        controlToken,
        since,
        timeoutMs: options.heartbeatTimeoutMs,
        pollMs: 1500,
        sleep,
      });
      if (!heartbeat.fresh) {
        record("fresh-heartbeat", false, {
          last_heartbeat_at: heartbeat.lastHeartbeatAt,
          error: heartbeat.error ?? null,
          gateway_log_tail: gateway.tail(),
        });
        throw new Error("Guard API 未收到新鲜 heartbeat");
      }
      const status = await fetchAdapterStatus(guardApiBaseUrl, controlToken);
      scopeAdapterStatus = {
        status: status.status,
        loaded: status.loaded,
        hook_count: status.hook_count,
        expected_hook_count: status.expected_hook_count,
        runtime_version: status.runtime_version,
        last_heartbeat_at: status.last_heartbeat_at,
      };
      const heartbeatOk =
        status.loaded === true &&
        status.hook_count === EXPECTED_HOOK_COUNT &&
        status.expected_hook_count === EXPECTED_HOOK_COUNT;
      record("fresh-heartbeat", heartbeatOk, scopeAdapterStatus);
      if (!heartbeatOk) {
        throw new Error("adapter 状态与 23 hooks/loaded 预期不符");
      }

      // Step 8 重启前台 Gateway 后执行安装器 verify 口径（多证据）
      // 重启时序加固：先等旧实例真正退出且端口释放，再拉起新实例，
      // 否则新实例会与旧实例争抢端口（触发 gateway 自身重启），verify 的
      // inspect/status/heartbeat 证据会撞上启动/重启窗口（hookCount=0、
      // runtime=stopped、无新鲜 heartbeat）。
      killGateway(gateway);
      await waitForGatewayExit(gateway, 10_000);
      if (!(await waitForPortFree(gatewayPort, 15_000))) {
        record("gateway-restart-ready", false, {
          detail: `端口 ${gatewayPort} 在旧实例退出后仍被占用：\n${gateway.tail()}`,
        });
        throw new Error(`重启 Gateway 前端口 ${gatewayPort} 未释放`);
      }
      since = new Date();
      gateway = spawnGateway({
        binDir,
        gatewayPort,
        profileDir,
        logPath: gatewayLogPath,
        secrets,
      });
      await waitForGatewayReady(gateway, gatewayPort, 60_000);
      // 新实例的“完全就绪”以新鲜 heartbeat 为准（插件启动后立即提交一次，
      // 其后每 60s 一次）：仅 TCP 可连时插件可能尚未加载完成，此时跑 verify
      // 会拿到启动期旧状态。heartbeat 晚于 since，必然来自新实例。
      const readiness = await waitForFreshHeartbeat({
        fetchImpl: (...args) => fetch(...args),
        baseUrl: guardApiBaseUrl,
        controlToken,
        since,
        timeoutMs: options.heartbeatTimeoutMs,
        pollMs: 1500,
        sleep,
      });
      if (!readiness.fresh) {
        record("gateway-restart-ready", false, {
          last_heartbeat_at: readiness.lastHeartbeatAt,
          error: readiness.error ?? null,
          gateway_log_tail: gateway.tail(),
        });
        throw new Error("重启后的 Gateway 未在限时内提交新鲜 heartbeat，verify 就绪条件不满足");
      }
      record("gateway-restart-ready", true, {
        last_heartbeat_at: readiness.lastHeartbeatAt,
      });
      try {
        // 隔离 Gateway 中 CLI inspect 的 hookCount 需 hooks 被 agent runtime
        // 实际触发后才上报；executeVerify 已内置 inspect-only 失败时的
        // heartbeat 回退（hook_evidence_source=heartbeat-fallback），其余失败
        // 仍为硬门禁，这里不再重复实现回退判定。
        // `now` 锚定重启前时刻 since：新实例的 heartbeat（晚于 since）已在
        // verify 前到达，证据 3 直接复用；否则会等下一次 heartbeat（60s 间隔），
        // 超出 verify 默认 45s 窗口造成误报“无新鲜 heartbeat”。
        // heartbeatTimeoutMs 同步放宽，兼容极端慢启动下的下一次 heartbeat。
        const verifyPayload = await executeVerify(
          makeDeps({
            record: false,
            now: () => since,
            heartbeatTimeoutMs: Math.max(options.heartbeatTimeoutMs, 90_000),
          }),
        );
        const fallback =
          verifyPayload.hook_evidence_source === "heartbeat-fallback";
        record("installer-verify", true, {
          source: fallback
            ? "installer-verify-fallback-heartbeat"
            : "installer-verify",
          ...(fallback
            ? {
                reason:
                  "隔离 Gateway 中 inspect hookCount 不达标（需 hooks 实际触发），以 Guard API heartbeat 23 hooks/loaded 实证替代",
                heartbeat: scopeAdapterStatus,
              }
            : {}),
          hook_count: verifyPayload.hook_count,
          runtime_version: verifyPayload.runtime_version,
          plugin_version: verifyPayload.plugin_version,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const failureLines = message
          .split("\n")
          .filter((line) => line.startsWith("- "))
          .map((line) => line.slice(2));
        record("installer-verify", false, { failures: failureLines });
        throw new Error(`安装器 verify 失败：\n${message}`);
      }
    } else {
      // 无 Guard API 测试库时：只验证到插件在真实 Gateway 中加载并产生运行证据
      const evidence = await pollGatewayPluginEvidence({
        timeoutMs: Math.min(options.heartbeatTimeoutMs, 60_000),
        gateway,
      });
      record("plugin-loaded-no-guard-api", evidence.ok, evidence.detail);
      if (!evidence.ok) {
        throw new Error("隔离 Gateway 中插件未加载或未产生运行诊断证据");
      }
    }

    // Step 9 uninstall 清理与残留检查
    await executeUninstall(makeDeps({ cleanStaging: true }));
    const residualChecks = [];
    const finalConfig = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, "utf8"))
      : {};
    const fragment = extractAgentGuardFragment(finalConfig, depsOverrides.stagingDir);
    residualChecks.push({
      name: "config-fragment-clean",
      ok:
        fragment.entry === null &&
        fragment.provider === null &&
        fragment.loadPath === null,
    });
    residualChecks.push({
      name: "staging-removed",
      ok: !fs.existsSync(depsOverrides.stagingDir),
    });
    const stateEnvPath = path.join(profileDir, ".env");
    residualChecks.push({
      name: "state-env-token-removed",
      ok: !fs.existsSync(stateEnvPath)
        ? true
        : !new RegExp(`^${STATE_ENV_TOKEN_KEY}=`, "m").test(
            fs.readFileSync(stateEnvPath, "utf8"),
          ),
    });
    killGateway(gateway);
    record(
      "uninstall-clean",
      residualChecks.every((item) => item.ok),
      residualChecks,
    );

    if (guardApi && runner) {
      await runner.stopGuardApi(guardApi);
      guardApi = null;
    }
    writeReport(failures.length === 0);
    return failures.length === 0;
  } catch (error) {
    const message = redactSecrets(
      error instanceof Error ? (error.stack ?? error.message) : String(error),
      { secrets },
    );
    failures.push({ message: "smoke run aborted", details: message });
    if (gateway) {
      failures.push({ message: "gateway log tail", details: gateway.tail() });
    }
    console.error(message);
    writeReport(false);
    return false;
  } finally {
    killGateway(gateway);
    if (guardApi && runner) {
      await runner.stopGuardApi(guardApi).catch(() => undefined);
    }
  }
}

// ---------- CLI 入口 ----------

function isCliEntrypoint() {
  return (
    process.argv[1] !== undefined &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isCliEntrypoint()) {
  let options = null;
  try {
    options = parseSmokeArgs(process.argv.slice(2), process.env);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    console.error(
      "用法：node scripts/openclaw-runtime-smoke.mjs [--openclaw-root <dir>] [--expect-version <ver>] [--skip-guard-api] [--provision-env] [--report <path>]",
    );
    process.exit(2);
  }
  runSmoke(options)
    .then((ok) => {
      process.exit(ok ? 0 : 1);
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.stack : String(error));
      process.exit(1);
    });
}
