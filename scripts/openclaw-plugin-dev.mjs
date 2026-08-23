#!/usr/bin/env node
// OpenClaw 插件开发安装器：事务化安装/回滚、多证据校验、精准卸载。
// 结构：可导出纯函数层（供测试注入）+ 薄编排层。

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { OPENCLAW_REQUIRED_HOOKS } from "../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import { resolveGuardApiBaseUrl } from "./guard-api-endpoint.mjs";
import { resolveToolCommand, runTool } from "./openclaw-command-resolve.mjs";

export const PLUGIN_ID = "agentguard-security";
export const PLUGIN_PACKAGE = "@agentguard-ai/openclaw-plugin";
export const SECRET_PROVIDER_NAME = "agentguard_adapter";
export const STATE_ENV_TOKEN_KEY = "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN";
// 子进程环境中必须剥离的敏感变量：OpenClaw state 目录 .env 的 dotenv 只在
// process.env[key] === undefined 时注入，父进程同名变量会遮蔽它。
export const TOKEN_ENV_VARS = [
  STATE_ENV_TOKEN_KEY,
  "AGENTGUARD_ADAPTER_TOKEN",
  "AGENTGUARD_CONTROL_TOKEN",
];
const REQUIRED_HOOKS = OPENCLAW_REQUIRED_HOOKS;
const AGENT_ID = "main";
const ENFORCEMENT_MODE = "enforce";
const STAGING_REQUIRED_FILES = [
  "hook-contract.mjs",
  "openclaw.plugin.json",
  "package.json",
  "README.md",
];

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PLUGIN_ROOT = path.join(ROOT, "packages", "agentguard-openclaw-plugin");
const DEV_ROOT = path.join(ROOT, ".openclaw-dev");
const STAGING_DIR = path.join(DEV_ROOT, PLUGIN_ID);
const BACKUP_DIR = path.join(DEV_ROOT, "backups");
const SECRET_DIR = path.join(DEV_ROOT, "secrets");
const ADAPTER_TOKEN_SECRET_PATH = path.join(SECRET_DIR, "openclaw-adapter-token");

// ---------- 纯函数层 ----------

// 只尊重显式 OPENCLAW_* 覆盖；无覆盖时交给 CLI 默认（~/.openclaw）。
export function resolveProfile(env = {}) {
  const configPath = optionalPath(env.OPENCLAW_CONFIG_PATH);
  const stateDir = optionalPath(env.OPENCLAW_STATE_DIR);
  const home = optionalPath(env.OPENCLAW_HOME);
  const isolated = Boolean(configPath ?? stateDir ?? home);
  const resolvedStateDir =
    stateDir ?? (configPath ? path.dirname(configPath) : null);
  const resolvedConfigPath =
    configPath ?? (stateDir ? path.join(stateDir, "openclaw.json") : null);
  return {
    configPath: resolvedConfigPath,
    stateDir: resolvedStateDir,
    home,
    isolated,
  };
}

// Windows：env provider（state 目录 .env 注入）；POSIX：0600 secret 文件。
export function pickCredentialStrategy(platform, { secretPath = null } = {}) {
  if (platform === "win32") {
    return {
      kind: "env",
      providerName: SECRET_PROVIDER_NAME,
      provider: { source: "env", allowlist: [STATE_ENV_TOKEN_KEY] },
      secretRef: {
        source: "env",
        provider: SECRET_PROVIDER_NAME,
        id: STATE_ENV_TOKEN_KEY,
      },
    };
  }
  return {
    kind: "file",
    providerName: SECRET_PROVIDER_NAME,
    provider: { source: "file", path: secretPath, mode: "singleValue" },
    secretRef: { source: "file", provider: SECRET_PROVIDER_NAME, id: "value" },
  };
}

export function isAgentGuardLoadPath(value, stagingDir) {
  const resolved = path.resolve(expandHome(String(value)));
  if (resolved === path.resolve(stagingDir)) {
    return true;
  }
  return /agentguard-openclaw-plugin-install-p2|agentguard-security/.test(
    String(value),
  );
}

// 单一完整安装 patch；只覆盖 AgentGuard 键，无关 entries 保留。
// plugins.allow 是可选 allowlist：仅当现有配置已声明时才维护，
// 避免凭空引入 allowlist 阻断其他插件加载。
export function buildInstallPatch({
  config = {},
  stagingDir,
  guardApiBaseUrl,
  strategy,
  agentId = AGENT_ID,
}) {
  const plugins = config.plugins ?? {};
  const existingLoad =
    plugins.load &&
    typeof plugins.load === "object" &&
    !Array.isArray(plugins.load)
      ? plugins.load
      : {};
  const currentPaths = Array.isArray(existingLoad.paths)
    ? existingLoad.paths
    : [];
  const existingEntry =
    plugins.entries?.[PLUGIN_ID] &&
    typeof plugins.entries[PLUGIN_ID] === "object" &&
    !Array.isArray(plugins.entries[PLUGIN_ID])
      ? plugins.entries[PLUGIN_ID]
      : {};
  const existingHooks =
    existingEntry.hooks &&
    typeof existingEntry.hooks === "object" &&
    !Array.isArray(existingEntry.hooks)
      ? existingEntry.hooks
      : {};
  const existingConfig =
    existingEntry.config &&
    typeof existingEntry.config === "object" &&
    !Array.isArray(existingEntry.config)
      ? existingEntry.config
      : {};
  const patch = {
    secrets: {
      providers: { [strategy.providerName]: strategy.provider },
    },
    plugins: {
      load: {
        ...existingLoad,
        paths: [
          ...currentPaths.filter(
            (item) =>
              typeof item === "string" &&
              !isAgentGuardLoadPath(item, stagingDir),
          ),
          stagingDir,
        ],
      },
      entries: {
        [PLUGIN_ID]: {
          ...existingEntry,
          enabled: true,
          hooks: {
            timeoutMs: 600_000,
            allowConversationAccess: true,
            ...existingHooks,
          },
          config: {
            enforcementMode: ENFORCEMENT_MODE,
            requestTimeoutMs: 60_000,
            approvalPollIntervalMs: 100,
            approvalTimeoutMs: 600_000,
            ...existingConfig,
            // Only installation-owned wiring is authoritative on reinstall.
            guardApiBaseUrl,
            adapterToken: strategy.secretRef,
            agentId,
          },
        },
      },
    },
  };
  if (Array.isArray(plugins.allow)) {
    patch.plugins.allow = [
      ...plugins.allow.filter(
        (item) => typeof item === "string" && item !== PLUGIN_ID,
      ),
      PLUGIN_ID,
    ];
  }
  return patch;
}

// 卸载 patch：只移除 AgentGuard 自有引用，不动无关配置。
export function buildUninstallPatch({ config = {}, stagingDir }) {
  const plugins = config.plugins ?? {};
  const currentPaths = Array.isArray(plugins.load?.paths)
    ? plugins.load.paths
    : [];
  const patch = {
    secrets: { providers: { [SECRET_PROVIDER_NAME]: null } },
    plugins: {
      load: {
        paths: currentPaths.filter(
          (item) =>
            typeof item === "string" && !isAgentGuardLoadPath(item, stagingDir),
        ),
      },
      entries: { [PLUGIN_ID]: null },
    },
  };
  if (Array.isArray(plugins.allow)) {
    patch.plugins.allow = plugins.allow.filter((item) => item !== PLUGIN_ID);
  }
  return patch;
}

// 提取配置中的 AgentGuard 片段，用于幂等基线比对。
export function extractAgentGuardFragment(config, stagingDir) {
  const plugins = config?.plugins ?? {};
  return {
    entry: plugins.entries?.[PLUGIN_ID] ?? null,
    provider: config?.secrets?.providers?.[SECRET_PROVIDER_NAME] ?? null,
    loadPath: Array.isArray(plugins.load?.paths)
      ? (plugins.load.paths.find(
          (item) =>
            typeof item === "string" && isAgentGuardLoadPath(item, stagingDir),
        ) ?? null)
      : null,
    allowListed: Array.isArray(plugins.allow)
      ? plugins.allow.includes(PLUGIN_ID)
      : null,
  };
}

// 构造子进程环境：剥离敏感 token 变量，仅在显式隔离 profile 时注入 OPENCLAW_*。
export function buildCommandEnv(
  env,
  { profile = {}, stripTokenVars = TOKEN_ENV_VARS } = {},
) {
  const next = { ...env };
  for (const key of stripTokenVars) {
    delete next[key];
  }
  if (profile.home) {
    next.OPENCLAW_HOME = profile.home;
  }
  if (profile.stateDir) {
    next.OPENCLAW_STATE_DIR = profile.stateDir;
  }
  if (profile.configPath) {
    next.OPENCLAW_CONFIG_PATH = profile.configPath;
  }
  return next;
}

// 统一脱敏：先替换已知密钥值，再覆盖常见 token 键值/Authorization 模式。
export function redactSecrets(text, { secrets = [] } = {}) {
  let out = String(text ?? "");
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length >= 4) {
      out = out.split(secret).join("[REDACTED]");
    }
  }
  out = out
    .replace(/(authorization\s*[:=]\s*bearer\s+)\S+/gi, "$1[REDACTED]")
    .replace(/(AGENTGUARD_[A-Z0-9_]*TOKEN[A-Z0-9_]*\s*[:=]\s*)\S+/gi, "$1[REDACTED]");
  return out;
}

// gateway status 输出判定：Connectivity probe 必须 ok；
// Runtime 允许 unknown（Windows 任务计划不可查询时）和 stopped（重启/启动窗口瞬态，
// connectivity=ok 已证明进程存活），仅明确异常态（failed/error/dead）才失败。
export function evaluateGatewayStatus(stdout) {
  const text = String(stdout ?? "");
  const runtime = (
    /Runtime:\s*(\S+)/.exec(text)?.[1] ?? "unknown"
  ).toLowerCase();
  const connectivity = (
    /Connectivity probe:\s*(\S+)/.exec(text)?.[1] ?? "unknown"
  ).toLowerCase();
  const failedRuntime = new Set(["failed", "error", "dead"]);
  const ok = connectivity === "ok" && !failedRuntime.has(runtime);
  return { ok, runtime, connectivity };
}

// 仅显式隔离 profile 且未指定 --no-restart 时允许重启 Gateway。
export function shouldRestartGateway(profile, { noRestart = false } = {}) {
  return Boolean(profile?.isolated) && !noRestart;
}

// inspect 类 hook 失败判定：hookCount=0 与 missing hooks 只在 hooks 未被
// agent runtime 实际触发时出现，此时允许以 Guard API 新鲜 heartbeat 作为
// hook 证据回退；其余失败仍为硬门禁。
const INSPECT_HOOK_FAILURE_PATTERNS = [
  /^expected hookCount=\d+, got 0$/,
  /^missing hooks: /,
];

export function isInspectOnlyHookFailure(failureLines) {
  const lines = Array.isArray(failureLines) ? failureLines : [];
  return (
    lines.length > 0 &&
    lines.every((line) =>
      INSPECT_HOOK_FAILURE_PATTERNS.some((pattern) => pattern.test(line)),
    )
  );
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// 纯函数改写 state 目录 .env：只动指定键；value === null 表示删除该键。
export function rewriteStateEnv(content, key, value) {
  const raw = String(content ?? "");
  const lines = raw === "" ? [] : raw.split(/\r?\n/);
  let touched = false;
  const next = [];
  for (const line of lines) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match && match[1] === key) {
      touched = true;
      if (value !== null) {
        next.push(`${key}=${value}`);
      }
      continue;
    }
    next.push(line);
  }
  if (!touched && value !== null) {
    next.push(`${key}=${value}`);
  }
  return next.join("\n");
}

export function parseOpenClawVersion(text) {
  const match = /\b(\d{4}\.\d{1,2}\.\d{1,2}(?:[-+][0-9A-Za-z.-]+)?)\b/.exec(
    String(text ?? ""),
  );
  return match ? match[1] : null;
}

export function compareCalVer(a, b) {
  const parts = (value) =>
    String(value).split(/[-+]/, 1)[0].split(".").map(Number);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < 3; i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) {
      return Math.sign(diff);
    }
  }
  return 0;
}

export function satisfiesCalVerRange(version, range) {
  if (!version || !range) {
    return false;
  }
  for (const part of String(range).trim().split(/\s+/)) {
    const match = /^(>=|<=|>|<|=)?(.+)$/.exec(part);
    if (!match) {
      return false;
    }
    const op = match[1] ?? "=";
    const diff = compareCalVer(version, match[2]);
    if (
      (op === ">=" && diff < 0) ||
      (op === "<=" && diff > 0) ||
      (op === ">" && diff <= 0) ||
      (op === "<" && diff >= 0) ||
      (op === "=" && diff !== 0)
    ) {
      return false;
    }
  }
  return true;
}

// ---------- 编排层 ----------

export async function executeInstall(deps) {
  const { fs, log, profile } = deps;
  const repoEnv = deps.readRepoEnv();
  const adapterToken = requireEnv(repoEnv, "AGENTGUARD_ADAPTER_TOKEN");
  const secrets = [adapterToken];
  const guardApiBaseUrl = resolveGuardApiBaseUrl(repoEnv);
  const strategy = pickCredentialStrategy(deps.platform, {
    secretPath: deps.secretPath,
  });
  const { stateDir, configPath } = effectivePaths(deps);
  fs.mkdirSync(stateDir, { recursive: true });
  const childEnv = buildCommandEnv(repoEnv, {
    profile,
    stripTokenVars: TOKEN_ENV_VARS,
  });
  const runBase = { env: childEnv, cwd: stateDir, secrets };

  // Step 1 预检：token 与工具可解析，快速失败
  deps.resolveTool("pnpm", deps.resolveToolOptions);
  deps.resolveTool("openclaw", deps.resolveToolOptions);

  // Step 2 基线记录
  const baseline = captureBaseline(deps, { configPath, stateDir, runBase });
  backupOpenClawConfig(deps, configPath, "install");
  const oldStagingDir = `${deps.stagingDir}.old-${deps.pid}`;

  try {
    // Step 3 构建插件
    log(`Building ${PLUGIN_PACKAGE}...`);
    deps.buildPlugin(deps, runBase);
    // Step 4 临时目录构建校验完整后原子切换 staging
    await switchStaging(deps, { oldStagingDir });
    // Step 5 凭证准备（平台分流）
    prepareCredentials(deps, { strategy, adapterToken, stateDir });
    // Step 6 单一 patch：dry-run 先行，成功后写入
    const config = readConfigJson(deps, configPath);
    const patch = buildInstallPatch({
      config,
      stagingDir: deps.stagingDir,
      guardApiBaseUrl,
      strategy,
    });
    const plannedFragment = {
      entry: patch.plugins.entries[PLUGIN_ID],
      provider: patch.secrets.providers[strategy.providerName],
      loadPath: deps.stagingDir,
      allowListed: Array.isArray(config.plugins?.allow) ? true : null,
    };
    if (
      JSON.stringify(extractAgentGuardFragment(config, deps.stagingDir)) ===
      JSON.stringify(plannedFragment)
    ) {
      log("现有 AgentGuard 配置与目标一致，重复安装收敛。");
    }
    const patchFile = path.join(
      deps.devRoot,
      `.openclaw-config-patch-${deps.pid}.json`,
    );
    fs.mkdirSync(deps.devRoot, { recursive: true });
    fs.writeFileSync(patchFile, `${JSON.stringify(patch, null, 2)}\n`, {
      mode: 0o600,
    });
    try {
      const dryRun = deps.run(
        "openclaw",
        ["config", "patch", "--file", patchFile, "--dry-run", "--json"],
        { ...runBase, allowFailure: true, capture: true },
      );
      if (dryRun.status !== 0) {
        throw new Error(
          `Config patch dry-run failed:\n${combinedOutput(dryRun)}`,
        );
      }
      log("Config patch dry-run 校验通过，开始写入。");
      const apply = deps.run("openclaw", ["config", "patch", "--file", patchFile], {
        ...runBase,
        allowFailure: true,
        capture: true,
      });
      if (apply.status !== 0) {
        throw new Error(`Config patch apply failed:\n${combinedOutput(apply)}`);
      }
    } finally {
      fs.rmSync(patchFile, { force: true });
    }
    // Step 7 registry 刷新 → 重启（仅隔离 profile）→ 等待健康
    refreshRegistry(deps, runBase);
    if (shouldRestartGateway(profile, { noRestart: deps.noRestart })) {
      deps.run("openclaw", ["gateway", "restart", "--safe"], {
        ...runBase,
        allowFailure: true,
        capture: true,
      });
      await waitForGateway(deps, runBase);
    } else {
      log(
        profile.isolated
          ? "已指定 --no-restart，跳过 gateway 重启。"
          : "未使用显式隔离 profile，跳过 gateway 重启；如需生效请自行重启 Gateway。",
      );
    }
    // Step 9 成功后清理保留的旧 staging
    fs.rmSync(oldStagingDir, { recursive: true, force: true });
    log(`Installed ${PLUGIN_ID} from ${relativePath(deps.root, deps.stagingDir)}.`);
    return {
      ok: true,
      baselineConfigHash: baseline.configHash,
      strategy: strategy.kind,
      restart: shouldRestartGateway(profile, { noRestart: deps.noRestart }),
    };
  } catch (error) {
    // Step 8 任一步失败：按基线回滚并报告原始错误与回滚结果
    const rollbackOutcome = await rollbackToBaseline(deps, baseline, {
      oldStagingDir,
      runBase,
    });
    const message = redactSecrets(
      error instanceof Error ? error.message : String(error),
      { secrets },
    );
    throw new Error(
      `Install failed, rolled back to baseline:\nCause: ${message}\nRollback: ${rollbackOutcome.summary}`,
    );
  }
}

export async function executeUninstall(deps) {
  const { fs, log, profile } = deps;
  let repoEnv;
  try {
    repoEnv = deps.readRepoEnv();
  } catch {
    repoEnv = { ...process.env };
  }
  const { stateDir, configPath } = effectivePaths(deps);
  const childEnv = buildCommandEnv(repoEnv, {
    profile,
    stripTokenVars: TOKEN_ENV_VARS,
  });
  const runBase = { env: childEnv, cwd: stateDir, secrets: [] };

  deps.resolveTool("openclaw", deps.resolveToolOptions);
  backupOpenClawConfig(deps, configPath, "uninstall");
  const config = readConfigJson(deps, configPath);
  const patch = buildUninstallPatch({ config, stagingDir: deps.stagingDir });
  const patchFile = path.join(
    deps.devRoot,
    `.openclaw-config-patch-uninstall-${deps.pid}.json`,
  );
  fs.mkdirSync(deps.devRoot, { recursive: true });
  fs.writeFileSync(patchFile, `${JSON.stringify(patch, null, 2)}\n`, {
    mode: 0o600,
  });
  try {
    const dryRun = deps.run(
      "openclaw",
      ["config", "patch", "--file", patchFile, "--dry-run", "--json"],
      { ...runBase, allowFailure: true, capture: true },
    );
    if (dryRun.status !== 0) {
      throw new Error(`Uninstall patch dry-run failed:\n${combinedOutput(dryRun)}`);
    }
    const apply = deps.run("openclaw", ["config", "patch", "--file", patchFile], {
      ...runBase,
      allowFailure: true,
      capture: true,
    });
    if (apply.status !== 0) {
      const output = combinedOutput(apply);
      if (output.includes("Config write rejected")) {
        commitRejectedUninstallPayload(deps, {
          configPath,
          baseline: config,
          stagingDir: deps.stagingDir,
          output,
        });
        log(
          "OpenClaw 拒绝写入缩减后的配置（size-drop 保护），已校验被拒载荷仅移除本插件引用后原子写入。",
        );
      } else {
        throw new Error(`Uninstall patch apply failed:\n${output}`);
      }
    }
  } finally {
    fs.rmSync(patchFile, { force: true });
  }
  // 清理自有凭证：Windows 只删 state .env 专用变量；POSIX 删 secret 文件
  if (deps.platform === "win32") {
    const envPath = path.join(stateDir, ".env");
    if (fs.existsSync(envPath)) {
      atomicWriteFile(
        deps,
        envPath,
        rewriteStateEnv(fs.readFileSync(envPath, "utf8"), STATE_ENV_TOKEN_KEY, null),
        0o600,
      );
    }
  } else {
    fs.rmSync(deps.secretPath, { force: true });
  }
  refreshRegistry(deps, runBase);
  if (shouldRestartGateway(profile, { noRestart: deps.noRestart })) {
    deps.run("openclaw", ["gateway", "restart", "--safe"], {
      ...runBase,
      allowFailure: true,
      capture: true,
    });
    await waitForGateway(deps, runBase);
  } else {
    log("跳过 gateway 重启（仅显式隔离 profile 且未指定 --no-restart 时重启）。");
  }
  if (deps.cleanStaging) {
    fs.rmSync(deps.stagingDir, { recursive: true, force: true });
    log(`Removed ${relativePath(deps.root, deps.stagingDir)}.`);
  }
  log(`Uninstalled ${PLUGIN_ID}.`);
  return { ok: true };
}

export async function executeVerify(deps) {
  const startedAt = deps.now();
  const repoEnv = deps.readRepoEnv();
  const guardApiBaseUrl = resolveGuardApiBaseUrl(repoEnv);
  const controlToken = requireEnv(repoEnv, "AGENTGUARD_CONTROL_TOKEN");
  const secrets = [controlToken];
  const { stateDir, configPath } = effectivePaths(deps);
  const childEnv = buildCommandEnv(repoEnv, {
    profile: deps.profile,
    stripTokenVars: TOKEN_ENV_VARS,
  });
  const runBase = { env: childEnv, cwd: stateDir, secrets };
  const failures = [];

  // 证据 1：plugins inspect（loaded、hookCount、staging 指向、hook 集合、会话访问）
  let plugin = {};
  const inspect = deps.run(
    "openclaw",
    ["plugins", "inspect", PLUGIN_ID, "--runtime", "--json"],
    { ...runBase, allowFailure: true, capture: true },
  );
  if (inspect.status !== 0) {
    failures.push(`plugins inspect failed:\n${combinedOutput(inspect)}`);
  } else {
    const parsed = parseJsonObject(inspect.stdout);
    plugin = parsed.plugin ?? {};
    const typedHooks = Array.isArray(parsed.typedHooks) ? parsed.typedHooks : [];
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
    if (!pluginUsesStaging(plugin, deps.stagingDir)) {
      failures.push(
        `expected plugin source/rootDir to use ${relativePath(deps.root, deps.stagingDir)}, got ${plugin.source ?? plugin.rootDir}`,
      );
    }
    if (missingHooks.length > 0) {
      failures.push(`missing hooks: ${missingHooks.join(", ")}`);
    }
    if (conversationAccessDiagnostics.length > 0) {
      failures.push(conversationAccessDiagnostics.join("; "));
    }
  }

  // 证据 2：Gateway RPC 连通（status 连通性证据；Runtime 允许 unknown）
  const gateway = deps.run("openclaw", ["gateway", "status"], {
    ...runBase,
    allowFailure: true,
    capture: true,
  });
  const gatewayEval = evaluateGatewayStatus(gateway.stdout ?? "");
  if (gateway.status !== 0 || !gatewayEval.ok) {
    failures.push(
      `Gateway RPC 连通异常 (exit=${gateway.status}, runtime=${gatewayEval.runtime}, connectivity=${gatewayEval.connectivity})`,
    );
  }

  // 证据 3：Guard API 新鲜 heartbeat（晚于本次验证开始时刻）
  const heartbeat = await waitForFreshHeartbeat({
    fetchImpl: deps.fetch,
    baseUrl: guardApiBaseUrl,
    controlToken,
    since: startedAt,
    timeoutMs: deps.heartbeatTimeoutMs ?? 45000,
    pollMs: deps.heartbeatPollMs ?? 2000,
    sleep: deps.sleep,
  });
  if (!heartbeat.fresh) {
    failures.push(
      `Guard API 无新鲜 heartbeat：last=${heartbeat.lastHeartbeatAt ?? "none"}${heartbeat.error ? `（${heartbeat.error}）` : ""}`,
    );
  }

  // 证据 4：enforce 模式、插件版本与 OpenClaw 版本一致性
  const config = readConfigJson(deps, configPath);
  const entry = config.plugins?.entries?.[PLUGIN_ID] ?? {};
  const entryHooks = entry.hooks ?? {};
  const entryConfig = entry.config ?? {};
  if (entryConfig.enforcementMode !== ENFORCEMENT_MODE) {
    failures.push(
      `expected enforcementMode=${ENFORCEMENT_MODE}, got ${String(entryConfig.enforcementMode)}`,
    );
  }
  const hookTimeoutMs = entryHooks.timeoutMs;
  const approvalTimeoutMs = entryConfig.approvalTimeoutMs;
  if (
    typeof hookTimeoutMs === "number" &&
    Number.isFinite(hookTimeoutMs) &&
    typeof approvalTimeoutMs === "number" &&
    Number.isFinite(approvalTimeoutMs) &&
    hookTimeoutMs < approvalTimeoutMs
  ) {
    failures.push(
      `hooks.timeoutMs (${hookTimeoutMs}) must be >= approvalTimeoutMs (${approvalTimeoutMs}); verify does not modify configuration`,
    );
  }
  const versionResult = deps.run("openclaw", ["--version"], {
    ...runBase,
    allowFailure: true,
    capture: true,
  });
  const openclawVersion = parseOpenClawVersion(combinedOutput(versionResult));
  const pluginVersion =
    readJsonSafe(deps, path.join(deps.stagingDir, "package.json"))?.version ??
    null;
  const peerRange =
    readJsonSafe(deps, path.join(deps.pluginRoot, "package.json"))
      ?.peerDependencies?.openclaw ?? null;
  if (!openclawVersion) {
    failures.push("无法解析 OpenClaw 版本（openclaw --version）");
  } else if (peerRange && !satisfiesCalVerRange(openclawVersion, peerRange)) {
    failures.push(
      `OpenClaw 版本 ${openclawVersion} 不在插件兼容范围 ${peerRange} 内`,
    );
  }

  const statusPayload = {
    status: "loaded",
    loaded: true,
    hook_count: typeof plugin.hookCount === "number" ? plugin.hookCount : null,
    expected_hook_count: REQUIRED_HOOKS.length,
    last_verified_at: new Date().toISOString(),
    last_heartbeat_at: heartbeat.lastHeartbeatAt,
    error: null,
    source: "openclaw-plugin-dev",
    hook_evidence_source: "inspect",
    agent_id: AGENT_ID,
    plugin_version: pluginVersion,
    runtime_version: openclawVersion,
    enforcement_mode: ENFORCEMENT_MODE,
  };

  // inspect 的 hookCount 需 hooks 被 agent runtime 实际触发后才上报；
  // 仅剩 inspect 类 hook 失败且 Guard API 新鲜 heartbeat 实证 loaded/24 hooks
  // 时，以 heartbeat 为 hook 证据通过并标记回退来源；两者皆缺时仍失败。
  if (failures.length > 0 && isInspectOnlyHookFailure(failures)) {
    if (
      heartbeat.fresh &&
      heartbeat.loaded === true &&
      heartbeat.hookCount === REQUIRED_HOOKS.length
    ) {
      statusPayload.hook_count = heartbeat.hookCount;
      statusPayload.hook_evidence_source = "heartbeat-fallback";
      failures.length = 0;
    }
  }

  if (failures.length > 0) {
    const errorMessage = redactSecrets(failures.join("\n- "), { secrets });
    if (deps.record) {
      await safeRecordStatus(deps, {
        ...statusPayload,
        status: "error",
        loaded: false,
        error: errorMessage,
        guardApiBaseUrl,
        controlToken,
      });
    }
    throw new Error(
      redactSecrets(
        `OpenClaw plugin verification failed:\n- ${failures.join("\n- ")}`,
        { secrets },
      ),
    );
  }
  if (deps.record) {
    await safeRecordStatus(deps, {
      ...statusPayload,
      guardApiBaseUrl,
      controlToken,
    });
  }
  deps.log(
    `Verified ${PLUGIN_ID}: status=loaded, hookCount=${statusPayload.hook_count}, hookEvidence=${statusPayload.hook_evidence_source}, heartbeat=${heartbeat.lastHeartbeatAt}, runtime=${gatewayEval.runtime}, openclaw=${openclawVersion}, plugin=${pluginVersion}.`,
  );
  return statusPayload;
}

export async function waitForFreshHeartbeat({
  fetchImpl,
  baseUrl,
  controlToken,
  since,
  timeoutMs,
  pollMs,
  sleep,
}) {
  const deadline = Date.now() + timeoutMs;
  let lastHeartbeatAt = null;
  let lastError = null;
  while (true) {
    try {
      const response = await fetchImpl(`${baseUrl}/v1/adapters/openclaw/status`, {
        redirect: "error",
        headers: { Authorization: `Bearer ${controlToken}` },
      });
      if (response.ok) {
        const body = await response.json();
        lastHeartbeatAt = body?.last_heartbeat_at ?? lastHeartbeatAt;
        const heartbeatMs = Date.parse(body?.last_heartbeat_at ?? "");
        if (Number.isFinite(heartbeatMs) && heartbeatMs >= since.getTime()) {
          return {
            fresh: true,
            lastHeartbeatAt: body.last_heartbeat_at,
            loaded: body?.loaded === true,
            hookCount:
              typeof body?.hook_count === "number" ? body.hook_count : null,
          };
        }
      } else {
        lastError = `HTTP ${response.status}`;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() + pollMs > deadline) {
      return {
        fresh: false,
        lastHeartbeatAt,
        loaded: null,
        hookCount: null,
        error: lastError,
      };
    }
    await sleep(pollMs);
  }
}

// ---------- 编排内部辅助 ----------

function effectivePaths(deps) {
  const stateDir =
    deps.profile.stateDir ??
    (deps.profile.configPath
      ? path.dirname(deps.profile.configPath)
      : path.join(os.homedir(), ".openclaw"));
  const configPath =
    deps.profile.configPath ?? path.join(stateDir, "openclaw.json");
  return { stateDir, configPath };
}

function captureBaseline(deps, { configPath, stateDir, runBase }) {
  const { fs, platform } = deps;
  const configBytes = fs.existsSync(configPath)
    ? fs.readFileSync(configPath)
    : null;
  const stateEnvPath =
    platform === "win32" ? path.join(stateDir, ".env") : null;
  const stateEnvBytes =
    stateEnvPath && fs.existsSync(stateEnvPath)
      ? fs.readFileSync(stateEnvPath)
      : null;
  const secretBytes =
    platform !== "win32" && fs.existsSync(deps.secretPath)
      ? fs.readFileSync(deps.secretPath)
      : null;
  const restartAllowed = shouldRestartGateway(deps.profile, {
    noRestart: deps.noRestart,
  });
  return {
    configPath,
    configBytes,
    configHash: configBytes ? sha256Hex(configBytes) : null,
    stateEnvPath,
    stateEnvBytes,
    secretBytes,
    stagingExisted: fs.existsSync(deps.stagingDir),
    restartAllowed,
    gatewayWasRunning: restartAllowed
      ? probeGatewayRunning(deps, runBase)
      : false,
  };
}

function probeGatewayRunning(deps, runBase) {
  try {
    const result = deps.run("openclaw", ["gateway", "status"], {
      ...runBase,
      allowFailure: true,
      capture: true,
    });
    return result.status === 0 && evaluateGatewayStatus(result.stdout ?? "").ok;
  } catch {
    return false;
  }
}

// Windows 上防病毒实时扫描等瞬时占用会使 rename 短暂失败（EPERM/EACCES/EBUSY），
// 目录切换与回滚路径均需短时重试，否则安装被瞬时锁击穿。
const RETRYABLE_RENAME_CODES = new Set([
  "EPERM",
  "EACCES",
  "EBUSY",
  "EAGAIN",
  "ENOTEMPTY",
]);
const DEFAULT_RENAME_ATTEMPTS = 3;
const DEFAULT_RENAME_RETRY_DELAY_MS = 250;

async function renameWithRetry(deps, from, to) {
  const attempts = deps.renameAttempts ?? DEFAULT_RENAME_ATTEMPTS;
  const delayMs = deps.renameRetryDelayMs ?? DEFAULT_RENAME_RETRY_DELAY_MS;
  for (let attempt = 1; ; attempt += 1) {
    try {
      deps.fs.renameSync(from, to);
      return;
    } catch (error) {
      const retryable =
        error && typeof error === "object"
          ? RETRYABLE_RENAME_CODES.has(error.code)
          : false;
      if (!retryable || attempt >= attempts) {
        throw error;
      }
      deps.warn(
        `rename 瞬时失败（${error.code}），重试 ${attempt}/${attempts}：${from} -> ${to}`,
      );
      await deps.sleep(delayMs);
    }
  }
}

async function switchStaging(deps, { oldStagingDir }) {
  const { fs } = deps;
  const tempDir = `${deps.stagingDir}.next-${deps.pid}`;
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });
  copyRecursive(fs, path.join(deps.pluginRoot, "dist"), path.join(tempDir, "dist"));
  for (const fileName of STAGING_REQUIRED_FILES) {
    const source = path.join(deps.pluginRoot, fileName);
    if (!fs.existsSync(source)) {
      throw new Error(`插件源文件缺失：${fileName}`);
    }
    fs.copyFileSync(source, path.join(tempDir, fileName));
  }
  for (const required of [
    "package.json",
    "openclaw.plugin.json",
    "hook-contract.mjs",
    path.join("dist", "index.js"),
  ]) {
    if (!fs.existsSync(path.join(tempDir, required))) {
      throw new Error(`staging 构建不完整，缺少 ${required}`);
    }
  }
  if (fs.existsSync(path.join(tempDir, "node_modules"))) {
    throw new Error("staging unexpectedly contains node_modules");
  }
  // 旧 staging 先改名保留，切换成功后才允许清理
  fs.rmSync(oldStagingDir, { recursive: true, force: true });
  if (fs.existsSync(deps.stagingDir)) {
    await renameWithRetry(deps, deps.stagingDir, oldStagingDir);
  }
  try {
    await renameWithRetry(deps, tempDir, deps.stagingDir);
  } catch (error) {
    if (fs.existsSync(oldStagingDir)) {
      await renameWithRetry(deps, oldStagingDir, deps.stagingDir);
    }
    // 失败不留临时 staging 残留
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

function prepareCredentials(deps, { strategy, adapterToken, stateDir }) {
  const { fs } = deps;
  if (strategy.kind === "env") {
    const envPath = path.join(stateDir, ".env");
    const original = fs.existsSync(envPath)
      ? fs.readFileSync(envPath, "utf8")
      : "";
    atomicWriteFile(
      deps,
      envPath,
      rewriteStateEnv(original, STATE_ENV_TOKEN_KEY, adapterToken),
      0o600,
    );
    return;
  }
  fs.mkdirSync(path.dirname(deps.secretPath), { recursive: true, mode: 0o700 });
  atomicWriteFile(deps, deps.secretPath, `${adapterToken}\n`, 0o600);
}

/**
 * 校验 OpenClaw 因 size-drop 保护而拒绝写入的卸载载荷：
 * 必须已移除全部本插件引用，且未改动任何无关配置键（meta 由 CLI 自动维护，忽略）。
 */
export function validateUninstallPayload(payload, { baseline, stagingDir }) {
  const entries = payload?.plugins?.entries;
  if (entries && Object.keys(entries).includes(PLUGIN_ID)) {
    throw new Error(
      `Rejected uninstall payload still contains plugins.entries.${PLUGIN_ID}`,
    );
  }
  const loadPaths = payload?.plugins?.load?.paths;
  if (
    Array.isArray(loadPaths) &&
    loadPaths.some((item) => isAgentGuardLoadPath(item, stagingDir))
  ) {
    throw new Error("Rejected uninstall payload still contains AgentGuard load path");
  }
  const providers = payload?.secrets?.providers;
  if (providers && Object.keys(providers).includes(SECRET_PROVIDER_NAME)) {
    throw new Error(
      `Rejected uninstall payload still contains secrets.providers.${SECRET_PROVIDER_NAME}`,
    );
  }
  const baselineRecord =
    baseline && typeof baseline === "object" ? baseline : {};
  for (const [key, value] of Object.entries(baselineRecord)) {
    if (key === "meta" || key === "plugins" || key === "secrets") {
      continue;
    }
    if (JSON.stringify(payload?.[key]) !== JSON.stringify(value)) {
      throw new Error(
        `Rejected uninstall payload altered unrelated config key "${key}"`,
      );
    }
  }
  return true;
}

function findLatestRejectedConfig(deps, configPath) {
  const dir = path.dirname(configPath);
  const prefix = `${path.basename(configPath)}.rejected.`;
  let latest = null;
  for (const name of deps.fs.readdirSync(dir)) {
    if (!name.startsWith(prefix)) {
      continue;
    }
    const candidate = path.join(dir, name);
    const mtimeMs = deps.fs.statSync(candidate).mtimeMs;
    if (latest === null || mtimeMs > latest.mtimeMs) {
      latest = { candidate, mtimeMs };
    }
  }
  return latest?.candidate ?? null;
}

function commitRejectedUninstallPayload(deps, { configPath, baseline, stagingDir, output }) {
  const rejectedPath = findLatestRejectedConfig(deps, configPath);
  if (!rejectedPath) {
    throw new Error(
      `Uninstall patch apply rejected but no rejected payload found:\n${output}`,
    );
  }
  const payload = JSON.parse(deps.fs.readFileSync(rejectedPath, "utf8"));
  validateUninstallPayload(payload, { baseline, stagingDir });
  atomicWriteFile(deps, configPath, `${JSON.stringify(payload, null, 2)}\n`, 0o600);
  JSON.parse(deps.fs.readFileSync(configPath, "utf8"));
  deps.fs.rmSync(rejectedPath, { force: true });
}

function atomicWriteFile(deps, targetPath, content, mode) {
  const tmpPath = `${targetPath}.tmp-${deps.pid}-${Date.now()}`;
  deps.fs.writeFileSync(tmpPath, content, { mode });
  deps.fs.renameSync(tmpPath, targetPath);
}

async function rollbackToBaseline(deps, baseline, { oldStagingDir, runBase }) {
  const { fs } = deps;
  const outcomes = [];
  const note = (label, ok) => outcomes.push(`${label}${ok ? "成功" : "失败"}`);
  try {
    if (baseline.configBytes !== null) {
      fs.writeFileSync(baseline.configPath, baseline.configBytes, {
        mode: 0o600,
      });
    } else if (fs.existsSync(baseline.configPath)) {
      fs.rmSync(baseline.configPath);
    }
    const restoredHash = fs.existsSync(baseline.configPath)
      ? sha256Hex(fs.readFileSync(baseline.configPath))
      : null;
    note("配置还原", restoredHash === baseline.configHash);
    if (baseline.stateEnvPath) {
      if (baseline.stateEnvBytes !== null) {
        fs.writeFileSync(baseline.stateEnvPath, baseline.stateEnvBytes);
      } else if (fs.existsSync(baseline.stateEnvPath)) {
        fs.rmSync(baseline.stateEnvPath);
      }
      note("state .env 还原", true);
    }
    if (deps.platform !== "win32") {
      if (baseline.secretBytes !== null) {
        fs.writeFileSync(deps.secretPath, baseline.secretBytes, { mode: 0o600 });
      } else if (fs.existsSync(deps.secretPath)) {
        fs.rmSync(deps.secretPath);
      }
      note("secret 文件还原", true);
    }
    if (fs.existsSync(oldStagingDir)) {
      fs.rmSync(deps.stagingDir, { recursive: true, force: true });
      await renameWithRetry(deps, oldStagingDir, deps.stagingDir);
      note("staging 还原", true);
    } else if (!baseline.stagingExisted && fs.existsSync(deps.stagingDir)) {
      fs.rmSync(deps.stagingDir, { recursive: true, force: true });
      note("staging 清理", true);
    }
    // 清理切换失败可能遗留的临时 staging 目录
    fs.rmSync(`${deps.stagingDir}.next-${deps.pid}`, {
      recursive: true,
      force: true,
    });
    if (baseline.restartAllowed && baseline.gatewayWasRunning) {
      try {
        deps.run("openclaw", ["gateway", "restart", "--safe"], {
          ...runBase,
          allowFailure: true,
          capture: true,
        });
        note("gateway 重启", true);
      } catch {
        note("gateway 重启", false);
      }
    }
  } catch (error) {
    outcomes.push(
      `回滚异常：${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return { outcomes, summary: outcomes.join("；") || "无需回滚动作" };
}

function refreshRegistry(deps, runBase) {
  const result = deps.run("openclaw", ["plugins", "registry", "--refresh"], {
    ...runBase,
    allowFailure: true,
    capture: true,
  });
  if (result.status !== 0) {
    throw new Error(
      `Failed to refresh OpenClaw plugin registry:\n${combinedOutput(result)}`,
    );
  }
  deps.log("Refreshed OpenClaw plugin registry.");
}

async function waitForGateway(deps, runBase) {
  const attempts = deps.gatewayWaitAttempts ?? 12;
  const intervalMs = deps.gatewayWaitIntervalMs ?? 1000;
  let lastOutput = "";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = deps.run("openclaw", ["gateway", "status"], {
      ...runBase,
      allowFailure: true,
      capture: true,
    });
    lastOutput = combinedOutput(result);
    if (result.status === 0 && evaluateGatewayStatus(result.stdout ?? "").ok) {
      return;
    }
    await deps.sleep(intervalMs);
  }
  throw new Error(`OpenClaw gateway did not become healthy:\n${lastOutput}`);
}

function backupOpenClawConfig(deps, configPath, reason) {
  const { fs } = deps;
  fs.mkdirSync(deps.backupDir, { recursive: true });
  if (!fs.existsSync(configPath)) {
    deps.warn(`OpenClaw config not found at ${configPath}; skipping backup.`);
    return null;
  }
  const backupPath = path.join(
    deps.backupDir,
    `${timestamp()}-${reason}-openclaw.json`,
  );
  fs.copyFileSync(configPath, backupPath);
  try {
    fs.chmodSync(backupPath, 0o600);
  } catch {
    // Windows 上 chmod 不受支持，忽略
  }
  return backupPath;
}

// Guard API AdapterStatusRecord 采用 extra=forbid 契约，记录前剥离契约外字段
//（如 hook_evidence_source 仅作为 verify 结果标记，不落库）。
const GUARD_API_ADAPTER_STATUS_FIELDS = [
  "status",
  "loaded",
  "hook_count",
  "expected_hook_count",
  "last_verified_at",
  "last_heartbeat_at",
  "error",
  "source",
  "runtime_id",
  "agent_id",
  "plugin_version",
  "runtime_version",
  "capabilities",
  "hooks",
  "fail_closed_stages",
  "enforcement_mode",
];

async function safeRecordStatus(deps, { guardApiBaseUrl, controlToken, ...status }) {
  try {
    const payload = {};
    for (const key of GUARD_API_ADAPTER_STATUS_FIELDS) {
      if (status[key] !== undefined) {
        payload[key] = status[key];
      }
    }
    const response = await deps.fetch(
      `${guardApiBaseUrl}/v1/adapters/openclaw/status`,
      {
        method: "PUT",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${controlToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      },
    );
    if (!response.ok) {
      throw new Error(`Guard API status record failed with HTTP ${response.status}`);
    }
  } catch (recordError) {
    deps.warn(
      `Failed to record OpenClaw verification status: ${recordError instanceof Error ? recordError.message : String(recordError)}`,
    );
  }
}

// ---------- 运行时默认依赖 ----------

export function createRuntimeDeps(overrides = {}) {
  const profile = resolveProfile(process.env);
  return {
    fs,
    platform: process.platform,
    pid: process.pid,
    now: () => new Date(),
    root: ROOT,
    pluginRoot: PLUGIN_ROOT,
    devRoot: DEV_ROOT,
    stagingDir: STAGING_DIR,
    backupDir: BACKUP_DIR,
    secretPath: ADAPTER_TOKEN_SECRET_PATH,
    profile,
    readRepoEnv: () => readDotEnv(ROOT),
    run: (tool, args, options = {}) => runTool(tool, args, options),
    resolveTool: resolveToolCommand,
    resolveToolOptions: undefined,
    buildPlugin: (deps, runBase) =>
      deps.run("pnpm", ["--filter", PLUGIN_PACKAGE, "build"], {
        ...runBase,
        cwd: deps.root,
      }),
    fetch: (...args) => fetch(...args),
    log: console.log,
    warn: console.warn,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    gatewayWaitAttempts: 12,
    gatewayWaitIntervalMs: 1000,
    heartbeatTimeoutMs: 45000,
    heartbeatPollMs: 2000,
    ...overrides,
  };
}

function readDotEnv(root) {
  const envPath = path.join(root, ".env");
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

function readConfigJson(deps, configPath) {
  if (!deps.fs.existsSync(configPath)) {
    return {};
  }
  return JSON.parse(deps.fs.readFileSync(configPath, "utf8"));
}

function readJsonSafe(deps, jsonPath) {
  try {
    return JSON.parse(deps.fs.readFileSync(jsonPath, "utf8"));
  } catch {
    return null;
  }
}

function pluginUsesStaging(plugin, stagingDir) {
  const staging = path.resolve(stagingDir);
  const source =
    typeof plugin.source === "string" ? path.resolve(plugin.source) : "";
  const rootDir =
    typeof plugin.rootDir === "string" ? path.resolve(plugin.rootDir) : "";
  return rootDir === staging || source.startsWith(`${staging}${path.sep}`);
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

function copyRecursive(fs, source, destination) {
  const stat = fs.statSync(source);
  if (stat.isDirectory()) {
    fs.mkdirSync(destination, { recursive: true });
    for (const entry of fs.readdirSync(source)) {
      copyRecursive(fs, path.join(source, entry), path.join(destination, entry));
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

function optionalPath(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return trimmed ? path.resolve(expandHome(trimmed)) : null;
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function relativePath(root, value) {
  return path.relative(root, value) || ".";
}

// ---------- CLI 入口 ----------

const command = process.argv[2];
const flags = new Set(process.argv.slice(3));

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(
      redactSecrets(error instanceof Error ? error.message : String(error)),
    );
    process.exit(1);
  });
}

async function main() {
  if (command === "install") {
    await executeInstall(
      createRuntimeDeps({ noRestart: flags.has("--no-restart") }),
    );
    return;
  }
  if (command === "verify") {
    await executeVerify(createRuntimeDeps({ record: flags.has("--record") }));
    return;
  }
  if (command === "uninstall") {
    await executeUninstall(
      createRuntimeDeps({
        cleanStaging: flags.has("--clean-staging"),
        noRestart: flags.has("--no-restart"),
      }),
    );
    return;
  }
  usage();
  process.exit(command ? 1 : 0);
}

function usage() {
  console.log(`Usage:
  node scripts/openclaw-plugin-dev.mjs install [--no-restart]
  node scripts/openclaw-plugin-dev.mjs verify [--record]
  node scripts/openclaw-plugin-dev.mjs uninstall [--clean-staging] [--no-restart]

隔离 profile：显式设置 OPENCLAW_HOME / OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH。
仅显式隔离 profile 且未指定 --no-restart 时才会重启 Gateway。`);
}
