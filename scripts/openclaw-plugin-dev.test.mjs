import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildCommandEnv,
  buildInstallPatch,
  buildUninstallPatch,
  compareCalVer,
  evaluateGatewayStatus,
  executeInstall,
  executeUninstall,
  executeVerify,
  extractAgentGuardFragment,
  isAgentGuardLoadPath,
  isInspectOnlyHookFailure,
  parseOpenClawVersion,
  pickCredentialStrategy,
  redactSecrets,
  resolveProfile,
  rewriteStateEnv,
  satisfiesCalVerRange,
  sha256Hex,
  shouldRestartGateway,
  waitForFreshHeartbeat,
} from "./openclaw-plugin-dev.mjs";
import { OPENCLAW_REQUIRED_HOOKS } from "../packages/agentguard-openclaw-plugin/hook-contract.mjs";

const SENTINEL_TOKEN = "tok_sentinel_supersecret_123456";
const PLUGIN_ID = "agentguard-security";

// ---------- 测试基建：临时 world + fake run ----------

// 模拟 `openclaw config patch` 语义：对象递归合并、数组/标量替换、null 删除。
function applyPatchToConfig(target, patch) {
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete target[key];
      continue;
    }
    if (
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof target[key] === "object" &&
      target[key] !== null &&
      !Array.isArray(target[key])
    ) {
      applyPatchToConfig(target[key], value);
      continue;
    }
    target[key] = value;
  }
  return target;
}

function createWorld({ platform = "win32", adapterToken = SENTINEL_TOKEN } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "plugin-dev-test-"));
  const pluginRoot = path.join(root, "plugin");
  fs.mkdirSync(path.join(pluginRoot, "dist"), { recursive: true });
  fs.writeFileSync(path.join(pluginRoot, "dist", "index.js"), "// dist");
  fs.writeFileSync(path.join(pluginRoot, "hook-contract.mjs"), "");
  fs.writeFileSync(path.join(pluginRoot, "openclaw.plugin.json"), "{}");
  fs.writeFileSync(
    path.join(pluginRoot, "package.json"),
    JSON.stringify({
      name: "@agentguard-ai/openclaw-plugin",
      version: "0.1.0-beta.1",
      peerDependencies: { openclaw: ">=2026.6.6 <2027.0.0" },
    }),
  );
  fs.writeFileSync(path.join(pluginRoot, "README.md"), "");

  const profileDir = path.join(root, "profile");
  fs.mkdirSync(profileDir, { recursive: true });
  const profile = {
    configPath: path.join(profileDir, "openclaw.json"),
    stateDir: profileDir,
    home: profileDir,
    isolated: true,
  };

  const devRoot = path.join(root, ".openclaw-dev");
  const stagingDir = path.join(devRoot, PLUGIN_ID);

  const calls = [];
  const logs = [];
  const dryRunConfigSnapshots = [];
  let failAt = null;
  let currentToken = adapterToken;

  const run = (tool, args) => {
    calls.push({ tool, args: [...args] });
    if (failAt) {
      const failure = failAt(tool, [...args]);
      if (failure) {
        return { status: 1, stdout: "", stderr: failure };
      }
    }
    if (tool === "openclaw" && args[0] === "config" && args[1] === "patch") {
      if (args.includes("--dry-run")) {
        dryRunConfigSnapshots.push(
          fs.existsSync(profile.configPath)
            ? fs.readFileSync(profile.configPath, "utf8")
            : null,
        );
        return { status: 0, stdout: "{}", stderr: "" };
      }
      const patchFile = args[args.indexOf("--file") + 1];
      const patch = JSON.parse(fs.readFileSync(patchFile, "utf8"));
      const current = fs.existsSync(profile.configPath)
        ? JSON.parse(fs.readFileSync(profile.configPath, "utf8"))
        : {};
      applyPatchToConfig(current, patch);
      fs.writeFileSync(profile.configPath, JSON.stringify(current, null, 2));
      return { status: 0, stdout: "{}", stderr: "" };
    }
    if (tool === "openclaw" && args[0] === "gateway" && args[1] === "status") {
      return {
        status: 0,
        stdout: "Runtime: running\nConnectivity probe: ok\n",
        stderr: "",
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };

  const deps = {
    fs,
    platform,
    pid: 4242,
    now: () => new Date(),
    root,
    pluginRoot,
    devRoot,
    stagingDir,
    backupDir: path.join(devRoot, "backups"),
    secretPath: path.join(devRoot, "secrets", "openclaw-adapter-token"),
    profile,
    readRepoEnv: () => ({
      AGENTGUARD_ADAPTER_TOKEN: currentToken,
      AGENTGUARD_CONTROL_TOKEN: "control-token-value",
      AGENTGUARD_API_URL: "http://127.0.0.1:8088",
      PATH: process.env.PATH ?? "",
    }),
    run,
    resolveTool: () => ({ command: "fake", prependArgs: [] }),
    resolveToolOptions: undefined,
    buildPlugin: () => {},
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    log: (message) => logs.push(String(message)),
    warn: (message) => logs.push(String(message)),
    sleep: async () => {},
    gatewayWaitAttempts: 2,
    gatewayWaitIntervalMs: 1,
    heartbeatTimeoutMs: 10,
    heartbeatPollMs: 1,
    noRestart: false,
    record: false,
    cleanStaging: false,
  };

  return {
    root,
    deps,
    calls,
    logs,
    profile,
    profileDir,
    stagingDir,
    dryRunConfigSnapshots,
    setFailAt: (fn) => {
      failAt = fn;
    },
    setToken: (token) => {
      currentToken = token;
    },
    seedConfig: (config) => {
      fs.writeFileSync(
        profile.configPath,
        `${JSON.stringify(config, null, 2)}\n`,
      );
    },
    readConfig: () => JSON.parse(fs.readFileSync(profile.configPath, "utf8")),
    backupFiles: () => {
      const dir = path.join(devRoot, "backups");
      if (!fs.existsSync(dir)) {
        return [];
      }
      return fs
        .readdirSync(dir)
        .map((name) => fs.readFileSync(path.join(dir, name), "utf8"));
    },
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

function callIndex(calls, predicate) {
  return calls.findIndex((call) => predicate(call.tool, call.args));
}

// ---------- resolveProfile ----------

test("resolveProfile honors explicit OPENCLAW_* overrides only", () => {
  const profile = resolveProfile({
    OPENCLAW_HOME: "/tmp/oc-home",
    OPENCLAW_STATE_DIR: "/tmp/oc-state",
    OPENCLAW_CONFIG_PATH: "/tmp/oc-state/openclaw.json",
  });
  assert.equal(profile.isolated, true);
  assert.equal(profile.stateDir, path.resolve("/tmp/oc-state"));
  assert.equal(profile.configPath, path.resolve("/tmp/oc-state/openclaw.json"));
  assert.equal(profile.home, path.resolve("/tmp/oc-home"));
});

test("resolveProfile without overrides defers to CLI defaults", () => {
  const profile = resolveProfile({});
  assert.equal(profile.isolated, false);
  assert.equal(profile.configPath, null);
  assert.equal(profile.stateDir, null);
  assert.equal(profile.home, null);
});

test("resolveProfile derives state dir from config path sibling", () => {
  const profile = resolveProfile({
    OPENCLAW_CONFIG_PATH: "/tmp/oc/openclaw.json",
  });
  assert.equal(profile.isolated, true);
  assert.equal(profile.stateDir, path.resolve("/tmp/oc"));
});

// ---------- 凭证策略分流 ----------

test("pickCredentialStrategy uses env provider on Windows", () => {
  const strategy = pickCredentialStrategy("win32");
  assert.equal(strategy.kind, "env");
  assert.deepEqual(strategy.provider, {
    source: "env",
    allowlist: ["AGENTGUARD_OPENCLAW_ADAPTER_TOKEN"],
  });
  assert.deepEqual(strategy.secretRef, {
    source: "env",
    provider: "agentguard_adapter",
    id: "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN",
  });
});

test("pickCredentialStrategy uses file provider on POSIX", () => {
  const strategy = pickCredentialStrategy("linux", {
    secretPath: "/repo/.openclaw-dev/secrets/openclaw-adapter-token",
  });
  assert.equal(strategy.kind, "file");
  assert.deepEqual(strategy.provider, {
    source: "file",
    path: "/repo/.openclaw-dev/secrets/openclaw-adapter-token",
    mode: "singleValue",
  });
  assert.deepEqual(strategy.secretRef, {
    source: "file",
    provider: "agentguard_adapter",
    id: "value",
  });
});

// ---------- patch 构造 ----------

test("buildInstallPatch keeps unrelated keys and manages allow only when present", () => {
  const strategy = pickCredentialStrategy("win32");
  const patch = buildInstallPatch({
    config: {
      channels: { qqbot: { enabled: true } },
      plugins: {
        load: {
          paths: ["/other/plugin", "/repo/.openclaw-dev/agentguard-security"],
        },
        entries: { "openclaw-weixin": { enabled: true } },
      },
    },
    stagingDir: "/repo/.openclaw-dev/agentguard-security",
    guardApiBaseUrl: "http://127.0.0.1:8088",
    strategy,
  });
  assert.deepEqual(patch.plugins.load.paths, [
    "/other/plugin",
    "/repo/.openclaw-dev/agentguard-security",
  ]);
  const entry = patch.plugins.entries[PLUGIN_ID];
  assert.equal(entry.enabled, true);
  assert.equal(entry.hooks.timeoutMs, 10000);
  assert.equal(entry.hooks.allowConversationAccess, true);
  assert.equal(entry.config.enforcementMode, "enforce");
  assert.equal(entry.config.agentId, "main");
  assert.equal(entry.config.guardApiBaseUrl, "http://127.0.0.1:8088");
  assert.deepEqual(entry.config.adapterToken, strategy.secretRef);
  assert.equal(Object.hasOwn(patch.plugins, "allow"), false);
  assert.equal(patch.secrets.providers.agentguard_adapter.source, "env");

  const withAllow = buildInstallPatch({
    config: { plugins: { allow: ["qqbot", PLUGIN_ID] } },
    stagingDir: "/staging",
    guardApiBaseUrl: "http://127.0.0.1:8088",
    strategy,
  });
  assert.deepEqual(withAllow.plugins.allow, ["qqbot", PLUGIN_ID]);
});

test("buildUninstallPatch removes only AgentGuard-owned references", () => {
  const patch = buildUninstallPatch({
    config: {
      plugins: {
        load: {
          paths: ["/other/plugin", "/repo/.openclaw-dev/agentguard-security"],
        },
        allow: ["qqbot", PLUGIN_ID],
        entries: {
          "openclaw-weixin": { enabled: true },
          [PLUGIN_ID]: { enabled: true },
        },
      },
      secrets: { providers: { agentguard_adapter: { source: "env" } } },
    },
    stagingDir: "/repo/.openclaw-dev/agentguard-security",
  });
  assert.deepEqual(patch.plugins.load.paths, ["/other/plugin"]);
  assert.deepEqual(patch.plugins.allow, ["qqbot"]);
  assert.equal(patch.plugins.entries[PLUGIN_ID], null);
  assert.equal(
    Object.hasOwn(patch.plugins.entries, "openclaw-weixin"),
    false,
  );
  assert.equal(patch.secrets.providers.agentguard_adapter, null);
});

test("isAgentGuardLoadPath matches staging and legacy install paths", () => {
  assert.equal(
    isAgentGuardLoadPath(
      "/repo/.openclaw-dev/agentguard-security",
      "/repo/.openclaw-dev/agentguard-security",
    ),
    true,
  );
  assert.equal(
    isAgentGuardLoadPath("/x/agentguard-openclaw-plugin-install-p2", "/s"),
    true,
  );
  assert.equal(isAgentGuardLoadPath("/other/plugin", "/s"), false);
});

// ---------- 子进程环境与脱敏 ----------

test("buildCommandEnv strips token vars and injects explicit profile only", () => {
  const env = buildCommandEnv(
    {
      PATH: "/bin",
      AGENTGUARD_ADAPTER_TOKEN: "a",
      AGENTGUARD_OPENCLAW_ADAPTER_TOKEN: "b",
      AGENTGUARD_CONTROL_TOKEN: "c",
    },
    {
      profile: { home: "/h", stateDir: "/s", configPath: "/s/openclaw.json" },
    },
  );
  assert.equal(env.AGENTGUARD_ADAPTER_TOKEN, undefined);
  assert.equal(env.AGENTGUARD_OPENCLAW_ADAPTER_TOKEN, undefined);
  assert.equal(env.AGENTGUARD_CONTROL_TOKEN, undefined);
  assert.equal(env.OPENCLAW_HOME, "/h");
  assert.equal(env.OPENCLAW_STATE_DIR, "/s");
  assert.equal(env.OPENCLAW_CONFIG_PATH, "/s/openclaw.json");
  assert.equal(env.PATH, "/bin");

  const passthrough = buildCommandEnv(
    { OPENCLAW_HOME: "stale", PATH: "/bin" },
    { profile: { isolated: false } },
  );
  assert.equal(passthrough.OPENCLAW_HOME, "stale");
});

test("redactSecrets removes known secrets and generic token patterns", () => {
  const text = `token=${SENTINEL_TOKEN} Authorization: Bearer abc.def
AGENTGUARD_ADAPTER_TOKEN: another-secret`;
  const redacted = redactSecrets(text, { secrets: [SENTINEL_TOKEN] });
  assert.equal(redacted.includes(SENTINEL_TOKEN), false);
  assert.equal(redacted.includes("abc.def"), false);
  assert.equal(redacted.includes("another-secret"), false);
  assert.equal(redacted.includes("[REDACTED]"), true);
});

// ---------- state .env 改写 ----------

test("rewriteStateEnv sets, replaces and deletes only the target key", () => {
  const seeded = rewriteStateEnv("", "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN", "v1");
  assert.equal(seeded, "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN=v1");
  const replaced = rewriteStateEnv(
    `OTHER=keep\nAGENTGUARD_OPENCLAW_ADAPTER_TOKEN=v1\n`,
    "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN",
    "v2",
  );
  assert.equal(replaced.split("AGENTGUARD_OPENCLAW_ADAPTER_TOKEN=v2").length, 2);
  assert.equal(replaced.includes("OTHER=keep"), true);
  const deleted = rewriteStateEnv(
    replaced,
    "AGENTGUARD_OPENCLAW_ADAPTER_TOKEN",
    null,
  );
  assert.equal(deleted.includes("AGENTGUARD_OPENCLAW_ADAPTER_TOKEN"), false);
  assert.equal(deleted.includes("OTHER=keep"), true);
});

// ---------- gateway 状态判定 ----------

test("evaluateGatewayStatus requires connectivity ok and tolerates transient runtime states", () => {
  assert.equal(
    evaluateGatewayStatus("Runtime: running\nConnectivity probe: ok").ok,
    true,
  );
  assert.equal(
    evaluateGatewayStatus("Runtime: unknown\nConnectivity probe: ok").ok,
    true,
  );
  assert.equal(
    evaluateGatewayStatus("Connectivity probe: ok").ok,
    true,
  );
  // stopped 是重启窗口瞬态，connectivity=ok 已证明网关可通；允许通过。
  assert.equal(
    evaluateGatewayStatus("Runtime: stopped\nConnectivity probe: ok").ok,
    true,
  );
  // 明确异常态（failed/error/dead）即使 connectivity=ok 仍拒绝。
  assert.equal(
    evaluateGatewayStatus("Runtime: failed\nConnectivity probe: ok").ok,
    false,
  );
  assert.equal(
    evaluateGatewayStatus("Runtime: running\nConnectivity probe: failed").ok,
    false,
  );
});

test("shouldRestartGateway only for explicit isolated profile without --no-restart", () => {
  assert.equal(
    shouldRestartGateway({ isolated: true }, { noRestart: false }),
    true,
  );
  assert.equal(
    shouldRestartGateway({ isolated: true }, { noRestart: true }),
    false,
  );
  assert.equal(
    shouldRestartGateway({ isolated: false }, { noRestart: false }),
    false,
  );
});

// ---------- 版本解析 ----------

test("parseOpenClawVersion and satisfiesCalVerRange", () => {
  assert.equal(parseOpenClawVersion("OpenClaw 2026.7.1-2 (0790d9f)"), "2026.7.1-2");
  assert.equal(parseOpenClawVersion("no version here"), null);
  assert.equal(compareCalVer("2026.7.1", "2026.6.6"), 1);
  assert.equal(compareCalVer("2026.6.6", "2026.6.6"), 0);
  assert.equal(satisfiesCalVerRange("2026.7.1-2", ">=2026.6.6 <2027.0.0"), true);
  assert.equal(satisfiesCalVerRange("2026.6.5", ">=2026.6.6 <2027.0.0"), false);
  assert.equal(satisfiesCalVerRange("2027.0.0", ">=2026.6.6 <2027.0.0"), false);
});

// ---------- install：dry-run 先于写入 + 顺序 ----------

test("install runs dry-run before config write and applies single patch", async () => {
  const world = createWorld();
  try {
    world.seedConfig({
      channels: { qqbot: { enabled: true } },
      plugins: { entries: { "openclaw-weixin": { enabled: true } } },
    });
    const baselineBytes = fs.readFileSync(world.profile.configPath);

    await executeInstall(world.deps);

    const dryRunIndex = callIndex(
      world.calls,
      (tool, args) => tool === "openclaw" && args.includes("--dry-run"),
    );
    const applyIndex = callIndex(
      world.calls,
      (tool, args) =>
        tool === "openclaw" &&
        args[0] === "config" &&
        args[1] === "patch" &&
        !args.includes("--dry-run"),
    );
    const registryIndex = callIndex(
      world.calls,
      (tool, args) => tool === "openclaw" && args.includes("--refresh"),
    );
    const restartIndex = callIndex(
      world.calls,
      (tool, args) => tool === "openclaw" && args[1] === "restart",
    );
    assert.ok(dryRunIndex !== -1, "dry-run 必须执行");
    assert.ok(applyIndex > dryRunIndex, "dry-run 必须先于写入");
    assert.ok(registryIndex > applyIndex, "registry 刷新在写入之后");
    assert.ok(restartIndex > registryIndex, "restart 在 registry 之后");
    // dry-run 发生时配置文件仍是基线字节
    assert.equal(world.dryRunConfigSnapshots.length, 1);
    assert.equal(world.dryRunConfigSnapshots[0], baselineBytes.toString("utf8"));

    // 单一 patch 应用后：AgentGuard 键就位，无关 entries 保留
    const config = world.readConfig();
    assert.equal(config.plugins.entries[PLUGIN_ID].enabled, true);
    assert.equal(
      config.plugins.entries[PLUGIN_ID].config.enforcementMode,
      "enforce",
    );
    assert.equal(config.plugins.entries["openclaw-weixin"].enabled, true);
    assert.deepEqual(config.channels, { qqbot: { enabled: true } });
    assert.equal(
      config.plugins.load.paths.includes(world.stagingDir),
      true,
    );
    assert.equal(config.secrets.providers.agentguard_adapter.source, "env");
    // 主配置只含 SecretRef，不含真实 token
    assert.equal(
      JSON.stringify(config).includes(SENTINEL_TOKEN),
      false,
    );
    // Windows：token 原子写入 state .env
    const stateEnv = fs.readFileSync(
      path.join(world.profileDir, ".env"),
      "utf8",
    );
    assert.equal(stateEnv.includes(`AGENTGUARD_OPENCLAW_ADAPTER_TOKEN=${SENTINEL_TOKEN}`), true);
    // staging 就位、旧 staging 已清理
    assert.equal(fs.existsSync(world.stagingDir), true);
    assert.equal(fs.existsSync(`${world.stagingDir}.old-4242`), false);
    assert.equal(fs.existsSync(`${world.stagingDir}.next-4242`), false);
  } finally {
    world.cleanup();
  }
});

// ---------- staging 切换：Windows 瞬时 EPERM 重试 ----------

function withFlakyRename(world, { flakes, targetDir }) {
  const realRename = fs.renameSync.bind(fs);
  let remaining = flakes;
  world.deps.fs = {
    ...fs,
    renameSync: (from, to) => {
      if (to === targetDir && remaining > 0) {
        remaining -= 1;
        const error = new Error(
          `EPERM: operation not permitted, rename '${from}' -> '${to}'`,
        );
        error.code = "EPERM";
        throw error;
      }
      return realRename(from, to);
    },
  };
  return () => remaining;
}

test("staging switch retries transient EPERM and completes reinstall", async () => {
  const world = createWorld();
  try {
    world.seedConfig({});
    await executeInstall(world.deps);
    // 第二次安装：目标 staging 目录前两次 rename 瞬时 EPERM（如防病毒实时扫描占用）
    const remaining = withFlakyRename(world, {
      flakes: 2,
      targetDir: world.stagingDir,
    });

    await executeInstall(world.deps);

    assert.equal(fs.existsSync(world.stagingDir), true);
    assert.equal(fs.existsSync(`${world.stagingDir}.next-4242`), false);
    assert.equal(fs.existsSync(`${world.stagingDir}.old-4242`), false);
    assert.equal(remaining(), 0);
  } finally {
    world.cleanup();
  }
});

test("staging switch gives up after retries, rolls back and restores old staging", async () => {
  const world = createWorld();
  try {
    world.seedConfig({});
    await executeInstall(world.deps);
    const baselineBytes = fs.readFileSync(world.profile.configPath);
    // 前 4 次 rename 到 staging 目标均 EPERM：足以耗尽单次切换的重试，
    // 但回滚路径的还原 rename 最终能成功（瞬时锁解除）
    withFlakyRename(world, { flakes: 4, targetDir: world.stagingDir });

    await assert.rejects(() => executeInstall(world.deps), /rolled back/i);

    assert.deepEqual(
      fs.readFileSync(world.profile.configPath),
      baselineBytes,
    );
    // 旧 staging 恢复，临时目录清理
    assert.equal(fs.existsSync(world.stagingDir), true);
    assert.equal(fs.existsSync(`${world.stagingDir}.next-4242`), false);
    assert.equal(fs.existsSync(`${world.stagingDir}.old-4242`), false);
  } finally {
    world.cleanup();
  }
});

// ---------- install：各故障点注入 → 回滚 ----------

test("dry-run failure rolls back config hash, state env and staging", async () => {
  const world = createWorld();
  try {
    world.seedConfig({ channels: { qqbot: { enabled: true } } });
    const baselineBytes = fs.readFileSync(world.profile.configPath);
    const baselineHash = sha256Hex(baselineBytes);
    world.setFailAt((tool, args) =>
      tool === "openclaw" && args.includes("--dry-run")
        ? `dry-run exploded with ${SENTINEL_TOKEN}`
        : null,
    );

    await assert.rejects(
      () => executeInstall(world.deps),
      (error) => {
        assert.equal(error.message.includes(SENTINEL_TOKEN), false);
        assert.equal(error.message.includes("[REDACTED]"), true);
        assert.match(error.message, /rolled back/i);
        return true;
      },
    );
    assert.equal(
      sha256Hex(fs.readFileSync(world.profile.configPath)),
      baselineHash,
    );
    assert.equal(fs.existsSync(path.join(world.profileDir, ".env")), false);
    assert.equal(fs.existsSync(world.stagingDir), false);
  } finally {
    world.cleanup();
  }
});

test("apply failure rolls back config to baseline bytes", async () => {
  const world = createWorld();
  try {
    world.seedConfig({ plugins: { entries: { qqbot: { enabled: true } } } });
    const baselineBytes = fs.readFileSync(world.profile.configPath);
    world.setFailAt((tool, args) =>
      tool === "openclaw" &&
      args[0] === "config" &&
      args[1] === "patch" &&
      !args.includes("--dry-run")
        ? "apply failed"
        : null,
    );

    await assert.rejects(() => executeInstall(world.deps), /rolled back/i);
    assert.deepEqual(
      fs.readFileSync(world.profile.configPath),
      baselineBytes,
    );
    assert.equal(fs.existsSync(world.stagingDir), false);
  } finally {
    world.cleanup();
  }
});

test("registry refresh failure rolls back and reports both errors", async () => {
  const world = createWorld();
  try {
    world.seedConfig({});
    const baselineBytes = fs.readFileSync(world.profile.configPath);
    world.setFailAt((tool, args) =>
      tool === "openclaw" && args.includes("--refresh")
        ? "registry refresh failed"
        : null,
    );

    await assert.rejects(
      () => executeInstall(world.deps),
      (error) => {
        assert.match(error.message, /registry refresh failed/);
        assert.match(error.message, /配置还原成功/);
        return true;
      },
    );
    assert.deepEqual(
      fs.readFileSync(world.profile.configPath),
      baselineBytes,
    );
  } finally {
    world.cleanup();
  }
});

test("gateway never becoming healthy triggers rollback with hash restore", async () => {
  const world = createWorld();
  try {
    world.seedConfig({});
    const baselineHash = sha256Hex(fs.readFileSync(world.profile.configPath));
    world.setFailAt((tool, args) =>
      tool === "openclaw" && args[0] === "gateway" && args[1] === "status"
        ? "gateway status unavailable"
        : null,
    );

    await assert.rejects(
      () => executeInstall(world.deps),
      /did not become healthy/,
    );
    assert.equal(
      sha256Hex(fs.readFileSync(world.profile.configPath)),
      baselineHash,
    );
    assert.equal(fs.existsSync(world.stagingDir), false);
  } finally {
    world.cleanup();
  }
});

// ---------- 幂等与凭证轮换 ----------

test("repeat install converges to a single AgentGuard fragment", async () => {
  const world = createWorld();
  try {
    world.seedConfig({ plugins: { allow: ["qqbot"] } });
    await executeInstall(world.deps);
    const first = world.readConfig();

    await executeInstall(world.deps);
    const second = world.readConfig();

    assert.deepEqual(
      extractAgentGuardFragment(second, world.stagingDir),
      extractAgentGuardFragment(first, world.stagingDir),
    );
    const loadPaths = second.plugins.load.paths.filter((item) =>
      String(item).includes("agentguard-security"),
    );
    assert.equal(loadPaths.length, 1);
    assert.deepEqual(second.plugins.allow, ["qqbot", PLUGIN_ID]);
    assert.equal(
      world.logs.some((line) => line.includes("重复安装收敛")),
      true,
    );
  } finally {
    world.cleanup();
  }
});

test("credential rotation rewrites only the dedicated state env key", async () => {
  const world = createWorld();
  try {
    world.seedConfig({});
    await executeInstall(world.deps);
    const envPath = path.join(world.profileDir, ".env");
    fs.writeFileSync(envPath, `UNRELATED=keep\n${fs.readFileSync(envPath, "utf8")}`);

    world.setToken("tok_rotated_999888777");
    await executeInstall(world.deps);

    const content = fs.readFileSync(envPath, "utf8");
    assert.equal(content.includes("AGENTGUARD_OPENCLAW_ADAPTER_TOKEN=tok_rotated_999888777"), true);
    assert.equal(content.includes(SENTINEL_TOKEN), false);
    assert.equal(content.includes("UNRELATED=keep"), true);
  } finally {
    world.cleanup();
  }
});

// ---------- POSIX secret 文件分流 ----------

test("POSIX install writes 0600 secret file and uninstall removes it", async () => {
  const world = createWorld({ platform: "linux" });
  try {
    world.seedConfig({});
    await executeInstall(world.deps);
    assert.equal(
      fs.readFileSync(world.deps.secretPath, "utf8"),
      `${SENTINEL_TOKEN}\n`,
    );
    const config = world.readConfig();
    assert.equal(config.secrets.providers.agentguard_adapter.source, "file");
    assert.equal(fs.existsSync(path.join(world.profileDir, ".env")), false);

    await executeUninstall(world.deps);
    assert.equal(fs.existsSync(world.deps.secretPath), false);
  } finally {
    world.cleanup();
  }
});

// ---------- uninstall 只清自有引用 ----------

test("uninstall removes only AgentGuard-owned references on Windows", async () => {
  const world = createWorld();
  try {
    world.seedConfig({
      channels: { qqbot: { enabled: true } },
      plugins: {
        allow: ["qqbot"],
        entries: { "openclaw-weixin": { enabled: true } },
      },
    });
    await executeInstall(world.deps);
    assert.equal(world.readConfig().plugins.entries[PLUGIN_ID].enabled, true);

    await executeUninstall(world.deps);

    const config = world.readConfig();
    assert.equal(Object.hasOwn(config.plugins.entries, PLUGIN_ID), false);
    assert.equal(config.plugins.entries["openclaw-weixin"].enabled, true);
    assert.deepEqual(config.channels, { qqbot: { enabled: true } });
    assert.deepEqual(config.plugins.allow, ["qqbot"]);
    assert.equal(
      config.plugins.load.paths.some((item) =>
        String(item).includes("agentguard-security"),
      ),
      false,
    );
    assert.equal(
      Object.hasOwn(config.secrets?.providers ?? {}, "agentguard_adapter"),
      false,
    );
    // Windows：state .env 专用变量被删除
    const stateEnv = fs.readFileSync(
      path.join(world.profileDir, ".env"),
      "utf8",
    );
    assert.equal(
      stateEnv.includes("AGENTGUARD_OPENCLAW_ADAPTER_TOKEN"),
      false,
    );
    // staging 默认保留（未加 --clean-staging）
    assert.equal(fs.existsSync(world.stagingDir), true);
  } finally {
    world.cleanup();
  }
});

test("uninstall commits validated rejected payload when OpenClaw size-drop guard blocks write", async () => {
  const world = createWorld();
  try {
    world.seedConfig({
      channels: { qqbot: { enabled: true } },
      plugins: {
        entries: { "openclaw-weixin": { enabled: true } },
      },
    });
    await executeInstall(world.deps);
    assert.equal(world.readConfig().plugins.entries[PLUGIN_ID].enabled, true);

    // 模拟 OpenClaw size-drop 保护：拒绝写入并把最终载荷保存为 .rejected.*
    const rejectedPath = `${world.profile.configPath}.rejected.2026-08-12T00-00-00-000Z`;
    world.setFailAt((tool, args) => {
      if (
        tool !== "openclaw" ||
        args[0] !== "config" ||
        args[1] !== "patch" ||
        args.includes("--dry-run")
      ) {
        return null;
      }
      const patchFile = args[args.indexOf("--file") + 1];
      const patch = JSON.parse(fs.readFileSync(patchFile, "utf8"));
      const current = JSON.parse(
        fs.readFileSync(world.profile.configPath, "utf8"),
      );
      applyPatchToConfig(current, patch);
      fs.writeFileSync(rejectedPath, JSON.stringify(current, null, 2));
      return (
        `Config write rejected: ${world.profile.configPath} ` +
        `(size-drop-vs-last-good:1200->400). Rejected payload saved to ${rejectedPath}.`
      );
    });

    await executeUninstall(world.deps);

    const config = world.readConfig();
    assert.equal(
      Object.hasOwn(config.plugins.entries ?? {}, PLUGIN_ID),
      false,
    );
    assert.equal(config.plugins.entries["openclaw-weixin"].enabled, true);
    assert.deepEqual(config.channels, { qqbot: { enabled: true } });
    assert.equal(
      Object.hasOwn(config.secrets?.providers ?? {}, "agentguard_adapter"),
      false,
    );
    // .rejected 载荷提交成功后应被清理
    assert.equal(
      fs
        .readdirSync(world.profileDir)
        .some((name) => name.includes(".rejected.")),
      false,
    );
  } finally {
    world.cleanup();
  }
});

// ---------- token 哨兵串泄漏扫描 ----------

test("token sentinel never leaks into config, backups, logs or errors", async () => {
  const world = createWorld();
  try {
    world.seedConfig({ plugins: { entries: { qqbot: {} } } });
    await executeInstall(world.deps);

    world.setFailAt((tool, args) =>
      tool === "openclaw" && args.includes("--dry-run")
        ? `boom ${SENTINEL_TOKEN} boom`
        : null,
    );
    let thrown = null;
    try {
      await executeInstall(world.deps);
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown, "第二次安装应失败以产生错误文本");

    const haystacks = [
      fs.readFileSync(world.profile.configPath, "utf8"),
      ...world.backupFiles(),
      ...world.logs,
      thrown.message,
    ];
    for (const haystack of haystacks) {
      assert.equal(
        haystack.includes(SENTINEL_TOKEN),
        false,
        `哨兵泄漏：${haystack.slice(0, 120)}`,
      );
    }
  } finally {
    world.cleanup();
  }
});

// ---------- waitForFreshHeartbeat ----------

test("waitForFreshHeartbeat accepts only heartbeats after the start time", async () => {
  const since = new Date("2026-08-12T00:00:00Z");
  const fresh = await waitForFreshHeartbeat({
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ last_heartbeat_at: "2026-08-12T00:00:05Z" }),
    }),
    baseUrl: "http://127.0.0.1:8088",
    controlToken: "ctl",
    since,
    timeoutMs: 50,
    pollMs: 1,
    sleep: async () => {},
  });
  assert.equal(fresh.fresh, true);

  const stale = await waitForFreshHeartbeat({
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ last_heartbeat_at: "2026-08-11T23:59:00Z" }),
    }),
    baseUrl: "http://127.0.0.1:8088",
    controlToken: "ctl",
    since,
    timeoutMs: 20,
    pollMs: 1,
    sleep: async () => {},
  });
  assert.equal(stale.fresh, false);
  assert.equal(stale.lastHeartbeatAt, "2026-08-11T23:59:00Z");
});

// ---------- isInspectOnlyHookFailure / executeVerify heartbeat 回退 ----------

test("isInspectOnlyHookFailure accepts only hookCount/missing-hooks lines", () => {
  assert.equal(isInspectOnlyHookFailure([]), false);
  assert.equal(
    isInspectOnlyHookFailure([
      "expected hookCount=23, got 0",
      "missing hooks: before_tool_call, llm_input",
    ]),
    true,
  );
  assert.equal(
    isInspectOnlyHookFailure([
      "expected hookCount=23, got 0",
      "Gateway RPC 连通异常 (exit=1, runtime=stopped, connectivity=failed)",
    ]),
    false,
  );
});

// 构造 executeVerify 可用的 world：staging/配置/命令路由/heartbeat mock。
function setupVerifyWorld(world, { hookCount, typedHooks, heartbeat }) {
  fs.mkdirSync(world.stagingDir, { recursive: true });
  fs.writeFileSync(
    path.join(world.stagingDir, "package.json"),
    JSON.stringify({ version: "0.1.0-beta.1" }),
  );
  world.seedConfig({
    plugins: {
      entries: {
        [PLUGIN_ID]: { enabled: true, config: { enforcementMode: "enforce" } },
      },
    },
  });
  world.deps.run = (tool, args) => {
    if (tool === "openclaw" && args[0] === "plugins" && args[1] === "inspect") {
      return {
        status: 0,
        stdout: JSON.stringify({
          plugin: {
            status: "loaded",
            hookCount,
            source: path.join(world.stagingDir, "dist", "index.js"),
          },
          typedHooks,
          diagnostics: [],
        }),
        stderr: "",
      };
    }
    if (tool === "openclaw" && args[0] === "gateway" && args[1] === "status") {
      return {
        status: 0,
        stdout: "Runtime: running\nConnectivity probe: ok\n",
        stderr: "",
      };
    }
    if (tool === "openclaw" && args[0] === "--version") {
      return { status: 0, stdout: "OpenClaw 2026.7.1-2 (0790d9f)\n", stderr: "" };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  world.deps.fetch = async () => ({ ok: true, json: async () => heartbeat });
  return world;
}

function freshHeartbeat(overrides = {}) {
  return {
    last_heartbeat_at: new Date(Date.now() + 60_000).toISOString(),
    loaded: true,
    hook_count: OPENCLAW_REQUIRED_HOOKS.length,
    ...overrides,
  };
}

test("executeVerify falls back to fresh heartbeat when inspect hookCount=0", async () => {
  const world = createWorld();
  try {
    setupVerifyWorld(world, { hookCount: 0, typedHooks: [], heartbeat: freshHeartbeat() });
    const payload = await executeVerify(world.deps);
    assert.equal(payload.hook_evidence_source, "heartbeat-fallback");
    assert.equal(payload.hook_count, OPENCLAW_REQUIRED_HOOKS.length);
    assert.equal(payload.status, "loaded");
  } finally {
    world.cleanup();
  }
});

test("executeVerify fails when inspect hookCount=0 and heartbeat is stale", async () => {
  const world = createWorld();
  try {
    setupVerifyWorld(world, {
      hookCount: 0,
      typedHooks: [],
      heartbeat: { last_heartbeat_at: "2020-01-01T00:00:00Z", loaded: true, hook_count: 23 },
    });
    world.deps.heartbeatTimeoutMs = 5;
    await assert.rejects(
      () => executeVerify(world.deps),
      /expected hookCount=23, got 0/,
    );
  } finally {
    world.cleanup();
  }
});

test("executeVerify fails when fresh heartbeat lacks loaded/23 hooks", async () => {
  const world = createWorld();
  try {
    setupVerifyWorld(world, {
      hookCount: 0,
      typedHooks: [],
      heartbeat: freshHeartbeat({ hook_count: 0 }),
    });
    await assert.rejects(
      () => executeVerify(world.deps),
      /expected hookCount=23, got 0/,
    );
  } finally {
    world.cleanup();
  }
});

test("executeVerify uses inspect evidence when hookCount reaches 23", async () => {
  const world = createWorld();
  try {
    setupVerifyWorld(world, {
      hookCount: OPENCLAW_REQUIRED_HOOKS.length,
      typedHooks: OPENCLAW_REQUIRED_HOOKS.map((name) => ({ name })),
      heartbeat: freshHeartbeat(),
    });
    const payload = await executeVerify(world.deps);
    assert.equal(payload.hook_evidence_source, "inspect");
    assert.equal(payload.hook_count, OPENCLAW_REQUIRED_HOOKS.length);
  } finally {
    world.cleanup();
  }
});
