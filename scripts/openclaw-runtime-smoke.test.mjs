// openclaw-runtime-smoke.mjs 纯函数层单测。
import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  assertIsolatedProfileDir,
  mergeGatewayConfig,
  parseDotEnvContent,
  parseSmokeArgs,
  pickFreePort,
  resolveOpenclawBinDir,
  withDiagnosticLogging,
  withGatewayAuthToken,
  withOpenclawBinOnPath,
} from "./openclaw-runtime-smoke.mjs";

test("parseSmokeArgs parses flags and requires openclaw root", () => {
  const options = parseSmokeArgs(
    [
      "--openclaw-root",
      "/tmp/openclaw-2026.6.6",
      "--expect-version=2026.6.6",
      "--report",
      "/tmp/report.json",
      "--heartbeat-timeout-ms",
      "5000",
      "--skip-guard-api",
      "--provision-env",
    ],
    {},
  );
  assert.equal(options.openclawRoot, "/tmp/openclaw-2026.6.6");
  assert.equal(options.expectVersion, "2026.6.6");
  assert.equal(options.reportPath, "/tmp/report.json");
  assert.equal(options.heartbeatTimeoutMs, 5000);
  assert.equal(options.skipGuardApi, true);
  assert.equal(options.provisionEnv, true);

  assert.throws(() => parseSmokeArgs([], {}), /--openclaw-root/);
  assert.throws(
    () => parseSmokeArgs(["--openclaw-root"], {}),
    /缺少 --openclaw-root 的取值/,
  );
  assert.throws(
    () => parseSmokeArgs(["--openclaw-root", "/x", "--bogus"], {}),
    /未知 smoke 参数/,
  );
  assert.throws(
    () =>
      parseSmokeArgs(["--openclaw-root", "/x", "--heartbeat-timeout-ms", "0"], {}),
    /正整数/,
  );
});

test("parseSmokeArgs accepts AGENTGUARD_OPENCLAW_ROOT from env", () => {
  const options = parseSmokeArgs([], {
    AGENTGUARD_OPENCLAW_ROOT: "/opt/openclaw",
    AGENTGUARD_OPENCLAW_EXPECT_VERSION: "2026.7.1-2",
  });
  assert.equal(options.openclawRoot, "/opt/openclaw");
  assert.equal(options.expectVersion, "2026.7.1-2");
});

test("resolveOpenclawBinDir prefers node_modules/.bin then root", () => {
  const resolvedRoot = path.resolve("/root");
  const existsInBinDir = (candidate) =>
    candidate === path.join(resolvedRoot, "node_modules", ".bin", "openclaw");
  assert.equal(
    resolveOpenclawBinDir("/root", {
      platform: "linux",
      fileExists: existsInBinDir,
    }),
    path.join(resolvedRoot, "node_modules", ".bin"),
  );

  const existsAtRoot = (candidate) =>
    candidate === path.join(resolvedRoot, "openclaw.cmd");
  assert.equal(
    resolveOpenclawBinDir("/root", {
      platform: "win32",
      fileExists: existsAtRoot,
    }),
    resolvedRoot,
  );

  assert.throws(
    () =>
      resolveOpenclawBinDir("/root", {
        platform: "linux",
        fileExists: () => false,
      }),
    /无法在 openclaw 根目录/,
  );
});

test("withOpenclawBinOnPath prepends bin dir and respects Windows Path key", () => {
  const posix = withOpenclawBinOnPath({ PATH: "/usr/bin" }, "/opt/bin", "linux");
  assert.equal(posix.PATH, `/opt/bin${path.delimiter}/usr/bin`);

  const windows = withOpenclawBinOnPath(
    { Path: "C:\\Windows" },
    "C:\\oc",
    "win32",
  );
  assert.equal(windows.Path, "C:\\oc;C:\\Windows");
  assert.equal(windows.PATH, undefined);

  const empty = withOpenclawBinOnPath({}, "/opt/bin", "linux");
  assert.equal(empty.PATH, "/opt/bin");
});

test("assertIsolatedProfileDir rejects real profile and workspace paths", () => {
  const home = process.platform === "win32" ? "C:\\Users\\tester" : "/home/tester";
  const workspace = process.platform === "win32" ? "D:\\Dev\\agent-guard" : "/dev/agent-guard";

  assert.throws(
    () =>
      assertIsolatedProfileDir(path.join(home, ".openclaw"), {
        homedir: home,
        workspaceRoot: workspace,
      }),
    /受保护目录/,
  );
  assert.throws(
    () =>
      assertIsolatedProfileDir(path.join(workspace, ".openclaw-dev"), {
        homedir: home,
        workspaceRoot: workspace,
      }),
    /受保护目录/,
  );

  const tmp = process.platform === "win32" ? "C:\\Temp\\smoke-1" : "/tmp/smoke-1";
  assert.equal(
    assertIsolatedProfileDir(tmp, { homedir: home, workspaceRoot: workspace }),
    path.resolve(tmp),
  );
});

test("mergeGatewayConfig keeps existing keys and fixes mode/port", () => {
  assert.deepEqual(mergeGatewayConfig(null, 12345), {
    gateway: { mode: "local", port: 12345 },
  });
  assert.deepEqual(
    mergeGatewayConfig({ gateway: { mode: "remote", other: 1 }, a: 2 }, 999),
    { gateway: { mode: "remote", other: 1, port: 999 }, a: 2 },
  );
});

test("withDiagnosticLogging enables diagnostics without mutating input", () => {
  const input = {
    gateway: { port: 1 },
    plugins: {
      entries: {
        "agentguard-security": {
          enabled: true,
          config: { guardApiBaseUrl: "http://127.0.0.1:8088" },
        },
      },
    },
  };
  const output = withDiagnosticLogging(input, "agentguard-security");
  assert.equal(
    output.plugins.entries["agentguard-security"].config.diagnosticLogging,
    true,
  );
  assert.equal(
    output.plugins.entries["agentguard-security"].config.guardApiBaseUrl,
    "http://127.0.0.1:8088",
  );
  assert.equal(
    input.plugins.entries["agentguard-security"].config.diagnosticLogging,
    undefined,
  );

  const empty = withDiagnosticLogging(null, "agentguard-security");
  assert.equal(
    empty.plugins.entries["agentguard-security"].config.diagnosticLogging,
    true,
  );
});

test("withGatewayAuthToken persists token auth without mutating input", () => {
  const input = { gateway: { mode: "local", port: 5 } };
  const output = withGatewayAuthToken(input, "tok-1");
  assert.deepEqual(output.gateway.auth, { mode: "token", token: "tok-1" });
  assert.equal(output.gateway.port, 5);
  assert.equal(input.gateway.auth, undefined);
});

test("parseDotEnvContent parses pairs, quotes and comments", () => {
  const parsed = parseDotEnvContent(
    [
      "# comment",
      "A=1",
      'B="two words"',
      "C='quoted'",
      "  D = spaced  ",
      "not a line",
      "",
    ].join("\n"),
  );
  assert.deepEqual(parsed, {
    A: "1",
    B: "two words",
    C: "quoted",
    D: "spaced",
  });
});

test("pickFreePort returns a usable port number", async () => {
  const port = await pickFreePort();
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
});
