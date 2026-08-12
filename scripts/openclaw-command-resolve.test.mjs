import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  findOnPath,
  parseWindowsShimEntry,
  resolveToolCommand,
} from "./openclaw-command-resolve.mjs";

const SAMPLE_OPENCLAW_SHIM = `@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0

IF EXIST "%dp0%\\node.exe" (
  SET "_prog=%dp0%\\node.exe"
) ELSE (
  SET "_prog=node"
)

endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & set PATHEXT=%PATHEXT:;.JS;=;% & "%_prog%"  "%dp0%\\node_modules\\openclaw\\openclaw.mjs" %*
`;

const SAMPLE_PNPM_SHIM = `@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0

IF EXIST "%dp0%\\node.exe" (
  SET "_prog=%dp0%\\node.exe"
) ELSE (
  SET "_prog=node"
  SET PATHEXT=%PATHEXT:;.JS;=;%
)

endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\node_modules\\pnpm\\bin\\pnpm.mjs" %*
`;

test("parseWindowsShimEntry extracts JS entry from npm-style openclaw shim", () => {
  assert.equal(
    parseWindowsShimEntry(SAMPLE_OPENCLAW_SHIM),
    "node_modules\\openclaw\\openclaw.mjs",
  );
});

test("parseWindowsShimEntry extracts JS entry from pnpm shim", () => {
  assert.equal(
    parseWindowsShimEntry(SAMPLE_PNPM_SHIM),
    "node_modules\\pnpm\\bin\\pnpm.mjs",
  );
});

test("parseWindowsShimEntry returns null when shim has no JS entry", () => {
  assert.equal(parseWindowsShimEntry("@ECHO off\r\necho hello"), null);
});

test("resolveToolCommand resolves Windows .cmd shim to node + entry JS", () => {
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    const shimPath = path.join(shimDir, "openclaw.cmd");
    const entryPath = path.join(shimDir, "node_modules", "openclaw");
    fs.mkdirSync(entryPath, { recursive: true });
    fs.writeFileSync(path.join(entryPath, "openclaw.mjs"), "// entry");
    fs.writeFileSync(shimPath, SAMPLE_OPENCLAW_SHIM);

    const resolved = resolveToolCommand("openclaw", {
      platform: "win32",
      env: { PATH: shimDir },
      execPath: "C:\\node\\node.exe",
    });
    assert.equal(resolved.kind, "node-shim");
    assert.equal(resolved.command, "C:\\node\\node.exe");
    assert.deepEqual(resolved.prependArgs, [
      path.join(entryPath, "openclaw.mjs"),
    ]);
  } finally {
    fs.rmSync(shimDir, { recursive: true, force: true });
  }
});

test("resolveToolCommand on Windows reports missing shim clearly", () => {
  assert.throws(
    () =>
      resolveToolCommand("openclaw", {
        platform: "win32",
        env: { PATH: os.tmpdir() },
      }),
    /openclaw\.cmd/,
  );
});

test("resolveToolCommand on Windows reports missing JS entry clearly", () => {
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    fs.writeFileSync(path.join(shimDir, "openclaw.cmd"), SAMPLE_OPENCLAW_SHIM);
    assert.throws(
      () =>
        resolveToolCommand("openclaw", {
          platform: "win32",
          env: { PATH: shimDir },
        }),
      /不存在/,
    );
  } finally {
    fs.rmSync(shimDir, { recursive: true, force: true });
  }
});

test("resolveToolCommand on POSIX returns resolved executable path", () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    const toolPath = path.join(binDir, "openclaw");
    fs.writeFileSync(toolPath, "#!/bin/sh\n");
    const resolved = resolveToolCommand("openclaw", {
      platform: "linux",
      env: { PATH: binDir },
    });
    assert.equal(resolved.kind, "posix-path");
    assert.equal(resolved.command, toolPath);
    assert.deepEqual(resolved.prependArgs, []);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("resolveToolCommand reports missing POSIX executable", () => {
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    assert.throws(
      () =>
        resolveToolCommand("openclaw", {
          platform: "linux",
          env: { PATH: emptyDir },
        }),
      /openclaw/,
    );
  } finally {
    fs.rmSync(emptyDir, { recursive: true, force: true });
  }
});

test("resolveToolCommand treats uv as native on both platforms", () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    fs.writeFileSync(path.join(binDir, "uv.exe"), "MZ");
    fs.writeFileSync(path.join(binDir, "uv"), "#!/bin/sh\n");
    const windows = resolveToolCommand("uv", {
      platform: "win32",
      env: { PATH: binDir },
    });
    assert.equal(windows.kind, "native");
    assert.equal(windows.command, path.join(binDir, "uv.exe"));
    assert.deepEqual(windows.prependArgs, []);

    const posix = resolveToolCommand("uv", {
      platform: "linux",
      env: { PATH: binDir },
    });
    assert.equal(posix.kind, "native");
    assert.equal(posix.command, path.join(binDir, "uv"));
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("resolveToolCommand falls back to bare name for native tools not on PATH", () => {
  const resolved = resolveToolCommand("uv", {
    platform: "linux",
    env: { PATH: "" },
  });
  assert.equal(resolved.command, "uv");
  assert.equal(resolved.kind, "native");
});

test("findOnPath honors PATH entry quoting", () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmdresolve-"));
  try {
    fs.writeFileSync(path.join(binDir, "tool.cmd"), "");
    const found = findOnPath("tool.cmd", {
      platform: "win32",
      env: { PATH: `"${binDir}"` },
    });
    assert.equal(found, path.join(binDir, "tool.cmd"));
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});
