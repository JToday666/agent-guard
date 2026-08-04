#!/usr/bin/env node

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const tarball = path.resolve(
  process.argv[2] ||
    "release-dist/npm/agentguard-ai-openclaw-plugin-0.1.0-beta.1.tgz",
);
const tempRoot = await mkdtemp(path.join(os.tmpdir(), "agentguard-npm-install-"));

try {
  await writeFile(
    path.join(tempRoot, "package.json"),
    `${JSON.stringify({ name: "agentguard-npm-verification", private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  const result = spawnSync(
    process.platform === "win32" ? "pnpm.cmd" : "pnpm",
    ["add", "openclaw@2026.6.6", tarball, "--ignore-scripts"],
    {
      cwd: tempRoot,
      encoding: "utf8",
      shell: process.platform === "win32",
      windowsHide: true,
    },
  );
  if (result.status !== 0) {
    throw new Error(
      [result.error?.message, result.stdout, result.stderr]
        .filter(Boolean)
        .join("\n"),
    );
  }

  const installedPackage = JSON.parse(
    await readFile(
      path.join(
        tempRoot,
        "node_modules",
        "@agentguard-ai",
        "openclaw-plugin",
        "package.json",
      ),
      "utf8",
    ),
  );
  if (installedPackage.version !== "0.1.0-beta.1") {
    throw new Error(`unexpected installed version: ${installedPackage.version}`);
  }
  const entry = path.join(
    tempRoot,
    "node_modules",
    "@agentguard-ai",
    "openclaw-plugin",
    "dist",
    "index.js",
  );
  const pluginModule = await import(pathToFileURL(entry).href);
  if (!pluginModule.default) {
    throw new Error("default plugin export is missing");
  }
  console.log("isolated npm tarball install: ok");
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
