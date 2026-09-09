/**
 * TEST ONLY: copy the actual built SDK into a private package with synthetic RC
 * metadata. This is a transport-contract assumption, never candidate evidence.
 * Production modules receive no version or metadata-path override.
 */
import {
  chmod,
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const DEFAULT_SOURCE = fileURLToPath(
  new URL("../../packages/agentguard-openclaw-plugin/", import.meta.url),
);
const SYNTHETIC_VERSION = "0.1.0-rc.1";

async function normalizePublishedModes(filename) {
  const entry = await lstat(filename);
  if (entry.isDirectory()) {
    await chmod(filename, 0o755);
    for (const child of await readdir(filename))
      await normalizePublishedModes(path.join(filename, child));
  } else if (entry.isFile()) {
    await chmod(filename, 0o644);
  } else {
    throw new Error("Synthetic candidate requires regular published files");
  }
}

/** Actual npm archive of the synthetic test candidate; never release evidence. */
export async function packSyntheticProductPackage({ packageRoot, directory }) {
  if (!path.isAbsolute(packageRoot) || !path.isAbsolute(directory))
    throw new Error("Synthetic candidate pack paths must be absolute");
  await mkdir(directory, { mode: 0o700 });
  const packEnvironment = {
    ...process.env,
    npm_config_cache: path.join(directory, "npm-cache"),
  };
  // npm's stdout is JSON, not a child node:test runner protocol stream.
  for (const key of Object.keys(packEnvironment))
    if (key.startsWith("NODE_TEST_")) delete packEnvironment[key];
  const { stdout } = await promisify(execFile)(
    "npm",
    [
      "pack",
      "--json",
      "--ignore-scripts",
      "--offline",
      "--pack-destination",
      directory,
    ],
    {
      cwd: packageRoot,
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      env: packEnvironment,
    },
  );
  const packed = JSON.parse(stdout);
  if (
    !Array.isArray(packed) ||
    packed.length !== 1 ||
    typeof packed[0].filename !== "string" ||
    path.basename(packed[0].filename) !== packed[0].filename ||
    !packed[0].filename.endsWith(".tgz")
  )
    throw new Error("Synthetic candidate archive was not produced");
  const candidateTgzPath = path.join(directory, packed[0].filename);
  const bytes = await readFile(candidateTgzPath);
  return Object.freeze({
    candidateTgzPath,
    artifactDigest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    syntheticMetadata: true,
    candidateAdmissionEvidence: false,
  });
}

export async function createSyntheticProductPackage({
  directory,
  sourcePackageRoot = DEFAULT_SOURCE,
}) {
  if (!path.isAbsolute(directory) || !path.isAbsolute(sourcePackageRoot)) {
    throw new Error("Transport test package paths must be absolute");
  }
  const sourceRoot = await realpath(sourcePackageRoot);
  const sourceMetadata = JSON.parse(
    await readFile(path.join(sourceRoot, "package.json"), "utf8"),
  );
  if (sourceMetadata.name !== "@agentguard-ai/openclaw-plugin") {
    throw new Error(
      "Transport test requires the actual OpenClaw plugin package",
    );
  }
  const requireSource = createRequire(path.join(sourceRoot, "package.json"));
  // The pinned Host does not export openclaw/package.json. Resolve the actual
  // public SDK entry, then locate its owning installed package metadata.
  const sdkEntry = await realpath(
    requireSource.resolve("openclaw/plugin-sdk/agent-harness"),
  );
  let hostRoot = path.dirname(sdkEntry);
  let hostMetadata;
  while (true) {
    try {
      const candidate = JSON.parse(
        await readFile(path.join(hostRoot, "package.json"), "utf8"),
      );
      if (candidate.name === "openclaw") {
        hostMetadata = candidate;
        break;
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const parent = path.dirname(hostRoot);
    if (parent === hostRoot)
      throw new Error("Actual Host package was not found");
    hostRoot = parent;
  }
  if (hostMetadata.version !== "2026.7.1-2") {
    throw new Error("Transport test requires the actual pinned OpenClaw Host");
  }

  // A fresh path is required: never modify an installed or previously used SDK.
  await mkdir(directory, { mode: 0o700 });
  const packageRoot = await realpath(directory);
  // Keep the complete published package surface, including the isolated
  // Product assets. New candidate checks compare real archive/installed bytes.
  if (!Array.isArray(sourceMetadata.files) || !sourceMetadata.files.length)
    throw new Error("Transport test requires an explicit package file list");
  for (const relative of sourceMetadata.files) {
    if (
      typeof relative !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(relative) ||
      relative === "package.json" ||
      relative === "node_modules"
    )
      throw new Error("Transport test package file list is unsupported");
    await cp(
      path.join(sourceRoot, relative),
      path.join(packageRoot, relative),
      {
        recursive: true,
        force: false,
        errorOnExist: true,
      },
    );
    // Match an npm install's non-writable published tree, not the checkout's
    // group-writable umask. This changes test installation modes only.
    await normalizePublishedModes(path.join(packageRoot, relative));
  }
  await writeFile(
    path.join(packageRoot, "package.json"),
    JSON.stringify({
      ...sourceMetadata,
      version: SYNTHETIC_VERSION,
      agentguardTransportContractFixture: {
        syntheticMetadata: true,
        candidateAdmissionEvidence: false,
        sourceVersion: sourceMetadata.version,
      },
    }),
    { mode: 0o600, flag: "wx" },
  );
  // The explicit Product entry is part of the same synthetic candidate. Keep
  // both installed entry declarations consistent before hashing its archive.
  for (const filename of ["package.json", "openclaw.plugin.json"]) {
    const target = path.join(
      packageRoot,
      "product-runtime",
      "product",
      filename,
    );
    const nested = JSON.parse(await readFile(target, "utf8"));
    await writeFile(
      target,
      JSON.stringify({ ...nested, version: SYNTHETIC_VERSION }),
      {
        mode: 0o600,
      },
    );
  }
  await mkdir(path.join(packageRoot, "node_modules"), { mode: 0o700 });
  await symlink(hostRoot, path.join(packageRoot, "node_modules", "openclaw"));
  const moduleUrl = (relative) =>
    pathToFileURL(path.join(packageRoot, "dist", relative)).href;
  return Object.freeze({
    packageRoot,
    clientModuleUrl: moduleUrl("guard-api-client.js"),
    manifestModuleUrl: moduleUrl("runtime/product-manifest.js"),
    sessionModuleUrl: moduleUrl("runtime/activation-session.js"),
    ackHandleModuleUrl: moduleUrl("runtime/activation-ack-handle.js"),
    sourceVersion: sourceMetadata.version,
    syntheticVersion: SYNTHETIC_VERSION,
    actualHostVersion: hostMetadata.version,
  });
}
