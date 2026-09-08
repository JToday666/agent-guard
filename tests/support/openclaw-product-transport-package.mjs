/**
 * TEST ONLY: copy the actual built SDK into a private package with synthetic RC
 * metadata. This is a transport-contract assumption, never candidate evidence.
 * Production modules receive no version or metadata-path override.
 */
import { cp, mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_SOURCE = fileURLToPath(
  new URL("../../packages/agentguard-openclaw-plugin/", import.meta.url),
);
const SYNTHETIC_VERSION = "0.1.0-rc.1";

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
    throw new Error("Transport test requires the actual OpenClaw plugin package");
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
    if (parent === hostRoot) throw new Error("Actual Host package was not found");
    hostRoot = parent;
  }
  if (hostMetadata.version !== "2026.7.1-2") {
    throw new Error("Transport test requires the actual pinned OpenClaw Host");
  }

  // A fresh path is required: never modify an installed or previously used SDK.
  await mkdir(directory, { mode: 0o700 });
  const packageRoot = await realpath(directory);
  await cp(path.join(sourceRoot, "dist"), path.join(packageRoot, "dist"), {
    recursive: true,
    force: false,
    errorOnExist: true,
  });
  await cp(
    path.join(sourceRoot, "hook-contract.mjs"),
    path.join(packageRoot, "hook-contract.mjs"),
    { force: false, errorOnExist: true },
  );
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
