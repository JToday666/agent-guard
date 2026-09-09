#!/usr/bin/env node
/** Clean-install one actual candidate against the compatible and pinned Hosts. */
import { spawnSync } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  NPM_CANDIDATE_VERSION,
  SDK_VERSIONS,
  rawDigest,
  readBoundedRegular,
} from "./verify-npm-tarball-worker.mjs";

const WORKER = fileURLToPath(
  new URL("./verify-npm-tarball-worker.mjs", import.meta.url),
);
export function installationEnvironment(original, privateHome) {
  const env = {};
  for (const key of [
    "PATH",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SystemRoot",
    "SYSTEMROOT",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
  ])
    if (original[key] !== undefined) env[key] = original[key];
  env.HOME = privateHome;
  env.COREPACK_ENABLE_DOWNLOAD_PROMPT = "0";
  env.NO_COLOR = "1";
  return env;
}
export function spawnWithProtectedUmask(command, args, options) {
  const previous = process.umask(0o022);
  try {
    return spawnSync(command, args, options);
  } finally {
    process.umask(previous);
  }
}
function requireSuccess(result, code) {
  if (result.error || result.signal || result.status !== 0)
    throw new Error(code);
}
export async function verifyTarball({
  tarball,
  environmentRoot,
  reportPath,
  sourceRevision,
}) {
  if (
    Boolean(environmentRoot) !== Boolean(reportPath) ||
    (reportPath && !/^[0-9a-f]{40}$/u.test(sourceRevision ?? ""))
  )
    throw new Error("npm_persistent_evidence_options_invalid");
  const manager = JSON.parse(
    (
      await readBoundedRegular(
        fileURLToPath(new URL("../package.json", import.meta.url)),
        128 * 1024,
      )
    ).toString("utf8"),
  ).packageManager;
  if (
    typeof manager !== "string" ||
    !/^pnpm@11\.9\.0\+sha512\.[a-f0-9]+$/u.test(manager)
  )
    throw new Error("npm_package_manager_pin_invalid");
  const originalPath = path.resolve(tarball);
  if ((await realpath(originalPath)) !== originalPath)
    throw new Error("npm_candidate_path_invalid");
  const bytes = await readBoundedRegular(originalPath, 32 * 1024 * 1024);
  const digest = rawDigest(bytes);
  let root;
  if (environmentRoot) {
    root = path.resolve(environmentRoot);
    if ((await realpath(path.dirname(root))) !== path.dirname(root))
      throw new Error("npm_environment_parent_invalid");
    await mkdir(root, { mode: 0o700 });
  } else
    root = await mkdtemp(path.join(os.tmpdir(), "agentguard-npm-install-"));
  const report = {
    schema_version: "1.0",
    kind: "openclaw_candidate_installation",
    source_revision: sourceRevision ?? null,
    artifact: { path: originalPath, size: bytes.length, raw_sha256: digest },
    package_version: NPM_CANDIDATE_VERSION,
    environment_root: root,
    lanes: [],
    product_active_enabled: false,
    external_provider_requests: 0,
    complete: false,
    exit_code: 1,
  };
  try {
    const candidateDirectory = path.join(root, "candidate");
    await mkdir(candidateDirectory, { mode: 0o700 });
    const candidateTgzPath = path.join(
      candidateDirectory,
      `agentguard-ai-openclaw-plugin-${NPM_CANDIDATE_VERSION}.tgz`,
    );
    await writeFile(candidateTgzPath, bytes, { flag: "wx", mode: 0o600 });
    for (const [index, hostVersion] of SDK_VERSIONS.entries()) {
      const lane = index === 0 ? "legacy" : "product";
      const installRoot = path.join(root, lane);
      await mkdir(installRoot, { mode: 0o700 });
      const privateHome = path.join(installRoot, "home");
      await mkdir(privateHome, { mode: 0o700 });
      const env = installationEnvironment(process.env, privateHome);
      env.COREPACK_HOME = path.join(root, "corepack-cache");
      await writeFile(
        path.join(installRoot, "package.json"),
        JSON.stringify({
          name: `agentguard-npm-verification-${lane}`,
          packageManager: manager,
          private: true,
          type: "module",
        }) + "\n",
        { mode: 0o600, flag: "wx" },
      );
      const installed = spawnWithProtectedUmask(
        process.platform === "win32" ? "pnpm.cmd" : "pnpm",
        [
          "add",
          `openclaw@${hostVersion}`,
          candidateTgzPath,
          "--ignore-scripts",
          "--ignore-workspace",
          "--save-exact",
          "--package-import-method=copy",
          "--store-dir",
          path.join(root, "pnpm-store"),
        ],
        {
          cwd: installRoot,
          env,
          encoding: "utf8",
          shell: process.platform === "win32",
          windowsHide: true,
          timeout: 300_000,
          maxBuffer: 2 * 1024 * 1024,
        },
      );
      requireSuccess(installed, `npm_${lane}_installation_failed`);
      const outputPath = path.join(installRoot, "verification.json");
      const result = spawnWithProtectedUmask(process.execPath, [WORKER], {
        cwd: installRoot,
        env,
        input: JSON.stringify({
          installRoot,
          hostVersion,
          candidateTgzPath,
          artifactDigest: digest,
          outputPath,
        }),
        encoding: "utf8",
        timeout: 60_000,
        maxBuffer: 2 * 1024 * 1024,
      });
      if (result.error || result.signal || result.status !== 0) {
        const code = result.stderr
          ?.split("\n")
          .findLast((line) => /^npm_[a-z_]+$/u.test(line));
        throw new Error(
          /^npm_[a-z_]+$/u.test(code ?? "")
            ? code
            : `npm_${lane}_verification_failed`,
        );
      }
      const evidenceBytes = await readBoundedRegular(
        outputPath,
        2 * 1024 * 1024,
      );
      report.lanes.push({
        lane,
        ...JSON.parse(evidenceBytes.toString("utf8")),
        evidence_file: {
          path: outputPath,
          size: evidenceBytes.length,
          raw_sha256: rawDigest(evidenceBytes),
        },
      });
    }
    if (
      rawDigest(await readBoundedRegular(originalPath, 32 * 1024 * 1024)) !==
        digest ||
      rawDigest(
        await readBoundedRegular(candidateTgzPath, 32 * 1024 * 1024),
      ) !== digest
    )
      throw new Error("npm_candidate_changed_during_installation");
    report.complete = true;
    report.exit_code = 0;
    return report;
  } catch (error) {
    report.error_code = /^npm_[a-z_]+$/u.test(error?.message ?? "")
      ? error.message
      : "npm_verification_failed";
    throw new Error(report.error_code);
  } finally {
    if (reportPath) {
      const output = path.resolve(reportPath);
      const parent = await lstat(path.dirname(output));
      if (
        !parent.isDirectory() ||
        parent.isSymbolicLink() ||
        (await realpath(path.dirname(output))) !== path.dirname(output)
      )
        throw new Error("npm_report_parent_invalid");
      await writeFile(output, JSON.stringify(report, null, 2) + "\n", {
        mode: 0o600,
        flag: "wx",
      });
    } else await rm(root, { recursive: true, force: true });
  }
}
async function main() {
  const { values, positionals } = parseArgs({
    options: {
      report: { type: "string" },
      "environment-root": { type: "string" },
      "source-revision": { type: "string" },
      help: { type: "boolean" },
    },
    allowPositionals: true,
  });
  if (values.help) {
    process.stdout.write(
      "Usage: node scripts/verify-npm-tarball.mjs [candidate.tgz] [--report FILE --environment-root NEW_DIR --source-revision FULL_SHA]\n",
    );
    return;
  }
  if (positionals.length > 1)
    throw new Error("npm_verification_arguments_invalid");
  const report = await verifyTarball({
    tarball:
      positionals[0] ??
      `release-dist/npm/agentguard-ai-openclaw-plugin-${NPM_CANDIDATE_VERSION}.tgz`,
    reportPath: values.report,
    environmentRoot: values["environment-root"],
    sourceRevision: values["source-revision"],
  });
  process.stdout.write(
    JSON.stringify({
      complete: report.complete,
      package_version: report.package_version,
      hosts: report.lanes.map((lane) => lane.runtime_version),
      artifact_digest: report.artifact.raw_sha256,
      product_active_enabled: false,
      external_provider_requests: 0,
      report: values.report ?? null,
    }) + "\n",
  );
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch((error) => {
    process.stderr.write(
      (/^npm_[a-z_]+$/u.test(error?.message ?? "")
        ? error.message
        : "npm_verification_failed") + "\n",
    );
    process.exitCode = 1;
  });
