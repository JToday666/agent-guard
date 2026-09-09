#!/usr/bin/env node
/** Native Host inventory preflight; never an official V2.1 activation result. */
import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { createBaselineRuntimeProfile as createProductRuntimeProfile } from "../packages/agentguard-openclaw-plugin/product-runtime/baseline-profile.mjs";
import { startFixtureInbox } from "../packages/agentguard-openclaw-plugin/product-runtime/inbox.mjs";
import { runProductRuntimeInventoryProbe } from "../tests/support/openclaw-product-runtime/probe.mjs";

/** Keep bounded private diagnostics for both successful and failed native runs. */
export async function archiveNativeDiagnostic({ root, report, outputPath }) {
  const sourceLog = path.join(
    root,
    "openclaw-state",
    "inventory-native-agent.log",
  );
  let stat;
  try {
    stat = await lstat(sourceLog);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) {
    throw new Error("Invalid native diagnostic file");
  }
  await mkdir(path.dirname(outputPath), { recursive: true });
  const retainedLog = outputPath + ".native.log";
  await writeFile(retainedLog, await readFile(sourceLog), {
    flag: "wx",
    mode: 0o600,
  });
  report.native_agent = { ...report.native_agent, log_path: retainedLog };
}

async function main() {
  const { values } = parseArgs({
    options: {
      output: { type: "string" },
      "openclaw-root": { type: "string" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    process.stdout.write(
      "Usage: node scripts/product-runtime-inventory.mjs --output /absolute/report.json --openclaw-root /absolute/host\n",
    );
    return;
  }
  if (!values.output || !path.isAbsolute(values.output)) {
    throw new Error("An absolute --output is required");
  }
  if (!values["openclaw-root"] || !path.isAbsolute(values["openclaw-root"])) {
    throw new Error("An absolute --openclaw-root is required");
  }
  const root = await mkdtemp(
    path.join(os.tmpdir(), "agentguard-product-inventory-"),
  );
  let inbox;
  let report;
  try {
    inbox = await startFixtureInbox({ acceptanceRoot: root });
    report = await runProductRuntimeInventoryProbe({
      createProfile: (model) =>
        createProductRuntimeProfile({ root, inboxUrl: inbox.url, ...model }),
      openclawRoot: values["openclaw-root"],
    });
  } catch (error) {
    report = {
      schema_version: "1.0",
      status: "incomplete",
      phase: "inventory_preflight",
      official_active: false,
      external_provider_requests: 0,
      error_code:
        typeof error.code === "string" && /^[a-z_]{1,100}$/.test(error.code)
          ? error.code
          : "native_inventory_preflight_failed",
    };
    process.exitCode = 2;
  } finally {
    await inbox?.close();
    try {
      await archiveNativeDiagnostic({
        root,
        report,
        outputPath: values.output,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
    report.temporary_profile_removed = true;
  }
  await mkdir(path.dirname(values.output), { recursive: true });
  await writeFile(values.output, JSON.stringify(report, null, 2) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
  process.stdout.write(
    JSON.stringify({
      report: values.output,
      phase: "inventory_preflight",
      exit_code: process.exitCode ?? 0,
    }) + "\n",
  );
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch(() => {
    process.stderr.write(
      "Product inventory preflight failed; check the explicit output and isolated Host prerequisites.\n",
    );
    process.exitCode = 2;
  });
