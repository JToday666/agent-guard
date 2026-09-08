import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { archiveNativeDiagnostic } from "./product-runtime-inventory.mjs";

test("a failed native run retains private diagnostics after profile cleanup", async () => {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "agentguard-product-diagnostics-"),
  );
  const profile = path.join(root, "profile");
  const state = path.join(profile, "openclaw-state");
  try {
    await mkdir(state, { recursive: true });
    await writeFile(
      path.join(state, "inventory-native-agent.log"),
      "controlled native failure\n",
    );
    const report = { status: "incomplete", error_code: "native_agent_failed" };
    await archiveNativeDiagnostic({
      root: profile,
      report,
      outputPath: path.join(root, "report.json"),
    });
    await rm(profile, { recursive: true });
    assert.equal(
      await readFile(report.native_agent.log_path, "utf8"),
      "controlled native failure\n",
    );
    assert.equal(
      (await stat(report.native_agent.log_path)).mode & 0o777,
      0o600,
    );
    assert.equal(report.native_agent.exit_code, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("diagnostic archiving rejects symlink input and does not overwrite evidence", async () => {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "agentguard-product-diagnostics-"),
  );
  try {
    const state = path.join(root, "openclaw-state");
    await mkdir(state);
    const source = path.join(state, "inventory-native-agent.log");
    const outside = path.join(root, "other.log");
    await writeFile(outside, "not native evidence");
    await symlink(outside, source);
    const args = {
      root,
      report: {},
      outputPath: path.join(root, "report.json"),
    };
    await assert.rejects(archiveNativeDiagnostic(args));
    await rm(source);
    await writeFile(source, "native evidence");
    await archiveNativeDiagnostic(args);
    await assert.rejects(archiveNativeDiagnostic(args), { code: "EEXIST" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
