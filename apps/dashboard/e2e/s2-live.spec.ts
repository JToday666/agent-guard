import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const guardApiURL = "http://127.0.0.1:4198";
const marker = "AGENTGUARD_S2_RESULT=";

test("real seven-event CT trace is readable in the live Dashboard", async ({ page }, testInfo) => {
  const workDir = testInfo.outputPath("runtime-s2-ct-001");
  const run = spawnSync(
    "uv",
    [
      "run",
      "--directory",
      repoRoot,
      "--group",
      "bench",
      "python",
      "-m",
      "tests.support.runtime_supervision_s2_harness",
      "run-scenario",
      "--base-url",
      guardApiURL,
      "--work-dir",
      workDir,
    ],
    { cwd: repoRoot, encoding: "utf8", env: process.env, timeout: 45_000 },
  );
  const stdout = run.stdout ?? "";
  const stderr = run.stderr ?? run.error?.message ?? "S2 harness did not return stderr";
  const line = stdout.split(/\r?\n/).find((item) => item.startsWith(marker));
  expect(run.error, stderr).toBeUndefined();
  expect(run.status, stderr).toBe(0);
  expect(line).toBeTruthy();
  const evidence = JSON.parse(line!.slice(marker.length)) as {
    trace_id: string;
    event_types: string[];
    full_envelope_event_types: string[];
    missing_event_types: string[];
    missing_full_envelopes: string[];
    typed_node_ids: string[];
    typed_edge_ids: string[];
    conditional_reads: { trace: number; provenance: number };
  };
  expect(evidence.missing_event_types).toEqual([]);
  expect(evidence.missing_full_envelopes).toEqual([]);
  expect(evidence.event_types).toHaveLength(7);
  expect(evidence.full_envelope_event_types).toHaveLength(7);
  expect(evidence.typed_node_ids.length).toBeGreaterThan(0);
  expect(evidence.typed_edge_ids.length).toBeGreaterThan(0);
  expect(evidence.conditional_reads).toEqual({ trace: 304, provenance: 304 });
  await testInfo.attach("s2-evidence", {
    path: `${workDir}/s2-evidence.json`,
    contentType: "application/json",
  });

  const launch = await page.request.post(`${guardApiURL}/v1/auth/browser/launch`, {
    headers: { Authorization: "Bearer runtime-demo-control" },
  });
  expect(launch.ok()).toBe(true);
  const { launch_code: launchCode } = (await launch.json()) as { launch_code: string };
  await page.goto(`/?launch_code=${encodeURIComponent(launchCode)}`);
  await expect(page.locator('[data-source-mode="live_api"]')).toContainText("LIVE API");
  await expect(page).not.toHaveURL(/launch_code=/);
  await page.goto(`/evidence/${evidence.trace_id}?view=provenance`);
  await expect(page.getByRole("tab", { name: "溯源关系" })).toBeVisible();
  await expect(page.locator(".prov-node").first()).toBeVisible();
  await expect(page.getByText("内容溯源证据不完整")).toBeVisible();
  await expect(page.getByText(/当前契约：mixed/)).toBeVisible();
  const provenanceResponse = await page.request.get(
    `/api/v1/traces/${evidence.trace_id}/provenance`,
  );
  expect(provenanceResponse.ok()).toBe(true);
  const graph = (await provenanceResponse.json()) as {
    nodes: Array<{
      node_id: string;
      metadata: { contract?: string; node_kind?: string };
    }>;
  };
  const typedSource = graph.nodes.find(
    (node) =>
      node.metadata.contract === "ct-provenance/1.0" && node.metadata.node_kind === "source",
  );
  expect(typedSource).toBeTruthy();
  await page.goto(
    `/evidence/${evidence.trace_id}?view=provenance&node_id=${encodeURIComponent(typedSource!.node_id)}`,
  );
  await expect(page.getByText("Source / Trust", { exact: true })).toBeVisible();
  await expect(page.getByText("EvidenceRef", { exact: true })).toBeVisible();
  await expect(page.locator(".prov-node").first()).toBeVisible();
  const screenshotPath = testInfo.outputPath("s2-provenance-live.png");
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await testInfo.attach("s2-provenance-live", {
    path: screenshotPath,
    contentType: "image/png",
  });
});
