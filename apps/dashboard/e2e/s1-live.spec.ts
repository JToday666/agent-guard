import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";

import { expect, test, type Page, type TestInfo } from "@playwright/test";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const guardApiURL = "http://127.0.0.1:4188";
const liveBaseURL = "http://127.0.0.1:4175";
const rollbackBaseURL = "http://127.0.0.1:4176";
const controlToken = "runtime-demo-control";
const resultMarker = "AGENTGUARD_S1_RESULT=";

interface ScenarioResult {
  case_id: string;
  conditional_reads: { provenance: number; trace: number };
  evidence_ids: {
    trace_id: string;
    calls: Array<{
      action_id: string;
      approval_ids: string[];
      decision_ids: string[];
      event_ids: string[];
      policy_audit_ids: string[];
      receipt_audit_ids: string[];
      start_audit_ids: string[];
      tool_name: string;
    }>;
  };
  semantics: {
    invocation_count: number;
    calls: Array<{
      approval_decision: string | null;
      decision: string;
      executed: boolean;
      outcomes: Array<{
        approval: string | null;
        disposition: string;
        execution: string;
        kind: string;
      }>;
      status: string;
      tool_name: string;
    }>;
  };
  trace_id: string;
}

interface RunningScenario {
  child: ChildProcess;
  result: Promise<ScenarioResult>;
}

let readableTraceId = "";

test.describe.serial("S1 live runtime supervision", () => {
  test("BN-001 shows an official allow and executed receipt from the live API", async ({
    page,
  }, testInfo) => {
    await authenticate(page, liveBaseURL);
    const running = startScenario("BN-001", testInfo);
    const result = await running.result;
    readableTraceId = result.trace_id;
    await recordScenarioEvidence(testInfo, result);

    expect(result.conditional_reads).toEqual({ provenance: 304, trace: 304 });
    expect(result.semantics.invocation_count).toBe(1);
    expect(result.semantics.calls).toMatchObject([
      {
        decision: "allow",
        executed: true,
        started: true,
        status: "executed",
        tool_name: "read_file",
      },
    ]);
    await expectRuntimeLayers(page, result, "read_file", {
      approval: "无需审批",
      decision: "允许",
      execution: "已执行",
    });
  });

  test("RUNTIME-SAFETY-001 waits for a real browser allow-once resolution", async ({
    page,
  }, testInfo) => {
    await authenticate(page, liveBaseURL);
    const running = startScenario("RUNTIME-SAFETY-001", testInfo);
    try {
      await waitForCodeExecApproval(page, liveBaseURL);
      await page.goto(`${liveBaseURL}/approvals`);
      await expect(page.getByRole("heading", { name: "人工审批" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "code_exec" })).toBeVisible();

      const allowOnce = page.getByRole("button", { name: "仅本次放行" });
      await expect(allowOnce).toBeEnabled();
      await allowOnce.click();
      const dialog = page.getByRole("dialog", { name: "确认仅本次放行？" });
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button", { name: "确认仅本次放行" }).click();

      const result = await running.result;
      await recordScenarioEvidence(testInfo, result);
      expect(result.semantics.invocation_count).toBe(2);
      const codeCall = result.semantics.calls.find((call) => call.tool_name === "code_exec");
      expect(codeCall).toMatchObject({
        approval_decision: "allow_once",
        decision: "ask",
        executed: true,
        status: "executed",
      });
      await expectRuntimeLayers(page, result, "code_exec", {
        approval: "单次放行",
        basis: "resolved",
        decision: "需审批",
        execution: "已执行",
      });
    } finally {
      if (running.child.exitCode === null) running.child.kill("SIGTERM");
    }
  });

  test("JB-003 proves deny means zero invocation and a strict not-invoked receipt", async ({
    page,
  }, testInfo) => {
    await authenticate(page, liveBaseURL);
    const result = await startScenario("JB-003", testInfo).result;
    await recordScenarioEvidence(testInfo, result);

    expect(result.semantics.invocation_count).toBe(0);
    expect(result.semantics.calls).toHaveLength(1);
    expect(result.semantics.calls[0]).toMatchObject({
      decision: "deny",
      executed: false,
      outcomes: [
        {
          disposition: "not_applicable",
          execution: "not_invoked",
          kind: "pre_execution_deny",
        },
      ],
      status: "blocked",
      tool_name: "code_exec",
    });
    await expectRuntimeLayers(page, result, "code_exec", {
      approval: "无需审批",
      decision: "拒绝",
      execution: "未调用",
    });
  });

  test("flag-off rollback performs no S1 write and keeps S0 evidence readable", async ({
    page,
  }, testInfo) => {
    expect(readableTraceId).not.toBe("");
    await authenticate(page, rollbackBaseURL);

    const observed: Array<{ method: string; pathname: string }> = [];
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin !== rollbackBaseURL || !url.pathname.startsWith("/api/")) return;
      observed.push({ method: request.method(), pathname: url.pathname });
    });

    await page.goto(
      `${rollbackBaseURL}/evidence/${readableTraceId}?view=execution&execution_layout=list`,
    );
    const rollbackAction = page.locator(".execution-list__item[data-action-id]").first();
    await rollbackAction.locator(":scope > button").click();
    const rollbackBasis = page
      .getByLabel("运行步骤详情")
      .locator(".execution-inspector__section")
      .filter({ hasText: "Approval Basis" });
    await expect(rollbackBasis).toContainText("不可用");

    await page.goto(`${rollbackBaseURL}/evidence/${readableTraceId}?view=provenance`);
    await expect(page.getByRole("heading", { name: "证据链详情" })).toBeVisible();
    await expect(page.getByText(readableTraceId, { exact: true })).toBeVisible();
    await expect(page.getByText(/节点 · .*关系/)).toBeVisible();

    await expect
      .poll(() => observed.some((item) => item.pathname.includes("/audit/window")))
      .toBe(true);
    await expect
      .poll(() => observed.some((item) => item.pathname.endsWith(`/traces/${readableTraceId}`)))
      .toBe(true);
    await expect
      .poll(() =>
        observed.some((item) => item.pathname.endsWith(`/traces/${readableTraceId}/provenance`)),
      )
      .toBe(true);

    const running = startScenario("RUNTIME-SAFETY-001", testInfo);
    const ignoredCompletion = running.result.catch(() => undefined);
    try {
      const approvalId = await waitForCodeExecApproval(page, rollbackBaseURL);
      await page.goto(`${rollbackBaseURL}/approvals/${approvalId}`);
      const allowOnce = page.getByRole("button", { name: "仅本次放行" });
      const deny = page.getByRole("button", { name: "拒绝授权" });
      await expect(allowOnce).toBeDisabled();
      await expect(deny).toBeDisabled();
      await allowOnce.evaluate((button: HTMLButtonElement) => button.click());
      await deny.evaluate((button: HTMLButtonElement) => button.click());
    } finally {
      if (running.child.exitCode === null) running.child.kill("SIGTERM");
      await ignoredCompletion;
    }
    expect(observed.filter((item) => item.method === "POST")).toEqual([]);
  });
});

async function authenticate(page: Page, baseURL: string): Promise<void> {
  const response = await page.request.post(`${guardApiURL}/v1/auth/browser/launch`, {
    headers: { Authorization: `Bearer ${controlToken}` },
  });
  expect(response.ok()).toBe(true);
  const payload = (await response.json()) as { launch_code: string };
  await page.goto(`${baseURL}/?launch_code=${encodeURIComponent(payload.launch_code)}`);
  await expect(page.locator('[data-source-mode="live_api"]')).toContainText("LIVE API");
  await expect(page).not.toHaveURL(/launch_code=/);
}

async function recordScenarioEvidence(testInfo: TestInfo, result: ScenarioResult): Promise<void> {
  const evidence = {
    case_id: result.case_id,
    conditional_reads: result.conditional_reads,
    evidence_ids: result.evidence_ids,
  };
  const serialized = JSON.stringify(evidence);
  console.log(`AGENTGUARD_S1_EVIDENCE=${serialized}`);
  await testInfo.attach(`s1-evidence-${result.case_id.toLowerCase()}`, {
    body: JSON.stringify(evidence, null, 2),
    contentType: "application/json",
  });
}

async function waitForCodeExecApproval(page: Page, baseURL: string): Promise<string> {
  let pendingApprovalId = "";
  await expect
    .poll(
      async () => {
        const response = await page.request.get(`${baseURL}/api/v1/approvals/pending`);
        if (!response.ok()) return false;
        const approvals = (await response.json()) as Array<{
          action_name?: string;
          approval_id?: string;
        }>;
        pendingApprovalId =
          approvals.find((approval) => approval.action_name === "code_exec")?.approval_id ?? "";
        return Boolean(pendingApprovalId);
      },
      { timeout: 20_000 },
    )
    .toBe(true);
  return pendingApprovalId;
}

async function expectRuntimeLayers(
  page: Page,
  result: ScenarioResult,
  toolName: string,
  expected: {
    approval: string;
    basis?: "resolved";
    decision: string;
    execution: string;
  },
): Promise<void> {
  await page.goto(
    `${liveBaseURL}/evidence/${result.trace_id}?view=execution&execution_layout=list`,
  );
  await expect(page.getByRole("heading", { name: "证据链详情" })).toBeVisible();
  await expect(page.getByText(result.trace_id, { exact: true })).toBeVisible();
  await expect(page.getByText(result.case_id, { exact: true })).toBeVisible();

  const action = page.locator(".execution-list__item[data-action-id]").filter({
    hasText: toolName,
  });
  await expect(action).toHaveCount(1);
  await expect(action.locator('[data-supervision-layer="decision"] dd')).toHaveText(
    expected.decision,
  );
  await expect(action.locator('[data-supervision-layer="approval"] dd')).toHaveText(
    expected.approval,
  );
  await expect(action.locator('[data-supervision-layer="execution"] dd')).toHaveText(
    expected.execution,
  );
  if (expected.basis === "resolved") {
    const evidenceCall = result.evidence_ids.calls.find((call) => call.tool_name === toolName);
    expect(evidenceCall).toBeTruthy();
    const policyAuditId = evidenceCall!.policy_audit_ids[0]!;
    const eventId = evidenceCall!.event_ids[0]!;

    await action.locator(":scope > button").click();
    const inspector = page.getByLabel("运行步骤详情");
    const basis = inspector
      .locator(".execution-inspector__section")
      .filter({ hasText: "Approval Basis" });
    await expect(basis).toContainText("已记录");
    await expect(basis).toContainText(policyAuditId);
    await expect(basis).toContainText(eventId);
    const resolution = inspector
      .locator(".execution-inspector__section")
      .filter({ hasText: "Approval Resolution" });
    await expect(resolution).toContainText("单次放行");
    await expect(inspector.getByText("V2 SHADOW", { exact: true })).toBeVisible();
    await expect(inspector).toContainText("不可用");

    await inspector.getByRole("button", { name: "查看审计记录" }).click();
    await expect(page).toHaveURL(new RegExp(`view=audit.*event_id=${policyAuditId}`));
    await expect(page.locator(`[data-event-id="${policyAuditId}"]`)).toBeVisible();
    await page.getByRole("button", { name: "关闭详情" }).click();

    await page.getByRole("tab", { name: "执行轨迹" }).click();
    await action.locator(":scope > button").click();
    await page.getByLabel("运行步骤详情").getByRole("button", { name: "查看溯源关系" }).click();
    await expect(page).toHaveURL(/view=provenance/);
    await expect(page.locator(".prov-node--selected")).toContainText(toolName);
  }
}

function startScenario(caseId: string, testInfo: TestInfo): RunningScenario {
  const workDir = testInfo.outputPath(`runtime-${caseId.toLowerCase()}`);
  const child = spawn(
    "uv",
    [
      "run",
      "--directory",
      repoRoot,
      "--group",
      "bench",
      "python",
      "-m",
      "tests.support.runtime_safety_harness",
      "run-scenario",
      "--base-url",
      guardApiURL,
      "--case-id",
      caseId,
      "--work-dir",
      workDir,
    ],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        UV_CACHE_DIR: process.env.UV_CACHE_DIR ?? "/tmp/agentguard-s1-live-uv-cache",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  if (!child.stdout || !child.stderr) {
    throw new Error(`scenario ${caseId} did not expose stdout/stderr pipes`);
  }
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));

  const result = new Promise<ScenarioResult>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`scenario ${caseId} timed out\n${stderr.slice(-4_000)}`));
    }, 35_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      const markedLine = stdout
        .split(/\r?\n/)
        .reverse()
        .find((line: string) => line.startsWith(resultMarker));
      if (code !== 0 || !markedLine) {
        reject(
          new Error(
            `scenario ${caseId} failed with exit ${code}\n${stderr.slice(-4_000)}\n${stdout.slice(-2_000)}`,
          ),
        );
        return;
      }
      resolve(JSON.parse(markedLine.slice(resultMarker.length)) as ScenarioResult);
    });
  });
  return { child, result };
}
