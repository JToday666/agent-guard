import { expect, test } from "@playwright/test";

test("evaluation page shows latest run, attack ASR and sample cases", async ({
  page,
}) => {
  await page.goto("/evaluation");

  const latestRun = page.locator(".evaluation-run");
  await expect(page.getByText("eval_mock_20260628")).toBeVisible();
  await expect(page.getByText("AttackBench / v1")).toBeVisible();
  await expect(
    latestRun.locator(".asr-stage").getByText("73.2%"),
  ).toBeVisible();
  await expect(latestRun.locator(".asr-stage").getByText("4.8%")).toBeVisible();
  await expect(
    page.locator(".attack-asr").getByText("prompt_injection"),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: /PI-002/ })).toBeVisible();
});

test("evaluation case query shows and clears the selected sample", async ({
  page,
}) => {
  await page.goto("/evaluation?case_id=PI-002");

  const locator = page.locator(".case-locator");
  await expect(locator).toBeVisible();
  await expect(locator).toContainText("当前定位样本：PI-002");

  await locator.getByRole("button", { name: "清除定位" }).click();
  await expect(page).toHaveURL(/\/evaluation$/);
});

test("evaluation case query reports a missing selected sample", async ({
  page,
}) => {
  await page.goto("/evaluation?case_id=UNKNOWN");

  await expect(page.locator(".case-locator")).toContainText(
    "未找到定位样本：UNKNOWN",
  );
});

test("system page shows OpenClaw verify status and config findings", async ({
  page,
}) => {
  await page.goto("/system");

  const verifyPanel = page.locator(".adapter-verify");
  await expect(
    page.getByRole("heading", { name: "OpenClaw 插件验证" }),
  ).toBeVisible();
  await expect(
    verifyPanel.locator(".adapter-verify__headline").getByText("16 / 16"),
  ).toBeVisible();
  await expect(page.getByText("OpenClaw 2026.6.6")).toBeVisible();
  await expect(page.getByText("Raw conversation access enabled")).toBeVisible();
  await expect(
    page.locator(".finding-list").getByText("agentguard-security").first(),
  ).toBeVisible();
  await expect(
    page
      .locator(".finding-list")
      .getByRole("link", { name: /trace_002/ })
      .first(),
  ).toBeVisible();
});

test("system page uses localized operator-facing terminology", async ({
  page,
}) => {
  await page.goto("/system");

  await expect(page.locator(".system-page")).toContainText("配置审计发现项");
  await expect(page.locator(".system-page")).toContainText("最近心跳");
  await expect(page.locator(".system-page")).toContainText("失败关闭阶段");
  await expect(page.locator(".system-page")).toContainText("运行时");
  await expect(page.locator(".system-page")).not.toContainText("Findings");
  await expect(page.locator(".system-page")).not.toContainText("Fail-closed");
  await expect(page.locator(".system-page")).not.toContainText("heartbeat");
  await expect(page.locator(".system-page")).not.toContainText("Runtime");
});

test("operator-facing pages do not expose raw policy rule numbers", async ({
  page,
}) => {
  for (const path of ["/overview", "/evaluation", "/system", "/evidence/trace_002"]) {
    await page.goto(path);
    await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  }

  await page.goto("/investigations");
  await page.locator("tbody tr").filter({ hasText: "send_email" }).first().click();

  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
});
