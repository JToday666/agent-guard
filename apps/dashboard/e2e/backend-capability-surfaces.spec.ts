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
