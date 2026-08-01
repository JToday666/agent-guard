import { expect, test } from "@playwright/test";

test("decision trend keeps decision words in the legend only", async ({ page }) => {
  await page.goto("/overview");

  await expect(page.locator(".trend-legend")).toContainText("放行");
  await expect(page.locator(".trend-legend")).toContainText("审批");
  await expect(page.locator(".trend-legend")).toContainText("拒绝");

  const svgLabels = await page.locator(".trend-chart svg text").allTextContents();
  expect(svgLabels.join(" ")).not.toMatch(/放行|审批|拒绝/);
});

test("top page headers use primary titles without category subtitles", async ({ page }) => {
  const removedSubtitles = ["安全态势", "监控与取证", "证据追踪", "人工控制", "防御效果", "运行状态"];

  for (const path of [
    "/overview",
    "/investigations",
    "/evidence",
    "/evidence/trace_002",
    "/approvals",
    "/evaluation",
    "/system",
  ]) {
    await page.goto(path);
    const header = page.locator(".page-header").first();
    await expect(header.locator("h1")).toBeVisible();
    await expect(header.locator("p")).toHaveCount(0);
    for (const subtitle of removedSubtitles) {
      await expect(header.getByText(subtitle, { exact: true })).toHaveCount(0);
    }
  }
});
