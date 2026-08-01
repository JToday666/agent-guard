import { expect, test } from "@playwright/test";

const primaryRoutes = [
  "/overview",
  "/investigations",
  "/evidence",
  "/evidence/trace_002",
  "/approvals",
  "/evaluation",
  "/system",
];

test("primary routes remain usable across supported desktop workspaces", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  for (const path of primaryRoutes) {
    await page.goto(path);
    await expect(page.locator("main")).toHaveCount(1);
    await expect(page.locator("main")).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      mainWidth: document.querySelector<HTMLElement>("main")?.getBoundingClientRect().width ?? 0,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.mainWidth).toBeGreaterThan(0);
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  }

  expect(runtimeErrors).toEqual([]);
});

test("desktop shell keeps the required navigation order", async ({ page }) => {
  await page.goto("/overview");

  await expect(page.locator(".sidebar__link")).toHaveText([
    "安全总览",
    "事件调查",
    "人工审批2",
    "证据链",
    "安全评测",
    "系统状态",
  ]);
});
