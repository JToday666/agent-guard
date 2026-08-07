import { expect, type Page } from "@playwright/test";

export function primaryDashboardRoutes(traceId: string): string[] {
  return [
    "/overview",
    "/investigations",
    "/evidence",
    `/evidence/${traceId}`,
    "/approvals",
    "/evaluation",
    "/system",
  ];
}

async function expectUnfilledDecisionTrend(page: Page): Promise<void> {
  const series = page.locator(".trend-chart polyline");
  await expect(series).toHaveCount(3);
  await expect
    .poll(() =>
      series.evaluateAll((elements) => elements.map((element) => getComputedStyle(element).fill)),
    )
    .toEqual(["none", "none", "none"]);
}

export async function expectPrimaryRoutesLayout(page: Page, traceId: string): Promise<void> {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  for (const path of primaryDashboardRoutes(traceId)) {
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
    if (path === "/overview") await expectUnfilledDecisionTrend(page);
  }

  expect(runtimeErrors).toEqual([]);
}
