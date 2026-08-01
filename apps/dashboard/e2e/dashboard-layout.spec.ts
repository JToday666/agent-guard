import { expect, test } from "@playwright/test";

test("approval desktop layout keeps queue and detail in separate scroll regions", async ({
  page,
}) => {
  await page.goto("/approvals");

  const layout = page.locator(".approvals-layout");
  await expect(layout).toBeVisible();
  const state = await layout.evaluate((element) => {
    const queue = element.querySelector<HTMLElement>(".approval-queue");
    const detailBody = element.querySelector<HTMLElement>(".approval-detail__body");
    return {
      detailBodyHeight: detailBody?.clientHeight ?? 0,
      detailOverflow: detailBody ? getComputedStyle(detailBody).overflowY : "",
      gridColumns: getComputedStyle(element).gridTemplateColumns,
      layoutWidth: element.clientWidth,
      queueOverflow: queue ? getComputedStyle(queue).overflowY : "",
    };
  });

  expect(state.gridColumns.split(" ").length).toBeGreaterThanOrEqual(2);
  expect(state.layoutWidth).toBeGreaterThan(0);
  expect(state.detailBodyHeight).toBeGreaterThan(120);
  expect(state.queueOverflow).toBe("auto");
  expect(state.detailOverflow).toBe("auto");
});

test("top bar remains visible while the workspace scrolls", async ({ page }) => {
  await page.goto("/overview");
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));

  await expect.poll(async () => (await page.locator(".top-bar").boundingBox())?.y).toBe(0);
});

test("desktop sidebar remains below the top bar while the workspace scrolls", async ({ page }) => {
  await page.goto("/overview");
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));

  const topBarBox = await page.locator(".top-bar").boundingBox();
  const sidebarBox = await page.locator(".sidebar").boundingBox();
  expect(Math.abs((sidebarBox?.y ?? 0) - (topBarBox?.height ?? 0))).toBeLessThanOrEqual(1);
});
