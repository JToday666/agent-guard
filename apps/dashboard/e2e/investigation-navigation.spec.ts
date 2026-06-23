import { expect, test, type Page } from "@playwright/test";

async function openResponsiveNavigation(page: Page) {
  const menuButton = page.getByRole("button", { name: "菜单" });
  if (await menuButton.isVisible()) await menuButton.click();
}

test("approval exposes separate trace and event evidence destinations", async ({ page }) => {
  await page.goto("/approvals");

  const fullTraceLink = page.getByRole("link", { name: "查看完整 Trace" });
  await expect(fullTraceLink).toBeVisible();
  await expect(fullTraceLink).toHaveAttribute("href", "/investigations/trace_002");

  const locateEventLink = page.getByRole("link", { name: "定位关联事件" });
  await expect(locateEventLink).toBeVisible();
  await locateEventLink.click();

  await expect(page).toHaveURL(/\/investigations\/trace_002\?event_id=evt_20260607_002$/);
  await expect(page.locator('[data-event-id="evt_20260607_002"]')).toHaveAttribute("aria-current", "true");
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("clicking a non-time event cell opens its evidence", async ({ page }) => {
  await page.goto("/investigations");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();

  await row.locator("td").nth(4).click();

  await expect(page).toHaveURL(/event_id=evt_20260607_002/);
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("keyboard opens event evidence and Escape restores row focus", async ({ page }) => {
  await page.goto("/investigations");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();

  await row.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");

  await expect(page).not.toHaveURL(/event_id=/);
  await expect(row).toBeFocused();
});

test("a missing event keeps the query and shows explicit feedback", async ({ page }) => {
  await page.goto("/investigations?event_id=missing-event");

  await expect(page).toHaveURL(/event_id=missing-event/);
  await expect(page.getByRole("dialog")).toContainText("未找到事件");
});

test("approval route synchronization does not cancel navigation", async ({ page }) => {
  await page.goto("/approvals");
  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "系统" }).click();

  await expect(page).toHaveURL(/\/system$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/system$/);
});

test("investigation search synchronization does not reopen a deactivated page", async ({ page }) => {
  await page.goto("/investigations?search=send");
  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "总览" }).click();

  await expect(page).toHaveURL(/\/overview$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/overview$/);
});

test("primary dashboard routes do not overflow the viewport", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  for (const path of ["/overview", "/investigations", "/approvals", "/evaluation", "/system"]) {
    await page.goto(path);
    await expect(page.locator("main").first()).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  }
  expect(runtimeErrors).toEqual([]);
});

test("mobile investigation core columns fit without horizontal scrolling", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile");
  await page.goto("/investigations");

  const dimensions = await page.locator(".event-table-wrap").evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
});

test("top bar remains visible while the workspace scrolls", async ({ page }) => {
  await page.goto("/overview");
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));

  await expect.poll(async () => (await page.locator(".top-bar").boundingBox())?.y).toBe(0);
});

test("desktop sidebar remains below the top bar while the workspace scrolls", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop");
  await page.goto("/overview");
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));

  const topBarBox = await page.locator(".top-bar").boundingBox();
  const sidebarBox = await page.locator(".sidebar").boundingBox();
  expect(Math.abs((sidebarBox?.y ?? 0) - (topBarBox?.height ?? 0))).toBeLessThanOrEqual(1);
});
