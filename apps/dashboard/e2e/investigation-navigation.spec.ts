import { expect, test, type Page } from "@playwright/test";

async function openResponsiveNavigation(page: Page) {
  const menuButton = page.getByRole("button", { name: "菜单" });
  if (await menuButton.isVisible()) await menuButton.click();
}

test("approval exposes separate trace and event evidence destinations", async ({
  page,
}) => {
  await page.goto("/approvals");

  const fullTraceLink = page.getByRole("link", { name: "查看完整 Trace" });
  await expect(fullTraceLink).toBeVisible();
  await expect(fullTraceLink).toHaveAttribute(
    "href",
    "/investigations/trace_002",
  );
  await fullTraceLink.click();

  await expect(page).toHaveURL(/\/investigations\/trace_002$/);
  const investigationNavigation = page.locator(
    '.sidebar__link[href="/investigations"]',
  );
  await expect(investigationNavigation).toHaveClass(/sidebar__link--active/);
  await expect(investigationNavigation).toHaveAttribute("aria-current", "page");
  const evidenceLink = page
    .locator('[data-event-id="evt_20260607_002"]')
    .getByRole("link", { name: "查看证据" });
  await expect(evidenceLink).toHaveClass(/page-action/);
  await evidenceLink.click();
  await expect(page.getByRole("dialog")).toContainText("风险分数");

  await page.goto("/approvals");

  const locateEventLink = page.getByRole("link", { name: "定位关联事件" });
  await expect(locateEventLink).toBeVisible();
  await locateEventLink.click();

  await expect(page).toHaveURL(
    /\/investigations\/trace_002\?event_id=evt_20260607_002$/,
  );
  await expect(investigationNavigation).toHaveClass(/sidebar__link--active/);
  await expect(investigationNavigation).toHaveAttribute("aria-current", "page");
  await expect(
    page.locator('[data-event-id="evt_20260607_002"]'),
  ).toHaveAttribute("aria-current", "true");
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("overview investigation links use the shared action style", async ({
  page,
}) => {
  await page.goto("/overview");

  for (const name of ["进入调查", "查看全部"]) {
    const link = page.getByRole("link", { name });
    await expect(link).toHaveClass(/page-action/);
    await expect(link).toHaveCSS("border-top-style", "solid");
    await expect(link).toHaveCSS("background-color", "rgb(241, 245, 249)");
  }
});

test("clicking a non-time event cell opens its evidence", async ({ page }) => {
  await page.goto("/investigations");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();

  await row.locator("td").nth(4).click();

  await expect(page).toHaveURL(/event_id=evt_20260607_002/);
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("keyboard opens event evidence and Escape restores row focus", async ({
  page,
}) => {
  await page.goto("/investigations");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();

  await row.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");

  await expect(page).not.toHaveURL(/event_id=/);
  await expect(row).toBeFocused();
});

test("a missing event keeps the query and shows explicit feedback", async ({
  page,
}) => {
  await page.goto("/investigations?event_id=missing-event");

  await expect(page).toHaveURL(/event_id=missing-event/);
  await expect(page.getByRole("dialog")).toContainText("未找到事件");
});

test("trace context evidence destinations use button styling", async ({
  page,
}) => {
  await page.goto("/investigations/trace_002");

  for (const name of ["查看关联审批", "查看评测样本"]) {
    const link = page.getByRole("link", { name });
    await expect(link).toHaveClass(/page-action/);
    await expect(link).toHaveCSS("border-top-style", "solid");
    await expect(link).toHaveCSS("text-decoration-line", "none");
    const linkBox = await link.boundingBox();
    const contextBox = await page.locator(".trace-context").boundingBox();
    expect(linkBox?.width ?? 0).toBeLessThan((contextBox?.width ?? 0) * 0.8);
  }
});

test("approval route synchronization does not cancel navigation", async ({
  page,
}) => {
  await page.goto("/approvals");
  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "系统" }).click();

  await expect(page).toHaveURL(/\/system$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/system$/);
});

test("investigation search synchronization does not reopen a deactivated page", async ({
  page,
}) => {
  await page.goto("/investigations?search=send");
  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "总览" }).click();

  await expect(page).toHaveURL(/\/overview$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/overview$/);
});

test("investigation selects preserve their closed and open states", async ({
  page,
}) => {
  await page.goto("/investigations");

  const tools = page.locator(".investigation-tools");
  const selectRoot = page
    .locator("#investigation-decision-trigger")
    .locator("..");
  const trigger = page.locator("#investigation-decision-trigger");
  const menu = page.locator("#investigation-decision-listbox");

  await expect(tools).toBeVisible();
  await expect(selectRoot).not.toHaveClass(/app-select--open/);
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
  await expect(trigger).toHaveCSS("min-height", "40px");
  await expect(trigger).toHaveCSS("border-top-style", "solid");
  await expect(menu).toHaveCount(0);

  await trigger.click();

  await expect(selectRoot).toHaveClass(/app-select--open/);
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
  await expect(menu).toBeVisible();
  await expect(menu).toHaveCSS("position", "absolute");
  await expect(menu).toHaveCSS("z-index", "40");
  await expect(page.getByRole("option", { name: "全部" })).toHaveClass(
    /app-select__option--selected/,
  );
});

test("investigation selects expose consistent combobox semantics", async ({
  page,
}) => {
  await page.goto("/investigations");

  await expect(page.getByRole("combobox", { name: /^决策/ })).toBeVisible();
  await expect(page.getByRole("combobox", { name: /^运行时/ })).toBeVisible();
  await expect(page.getByRole("combobox", { name: /^严重性/ })).toBeVisible();
});

test("investigation select supports mouse selection and outside dismissal", async ({
  page,
}) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  const runtimeSelect = page.getByRole("combobox", { name: /^运行时/ });

  await decisionSelect.click();
  await page.getByRole("option", { name: "拒绝" }).click();
  await expect(page).toHaveURL(/decision=deny/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");

  await runtimeSelect.click();
  await page.locator(".result-summary").click();
  await expect(runtimeSelect).toHaveAttribute("aria-expanded", "false");
});

test("investigation select supports standard keyboard navigation", async ({
  page,
}) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });

  await decisionSelect.focus();
  await page.keyboard.press("ArrowDown");
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("End");
  await expect(page.locator(".app-select__option--active")).toHaveText("放行");
  await page.keyboard.press("Home");
  await expect(page.locator(".app-select__option--active")).toHaveText("全部");
  await page.keyboard.press("ArrowUp");
  await expect(page.locator(".app-select__option--active")).toHaveText("放行");
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/decision=allow/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
  await expect(decisionSelect).toBeFocused();
});

test("investigation select supports typeahead Escape and Tab", async ({
  page,
}) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  const runtimeSelect = page.getByRole("combobox", { name: /^运行时/ });

  await runtimeSelect.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("o");
  await expect(page.locator(".app-select__option--active")).toHaveText(
    "OpenClaw",
  );
  await page.keyboard.press("Escape");
  await expect(runtimeSelect).toHaveAttribute("aria-expanded", "false");
  await expect(runtimeSelect).toBeFocused();

  await decisionSelect.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Tab");
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
  await expect(runtimeSelect).toBeFocused();
});

test("investigation select closes when its KeepAlive page is deactivated", async ({
  page,
}) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  await decisionSelect.click();

  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "总览" }).click();
  await expect(page).toHaveURL(/\/overview$/);
  await openResponsiveNavigation(page);
  await page.getByRole("link", { name: "调查", exact: true }).click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
});

test("primary dashboard routes do not overflow the viewport", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  for (const path of [
    "/overview",
    "/investigations",
    "/approvals",
    "/evaluation",
    "/system",
  ]) {
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

test("mobile investigation core columns fit without horizontal scrolling", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "mobile");
  await page.goto("/investigations");

  const dimensions = await page
    .locator(".event-table-wrap")
    .evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
});

test("top bar remains visible while the workspace scrolls", async ({
  page,
}) => {
  await page.goto("/overview");
  await page.evaluate(() =>
    window.scrollTo(0, document.documentElement.scrollHeight),
  );

  await expect
    .poll(async () => (await page.locator(".top-bar").boundingBox())?.y)
    .toBe(0);
});

test("desktop sidebar remains below the top bar while the workspace scrolls", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop");
  await page.goto("/overview");
  await page.evaluate(() =>
    window.scrollTo(0, document.documentElement.scrollHeight),
  );

  const topBarBox = await page.locator(".top-bar").boundingBox();
  const sidebarBox = await page.locator(".sidebar").boundingBox();
  expect(
    Math.abs((sidebarBox?.y ?? 0) - (topBarBox?.height ?? 0)),
  ).toBeLessThanOrEqual(1);
});
