import { expect, test } from "@playwright/test";

test("clicking a non-time event cell opens its evidence", async ({ page }) => {
  await page.goto("/investigations");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();

  await row.locator("td").nth(4).click();

  await expect(page).toHaveURL(/event_id=evt_20260607_002/);
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("CSV export uses rule names without raw policy numbers", async ({ page }) => {
  await page.goto("/investigations");

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "导出当前筛选结果" }).click(),
  ]);
  const stream = await download.createReadStream();
  if (!stream) throw new Error("CSV 下载流不可用");

  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const csv = Buffer.concat(chunks).toString("utf8");

  expect(csv).toContain("外部发送需确认");
  expect(csv).not.toMatch(/P\d{3}/);
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

test("a stage-only URL filter exposes the clear-filter action", async ({ page }) => {
  await page.goto("/investigations?stage=before_tool_call");

  const clearButton = page.getByRole("button", { name: "清除筛选" });
  await expect(clearButton).toBeVisible();
  await clearButton.click();
  await expect(page).toHaveURL(/\/investigations$/);
});

test("approval route synchronization does not cancel navigation", async ({ page }) => {
  await page.goto("/approvals");
  await page.getByRole("link", { name: "系统状态" }).click();

  await expect(page).toHaveURL(/\/system$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/system$/);
});

test("investigation search synchronization does not reopen a deactivated page", async ({
  page,
}) => {
  await page.goto("/investigations?search=send");
  await page.getByRole("link", { name: "安全总览" }).click();

  await expect(page).toHaveURL(/\/overview$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/overview$/);
});

test("investigation selects preserve their closed and open states", async ({ page }) => {
  await page.goto("/investigations");

  const tools = page.locator(".investigation-tools");
  const selectRoot = page.locator("#investigation-decision-trigger").locator("..");
  const trigger = page.locator("#investigation-decision-trigger");
  const menu = page.locator("#investigation-decision-listbox");

  await expect(tools).toBeVisible();
  await expect(selectRoot).not.toHaveClass(/app-select--open/);
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
  await expect(trigger).toHaveCSS("min-height", "40px");
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

test("investigation selects expose consistent combobox semantics", async ({ page }) => {
  await page.goto("/investigations");

  await expect(page.getByRole("combobox", { name: /^决策/ })).toBeVisible();
  await expect(page.getByRole("combobox", { name: /^运行时/ })).toBeVisible();
  await expect(page.getByRole("combobox", { name: /^严重性/ })).toBeVisible();
});

test("investigation select supports mouse selection and outside dismissal", async ({ page }) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  const runtimeSelect = page.getByRole("combobox", { name: /^运行时/ });

  await decisionSelect.click();
  await page.getByRole("option", { name: "已阻断" }).click();
  await expect(page).toHaveURL(/decision=deny/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");

  await runtimeSelect.click();
  await page.locator(".page-header h1").click();
  await expect(runtimeSelect).toHaveAttribute("aria-expanded", "false");
});

test("investigation select supports standard keyboard navigation", async ({ page }) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });

  await decisionSelect.focus();
  await page.keyboard.press("ArrowDown");
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("End");
  await expect(page.locator(".app-select__option--active")).toHaveText("已放行");
  await page.keyboard.press("Home");
  await expect(page.locator(".app-select__option--active")).toHaveText("全部");
  await page.keyboard.press("ArrowUp");
  await expect(page.locator(".app-select__option--active")).toHaveText("已放行");
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/decision=allow/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
  await expect(decisionSelect).toBeFocused();
});

test("investigation select supports typeahead Escape and Tab", async ({ page }) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  const runtimeSelect = page.getByRole("combobox", { name: /^运行时/ });

  await runtimeSelect.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("o");
  await expect(page.locator(".app-select__option--active")).toHaveText("OpenClaw");
  await page.keyboard.press("Escape");
  await expect(runtimeSelect).toHaveAttribute("aria-expanded", "false");
  await expect(runtimeSelect).toBeFocused();

  await decisionSelect.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Tab");
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
  await expect(runtimeSelect).toBeFocused();
});

test("investigation select closes when its KeepAlive page is deactivated", async ({ page }) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  await decisionSelect.click();

  await page.getByRole("link", { name: "安全总览" }).click();
  await expect(page).toHaveURL(/\/overview$/);
  await page.getByRole("link", { name: "事件调查", exact: true }).click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(decisionSelect).toHaveAttribute("aria-expanded", "false");
});
