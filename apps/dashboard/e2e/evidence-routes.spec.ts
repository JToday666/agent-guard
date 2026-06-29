import { expect, test } from "@playwright/test";

test("approval exposes separate trace and event evidence destinations", async ({
  page,
}) => {
  await page.goto("/approvals");

  const fullTraceLink = page.getByRole("link", { name: "查看完整证据链" });
  await expect(fullTraceLink).toBeVisible();
  await expect(fullTraceLink).toHaveAttribute("href", "/evidence/trace_002");
  await fullTraceLink.click();

  await expect(page).toHaveURL(/\/evidence\/trace_002$/);
  const evidenceNavigation = page.locator('.sidebar__link[href="/evidence"]');
  await expect(evidenceNavigation).toHaveClass(/sidebar__link--active/);
  await expect(evidenceNavigation).toHaveAttribute("aria-current", "page");
  const evidenceLink = page
    .locator('[data-event-id="evt_20260607_002"]')
    .getByRole("link", { name: "查看证据" });
  await expect(evidenceLink).toBeVisible();
  await evidenceLink.click();
  await expect(page.getByRole("dialog")).toContainText("风险分数");

  await page.goto("/approvals");

  const locateEventLink = page.getByRole("link", { name: "定位关联事件" });
  await expect(locateEventLink).toBeVisible();
  await locateEventLink.click();

  await expect(page).toHaveURL(
    /\/evidence\/trace_002\?event_id=evt_20260607_002$/,
  );
  await expect(evidenceNavigation).toHaveClass(/sidebar__link--active/);
  await expect(evidenceNavigation).toHaveAttribute("aria-current", "page");
  await expect(
    page.locator('[data-event-id="evt_20260607_002"]'),
  ).toHaveAttribute("aria-current", "true");
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("evidence detail keeps related approval and evaluation destinations", async ({
  page,
}) => {
  await page.goto("/evidence/trace_002");

  const approvalLink = page.getByRole("link", { name: "查看关联审批" });
  const evaluationLink = page.getByRole("link", { name: "查看评测样本" });

  await expect(approvalLink).toBeVisible();
  await expect(approvalLink).toHaveAttribute("href", /\/approvals\/ask_001$/);
  await expect(evaluationLink).toBeVisible();
  await expect(evaluationLink).toHaveAttribute(
    "href",
    /\/evaluation\?case_id=PI-002$/,
  );
});
