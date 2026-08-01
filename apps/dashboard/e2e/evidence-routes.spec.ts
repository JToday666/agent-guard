import { expect, test } from "@playwright/test";

test("approval exposes separate trace and event evidence destinations", async ({ page }) => {
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

  await expect(page).toHaveURL(/\/evidence\/trace_002\?event_id=evt_20260607_002$/);
  await expect(evidenceNavigation).toHaveClass(/sidebar__link--active/);
  await expect(evidenceNavigation).toHaveAttribute("aria-current", "page");
  await expect(page.locator('[data-event-id="evt_20260607_002"]')).toHaveAttribute(
    "aria-current",
    "true",
  );
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("approval detail exposes explicit control-flow evidence fields", async ({ page }) => {
  await page.goto("/approvals");

  const detail = page.locator(".approval-detail");
  await expect(detail).toContainText("关联事件");
  await expect(detail).toContainText("evt_20260607_002");
  await expect(detail).toContainText("证据链");
  await expect(detail).toContainText("trace_002");
  await expect(detail).toContainText("审批主体");
  await expect(detail).toContainText("tool_call / call_send_email_001");
  await expect(detail).toContainText("动作");
  await expect(detail).toContainText("send_email / action_send_email_001");
  await expect(detail).not.toContainText("approvalNonce");
});

test("one-time approval requires confirmation and restores trigger focus", async ({ page }) => {
  await page.goto("/approvals");

  const trigger = page.getByRole("button", { name: "仅本次放行" });
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "确认仅本次放行？" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("该动作将绕过当前 Guard 决策并继续执行一次");
  await expect(page.getByRole("button", { name: "取消" })).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("evidence detail keeps related approval and evaluation destinations", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const approvalLink = page.getByRole("link", { name: "查看关联审批" });
  const evaluationLink = page.getByRole("link", { name: "查看评测样本" });

  await expect(approvalLink).toBeVisible();
  await expect(approvalLink).toHaveAttribute("href", /\/approvals\/ask_001$/);
  await expect(evaluationLink).toBeVisible();
  await expect(evaluationLink).toHaveAttribute("href", /\/evaluation\?case_id=PI-002$/);
});

test("evidence detail surfaces the final security conclusion", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const conclusion = page.locator(".trace-conclusion");
  await expect(conclusion).toBeVisible();
  await expect(conclusion).toContainText("等待人工审批");
  await expect(conclusion).toContainText("发送目标不在当前任务允许范围内，需要人工确认");
  await expect(conclusion).toContainText("外部发送需确认");
  await expect(conclusion).toContainText("任务与行为不一致");
  await expect(conclusion).not.toContainText(/P\d{3}/);
});
