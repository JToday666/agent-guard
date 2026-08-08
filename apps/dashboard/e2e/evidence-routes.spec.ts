import { expect, test } from "@playwright/test";

test("approval exposes separate trace and event evidence destinations", async ({ page }) => {
  await page.goto("/approvals");

  const fullTraceLink = page.getByRole("link", { name: "查看完整证据链" });
  await expect(fullTraceLink).toBeVisible();
  await expect(fullTraceLink).toHaveAttribute("href", "/evidence/trace_005");
  await fullTraceLink.click();

  await expect(page).toHaveURL(/\/evidence\/trace_005$/);
  const evidenceNavigation = page.locator('.sidebar__link[href="/evidence"]');
  await expect(evidenceNavigation).toHaveClass(/sidebar__link--active/);
  await expect(evidenceNavigation).toHaveAttribute("aria-current", "page");
  await page.getByRole("tab", { name: "审计记录" }).click();
  const evidenceButton = page
    .locator('[data-event-id="evt_20260607_005"]')
    .getByRole("button", { name: "定位证据" });
  await expect(evidenceButton).toBeVisible();
  await evidenceButton.click();
  await expect(page.getByRole("dialog")).toContainText("风险分数");

  await page.goto("/approvals");

  const locateEventLink = page.getByRole("link", { name: "定位关联事件" });
  await expect(locateEventLink).toBeVisible();
  await locateEventLink.click();

  await expect(page).toHaveURL(/\/evidence\/trace_005\?event_id=evt_20260607_005$/);
  await expect(evidenceNavigation).toHaveClass(/sidebar__link--active/);
  await expect(evidenceNavigation).toHaveAttribute("aria-current", "page");
  await expect(page.locator('[data-event-id="evt_20260607_005"]')).toHaveAttribute(
    "aria-current",
    "true",
  );
  await expect(page.getByRole("dialog")).toContainText("风险分数");
});

test("approval detail exposes explicit control-flow evidence fields", async ({ page }) => {
  await page.goto("/approvals");

  const detail = page.locator(".approval-detail");
  await expect(detail).toContainText("关联事件");
  await expect(detail).toContainText("evt_20260607_005");
  await expect(detail).toContainText("证据链");
  await expect(detail).toContainText("trace_005");
  await expect(detail).toContainText("审批主体");
  await expect(detail).toContainText("tool_call / action_trace_005");
  await expect(detail).toContainText("动作");
  await expect(detail).toContainText("code_exec / action_trace_005");
  await expect(detail.locator(".approval-rule-list")).toContainText("危险代码执行");
  await expect(detail).not.toContainText(/P\d{3}/);
  await expect(detail).not.toContainText("approvalNonce");

  const content = await detail.textContent();
  expect(content?.indexOf("用户任务")).toBeLessThan(content?.indexOf("智能体请求执行的动作") ?? -1);
  expect(content?.indexOf("智能体请求执行的动作")).toBeLessThan(content?.indexOf("命中规则") ?? -1);
  expect(content?.indexOf("命中规则")).toBeLessThan(content?.indexOf("判定原因") ?? -1);
  expect(content?.indexOf("判定原因")).toBeLessThan(content?.indexOf("放行影响") ?? -1);
});

test("one-time approval requires confirmation and restores trigger focus", async ({ page }) => {
  await page.goto("/approvals");

  const trigger = page.getByRole("button", { name: "仅本次放行" });
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "确认仅本次放行？" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("该动作将绕过当前安全判断并继续执行一次");
  await expect(page.getByRole("button", { name: "取消" })).toBeFocused();
  await expect(dialog.locator(".confirm-dialog__signal")).toHaveClass(
    /confirm-dialog__signal--warning/,
  );

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("deny approval uses a danger confirmation and restores trigger focus", async ({ page }) => {
  await page.goto("/approvals");

  const trigger = page.getByRole("button", { name: "拒绝授权" });
  await expect(trigger).toHaveCSS("min-height", "44px");
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "确认拒绝本次授权？" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("本次授权将被拒绝");
  await expect(dialog.locator(".confirm-dialog__signal")).toHaveClass(
    /confirm-dialog__signal--danger/,
  );
  await expect(page.getByRole("button", { name: "确认拒绝授权" })).toHaveCSS("min-height", "44px");

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

  const conclusion = page.locator(".evidence-hero");
  await expect(conclusion).toBeVisible();
  await expect(conclusion).toContainText("审批后放行");
  await expect(conclusion).toContainText("发送目标不在当前任务允许范围内，需要人工确认");
  await expect(conclusion).toContainText("外部发送");
  await expect(conclusion).toContainText("任务目标偏离");
  await expect(conclusion).toContainText("审批释放后：已执行");
  await expect(conclusion).not.toContainText(/P\d{3}/);
  await expect(page.getByRole("heading", { name: "证据链详情" })).toBeVisible();
  await expect(page.getByText("旧版阻断标记", { exact: true })).toHaveCount(0);
});

test("execution trace keeps decision, approval and runtime facts distinct", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const executionTab = page.getByRole("tab", { name: "执行轨迹" });
  await expect(executionTab).toHaveAttribute("aria-selected", "true");
  const action = page.locator(".execution-action").filter({ hasText: "发送邮件" });
  await expect(action).toBeVisible();
  await expect(action).toHaveClass(/execution-action--ask/);
  await expect(action).toContainText("需审批");
  await expect(action).toContainText("单次放行");
  await expect(action).toContainText("已执行");
  await expect(action).not.toContainText("当前");

  await action.locator(".execution-action__summary").click();
  await action.getByRole("button", { name: "查看安全依据" }).click();
  await expect(page).toHaveURL(/view=provenance/);
  await expect(page).toHaveURL(/action_id=action_trace_002/);
  await expect(page).toHaveURL(/node_id=/);
  await expect(page.getByRole("tab", { name: "溯源关系" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.locator(".prov-node--selected")).toContainText("send_email");

  const auditTab = page.getByRole("tab", { name: "审计记录" });
  await auditTab.focus();
  await page.keyboard.press("ArrowLeft");
  await expect(page.getByRole("tab", { name: "溯源关系" })).toBeFocused();

  await page.goto("/evidence/trace_002?event_id=evt_20260607_002");
  await page.getByRole("button", { name: "查看溯源位置" }).click();
  await expect(page).toHaveURL(/action_id=action_trace_002/);
  await expect(page).toHaveURL(/node_id=/);
  await expect(page.locator(".prov-node--selected")).toContainText("send_email");
});

test("evidence detail keeps five intervention outcomes distinct", async ({ page }) => {
  const scenarios = [
    {
      execution: "未调用",
      title: "执行前拒绝已确认",
      traceId: "trace_001",
    },
    {
      execution: "已执行",
      title: "审批后放行",
      traceId: "trace_002",
    },
    {
      execution: "已执行",
      title: "仅审计观察",
      traceId: "trace_003",
    },
    {
      execution: "已执行",
      title: "工具结果隔离",
      traceId: "trace_004",
    },
    {
      execution: "暂无执行回执",
      title: "模型输出修订",
      traceId: "trace_008",
    },
  ];

  for (const scenario of scenarios) {
    await page.goto(`/evidence/${scenario.traceId}`);
    await expect(page.locator(".evidence-hero")).toContainText(scenario.title);
    await expect(
      page.locator(".evidence-facts__item").filter({ hasText: "实际执行" }),
    ).toContainText(scenario.execution);
    await expect(page.locator("body")).not.toContainText(/Mock 数据|API 数据/);
  }

  await page.goto("/evidence/trace_004");
  await expect(page.locator(".evidence-hero")).toContainText("不代表撤销");
  await expect(
    page.locator(".evidence-facts__item").filter({ hasText: /^\s*副作用/ }),
  ).toContainText("未测量");

  const visibleSummaryHeights = await page.evaluate(() => ({
    facts: document.querySelector(".evidence-facts")?.getBoundingClientRect().height ?? 0,
    hero: document.querySelector(".evidence-hero")?.getBoundingClientRect().height ?? 0,
  }));
  expect(visibleSummaryHeights.hero).toBeGreaterThan(120);
  expect(visibleSummaryHeights.facts).toBeGreaterThan(120);
});

test("evidence list keeps search and final status in the URL", async ({ page }) => {
  await page.goto("/evidence");

  await page.getByRole("searchbox", { name: "搜索证据链", exact: true }).fill("PI-004");
  await expect(page).toHaveURL(/search=PI-004/);
  await expect(page.locator(".trace-table tbody tr")).toHaveCount(1);

  const statusSelect = page.getByRole("combobox", { name: /^最终状态/ });
  await statusSelect.click();
  await page.getByRole("option", { name: "需审批" }).click();
  await expect(page).toHaveURL(/status=paused/);
  await expect(page.locator(".trace-table tbody tr")).toHaveCount(1);

  await page.getByRole("button", { name: "清除筛选" }).click();
  await expect(page).toHaveURL(/\/evidence$/);
  await expect(page.locator(".trace-table tbody tr")).toHaveCount(8);
});
