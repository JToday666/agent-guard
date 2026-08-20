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
  await expect(detail).toContainText("guard_event_trace_005");
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

test("mock preview approval is read only and never sends a resolution request", async ({
  page,
}) => {
  const resolutionRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/approvals/") && request.url().endsWith("/resolve")) {
      resolutionRequests.push(request.url());
    }
  });
  await page.goto("/approvals?readonly=1");

  await expect(page.getByText("只读审批视图")).toBeVisible();
  await expect(page.getByText(/Mock Preview 使用固定合成样例/)).toBeVisible();
  await expect(page.getByRole("button", { name: "仅本次放行" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "拒绝授权" })).toBeDisabled();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(resolutionRequests).toEqual([]);
});

test("evidence detail keeps related approval and evaluation destinations", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const approvalLink = page.getByRole("link", { name: "查看关联审批" });
  const evaluationLink = page.getByRole("link", { name: "查看评测样本" });

  await expect(approvalLink).toBeVisible();
  await expect(approvalLink).toHaveAttribute("href", /\/approvals\/ask_001\?readonly=1$/);
  await expect(evaluationLink).toBeVisible();
  await expect(evaluationLink).toHaveAttribute("href", /\/evaluation\?case_id=PI-002$/);

  await approvalLink.click();
  await expect(page).toHaveURL(/\/approvals(?:\/[^?]+)?\?readonly=1$/);
  await expect(page.getByRole("heading", { name: "人工审批" })).toBeVisible();
  await expect(page.getByText("页面渲染异常")).toHaveCount(0);
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
  const action = page.locator(".execution-node").filter({ hasText: "发送邮件" });
  await expect(action).toBeVisible();
  await expect(action).toHaveClass(/execution-node--ask/);
  await expect(action.locator('[data-supervision-layer="decision"]')).toContainText("需审批");
  await expect(action.locator('[data-supervision-layer="approval"]')).toContainText("单次放行");
  // Enforcement 层因 RTE-05 资格链未就绪而隐藏（SHOW_ENFORCEMENT_PANEL=false）
  await expect(action.locator('[data-supervision-layer="enforcement"]')).toHaveCount(0);
  await expect(action.locator('[data-supervision-layer="execution"]')).toContainText("已执行");
  await expect(action).not.toContainText("当前");

  await action.click();
  const inspector = page.locator(".execution-inspector");
  await expect(inspector).toContainText("单次放行");
  await expect(inspector).toContainText("正式决策 / V2 Shadow");
  await expect(inspector).not.toContainText("强绑定门控证据尚未随 Trace 返回");
  await expect(inspector.getByRole("link", { name: "查看审批依据（只读）" })).toHaveAttribute(
    "href",
    /readonly=1/,
  );
  await inspector.getByRole("button", { name: "查看溯源关系" }).click();
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

test("graph and list reuse the same supervision presentation", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const graphAction = page.locator(".execution-node").filter({ hasText: "发送邮件" });
  await expect(graphAction).toBeVisible();
  const graphValues = await graphAction
    .locator("[data-supervision-layer]")
    .evaluateAll((nodes) => nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim()));

  await page.getByRole("button", { name: "列表", exact: true }).click();
  const listAction = page.locator(".execution-list__item").filter({ hasText: "发送邮件" });
  await expect(listAction).toBeVisible();
  const listValues = await listAction
    .locator("[data-supervision-layer]")
    .evaluateAll((nodes) => nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim()));

  expect(listValues).toEqual(graphValues);
  // Enforcement 层隐藏后仅展示 decision/approval/execution 三层
  expect(graphValues).toHaveLength(3);
});

test("multi-step preview shows ordered checkpoints and exact action outcomes", async ({ page }) => {
  await page.goto("/evidence/trace_009");

  const summary = page.locator(".execution-trace__summary");
  await expect(page.getByRole("heading", { name: "运行已结束" })).toBeVisible();
  await expect(summary).toContainText(/运行步骤\s*5/);
  await expect(summary).toContainText(/受控动作\s*2/);
  await expect(summary).toContainText(/等待审批\s*0/);
  await expect(summary).toContainText(/风险步骤\s*1/);

  const graphNodes = page.locator(".execution-node");
  await expect(graphNodes).toHaveCount(5);
  await expect(page.locator(".execution-node--checkpoint")).toHaveCount(3);
  await expect(graphNodes.nth(0)).toContainText("获取网页内容");
  await expect(graphNodes.nth(1)).toContainText("检查网页内容");
  await expect(graphNodes.nth(2)).toContainText("检查输入上下文");
  await expect(graphNodes.nth(3)).toContainText("检查模型输入");
  await expect(graphNodes.nth(4)).toContainText("执行代码");
  await expect(page.locator(".execution-flow__vue-flow .vue-flow__edge")).toHaveCount(4);

  const fetch = graphNodes.filter({ hasText: "获取网页内容" });
  await expect(fetch.locator('[data-supervision-layer="decision"]')).toContainText("允许");
  await expect(fetch.locator('[data-supervision-layer="approval"]')).toContainText("无需审批");
  await expect(fetch.locator('[data-supervision-layer="enforcement"]')).toHaveCount(0);
  await expect(fetch.locator('[data-supervision-layer="execution"]')).toContainText("已执行");

  const exec = graphNodes.filter({ hasText: "执行代码" });
  await expect(exec.locator('[data-supervision-layer="decision"]')).toContainText("拒绝");
  await expect(exec.locator('[data-supervision-layer="approval"]')).toContainText("无需审批");
  await expect(exec.locator('[data-supervision-layer="enforcement"]')).toHaveCount(0);
  await expect(exec.locator('[data-supervision-layer="execution"]')).toContainText("未调用");
  await exec.click();
  await expect(page.locator(".execution-inspector")).toContainText("运行时收据");
  await expect(page.locator(".execution-inspector")).toContainText("已唯一关联");

  const graphActionValues = await exec
    .locator("[data-supervision-layer]")
    .evaluateAll((nodes) => nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim()));
  await page.getByRole("button", { name: "列表", exact: true }).click();
  const listItems = page.locator(".execution-list__item");
  await expect(listItems).toHaveCount(5);
  const listExec = listItems.filter({ hasText: "执行代码" });
  const listActionValues = await listExec
    .locator("[data-supervision-layer]")
    .evaluateAll((nodes) => nodes.map((node) => node.textContent?.replace(/\s+/g, " ").trim()));
  expect(listActionValues).toEqual(graphActionValues);
});

test("mock provenance shows Web content assembled into context without changing execution edges", async ({
  page,
}) => {
  await page.goto("/evidence/trace_005");
  await page.getByRole("tab", { name: "溯源关系" }).click();

  const mockNodes = page.locator('.prov-node[data-source-mode="mock"]');
  await expect(mockNodes).toHaveCount(4);
  await expect(mockNodes).toContainText([/Web 内容来源/, /上下文拼接/, /模型输入/, /高影响动作/]);

  const sourceNode = mockNodes.filter({ hasText: "Web 内容来源" });
  await sourceNode.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".provenance-inspector")).toContainText(
    "MOCK PREVIEW · 固定合成内容入口，不是真实运行结果",
  );
  await expect(
    page.locator(".vue-flow__edge-text").filter({ hasText: "汇入上下文" }),
  ).toBeVisible();

  const unknownLegacyEdge = page.locator(
    '.prov-edge--certainty-unknown[data-id="mock_edge_model_input_to_action_001"]',
  );
  await expect(unknownLegacyEdge).toHaveCount(1);
  const unknownEdgeDash = await unknownLegacyEdge
    .locator(".vue-flow__edge-path")
    .evaluate((path) => getComputedStyle(path).strokeDasharray);
  expect(unknownEdgeDash).not.toBe("none");
  const modelInputNode = mockNodes.filter({ hasText: "模型输入" });
  await modelInputNode.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".prov-edge--certainty-possible")).toHaveCount(0);

  await page.getByRole("tab", { name: "执行轨迹" }).click();
  await expect(page.locator('.execution-flow [data-source-mode="mock"]')).toHaveCount(0);
});

test("execution trace defaults to graph and keeps the list layout in the URL", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  await expect(page.locator(".execution-flow")).toBeVisible();
  await expect(page.getByRole("button", { name: "图形", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await page.getByRole("button", { name: "列表", exact: true }).click();
  await expect(page).toHaveURL(/execution_layout=list/);
  await expect(page.locator(".execution-list")).toBeVisible();

  await page.reload();
  await expect(page.locator(".execution-list")).toBeVisible();
  await expect(page.getByRole("button", { name: "列表", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );

  await page.getByRole("button", { name: "图形", exact: true }).click();
  await expect(page).not.toHaveURL(/execution_layout=/);
  await expect(page.locator(".execution-flow")).toBeVisible();
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
    await page.locator(".evidence-context > summary").click();
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
  await expect(page.locator(".trace-table tbody tr")).toHaveCount(9);
});
