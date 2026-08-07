import { expect, test } from "@playwright/test";

function relativeLuminance(hex: string): number {
  const channels = hex
    .replace("#", "")
    .match(/.{2}/g)!
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4));
  return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
}

function contrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  return (
    (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
    (Math.min(foregroundLuminance, backgroundLuminance) + 0.05)
  );
}

test("decision trend keeps decision words in the legend only", async ({ page }) => {
  await page.goto("/overview");

  await expect(page.locator(".trend-legend")).toContainText("允许");
  await expect(page.locator(".trend-legend")).toContainText("需审批");
  await expect(page.locator(".trend-legend")).toContainText("拒绝");

  const svgLabels = await page.locator(".trend-chart svg text").allTextContents();
  expect(svgLabels.join(" ")).not.toMatch(/允许|需审批|拒绝/);
});

test("decision trend supports one-stop keyboard inspection", async ({ page }) => {
  await page.goto("/overview");

  const chart = page.locator(".trend-chart svg");
  await chart.focus();
  await expect(page.locator(".trend-inspector")).toBeVisible();
  const latestSummary = await chart.getAttribute("aria-label");
  expect(latestSummary).toContain("使用左右方向键");

  await page.keyboard.press("ArrowLeft");
  const previousSummary = await chart.getAttribute("aria-label");
  expect(previousSummary).not.toBe(latestSummary);
  await page.keyboard.press("End");
  await expect(chart).toHaveAttribute("aria-label", latestSummary ?? "");
});

test("top page headers use primary titles without category subtitles", async ({ page }) => {
  const removedSubtitles = [
    "安全态势",
    "监控与取证",
    "证据追踪",
    "人工控制",
    "防御效果",
    "运行状态",
  ];

  for (const path of [
    "/overview",
    "/investigations",
    "/evidence",
    "/evidence/trace_002",
    "/approvals",
    "/evaluation",
    "/system",
  ]) {
    await page.goto(path);
    const header = page.locator(".page-header").first();
    await expect(header.locator("h1")).toBeVisible();
    if (path === "/evidence/trace_002") {
      await expect(header.locator("p")).toContainText("关键证据");
    } else {
      await expect(header.locator("p")).toHaveCount(0);
    }
    for (const subtitle of removedSubtitles) {
      await expect(header.getByText(subtitle, { exact: true })).toHaveCount(0);
    }
  }
});

test("skip link moves keyboard focus to the single main workspace", async ({ page }) => {
  await page.goto("/overview");

  const skipLink = page.getByRole("link", { name: "跳到主要内容" });
  await expect(page.getByRole("heading", { name: "安全总览" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(skipLink).toBeFocused();
  await skipLink.press("Enter");

  await expect(page.locator("main#main-content")).toBeFocused();
  await expect(page.locator("main#main-content")).toHaveCSS("outline-color", "rgb(201, 121, 29)");
  await expect(page.locator("main")).toHaveCount(1);
});

test("small muted and semantic text tokens keep readable contrast", async ({ page }) => {
  await page.goto("/overview");

  const tokens = await page.evaluate(() => {
    const styles = getComputedStyle(document.documentElement);
    return {
      danger: styles.getPropertyValue("--color-danger").trim(),
      dangerSoft: styles.getPropertyValue("--color-danger-soft").trim(),
      page: styles.getPropertyValue("--color-page").trim(),
      subtle: styles.getPropertyValue("--color-text-subtle").trim(),
      surfaceMuted: styles.getPropertyValue("--color-surface-muted").trim(),
      warning: styles.getPropertyValue("--color-warning").trim(),
      warningSoft: styles.getPropertyValue("--color-warning-soft").trim(),
    };
  });

  expect(contrastRatio(tokens.subtle, tokens.page)).toBeGreaterThanOrEqual(4.5);
  expect(contrastRatio(tokens.subtle, tokens.surfaceMuted)).toBeGreaterThanOrEqual(4.5);
  expect(contrastRatio(tokens.warning, tokens.warningSoft)).toBeGreaterThanOrEqual(4.5);
  expect(contrastRatio(tokens.danger, tokens.dangerSoft)).toBeGreaterThanOrEqual(4.5);
});

test("global search shortcut opens event investigation with URL state", async ({ page }) => {
  await page.goto("/overview");

  await expect(page.getByRole("heading", { name: "安全总览" })).toBeVisible();
  await page.keyboard.press("/");
  const search = page.getByRole("searchbox", {
    name: "搜索证据链、评测样本、资源或规则",
  });
  await expect(search).toBeFocused();
  await search.fill("trace_002");
  await search.press("Enter");

  await expect(page).toHaveURL(/\/investigations\?search=trace_002$/);
});

test("browser theme and primary actions match the dashboard interaction contract", async ({
  page,
}) => {
  await page.goto("/overview");

  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#102724");
  const actionHeights = await page
    .locator(".chart-link, .page-action")
    .evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().height));
  expect(actionHeights.length).toBeGreaterThan(0);
  expect(actionHeights.every((height) => height >= 36)).toBe(true);

  const approvalMetric = page.locator(".metric-strip__item").filter({ hasText: "需审批" });
  const box = await approvalMetric.boundingBox();
  if (!box) throw new Error("需审批指标卡不可见");
  await page.mouse.click(box.x + 12, box.y + 12);
  await expect(page).toHaveURL(/\/investigations\?decision=ask$/);
});

test("overview uses user-facing copy and semantic decision colors", async ({ page }) => {
  await page.goto("/overview");

  const body = page.locator("body");
  for (const removedCopy of [
    "Guard 决策随当前审计窗口变化",
    "优先处理待审批与高风险事件",
    "识别当前窗口中的主要攻击面",
    "当前窗口中的逻辑唯一策略评估",
  ]) {
    await expect(body).not.toContainText(removedCopy);
  }
  await expect(body).toContainText("查看近期允许、需审批与拒绝的变化");
  await expect(body).toContainText("查看近期风险主要来自哪些攻击类型");

  const colors = await page.evaluate(() => {
    const probe = document.createElement("span");
    document.body.append(probe);
    const resolveColor = (token: string) => {
      probe.style.color = `var(${token})`;
      return getComputedStyle(probe).color;
    };
    const result = {
      allow: getComputedStyle(document.querySelector(".trend-chart .series-allow")!).stroke,
      ask: getComputedStyle(document.querySelector(".trend-chart .series-ask")!).stroke,
      danger: resolveColor("--color-danger"),
      deny: getComputedStyle(document.querySelector(".trend-chart .series-deny")!).stroke,
      success: resolveColor("--color-success"),
      warning: resolveColor("--color-chart-warning"),
    };
    probe.remove();
    return result;
  });
  expect(colors.allow).toBe(colors.success);
  expect(colors.ask).toBe(colors.warning);
  expect(colors.deny).toBe(colors.danger);
});
