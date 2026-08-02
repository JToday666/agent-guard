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

  await expect(page.locator(".trend-legend")).toContainText("已放行");
  await expect(page.locator(".trend-legend")).toContainText("待审批");
  await expect(page.locator(".trend-legend")).toContainText("已阻断");

  const svgLabels = await page.locator(".trend-chart svg text").allTextContents();
  expect(svgLabels.join(" ")).not.toMatch(/已放行|待审批|已阻断/);
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
    await expect(header.locator("p")).toHaveCount(0);
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
    name: "搜索证据链、Case、资源或规则",
  });
  await expect(search).toBeFocused();
  await search.fill("trace_002");
  await search.press("Enter");

  await expect(page).toHaveURL(/\/investigations\?search=trace_002$/);
});
