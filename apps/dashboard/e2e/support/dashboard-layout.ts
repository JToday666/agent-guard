import { expect, type Page } from "@playwright/test";

export function primaryDashboardRoutes(traceId: string): string[] {
  return [
    "/overview",
    "/investigations",
    "/evidence",
    `/evidence/${traceId}`,
    "/approvals",
    "/evaluation",
    "/system",
  ];
}

async function expectUnfilledDecisionTrend(page: Page): Promise<void> {
  const series = page.locator(".trend-chart polyline");
  await expect(series).toHaveCount(3);
  await expect
    .poll(() =>
      series.evaluateAll((elements) => elements.map((element) => getComputedStyle(element).fill)),
    )
    .toEqual(["none", "none", "none"]);

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
}

export async function expectPrimaryRoutesLayout(page: Page, traceId: string): Promise<void> {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  for (const path of primaryDashboardRoutes(traceId)) {
    await page.goto(path);
    await expect(page.locator("main")).toHaveCount(1);
    await expect(page.locator("main")).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      mainWidth: document.querySelector<HTMLElement>("main")?.getBoundingClientRect().width ?? 0,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.mainWidth).toBeGreaterThan(0);
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
    const undersizedButtons = await page.locator("main button:visible").evaluateAll((elements) =>
      elements
        .map((element) => ({
          height: element.getBoundingClientRect().height,
          text: element.textContent?.trim() ?? "",
        }))
        .filter((item) => item.height < 36),
    );
    expect(undersizedButtons).toEqual([]);
    if (path === "/overview") {
      await expectUnfilledDecisionTrend(page);
      await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#102724");
    }
  }

  expect(runtimeErrors).toEqual([]);
}
