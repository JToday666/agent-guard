import { expect, test } from "@playwright/test";

async function openResponsiveNavigationIfNeeded(
  page: import("@playwright/test").Page,
) {
  const menuButton = page.getByRole("button", { name: "菜单" });
  if (await menuButton.isVisible()) await menuButton.click();
}

test("evidence context does not trap desktop wheel scrolling", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop");

  await page.goto("/evidence/trace_007?event_id=evt_20260607_007");

  const main = page.locator(".evidence-detail__main");
  const context = page.locator(".trace-context");
  const drawerBody = page.locator(".detail-drawer__body");

  await expect(context).toBeVisible();
  await expect(drawerBody).toHaveCSS("overscroll-behavior-y", "contain");
  await expect(context).toHaveCSS("overscroll-behavior-y", "auto");

  await main.evaluate((element) => {
    element.scrollTop = 0;
  });
  await context.hover();
  await page.mouse.wheel(0, 700);

  await expect
    .poll(() => main.evaluate((element) => element.scrollTop))
    .toBeGreaterThan(0);
});

test("dashboard routes use the shell transition layer", async ({ page }) => {
  await page.goto("/overview");

  const routeStage = page.locator(".dashboard-route-stage");
  const routeView = page.locator(".dashboard-route-view");

  await expect(routeStage).toBeVisible();
  await expect(routeStage).toHaveCSS("position", "relative");
  await expect(routeView).toBeVisible();
  await expect(routeView).toHaveCSS("animation-name", "none");

  const hasRouteTransitionRules = await page.evaluate(() =>
    [...document.styleSheets].some((sheet) => {
      try {
        return [...sheet.cssRules].some((rule) => {
          if (!("selectorText" in rule)) return false;
          return String(rule.selectorText).includes(
            "dashboard-route-enter-active",
          );
        });
      } catch {
        return false;
      }
    }),
  );
  expect(hasRouteTransitionRules).toBe(true);

  await openResponsiveNavigationIfNeeded(page);
  await page.getByRole("link", { name: /^事件调查/ }).click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(page.locator(".dashboard-route-view")).toHaveCount(1);
  await expect(page.locator(".dashboard-route-view").first()).toBeVisible();
});
