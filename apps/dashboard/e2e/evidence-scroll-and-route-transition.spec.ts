import { expect, test } from "@playwright/test";

async function openResponsiveNavigationIfNeeded(page: import("@playwright/test").Page) {
  const menuButton = page.getByRole("button", { name: "菜单" });
  if (await menuButton.isVisible()) await menuButton.click();
}

test("evidence context does not trap desktop wheel scrolling", async ({ page }) => {
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

  await expect.poll(() => main.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
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
          return String(rule.selectorText).includes("dashboard-route-enter-active");
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

test("provenance graph keeps node text readable without label overlap", async ({ page }) => {
  await page.goto("/evidence/trace_002");

  const graph = page.locator(".provenance-wrap");
  await expect(graph).toBeVisible();
  await expect(graph.locator(".prov-node").first()).toBeVisible();

  const layout = await graph.evaluate((root) => {
    const boxes = (selector: string) =>
      Array.from(root.querySelectorAll(selector)).map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          text: element.textContent ?? "",
        };
      });

    const nodes = boxes(".vue-flow__node");
    const edgeLabels = boxes(".vue-flow__edge-text");
    const overflowingText = Array.from(
      root.querySelectorAll(".prov-node__label, .prov-node__summary"),
    ).filter((element) => {
      const html = element as HTMLElement;
      return html.scrollWidth > html.clientWidth + 1;
    }).length;

    function intersects(
      left: { x: number; y: number; width: number; height: number },
      right: { x: number; y: number; width: number; height: number },
      padding = 0,
    ) {
      return !(
        left.x + left.width + padding <= right.x ||
        right.x + right.width + padding <= left.x ||
        left.y + left.height + padding <= right.y ||
        right.y + right.height + padding <= left.y
      );
    }

    let nodeOverlaps = 0;
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        if (intersects(nodes[i]!, nodes[j]!, 8)) nodeOverlaps += 1;
      }
    }

    let edgeLabelOverlaps = 0;
    for (const label of edgeLabels) {
      if (nodes.some((node) => intersects(label, node, 4))) {
        edgeLabelOverlaps += 1;
      }
    }

    return {
      edgeLabelCount: edgeLabels.length,
      nodeCount: nodes.length,
      edgeLabelOverlaps,
      nodeOverlaps,
      overflowingText,
    };
  });

  expect(layout.nodeCount).toBeGreaterThan(4);
  expect(layout.edgeLabelCount).toBeGreaterThan(0);
  expect(layout.nodeOverlaps).toBe(0);
  expect(layout.edgeLabelOverlaps).toBe(0);
  expect(layout.overflowingText).toBe(0);
});
