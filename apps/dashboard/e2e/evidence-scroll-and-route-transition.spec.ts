import { expect, test } from "@playwright/test";

test("evidence detail uses document scrolling and the dossier does not trap the wheel", async ({
  page,
}) => {
  await page.goto("/evidence/trace_007?event_id=evt_20260607_007");

  const workspace = page.locator(".dashboard-shell__workspace");
  const main = page.locator(".evidence-detail__main");
  const context = page.locator(".trace-dossier");
  const drawerBody = page.locator(".detail-drawer__body");

  await expect(context).toBeVisible();
  await expect(drawerBody).toHaveCSS("overscroll-behavior-y", "contain");
  await expect(context).toHaveCSS("overscroll-behavior-y", "auto");
  await page.getByRole("button", { name: "关闭详情" }).click();
  await expect(page.locator(".detail-drawer")).toBeHidden();

  await expect(workspace).toHaveCSS("overflow-y", "visible");
  await expect(main).toHaveCSS("overflow-y", "visible");
  await page.evaluate(() => window.scrollTo(0, 0));
  await context.hover();
  await page.mouse.wheel(0, 700);

  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
});

test("embedded execution graph scrolls the page and fullscreen graph owns the wheel", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/evidence/trace_002");

  const graph = page.locator(".execution-flow");
  const canvas = graph.locator(".execution-flow__canvas");
  const viewport = graph.locator(".vue-flow__transformationpane");
  await expect(graph).toBeVisible();
  await expect(graph.locator(".execution-node")).toBeVisible();
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  });
  await page.evaluate(() => {
    const graphElement = document.querySelector<HTMLElement>(".execution-flow");
    const graphTop = graphElement ? graphElement.getBoundingClientRect().top + window.scrollY : 0;
    window.scrollTo(0, Math.max(0, graphTop - 180));
  });
  const embeddedScrollY = await page.evaluate(() => window.scrollY);
  await canvas.hover();
  const embeddedTransform = await viewport.getAttribute("style");
  await page.mouse.wheel(0, 320);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(embeddedScrollY);
  await expect(viewport).toHaveAttribute("style", embeddedTransform ?? "");

  const topBarHeight = (await page.locator(".top-bar").boundingBox())?.height ?? 0;
  const viewHeaderY = (await page.locator(".trace-workspace__header").boundingBox())?.y ?? -1;
  expect(Math.abs(viewHeaderY - topBarHeight)).toBeLessThanOrEqual(1);

  await graph.getByRole("button", { name: "全屏" }).click();
  await expect(graph).toHaveClass(/execution-flow--fullscreen/);
  await canvas.hover();
  const fullscreenScrollY = await page.evaluate(() => window.scrollY);
  const fullscreenTransform = await viewport.getAttribute("style");
  await page.mouse.wheel(0, -260);
  await expect.poll(() => viewport.getAttribute("style")).not.toBe(fullscreenTransform);
  expect(await page.evaluate(() => window.scrollY)).toBe(fullscreenScrollY);

  await page.keyboard.press("Escape");
  await expect(graph).not.toHaveClass(/execution-flow--fullscreen/);
});

test("dashboard routes use the shell transition layer", async ({ page }) => {
  await page.goto("/overview");

  const routeStage = page.locator(".dashboard-route-stage");
  const routeView = page.locator(".dashboard-route-view");

  await expect(routeStage).toBeVisible();
  await expect(routeStage).toHaveCSS("position", "relative");
  await expect(routeView).toBeVisible();
  await expect(routeView).toHaveCSS("animation-name", "none");

  const routeTransitionRule = await page.evaluate(() => {
    const visitRules = (rules: CSSRuleList): string => {
      for (const rule of rules) {
        if (
          rule instanceof CSSStyleRule &&
          rule.selectorText.includes("dashboard-route-enter-active")
        ) {
          return rule.cssText;
        }
        const nestedRules = (rule as CSSRule & { cssRules?: CSSRuleList }).cssRules;
        if (nestedRules) {
          const match = visitRules(nestedRules);
          if (match) return match;
        }
      }
      return "";
    };
    for (const sheet of document.styleSheets) {
      try {
        const match = visitRules(sheet.cssRules);
        if (match) return match;
      } catch {
        continue;
      }
    }
    return "";
  });
  expect(routeTransitionRule).toContain("opacity");
  expect(routeTransitionRule).not.toContain("transform");
  const routeDuration = await page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue("--transition-route").trim(),
  );
  expect(routeDuration).toMatch(/^1[2345]0ms /);

  await page.getByRole("link", { name: /^事件调查/ }).click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(page.getByRole("heading", { name: "事件调查" })).toBeVisible();
  await expect(page.locator(".dashboard-route-view")).toHaveCount(1);
  await expect(page.locator(".dashboard-route-view").first()).toBeVisible();

  await page.getByRole("link", { name: "系统状态" }).click();
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect(page.locator(".system-page .is-spinning")).toHaveCount(0);
});

test("detail drawer overlays the workspace without changing table width", async ({ page }) => {
  await page.goto("/investigations");

  const main = page.locator(".investigations-page__main");
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();
  const beforeWidth = (await main.boundingBox())?.width ?? 0;
  await row.focus();
  await page.keyboard.press("Enter");

  const drawer = page.locator(".detail-drawer");
  await expect(drawer).toBeVisible();
  await expect(drawer).toHaveCSS("position", "fixed");
  const drawerTransitionRule = await page.evaluate(() => {
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules) {
          if (
            rule instanceof CSSStyleRule &&
            rule.selectorText.includes("detail-drawer-enter-active")
          ) {
            return rule.cssText;
          }
        }
      } catch {
        continue;
      }
    }
    return "";
  });
  expect(drawerTransitionRule).toContain("opacity");
  expect(drawerTransitionRule).toContain("transform");

  const afterWidth = (await main.boundingBox())?.width ?? 0;
  expect(Math.abs(afterWidth - beforeWidth)).toBeLessThanOrEqual(1);

  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(row).toBeFocused();
});

test("reduced motion removes panel and dialog animations", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/investigations");

  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();
  await row.focus();
  await page.keyboard.press("Enter");
  const drawer = page.locator(".detail-drawer");
  await expect(drawer).toBeVisible();
  const reducedDuration = await drawer.evaluate((element) =>
    Number.parseFloat(getComputedStyle(element).transitionDuration),
  );
  expect(reducedDuration).toBeLessThanOrEqual(0.00001);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await page.goto("/evidence/trace_002");
  const actionNode = page.locator(".execution-node").filter({ hasText: "发送邮件" });
  await actionNode.focus();
  await page.keyboard.press("Space");
  await expect(actionNode).toHaveAttribute("aria-pressed", "true");
  await expect(actionNode).toHaveCSS("animation-name", "none");
  const nodeTransitionDuration = await actionNode.evaluate((element) =>
    Number.parseFloat(getComputedStyle(element).transitionDuration),
  );
  expect(nodeTransitionDuration).toBeLessThanOrEqual(0.00001);
});

test("provenance graph keeps node text readable without label overlap", async ({ page }) => {
  await page.goto("/evidence/trace_002");
  await page.getByRole("tab", { name: "溯源关系" }).click();

  const graph = page.locator(".provenance-workbench");
  await expect(graph).toBeVisible();
  await expect(graph.locator(".prov-node").first()).toBeVisible();
  await graph.getByRole("button", { name: "适配" }).click();
  const contextNode = graph.locator(".prov-node--task").first();
  await contextNode.focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/node_id=/);
  await expect(graph.locator(".vue-flow__edge-text").first()).toBeVisible();

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
    const unclippedText = Array.from(
      root.querySelectorAll(".prov-node__label, .prov-node__summary"),
    ).filter((element) => {
      const style = getComputedStyle(element);
      return style.overflow !== "hidden" || style.overflowWrap !== "anywhere";
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
      unclippedText,
    };
  });

  expect(layout.nodeCount).toBeGreaterThan(4);
  expect(layout.edgeLabelCount).toBeGreaterThan(0);
  expect(layout.nodeOverlaps).toBe(0);
  expect(layout.edgeLabelOverlaps).toBe(0);
  expect(layout.unclippedText).toBe(0);

  await expect(page).toHaveURL(/node_id=/);
  await expect(contextNode).toHaveAttribute("aria-pressed", "true");
  await expect(graph.locator(".prov-flow-node--dimmed").first()).toBeVisible();
});
