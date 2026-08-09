import { expect, test, type Locator, type Page } from "@playwright/test";

import { expectPrimaryRoutesLayout } from "./support/dashboard-layout";
import {
  expectExecutionFlowFullscreenLayout,
  expectExecutionFlowGeometry,
} from "./support/execution-flow-geometry";

async function expectProvenanceGeometry(graph: Locator): Promise<void> {
  await expect(graph).toHaveAttribute("aria-busy", "false");
  await expect(graph.locator(".vue-flow__node-provenance").first()).toBeVisible();
  await graph.getByRole("button", { name: "适配" }).click();
  const contextNode = graph.locator(".prov-node--task").first();
  if ((await contextNode.getAttribute("aria-pressed")) !== "true") {
    await contextNode.focus();
    await contextNode.press("Enter");
  }
  await expect(contextNode).toHaveAttribute("aria-pressed", "true");
  await expect(graph.locator(".vue-flow__edge-text").first()).toBeVisible();

  const geometry = await graph.evaluate((root) => {
    const boxes = (selector: string) =>
      Array.from(root.querySelectorAll<HTMLElement>(selector)).map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          bottom: rect.bottom,
          id: element.getAttribute("data-id") ?? "",
          left: rect.left,
          text: element.textContent?.trim() ?? "",
          right: rect.right,
          top: rect.top,
        };
      });
    const nodes = boxes(".vue-flow__node-provenance");
    const edgeLabels = boxes(".vue-flow__edge-text");
    const intersects = (left: (typeof nodes)[number], right: (typeof nodes)[number], padding = 0) =>
      !(
        left.right + padding <= right.left ||
        right.right + padding <= left.left ||
        left.bottom + padding <= right.top ||
        right.bottom + padding <= left.top
      );
    let nodeOverlaps = 0;
    for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
        if (intersects(nodes[leftIndex]!, nodes[rightIndex]!, 8)) nodeOverlaps += 1;
      }
    }
    return {
      edgeLabelCount: edgeLabels.length,
      edgeLabelOverlaps: edgeLabels.flatMap((label) => {
        const node = nodes.find((candidate) => intersects(label, candidate, 4));
        return node ? [{ label, node }] : [];
      }),
      nodeCount: nodes.length,
      nodeOverlaps,
      rootClientWidth: root.clientWidth,
      rootScrollWidth: root.scrollWidth,
    };
  });

  expect(geometry.nodeCount).toBeGreaterThan(4);
  expect(geometry.edgeLabelCount).toBeGreaterThan(0);
  expect(geometry.nodeOverlaps).toBe(0);
  expect(geometry.edgeLabelOverlaps).toEqual([]);
  expect(geometry.rootScrollWidth).toBeLessThanOrEqual(geometry.rootClientWidth + 1);
}

async function expectProvenanceFullscreenLayout(page: Page, graph: Locator): Promise<void> {
  await expect(graph).toHaveClass(/provenance-workbench--fullscreen/);
  const layout = await graph.evaluate((root) => {
    const toolbar = root.querySelector<HTMLElement>(".provenance-toolbar");
    const phases = root.querySelector<HTMLElement>(".provenance-phases");
    const canvas = root.querySelector<HTMLElement>(".provenance-canvas");
    if (!toolbar || !phases || !canvas) return null;
    const rootRect = root.getBoundingClientRect();
    const toolbarRect = toolbar.getBoundingClientRect();
    const phasesRect = phases.getBoundingClientRect();
    const canvasRect = canvas.getBoundingClientRect();
    return {
      canvasBottom: canvasRect.bottom,
      canvasTop: canvasRect.top,
      phasesBottom: phasesRect.bottom,
      phasesTop: phasesRect.top,
      rootBottom: rootRect.bottom,
      rootClientWidth: root.clientWidth,
      rootScrollWidth: root.scrollWidth,
      rootTop: rootRect.top,
      toolbarBottom: toolbarRect.bottom,
    };
  });

  expect(layout).not.toBeNull();
  expect(Math.abs(layout!.rootTop)).toBeLessThanOrEqual(1);
  expect(
    Math.abs(layout!.rootBottom - (await page.evaluate(() => window.innerHeight))),
  ).toBeLessThanOrEqual(1);
  expect(Math.abs(layout!.phasesTop - layout!.toolbarBottom)).toBeLessThanOrEqual(1);
  expect(Math.abs(layout!.canvasTop - layout!.phasesBottom)).toBeLessThanOrEqual(1);
  expect(Math.abs(layout!.canvasBottom - layout!.rootBottom)).toBeLessThanOrEqual(2);
  expect(layout!.rootScrollWidth).toBeLessThanOrEqual(layout!.rootClientWidth + 1);
}

test("primary routes remain usable across supported tablet workspaces", async ({ page }) => {
  await expectPrimaryRoutesLayout(page, "trace_002");
});

test("tablet navigation expands as an overlay without resizing the workspace", async ({ page }) => {
  await page.goto("/overview");
  const sidebar = page.locator(".sidebar");
  const main = page.locator("main");
  const toggle = page.getByRole("button", { name: "展开侧栏" });
  await expect(sidebar).toHaveClass(/sidebar--collapsed/);
  const collapsedMainWidth = (await main.boundingBox())?.width ?? 0;

  await toggle.click();
  await expect(sidebar).toHaveClass(/sidebar--tablet-expanded/);
  await expect(page.locator(".dashboard-shell__sidebar-backdrop")).toBeVisible();
  expect(
    Math.abs(((await main.boundingBox())?.width ?? 0) - collapsedMainWidth),
  ).toBeLessThanOrEqual(1);

  await page.keyboard.press("Escape");
  await expect(sidebar).toHaveClass(/sidebar--collapsed/);
  await expect(page.locator(".dashboard-shell__sidebar-backdrop")).toBeHidden();
  await expect(page.getByRole("button", { name: "展开侧栏" })).toBeFocused();
});

test("compact shell and approval panes switch cleanly at the 900px boundary", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "tablet-768", "边界只需在一个浏览器项目中验证");

  for (const width of [900, 901]) {
    await page.setViewportSize({ height: 900, width });
    await page.goto("/approvals");
    const queue = page.locator(".approval-queue");
    const detail = page.locator(".approval-detail-pane");
    await expect(queue).toBeVisible();
    const layout = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      topBarHeight:
        document.querySelector<HTMLElement>(".top-bar")?.getBoundingClientRect().height ?? 0,
    }));
    expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth);

    if (width === 900) {
      expect(layout.topBarHeight).toBeGreaterThan(80);
      await expect(detail).toBeHidden();
    } else {
      expect(layout.topBarHeight).toBeLessThan(80);
      await expect(detail).toBeVisible();
    }
  }
});

test("tablet filters reflow while data tables own horizontal scrolling", async ({ page }) => {
  await page.goto("/investigations");
  const tools = page.locator(".investigation-tools");
  await expect(tools).toBeVisible();
  const toolGeometry = await tools.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  expect(toolGeometry.scrollWidth).toBeLessThanOrEqual(toolGeometry.clientWidth + 1);

  const tableWrap = page.locator(".event-table-wrap");
  const tableGeometry = await tableWrap.evaluate((element) => ({
    clientWidth: element.clientWidth,
    overflowX: getComputedStyle(element).overflowX,
    scrollWidth: element.scrollWidth,
  }));
  expect(tableGeometry.overflowX).toBe("auto");
  expect(tableGeometry.scrollWidth).toBeGreaterThanOrEqual(tableGeometry.clientWidth);
});

test("tablet approval workspace uses one pane only when the compact top bar is active", async ({
  page,
}) => {
  await page.goto("/approvals");
  const compact = await page.evaluate(() => window.matchMedia("(max-width: 56.25rem)").matches);
  const queue = page.locator(".approval-queue");
  const detail = page.locator(".approval-detail-pane");
  await expect(queue).toHaveCSS("grid-auto-rows", "max-content");

  if (!compact) {
    await expect(queue).toBeVisible();
    await expect(detail).toBeVisible();
    await expect(page.getByRole("link", { name: "返回审批队列" })).toBeHidden();
    return;
  }

  await expect(queue).toBeVisible();
  await expect(detail).toBeHidden();
  await queue.getByRole("button").first().click();
  await expect(page).toHaveURL(/\/approvals\//);
  await expect(queue).toBeHidden();
  await expect(detail).toBeVisible();
  const back = page.getByRole("link", { name: "返回审批队列" });
  await expect(back).toBeFocused();
  await back.click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(queue).toBeVisible();
  await expect(detail).toBeHidden();
  await expect(queue.getByRole("button").first()).toBeFocused();
});

test("execution graph remains separated in embedded and fullscreen tablet layouts", async ({
  page,
}) => {
  await page.goto("/evidence/trace_008");
  const graph = page.locator(".execution-flow");
  await expectExecutionFlowGeometry(graph);
  await expect(page.locator(".execution-inspector")).toHaveCSS("grid-auto-rows", "max-content");
  await graph.getByRole("button", { name: "全屏" }).click();
  await expectExecutionFlowFullscreenLayout(page, graph);
  await expectExecutionFlowGeometry(graph);
  await page.keyboard.press("Escape");
  await expect(graph).not.toHaveClass(/execution-flow--fullscreen/);

  await page.goto("/evidence/trace_002");
  await expectExecutionFlowGeometry(page.locator(".execution-flow"));
});

test("provenance graph reflows from its container and fills fullscreen without collisions", async ({
  page,
}) => {
  await page.goto("/evidence/trace_002");
  await page.getByRole("tab", { name: "溯源关系" }).click();
  const graph = page.locator(".provenance-workbench");
  await expectProvenanceGeometry(graph);

  const embeddedWidth = (await graph.boundingBox())?.width ?? 0;
  if (embeddedWidth < 960) await expect(graph).toHaveClass(/provenance-workbench--compact/);
  else await expect(graph).not.toHaveClass(/provenance-workbench--compact/);

  await graph.getByRole("button", { name: "全屏" }).click();
  await expectProvenanceFullscreenLayout(page, graph);
  await expectProvenanceGeometry(graph);
  await page.keyboard.press("Escape");
  await expect(graph).not.toHaveClass(/provenance-workbench--fullscreen/);
});

test("tablet overlays stay inside the viewport and restore their triggers", async ({ page }) => {
  await page.goto("/investigations");
  const decisionSelect = page.getByRole("combobox", { name: /^决策/ });
  await decisionSelect.click();
  const listbox = page.getByRole("listbox", { name: "决策" });
  await expect(listbox).toBeVisible();
  await expect(listbox).toHaveCSS("grid-auto-rows", "max-content");
  const listboxRect = await listbox.boundingBox();
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(listboxRect).not.toBeNull();
  expect(listboxRect!.x).toBeGreaterThanOrEqual(0);
  expect(listboxRect!.x + listboxRect!.width).toBeLessThanOrEqual(viewportWidth);
  await page.keyboard.press("Escape");
  await expect(decisionSelect).toBeFocused();

  const workspace = page.locator(".investigations-page__main");
  const workspaceWidth = (await workspace.boundingBox())?.width ?? 0;
  const row = page.getByRole("row").filter({ hasText: "send_email" }).first();
  await row.focus();
  await page.keyboard.press("Enter");
  const drawer = page.locator(".detail-drawer");
  await expect(drawer).toBeVisible();
  await expect(drawer.locator(".detail-drawer__body")).toHaveCSS("grid-auto-rows", "max-content");
  const drawerRect = await drawer.boundingBox();
  expect(drawerRect).not.toBeNull();
  expect(drawerRect!.x).toBeGreaterThanOrEqual(0);
  expect(drawerRect!.x + drawerRect!.width).toBeLessThanOrEqual(viewportWidth);
  expect(
    Math.abs(((await workspace.boundingBox())?.width ?? 0) - workspaceWidth),
  ).toBeLessThanOrEqual(1);
  await page.keyboard.press("Escape");
  await expect(row).toBeFocused();

  await page.goto("/approvals");
  if (await page.evaluate(() => window.matchMedia("(max-width: 56.25rem)").matches)) {
    await page.locator(".approval-queue").getByRole("button").first().click();
  }
  const evidenceGridGeometry = await page.locator(".evidence-grid").evaluate((grid) => ({
    clientHeight: grid.clientHeight,
    scrollHeight: grid.scrollHeight,
  }));
  expect(evidenceGridGeometry.clientHeight).toBeGreaterThanOrEqual(
    evidenceGridGeometry.scrollHeight - 1,
  );
  const approvalTrigger = page.getByRole("button", { name: "仅本次放行", exact: true });
  await approvalTrigger.click();
  const dialog = page.getByRole("dialog", { name: "确认仅本次放行？" });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator(".confirm-dialog__surface")).toHaveCSS(
    "grid-auto-rows",
    "max-content",
  );
  const dialogRect = await dialog.locator(".confirm-dialog__surface").boundingBox();
  expect(dialogRect).not.toBeNull();
  expect(dialogRect!.x).toBeGreaterThanOrEqual(0);
  expect(dialogRect!.x + dialogRect!.width).toBeLessThanOrEqual(viewportWidth);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(approvalTrigger).toBeFocused();
});
