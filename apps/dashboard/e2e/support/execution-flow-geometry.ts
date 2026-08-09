import { expect, type Locator, type Page } from "@playwright/test";

export async function expectExecutionFlowGeometry(graph: Locator): Promise<void> {
  await expect(graph.locator(".execution-lane__header").first()).toBeVisible();
  await expect(graph.locator(".execution-node").first()).toBeVisible();

  const geometry = await graph.evaluate((root) => {
    const boxes = (selector: string) =>
      Array.from(root.querySelectorAll<HTMLElement>(selector)).map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          bottom: rect.bottom,
          height: rect.height,
          left: rect.left,
          right: rect.right,
          top: rect.top,
          width: rect.width,
        };
      });
    const lanes = boxes(".vue-flow__node-execution-lane");
    const headers = boxes(".execution-lane__header");
    const nodes = boxes(".vue-flow__node-execution-step");
    const edgeLabels = boxes(".vue-flow__edge-text");
    const intersects = (left: (typeof nodes)[number], right: (typeof nodes)[number], padding = 0) =>
      !(
        left.right + padding <= right.left ||
        right.right + padding <= left.left ||
        left.bottom + padding <= right.top ||
        right.bottom + padding <= left.top
      );
    const contains = (outer: (typeof lanes)[number], inner: (typeof nodes)[number]) =>
      inner.left >= outer.left - 1 &&
      inner.right <= outer.right + 1 &&
      inner.top >= outer.top - 1 &&
      inner.bottom <= outer.bottom + 1;

    let nodeOverlaps = 0;
    for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
        if (intersects(nodes[leftIndex]!, nodes[rightIndex]!, 4)) nodeOverlaps += 1;
      }
    }

    return {
      edgeLabelCount: edgeLabels.length,
      edgeLabelOverlaps: edgeLabels.filter((label) =>
        nodes.some((node) => intersects(label, node, 3)),
      ).length,
      headerCount: headers.length,
      headerNodeOverlaps: headers.filter((header) => nodes.some((node) => intersects(header, node)))
        .length,
      laneCount: lanes.length,
      nodeCount: nodes.length,
      nodeOverlaps,
      nodesOutsideLane: nodes.filter(
        (node) => lanes.filter((lane) => contains(lane, node)).length !== 1,
      ).length,
    };
  });

  expect(geometry.laneCount).toBeGreaterThan(0);
  expect(geometry.headerCount).toBe(geometry.laneCount);
  expect(geometry.nodeCount).toBeGreaterThan(0);
  if (geometry.nodeCount > 1) expect(geometry.edgeLabelCount).toBeGreaterThan(0);
  expect(geometry.headerNodeOverlaps).toBe(0);
  expect(geometry.nodesOutsideLane).toBe(0);
  expect(geometry.nodeOverlaps).toBe(0);
  expect(geometry.edgeLabelOverlaps).toBe(0);
}

export async function expectExecutionFlowFullscreenLayout(
  page: Page,
  graph: Locator,
): Promise<void> {
  await expect(graph).toHaveClass(/execution-flow--fullscreen/);
  const layout = await graph.evaluate((root) => {
    const toolbar = root.querySelector<HTMLElement>(".execution-flow__toolbar");
    const canvas = root.querySelector<HTMLElement>(".execution-flow__canvas");
    if (!toolbar || !canvas) return null;
    const rootRect = root.getBoundingClientRect();
    const toolbarRect = toolbar.getBoundingClientRect();
    const canvasRect = canvas.getBoundingClientRect();
    const toolbarStyle = getComputedStyle(toolbar);
    const children = Array.from(toolbar.children).map((child) => child.getBoundingClientRect());
    const naturalToolbarHeight =
      Math.max(...children.map((child) => child.height), 0) +
      Number.parseFloat(toolbarStyle.paddingTop) +
      Number.parseFloat(toolbarStyle.paddingBottom) +
      Number.parseFloat(toolbarStyle.borderTopWidth) +
      Number.parseFloat(toolbarStyle.borderBottomWidth);
    return {
      canvasBottom: canvasRect.bottom,
      canvasTop: canvasRect.top,
      naturalToolbarHeight,
      rootBottom: rootRect.bottom,
      rootTop: rootRect.top,
      toolbarBottom: toolbarRect.bottom,
      toolbarHeight: toolbarRect.height,
    };
  });

  expect(layout).not.toBeNull();
  expect(Math.abs(layout!.rootTop)).toBeLessThanOrEqual(1);
  expect(
    Math.abs(layout!.rootBottom - (await page.evaluate(() => window.innerHeight))),
  ).toBeLessThanOrEqual(1);
  expect(Math.abs(layout!.toolbarHeight - layout!.naturalToolbarHeight)).toBeLessThanOrEqual(2);
  expect(Math.abs(layout!.canvasTop - layout!.toolbarBottom)).toBeLessThanOrEqual(1);
  expect(Math.abs(layout!.canvasBottom - layout!.rootBottom)).toBeLessThanOrEqual(1);
}
