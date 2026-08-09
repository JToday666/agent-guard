import { expect, test } from "@playwright/test";

import { expectPrimaryRoutesLayout } from "./support/dashboard-layout";
import {
  expectExecutionFlowFullscreenLayout,
  expectExecutionFlowGeometry,
} from "./support/execution-flow-geometry";

test("primary routes remain usable across supported desktop workspaces", async ({ page }) => {
  await expectPrimaryRoutesLayout(page, "trace_002");
});

test("desktop shell keeps the required navigation order", async ({ page }) => {
  await page.goto("/overview");

  await expect(page.locator(".sidebar__link")).toHaveText([
    "安全总览",
    "事件调查",
    "人工审批1",
    "证据链",
    "安全评测",
    "系统状态",
  ]);
});

test("standard routes leave vertical scrolling to the document", async ({ page }) => {
  const routes = [
    ["/overview", ".overview-page"],
    ["/investigations", ".investigations-page__main"],
    ["/evidence", ".evidence-page"],
    ["/evidence/trace_002", ".evidence-detail__main"],
    ["/evaluation", ".evaluation-page"],
    ["/system", ".system-page"],
  ] as const;

  for (const [path, routeRoot] of routes) {
    await page.goto(path);
    await expect(page.locator(routeRoot)).toBeVisible();
    if (path === "/evidence/trace_002") {
      await expect(page.getByRole("tab", { name: "执行轨迹" })).toBeVisible();
    }

    const scrollState = await page.evaluate((selector) => {
      const workspace = document.querySelector<HTMLElement>(".dashboard-shell__workspace");
      const root = document.querySelector<HTMLElement>(selector);
      return {
        documentScrollable:
          document.documentElement.scrollHeight > document.documentElement.clientHeight,
        rootOverflowY: root ? getComputedStyle(root).overflowY : "missing",
        workspaceOverflowY: workspace ? getComputedStyle(workspace).overflowY : "missing",
      };
    }, routeRoot);

    expect(scrollState.workspaceOverflowY, path).toBe("visible");
    expect(scrollState.rootOverflowY, path).toBe("visible");
    if (path === "/evidence/trace_002") {
      expect(scrollState.documentScrollable, path).toBe(true);
    }
  }
});

test("execution graph geometry remains separated across desktop widths and sidebar states", async ({
  page,
}) => {
  await page.goto("/evidence/trace_008");
  const graph = page.locator(".execution-flow");
  await expectExecutionFlowGeometry(graph);

  await page.getByRole("button", { name: "收起侧栏" }).click();
  await expect(page.locator(".sidebar")).toHaveClass(/sidebar--collapsed/);
  await expectExecutionFlowGeometry(graph);

  await graph.getByRole("button", { name: "全屏" }).click();
  await expectExecutionFlowFullscreenLayout(page, graph);
  await expectExecutionFlowGeometry(graph);
  await page.keyboard.press("Escape");
  await expect(graph).not.toHaveClass(/execution-flow--fullscreen/);

  await page.goto("/evidence/trace_002");
  await expectExecutionFlowGeometry(page.locator(".execution-flow"));
});
