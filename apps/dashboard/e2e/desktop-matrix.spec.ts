import { expect, test } from "@playwright/test";

import { expectPrimaryRoutesLayout } from "./support/dashboard-layout";

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
