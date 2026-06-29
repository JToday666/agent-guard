import { expect, test } from "@playwright/test";

test("approval desktop layout keeps queue and detail in separate scroll regions", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop");
  await page.goto("/approvals");

  const layout = page.locator(".approvals-layout");
  await expect(layout).toBeVisible();
  const state = await layout.evaluate((element) => {
    const queue = element.querySelector<HTMLElement>(".approval-queue");
    const detail = element.querySelector<HTMLElement>(".approval-detail");
    return {
      detailOverflow: detail ? getComputedStyle(detail).overflowY : "",
      gridColumns: getComputedStyle(element).gridTemplateColumns,
      layoutWidth: element.clientWidth,
      queueOverflow: queue ? getComputedStyle(queue).overflowY : "",
    };
  });

  expect(state.gridColumns.split(" ").length).toBeGreaterThanOrEqual(2);
  expect(state.layoutWidth).toBeGreaterThan(0);
  expect(state.queueOverflow).toBe("auto");
  expect(state.detailOverflow).toBe("auto");
});

test("primary dashboard routes do not overflow the viewport", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

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
    await expect(page.locator("main").first()).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  }
  expect(runtimeErrors).toEqual([]);
});

test("mobile investigation core columns fit without horizontal scrolling", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "mobile");
  await page.goto("/investigations");

  const dimensions = await page
    .locator(".event-table-wrap")
    .evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
});

test("top bar remains visible while the workspace scrolls", async ({
  page,
}) => {
  await page.goto("/overview");
  await page.evaluate(() =>
    window.scrollTo(0, document.documentElement.scrollHeight),
  );

  await expect
    .poll(async () => (await page.locator(".top-bar").boundingBox())?.y)
    .toBe(0);
});

test("desktop sidebar remains below the top bar while the workspace scrolls", async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop");
  await page.goto("/overview");
  await page.evaluate(() =>
    window.scrollTo(0, document.documentElement.scrollHeight),
  );

  const topBarBox = await page.locator(".top-bar").boundingBox();
  const sidebarBox = await page.locator(".sidebar").boundingBox();
  expect(
    Math.abs((sidebarBox?.y ?? 0) - (topBarBox?.height ?? 0)),
  ).toBeLessThanOrEqual(1);
});
